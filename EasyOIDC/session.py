import json
import logging
import os
import pickle
import shelve
import sys
import threading

logger = logging.getLogger('EasyOIDC')


def _argv_workers(argv) -> int:
    """Worker count from ``--workers N`` / ``--workers=N`` / ``-w N`` /
    ``-wN`` in ``argv`` (uvicorn, gunicorn, hypercorn). 0 when absent."""
    for i, arg in enumerate(argv):
        value = None
        if arg in ('--workers', '-w') and i + 1 < len(argv):
            value = argv[i + 1]
        elif arg.startswith('--workers='):
            value = arg.split('=', 1)[1]
        elif arg.startswith('-w') and arg[2:].isdigit():
            value = arg[2:]
        if value is not None:
            try:
                return int(value)
            except ValueError:
                return 0
    return 0


def detect_multiple_workers(environ=None, argv=None) -> str:
    """Return why the app seems to run in several processes, or ``''``.

    Best effort: looks at ``WEB_CONCURRENCY`` (honoured by uvicorn and
    gunicorn) and at ``--workers`` / ``-w`` on the command line. Several
    processes started by hand on the same port can't be detected.
    """
    environ = os.environ if environ is None else environ
    argv = sys.argv if argv is None else argv
    try:
        if int(environ.get('WEB_CONCURRENCY') or 0) > 1:
            return f"WEB_CONCURRENCY={environ['WEB_CONCURRENCY']}"
    except ValueError:
        pass
    workers = _argv_workers(argv)
    if workers > 1:
        return f'{workers} workers on the command line'
    return ''


DEFAULT_REDIS_TTL = 14 * 24 * 60 * 60  # same as the FastAPI session cookie
DEFAULT_REDIS_TIMEOUT = 5
_REDIS_CLIENT_METHODS = ('get', 'set', 'delete', 'exists', 'scan_iter', 'ping')


def _escape_glob(text: str) -> str:
    return ''.join('\\' + c if c in '*?[]\\' else c for c in text)


class SessionHandler:
    """Session storage for EasyOIDC.

    Available modes:
      - 'memory': in-memory dict guarded by a lock. Thread-safe and free of
        external dependencies. Ideal for development/testing. Sessions are lost
        when the process restarts and are not shared between processes.
      - 'shelve': on-disk persistence via the standard-library ``shelve``.
        Note: on Python 3.13+ the default backend (``dbm.sqlite3``) is not
        thread-safe, so it is unsuitable for multi-threaded WSGI servers.
      - 'redis': Redis persistence via ``redis-py`` (optional dependency).
        Install with: ``pip install easyoidc[redis]``. Each session is its own
        key, ``{namespace}:{session id}``, holding JSON and expiring after
        ``ttl`` seconds (renewed on every write, e.g. a token refresh).

    Redis options (``mode='redis'``):
      - ``url``: ``redis://`` / ``rediss://`` URL (``redis.Redis.from_url``).
      - ``host``, ``port``, ``db``, ``username``, ``password``, ``ssl``,
        ``socket_timeout``, ``health_check_interval``, ...: any other keyword
        is passed to ``redis.Redis``. ``socket_timeout`` and
        ``socket_connect_timeout`` default to 5 seconds.
      - ``redis_client``: a ready client; any object with ``get``, ``set``,
        ``delete``, ``exists``, ``scan_iter`` and ``ping`` works.
      - ``ttl``: session lifetime in seconds (default 14 days, the FastAPI
        cookie lifetime). ``None`` or ``0`` = no expiry.
      - ``allow_pickle``: read sessions written by EasyOIDC < 0.5 (pickle
        values in the ``{namespace}`` hash) and move them to the new format.
        Only enable it while migrating: unpickling data from Redis lets
        whoever can write to Redis run code in the app.

    In ``memory`` mode a warning is logged when the app seems to run in
    several processes (see :func:`detect_multiple_workers`): each process
    would have its own sessions, so logins and logouts break at random.
    """

    def __init__(self, mode='memory', namespace='sessions', **kwargs):
        self.mode = mode
        if mode == 'redis':
            self._init_redis(namespace, **kwargs)
        elif mode == 'shelve':
            filename = kwargs.get('filename', 'session_data/sessions.db')
            directory = os.path.dirname(filename)
            if directory:
                os.makedirs(directory, exist_ok=True)
            self.shelve_store = shelve.open(filename)
        elif mode == 'memory':
            self._memory_store = {}
            self._memory_lock = threading.Lock()
            reason = detect_multiple_workers()
            if reason:
                logger.warning(f"SessionHandler(mode='memory') with several processes ({reason}): "
                               "sessions are not shared between them, so logins and logouts will "
                               "fail at random. Use mode='redis'.")
        else:
            raise Exception(f"Unknown mode: {mode}")

    # ------------------------------------------------------------------
    # Redis
    # ------------------------------------------------------------------
    def _init_redis(self, namespace, redis_client=None, url=None, ttl=DEFAULT_REDIS_TTL,
                    allow_pickle=False, **redis_kwargs):
        self.namespace = namespace
        self.ttl = int(ttl) if ttl else None
        self.allow_pickle = bool(allow_pickle)
        if redis_client is not None:
            missing = [m for m in _REDIS_CLIENT_METHODS if not callable(getattr(redis_client, m, None))]
            if missing:
                raise TypeError(f"redis_client lacks the methods: {', '.join(missing)}")
            self.redis = redis_client
        else:
            # Deferred import: redis-py is an optional dependency. It is only
            # imported when the redis mode is actually used.
            try:
                import redis
            except ImportError as e:
                raise ImportError(
                    "The 'redis' mode requires the optional Redis "
                    "dependencies. Install with: pip install easyoidc[redis]"
                ) from e
            redis_kwargs.setdefault('socket_timeout', DEFAULT_REDIS_TIMEOUT)
            redis_kwargs.setdefault('socket_connect_timeout', DEFAULT_REDIS_TIMEOUT)
            if url:
                self.redis = redis.Redis.from_url(url, **redis_kwargs)
            else:
                self.redis = redis.Redis(**redis_kwargs)
        if not self.allow_pickle:
            try:
                if self.redis.exists(self.namespace):
                    logger.warning(f"Redis key '{self.namespace}' holds sessions from EasyOIDC < 0.5; "
                                   "they are ignored (users log in again). Delete the key, or pass "
                                   "allow_pickle=True once to migrate them.")
            except Exception as e:
                logger.warning(f'Redis is not reachable: {e}')

    def _redis_key(self, key_name) -> str:
        return f'{self.namespace}:{key_name}'

    def _redis_pattern(self) -> str:
        return f'{_escape_glob(self.namespace)}:*'

    def _redis_legacy_pop(self, key_name):
        """Move a pre-0.5 session (pickle, in the namespace hash) to its own
        key. Only with ``allow_pickle``."""
        raw = self.redis.hget(self.namespace, key_name)
        if raw is None:
            return None
        value = pickle.loads(raw)  # noqa: S301 - opt-in, see allow_pickle
        self.redis.hdel(self.namespace, key_name)
        self.set(key_name, value)
        return value

    def ping(self) -> bool:
        """Health check: ``True`` when the store is usable. In redis mode a
        connection error is raised as is."""
        if self.mode == 'redis':
            return bool(self.redis.ping())
        return True

    def reset_keys(self):
        if self.mode == 'redis':
            for key in list(self.redis.scan_iter(match=self._redis_pattern())):
                self.redis.delete(key)
            self.redis.delete(self.namespace)  # pre-0.5 hash
        elif self.mode == 'shelve':
            self.shelve_store.clear()
        elif self.mode == 'memory':
            with self._memory_lock:
                self._memory_store.clear()

    def set(self, key_name, value: any):
        if self.mode == 'redis':
            self.redis.set(self._redis_key(key_name), json.dumps(value, separators=(',', ':')),
                           ex=self.ttl)
        elif self.mode == 'shelve':
            self.shelve_store[key_name] = value
        elif self.mode == 'memory':
            with self._memory_lock:
                self._memory_store[key_name] = value

    def get(self, key_name, default=None):
        if self.mode == 'redis':
            raw = self.redis.get(self._redis_key(key_name))
            if raw is not None:
                return json.loads(raw)
            if self.allow_pickle:
                value = self._redis_legacy_pop(key_name)
                if value is not None:
                    return value
            return default
        elif self.mode == 'shelve':
            if key_name in self.shelve_store:
                return self.shelve_store[key_name]
        elif self.mode == 'memory':
            with self._memory_lock:
                return self._memory_store.get(key_name, default)
        return default

    def has_session_key(self, key_name):
        if self.mode == 'redis':
            if self.redis.exists(self._redis_key(key_name)):
                return True
            return self.allow_pickle and bool(self.redis.hexists(self.namespace, key_name))
        elif self.mode == 'shelve':
            return key_name in self.shelve_store
        elif self.mode == 'memory':
            with self._memory_lock:
                return key_name in self._memory_store
        return False

    def __setitem__(self, key_name: str, value: any):
        self.set(key_name, value)

    def __getitem__(self, key_name: str):
        return self.get(key_name)

    def __contains__(self, item):
        return self.has_session_key(item)

    def __delitem__(self, key_name: str):
        if self.mode == 'redis':
            self.redis.delete(self._redis_key(key_name))
            if self.allow_pickle:
                self.redis.hdel(self.namespace, key_name)
        elif self.mode == 'shelve':
            del self.shelve_store[key_name]
        elif self.mode == 'memory':
            with self._memory_lock:
                del self._memory_store[key_name]

    def keys(self):
        if self.mode == 'redis':
            prefix = len(self.namespace) + 1
            return [(k.decode() if isinstance(k, bytes) else k)[prefix:]
                    for k in self.redis.scan_iter(match=self._redis_pattern())]
        elif self.mode == 'shelve':
            return self.shelve_store.keys()
        elif self.mode == 'memory':
            with self._memory_lock:
                return list(self._memory_store.keys())
