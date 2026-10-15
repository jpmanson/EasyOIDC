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


class SessionHandler:
    """Session storage for EasyOIDC.

    Available modes:
      - 'memory': in-memory dict guarded by a lock. Thread-safe and free of
        external dependencies. Ideal for development/testing. Sessions are lost
        when the process restarts.
      - 'shelve': on-disk persistence via the standard-library ``shelve``.
        Note: on Python 3.13+ the default backend (``dbm.sqlite3``) is not
        thread-safe, so it is unsuitable for multi-threaded WSGI servers.
      - 'redis': Redis persistence via ``redis-py`` (optional dependency).
        Install with: ``pip install easyoidc[redis]``. Sessions are stored as
        fields of a Redis hash (one key per ``namespace``), serialized with
        ``pickle``.

    In ``memory`` mode a warning is logged when the app seems to run in
    several processes (see :func:`detect_multiple_workers`): each process
    would have its own sessions, so logins and logouts break at random.
    """

    def __init__(self, mode='memory', namespace='sessions', **kwargs):
        self.mode = mode
        if mode == 'redis':
            # Deferred import: redis-py is an optional dependency. It is only
            # imported when the redis mode is actually used.
            try:
                import redis
            except ImportError as e:
                raise ImportError(
                    "The 'redis' mode requires the optional Redis "
                    "dependencies. Install with: pip install easyoidc[redis]"
                ) from e

            self.namespace = namespace
            if isinstance(kwargs.get('redis_client', None), redis.Redis):
                self.redis = kwargs['redis_client']  # User supplied redis instance
            else:
                # Create redis.StrictRedis instance
                redis_params = {}
                if 'host' in kwargs:
                    redis_params['host'] = kwargs['host']
                if 'port' in kwargs:
                    redis_params['port'] = kwargs['port']
                if 'db' in kwargs:
                    redis_params['db'] = kwargs['db']
                if 'password' in kwargs:
                    redis_params['password'] = kwargs['password']
                self.redis = redis.StrictRedis(**redis_params)
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

    def reset_keys(self):
        if self.mode == 'redis':
            self.redis.delete(self.namespace)
        elif self.mode == 'shelve':
            self.shelve_store.clear()
        elif self.mode == 'memory':
            with self._memory_lock:
                self._memory_store.clear()

    def set(self, key_name, value: any):
        if self.mode == 'redis':
            self.redis.hset(self.namespace, key_name, pickle.dumps(value))
        elif self.mode == 'shelve':
            self.shelve_store[key_name] = value
        elif self.mode == 'memory':
            with self._memory_lock:
                self._memory_store[key_name] = value

    def get(self, key_name, default=None):
        if self.mode == 'redis':
            raw = self.redis.hget(self.namespace, key_name)
            return pickle.loads(raw) if raw is not None else default
        elif self.mode == 'shelve':
            if key_name in self.shelve_store:
                return self.shelve_store[key_name]
        elif self.mode == 'memory':
            with self._memory_lock:
                return self._memory_store.get(key_name, default)
        return default

    def has_session_key(self, key_name):
        if self.mode == 'redis':
            return bool(self.redis.hexists(self.namespace, key_name))
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
            self.redis.hdel(self.namespace, key_name)
        elif self.mode == 'shelve':
            del self.shelve_store[key_name]
        elif self.mode == 'memory':
            with self._memory_lock:
                del self._memory_store[key_name]

    def keys(self):
        if self.mode == 'redis':
            return [k.decode() if isinstance(k, bytes) else k
                    for k in self.redis.hkeys(self.namespace)]
        elif self.mode == 'shelve':
            return self.shelve_store.keys()
        elif self.mode == 'memory':
            with self._memory_lock:
                return list(self._memory_store.keys())
