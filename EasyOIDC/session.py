import os
import pickle
import shelve
import threading


class SessionHandler:
    """Almacenamiento de sesiones para EasyOIDC.

    Modos disponibles:
      - 'memory': dict en memoria protegido por lock. Thread-safe y sin
        dependencias externas. Ideal para desarrollo/tests. Las sesiones se
        pierden al reiniciar el proceso.
      - 'shelve': persistencia en disco vía la librería estándar ``shelve``.
        Nota: en Python 3.13+ el backend por defecto (``dbm.sqlite3``) no es
        thread-safe, por lo que no conviene con servidores WSGI multihilo.
      - 'redis': persistencia en Redis vía ``redis-py`` (dependencia opcional).
        Instalar con: ``pip install easyoidc[redis]``. Las sesiones se guardan
        como campos de un hash de Redis (una clave por ``namespace``),
        serializadas con ``pickle``.
    """

    def __init__(self, mode='memory', namespace='sessions', **kwargs):
        self.mode = mode
        if mode == 'redis':
            # Import diferido: redis-py es una dependencia opcional. Solo se
            # importa si realmente se usa el modo redis.
            try:
                import redis
            except ImportError as e:
                raise ImportError(
                    "El modo 'redis' requiere las dependencias opcionales de "
                    "Redis. Instalá con: pip install easyoidc[redis]"
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
