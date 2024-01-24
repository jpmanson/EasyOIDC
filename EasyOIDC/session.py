from redis_collections import Dict, List, Set
import shelve
import redis

class SessionHandler:
    def __init__(self, mode='redis', namespace='sessions', **kwargs):
        self.mode = mode
        if mode == 'redis':
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
            self.redis_dict = Dict(key=namespace)
        elif mode == 'shelve':
            filename = kwargs.get('filename', 'session_data/sessions.db')
            self.shelve_store = shelve.open(filename)
        else:
            raise Exception(f"Unknown mode: {mode}")

    def reset_keys(self):
        if self.mode == 'redis':
            self.redis_dict.clear()
        elif self.mode == 'shelve':
            self.shelve_store.clear()

    def set(self, key_name, value: any):
        if self.mode == 'redis':
            self.redis_dict[key_name] = value
            assert self.redis_dict[key_name] == value
        elif self.mode == 'shelve':
            self.shelve_store[key_name] = value

    def get(self, key_name, default=None):
        if self.mode == 'redis':
            if self.has_session_key(key_name):
                return self.redis_dict[key_name]
        elif self.mode == 'shelve':
            if key_name in self.shelve_store:
                return self.shelve_store[key_name]
        return default

    def has_session_key(self, key_name):
        if self.mode == 'redis':
            return key_name in self.redis_dict
        elif self.mode == 'shelve':
            return key_name in self.shelve_store
        return False

    def __setitem__(self, key_name: str, value: any):
        self.set(key_name, value)

    def __getitem__(self, key_name: str):
        return self.get(key_name)

    def __contains__(self, item):
        return self.has_session_key(item)

    def __delitem__(self, key_name: str):
        if self.mode == 'redis':
            del self.redis_dict[key_name]
        elif self.mode == 'shelve':
            del self.shelve_store[key_name]

    def keys(self):
        if self.mode == 'redis':
            return self.redis_dict.keys()
        elif self.mode == 'shelve':
            return self.shelve_store.keys()


if __name__ == '__main__':
    session_store = SessionHandler(mode='redis')
    print(session_store.get('test', 'default'))
    session_store.set('test', 'other')
    print(session_store.get('test', 'default'))