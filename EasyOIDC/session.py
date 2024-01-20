from redis_collections import Dict, List, Set


class SessionHandler:
    def __init__(self, mode='redis', namespace='session'):
        self.mode = mode
        if mode == 'redis':
            self.redis_dict = Dict(key=namespace)

    def set(self, key_name, value: any):
        if self.mode == 'redis':
            self.redis_dict[key_name] = value
            assert self.redis_dict[key_name] == value

    def get(self, key_name, default=None):
        if self.mode == 'redis':
            if self.has_session_key(key_name):
                return self.redis_dict[key_name]
        return default

    def has_session_key(self, key_name):
        if self.mode == 'redis':
            return key_name in self.redis_dict
        return False

    def __setitem__(self, key_name: str, value: any):
        self.set(key_name, value)

    def __getitem__(self, key_name: str):
        return self.get(key_name)

    def __contains__(self, item):
        return self.has_session_key(item)

    def keys(self):
        if self.mode == 'redis':
            return self.redis_dict.keys()


if __name__ == '__main__':
    session_store = SessionHandler(mode='redis')
    print(session_store.get('test', 'default'))
    session_store.set('test', 'other')
    print(session_store.get('test', 'default'))