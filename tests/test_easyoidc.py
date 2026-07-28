import pytest
from EasyOIDC import OIDClient, SessionHandler, Config


def test_validate_config():
    # Setup a complete and valid configuration
    valid_config = Config()
    valid_config.authorization_endpoint = 'https://example.com/auth'
    valid_config.token_endpoint = 'https://example.com/token'
    valid_config.userinfo_endpoint = 'https://example.com/userinfo'
    valid_config.redirect_uri = 'https://example.com/redirect'
    valid_config.client_id = 'client-id'
    valid_config.client_secret = 'client-secret'
    valid_config.cookie_secret_key = 'secret-key'
    valid_config.scope = ['openid']

    client = OIDClient(valid_config)
    # No exception should be raised
    valid_config.is_valid_config()

    # Setup an invalid configuration (missing client_id)
    invalid_config = Config()
    invalid_config.authorization_endpoint = 'https://example.com/auth'
    # ... other configurations except client_id

    with pytest.raises(Exception):
        client = OIDClient(invalid_config)

    valid_config = Config(well_known_openid_url='https://accounts.google.com/.well-known/openid-configuration',
                          redirect_uri='https://example.com/redirect',
                          client_id='client-id',
                          client_secret='client-secret',
                          cookie_secret_key='secret-key')
    client = OIDClient(valid_config)


def _exercise_store(session_store):
    session_store.reset_keys()
    assert session_store.get('test', 'default') == 'default'
    session_store.set('test', 'other')
    assert session_store.get('test', 'default') == 'other'
    assert 'test' in session_store
    del session_store['test']
    assert 'test' not in session_store


def test_session_storage_memory():
    _exercise_store(SessionHandler(mode='memory'))


def test_session_storage_shelve(tmp_path):
    _exercise_store(SessionHandler(mode='shelve', filename=str(tmp_path / 'sessions.db')))


def test_session_storage_redis():
    # redis mode: requires redis-py (optional extra) and a reachable Redis.
    pytest.importorskip('redis')
    import redis
    try:
        redis.StrictRedis().ping()
    except Exception:
        pytest.skip('No reachable Redis server')
    _exercise_store(SessionHandler(mode='redis'))


def test_session_storage_redis_missing_dep(monkeypatch):
    # Without redis-py installed, redis mode must raise a clear error.
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == 'redis':
            raise ImportError(f"No module named '{name}'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, '__import__', fake_import)
    with pytest.raises(ImportError, match='easyoidc\\[redis\\]'):
        SessionHandler(mode='redis')