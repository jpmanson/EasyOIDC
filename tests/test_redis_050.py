"""Redis session storage (0.5.0): one key per session with TTL, JSON values,
connection options. Runs against a real Redis (``EASYOIDC_TEST_REDIS_URL``,
default db 15 on localhost) and is skipped when none is reachable."""
import json
import logging
import os
import pickle

import pytest

from EasyOIDC import SessionHandler

redis = pytest.importorskip('redis')

REDIS_URL = os.environ.get('EASYOIDC_TEST_REDIS_URL', 'redis://localhost:6379/15')
NS = 'easyoidc-test'


@pytest.fixture
def r():
    client = redis.Redis.from_url(REDIS_URL, socket_connect_timeout=2)
    try:
        client.ping()
    except Exception:
        pytest.skip(f'No reachable Redis at {REDIS_URL}')
    _clean(client)
    yield client
    _clean(client)


def _clean(client):
    for key in client.scan_iter(match=f'{NS}*'):
        client.delete(key)


def _store(**kwargs):
    return SessionHandler(mode='redis', namespace=NS, url=REDIS_URL, **kwargs)


def test_one_json_key_per_session_with_ttl(r):
    store = _store(ttl=120)
    store['sid-1'] = {'userinfo': {'sub': 'u'}, 'roles': ['a'], 'n': 1.5}
    assert json.loads(r.get(f'{NS}:sid-1')) == store['sid-1']
    assert 0 < r.ttl(f'{NS}:sid-1') <= 120
    assert not r.exists(NS)
    assert 'sid-1' in store and 'other' not in store
    assert store.get('other', 'default') == 'default'


def test_ttl_is_renewed_on_write(r):
    store = _store(ttl=120)
    store['sid-1'] = {'a': 1}
    r.expire(f'{NS}:sid-1', 5)
    store['sid-1'] = {'a': 2}
    assert r.ttl(f'{NS}:sid-1') > 5


def test_ttl_none_means_no_expiry(r):
    store = _store(ttl=None)
    store['sid-1'] = {'a': 1}
    assert r.ttl(f'{NS}:sid-1') == -1


def test_default_ttl_is_14_days(r):
    _store()['sid-1'] = {'a': 1}
    assert 13 * 24 * 3600 < r.ttl(f'{NS}:sid-1') <= 14 * 24 * 3600


def test_keys_delete_and_reset_only_touch_the_namespace(r):
    store = _store()
    store['a'] = {}
    store['b'] = {}
    r.set(f'{NS}x:other', '1')
    assert sorted(store.keys()) == ['a', 'b']
    del store['a']
    assert store.keys() == ['b']
    store.reset_keys()
    assert store.keys() == [] and r.exists(f'{NS}x:other')


def test_legacy_pickle_hash_is_ignored_and_reported(r, caplog):
    r.hset(NS, 'old-sid', pickle.dumps({'userinfo': {'sub': 'u'}}))
    with caplog.at_level(logging.WARNING, logger='EasyOIDC'):
        store = _store()
    assert 'allow_pickle' in caplog.text
    assert 'old-sid' not in store and store.get('old-sid') is None


def test_legacy_pickle_hash_is_migrated_with_allow_pickle(r):
    r.hset(NS, 'old-sid', pickle.dumps({'userinfo': {'sub': 'u'}}))
    store = _store(allow_pickle=True)
    assert 'old-sid' in store
    assert store['old-sid'] == {'userinfo': {'sub': 'u'}}
    assert json.loads(r.get(f'{NS}:old-sid')) == {'userinfo': {'sub': 'u'}}
    assert not r.hexists(NS, 'old-sid')


def test_ping_and_default_timeouts(r):
    store = _store()
    assert store.ping() is True
    kwargs = store.redis.connection_pool.connection_kwargs
    assert kwargs['socket_timeout'] == 5 and kwargs['socket_connect_timeout'] == 5
    assert _store(socket_timeout=1).redis.connection_pool.connection_kwargs['socket_timeout'] == 1


def test_host_port_db_kwargs(r):
    pool = r.connection_pool.connection_kwargs
    store = SessionHandler(mode='redis', namespace=NS, host=pool['host'], port=pool['port'], db=pool['db'])
    store['sid-1'] = {'a': 1}
    assert r.exists(f'{NS}:sid-1')


def test_duck_typed_client_is_accepted(r):
    class Wrapper:
        def __init__(self, inner):
            self._inner = inner

        def __getattr__(self, name):
            return getattr(self._inner, name)

    store = SessionHandler(mode='redis', namespace=NS, redis_client=Wrapper(r))
    store['sid-1'] = {'a': 1}
    assert store['sid-1'] == {'a': 1}


def test_client_without_redis_methods_is_rejected():
    with pytest.raises(TypeError, match='scan_iter'):
        SessionHandler(mode='redis', namespace=NS, redis_client=object())


def test_ping_without_redis_modes():
    assert SessionHandler(mode='memory').ping() is True


def test_full_login_logout_with_redis(r, idp):
    """Real session data (tokens, claims, roles) round-trips through JSON."""
    pytest.importorskip('fastapi')
    pytest.importorskip('httpx')
    from fastapi import FastAPI, Request
    from fastapi.testclient import TestClient

    from EasyOIDC.frameworks.fastapi import FastAPIOIDClient
    from tests.fake_idp import make_config

    app = FastAPI()
    store = _store()
    auth = FastAPIOIDClient(app, auth_config=make_config(), session_storage=store,
                            validate_session_on_each_request=False)

    @app.get('/protected')
    def protected(request: Request):
        return {'user': auth.get_userinfo(request)}

    client = TestClient(app, base_url='http://localhost:5000', follow_redirects=False)
    code, q = idp.authorize(client.get('/login').headers['location'])
    client.get(f"/authorize?code={code}&state={q['state']}")
    [sid] = store.keys()
    assert store[sid]['id_claims']['sub'] == 'user-1'
    assert client.get('/protected').json()['user']['email'] == 'u@example.com'
    assert 'id_token_hint=' in client.get('/logout').headers['location']
    assert store.keys() == []
