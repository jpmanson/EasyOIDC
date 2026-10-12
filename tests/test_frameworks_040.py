"""End-to-end FastAPI / Flask flows against the in-process fake IdP (0.4.0)."""
import time

import pytest

from EasyOIDC import SessionHandler
from tests.fake_idp import CLIENT_ID, make_config

fastapi = pytest.importorskip('fastapi')
pytest.importorskip('httpx')
from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from EasyOIDC.frameworks.fastapi import FastAPIOIDClient  # noqa: E402


def _fastapi_app(**kwargs):
    app = FastAPI()
    storage = SessionHandler(mode='memory')
    cfg_kwargs = kwargs.pop('config', {})
    auth = FastAPIOIDClient(app, auth_config=make_config(**cfg_kwargs), session_storage=storage,
                            validate_session_on_each_request=False, **kwargs)

    @app.get('/protected')
    def protected(request: Request):
        return {'user': auth.get_userinfo(request), 'roles': auth.get_user_roles(request)}

    return TestClient(app, base_url='http://localhost:5000', follow_redirects=False), auth, storage


def _fastapi_login(client, idp, next_path=None):
    url = '/login' + (f'?next={next_path}' if next_path else '')
    location = client.get(url).headers['location']
    code, q = idp.authorize(location)
    return client.get(f"/authorize?code={code}&state={q['state']}")


def test_full_flow_and_session_rotation(idp):
    client, _, storage = _fastapi_app()
    client.get('/login')
    pending_sid = next(iter(storage.keys()))
    location = client.get('/login').headers['location']
    assert pending_sid not in storage
    code, q = idp.authorize(location)
    response = client.get(f"/authorize?code={code}&state={q['state']}")
    assert response.status_code in (302, 307) and response.headers['location'] == '/'
    [sid] = list(storage.keys())
    assert sid != q['state']
    assert storage[sid]['id_claims']['sub'] == 'user-1'
    assert client.get('/protected').json()['user']['email'] == 'u@example.com'


def test_next_param_is_honoured_but_not_open(idp):
    client, _, _ = _fastapi_app()
    assert _fastapi_login(client, idp, '/protected').headers['location'] == '/protected'
    client2, _, _ = _fastapi_app()
    assert _fastapi_login(client2, idp, 'https://evil.com').headers['location'] == '/'


def test_middleware_remembers_requested_path(idp):
    client, _, _ = _fastapi_app()
    assert client.get('/protected?x=1').headers['location'] == '/login'
    location = client.get('/login').headers['location']
    code, q = idp.authorize(location)
    assert client.get(f"/authorize?code={code}&state={q['state']}").headers['location'] == '/protected?x=1'


def test_idp_error_does_not_loop(idp):
    client, _, _ = _fastapi_app()
    client.get('/login')
    response = client.get('/authorize?error=invalid_request&error_description=Missing+PKCE')
    assert response.status_code == 400
    assert 'Authentication error' in response.text


def test_required_roles_and_client_roles(idp):
    idp.claims['resource_access'] = {CLIENT_ID: {'roles': ['app-user']}}
    idp.claims['realm_access'] = {'roles': ['admin']}
    client, auth, storage = _fastapi_app(required_roles=['app-user'], config={'roles_source': 'client'})
    assert _fastapi_login(client, idp).status_code in (302, 307)
    assert client.get('/protected').json()['roles'] == ['app-user']


def test_missing_role_gets_403_with_logout_link(idp):
    client, _, storage = _fastapi_app(required_roles=['app-user'], config={'roles_source': 'client'})
    response = _fastapi_login(client, idp)
    assert response.status_code == 403
    assert 'id_token_hint=' in response.text and 'client_id=cid' in response.text
    assert list(storage.keys()) == []
    assert client.get('/protected').headers['location'] == '/login'


def test_email_verified_is_enforced(idp):
    idp.claims['email_verified'] = False
    client, _, _ = _fastapi_app(require_email_verified=True)
    assert _fastapi_login(client, idp).status_code == 403


def test_custom_roles_getter_and_denied_handler(idp):
    from fastapi.responses import JSONResponse
    idp.claims['groups'] = ['g1']
    client, _, _ = _fastapi_app(roles_getter=lambda u: u.get('groups', []), required_roles=['g2'],
                                access_denied_handler=lambda req, err, url: JSONResponse(
                                    {'reason': err.reason}, status_code=403))
    response = _fastapi_login(client, idp)
    assert response.json() == {'reason': 'missing_role'}


def test_expired_token_is_refreshed_and_persisted(idp):
    client, _, storage = _fastapi_app()
    _fastapi_login(client, idp)
    [sid] = list(storage.keys())
    data = storage[sid]
    data['token']['expires_at'] = time.time() - 10
    storage[sid] = data
    assert client.get('/protected').status_code == 200
    assert storage[sid]['token']['refresh_token'] == 'rt-2'
    assert storage[sid]['token']['expires_at'] > time.time()


def test_failed_refresh_drops_session(idp):
    client, _, storage = _fastapi_app()
    _fastapi_login(client, idp)
    [sid] = list(storage.keys())
    data = storage[sid]
    data['token']['expires_at'] = time.time() - 10
    storage[sid] = data
    idp.refresh_ok = False
    assert client.get('/protected').headers['location'] == '/login'
    assert sid not in storage


def test_role_removed_on_refresh_drops_session(idp):
    idp.claims['resource_access'] = {CLIENT_ID: {'roles': ['app-user']}}
    client, _, storage = _fastapi_app(required_roles=['app-user'], config={'roles_source': 'client'})
    _fastapi_login(client, idp)
    [sid] = list(storage.keys())
    data = storage[sid]
    data['token']['expires_at'] = time.time() - 10
    storage[sid] = data
    idp.claims['resource_access'] = {}
    assert client.get('/protected').headers['location'] == '/login'


def test_logout_url_for_keycloak_26(idp):
    client, _, storage = _fastapi_app()
    _fastapi_login(client, idp)
    location = client.get('/logout').headers['location']
    assert location.startswith('https://idp.example.com/logout?client_id=cid')
    assert 'id_token_hint=' in location
    assert list(storage.keys()) == []


def test_legacy_store_entry_still_authenticates(idp):
    """A 0.3.x store entry ({'userinfo', 'token'} keyed by the old OAuth
    state) is still a valid session after upgrading."""
    from EasyOIDC import OIDClient
    from EasyOIDC.flow import load_session
    client = OIDClient(make_config())
    storage = SessionHandler(mode='memory')
    storage['legacy-state'] = {'userinfo': {'sub': 'old', 'realm_access': {'roles': ['r']}},
                               'token': {'access_token': 'x'}}
    data = load_session(client, storage, 'legacy-state', client.roles_from_session)
    assert data['userinfo']['sub'] == 'old'
    assert data['roles'] == ['r']


# ----------------------------------------------------------------------
# Flask
# ----------------------------------------------------------------------
flask = pytest.importorskip('flask')
from flask import Flask  # noqa: E402

from EasyOIDC.frameworks.flask import FlaskOIDClient  # noqa: E402


def _flask_app(**kwargs):
    app = Flask(__name__)
    storage = SessionHandler(mode='memory')
    cfg_kwargs = kwargs.pop('config', {})
    auth = FlaskOIDClient(app, auth_config=make_config(**cfg_kwargs), session_storage=storage,
                          validate_session_on_each_request=False, **kwargs)

    @app.route('/')
    def root():
        return {'authenticated': auth.is_authenticated()}

    @app.route('/protected')
    def protected():
        return {'user': auth.get_userinfo(), 'roles': auth.get_user_roles()}

    @app.route('/admin')
    @auth.require_roles('/denied', or_allow_roles=['admin'])
    def admin():
        return 'admin'

    return app.test_client(), auth, storage


def _flask_login(client, idp):
    location = client.get('/login').headers['location']
    code, q = idp.authorize(location)
    return client.get(f"/authorize?code={code}&state={q['state']}")


def test_flask_anonymous_does_not_crash(idp):
    client, _, _ = _flask_app()
    assert client.get('/').get_json() == {'authenticated': False}
    assert client.get('/admin').status_code == 302


def test_flask_full_flow_pkce_and_redirect_back(idp):
    client, _, storage = _flask_app()
    response = client.get('/protected?x=1')
    assert response.headers['location'].endswith('/login')
    login = client.get('/login').headers['location']
    assert 'code_challenge_method=S256' in login and 'nonce=' in login
    code, q = idp.authorize(login)
    response = client.get(f"/authorize?code={code}&state={q['state']}")
    assert response.headers['location'].endswith('/protected?x=1')
    [sid] = list(storage.keys())
    assert sid != q['state']
    assert client.get('/protected').get_json()['user']['sub'] == 'user-1'


def test_flask_client_roles_and_required_roles(idp):
    idp.claims['resource_access'] = {CLIENT_ID: {'roles': ['admin']}}
    client, _, _ = _flask_app(required_roles=['admin'], config={'roles_source': 'client'})
    _flask_login(client, idp)
    assert client.get('/protected').get_json()['roles'] == ['admin']
    assert client.get('/admin').data == b'admin'


def test_flask_missing_role_is_403(idp):
    client, _, storage = _flask_app(required_roles=['admin'])
    assert _flask_login(client, idp).status_code == 403
    assert list(storage.keys()) == []


def test_flask_idp_error_is_400(idp):
    client, _, _ = _flask_app()
    client.get('/login')
    assert client.get('/authorize?error=access_denied').status_code == 400


def test_flask_logout(idp):
    client, _, storage = _flask_app()
    _flask_login(client, idp)
    location = client.get('/logout').headers['location']
    assert 'client_id=cid' in location and 'id_token_hint=' in location
    assert list(storage.keys()) == []
