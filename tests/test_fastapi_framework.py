"""Tests for the FastAPI integration.

They exercise the middleware, the OIDC routes, the dependencies and the
role-based access control without touching a real OIDC server: the token
validation round-trip is disabled with ``validate_session_on_each_request=False``
and the server-side session store is populated directly.
"""
import pytest

pytest.importorskip('fastapi')
pytest.importorskip('itsdangerous')
# Starlette's TestClient is built on httpx
pytest.importorskip('httpx')

from fastapi import Depends, FastAPI, Request           # noqa: E402
from fastapi.testclient import TestClient               # noqa: E402

from EasyOIDC import Config, SessionHandler             # noqa: E402
from EasyOIDC.frameworks.fastapi import FastAPIOIDClient  # noqa: E402

ADMIN_USERINFO = {
    'sub': 'testuser',
    'email': 'test@example.com',
    'realm_access': {'roles': ['admin']},
}


@pytest.fixture
def auth_config() -> Config:
    return Config(
        authorization_endpoint='https://oidc.example.com/auth',
        token_endpoint='https://oidc.example.com/token',
        userinfo_endpoint='https://oidc.example.com/userinfo',
        redirect_uri='http://localhost:5000/authorize',
        client_id='cid',
        client_secret='csecret',
        cookie_secret_key='super-secret',
        scope=['openid', 'profile', 'email'],
        unrestricted_routes=['/', '/public'],
    )


@pytest.fixture
def app_ctx(auth_config):
    """Build an app wired to EasyOIDC and return (client, auth, storage)."""
    app = FastAPI()
    storage = SessionHandler(mode='memory')
    auth = FastAPIOIDClient(app, auth_config=auth_config, session_storage=storage,
                            validate_session_on_each_request=False)

    @app.get('/')
    def root(request: Request):
        return {'authenticated': auth.is_authenticated(request)}

    @app.get('/public')
    def public():
        return {'ok': 'public'}

    @app.get('/protected')
    def protected(request: Request):
        return {'user': auth.get_userinfo(request)}

    @app.get('/me')
    def me(user: dict = Depends(auth.current_user)):
        return {'user': user}

    @app.get('/private')
    def private(user: dict = Depends(auth.require_user)):
        return {'user': user}

    @app.get('/admin')
    @auth.require_roles('/denied', and_allow_roles=['admin'])
    def admin():
        return {'ok': 'admin'}

    @app.get('/admin-async')
    @auth.require_roles('/denied', or_allow_roles=['admin', 'staff'])
    async def admin_async(request: Request):
        return {'ok': 'admin-async', 'roles': auth.get_user_roles(request)}

    @app.get('/denied')
    def denied():
        return {'error': 'access denied'}

    return TestClient(app, follow_redirects=False), auth, storage


def _login_and_authenticate(client, storage, userinfo=None):
    """Run the /login leg and fake the server's answer in the session store."""
    response = client.get('/login')
    assert response.status_code in (302, 307)
    state = next(iter(storage.keys()))
    storage[state] = {
        'userinfo': userinfo if userinfo is not None else ADMIN_USERINFO,
        'token': {'access_token': 'fake-token', 'id_token': 'fake-id-token'},
    }
    return state


def test_unrestricted_routes_are_reachable_anonymously(app_ctx):
    client, _, _ = app_ctx
    assert client.get('/').json() == {'authenticated': False}
    assert client.get('/public').json() == {'ok': 'public'}


def test_restricted_route_redirects_to_login(app_ctx):
    client, _, _ = app_ctx
    response = client.get('/protected')
    assert response.status_code in (302, 307)
    assert response.headers['location'] == '/login'


def test_login_redirects_to_authorization_endpoint(app_ctx):
    client, _, storage = app_ctx
    response = client.get('/login')
    location = response.headers['location']
    assert response.status_code in (302, 307)
    assert location.startswith('https://oidc.example.com/auth')
    assert 'client_id=cid' in location
    assert 'state=' in location
    # The state is registered in the server-side store, still unauthenticated
    state = next(iter(storage.keys()))
    assert storage[state] == {'userinfo': None, 'token': None}


def test_authorize_route_rejects_state_mismatch(app_ctx):
    client, _, _ = app_ctx
    client.get('/login')
    response = client.get('/authorize?state=not-the-stored-one&code=abc')
    assert response.status_code in (302, 307)
    assert response.headers['location'] == '/login'


def test_authenticated_session_reaches_protected_route(app_ctx):
    client, _, storage = app_ctx
    _login_and_authenticate(client, storage)
    response = client.get('/protected')
    assert response.status_code == 200
    assert response.json()['user']['sub'] == 'testuser'


def test_current_user_dependency(app_ctx):
    client, _, storage = app_ctx
    assert client.get('/me').status_code in (302, 307)  # anonymous -> login
    _login_and_authenticate(client, storage)
    assert client.get('/me').json()['user']['email'] == 'test@example.com'


def test_require_user_dependency(app_ctx):
    client, _, storage = app_ctx
    _login_and_authenticate(client, storage)
    assert client.get('/private').status_code == 200


def test_require_roles_allows_matching_role(app_ctx):
    client, _, storage = app_ctx
    _login_and_authenticate(client, storage)
    assert client.get('/admin').json() == {'ok': 'admin'}
    assert client.get('/admin-async').json()['roles'] == ['admin']


def test_require_roles_denies_missing_role(app_ctx):
    client, _, storage = app_ctx
    _login_and_authenticate(client, storage,
                            userinfo={'sub': 'guest', 'realm_access': {'roles': ['guest']}})
    for route in ('/admin', '/admin-async'):
        response = client.get(route)
        assert response.status_code in (302, 307)
        assert response.headers['location'] == '/denied'


def test_oidc_routes_are_not_exposed_in_openapi(app_ctx):
    client, _, storage = app_ctx
    _login_and_authenticate(client, storage)
    paths = client.get('/openapi.json').json()['paths']
    for route in ('/login', '/logout', '/authorize'):
        assert route not in paths


def test_docs_routes_are_protected_by_default(app_ctx):
    """FastAPI's /docs and /openapi.json are ordinary routes, so the middleware
    guards them unless they are listed as unrestricted."""
    client, _, _ = app_ctx
    for route in ('/docs', '/openapi.json'):
        assert client.get(route).status_code in (302, 307)


def test_logout_clears_the_session(app_ctx):
    client, _, storage = app_ctx
    _login_and_authenticate(client, storage)
    assert client.get('/protected').status_code == 200

    response = client.get('/logout')
    assert response.status_code in (302, 307)
    assert list(storage.keys()) == []

    # Back to being anonymous
    assert client.get('/protected').headers['location'] == '/login'


def test_missing_cookie_secret_key_is_rejected(auth_config):
    """A signing key is mandatory: the session cookie is signed with it."""
    auth_config.cookie_secret_key = None
    with pytest.raises(Exception, match='configuration'):
        FastAPIOIDClient(FastAPI(), auth_config=auth_config,
                         session_storage=SessionHandler(mode='memory'))


def test_session_middleware_wraps_the_auth_middleware(auth_config):
    """SessionMiddleware must end up outside AuthMiddleware, otherwise
    `request.session` would not exist yet when authentication runs. In
    Starlette's user_middleware list, index 0 is the outermost layer."""
    app = FastAPI()
    FastAPIOIDClient(app, auth_config=auth_config,
                     session_storage=SessionHandler(mode='memory'),
                     validate_session_on_each_request=False)
    installed = [m.cls.__name__ for m in app.user_middleware]
    assert installed.index('SessionMiddleware') < installed.index('AuthMiddleware')


def test_app_can_provide_its_own_session_middleware(auth_config):
    """With add_session_middleware=False EasyOIDC does not install Starlette's
    SessionMiddleware. The app must then add it AFTER building the client, so it
    still wraps the authentication middleware."""
    from starlette.middleware.sessions import SessionMiddleware

    app = FastAPI()
    auth = FastAPIOIDClient(app, auth_config=auth_config,
                            session_storage=SessionHandler(mode='memory'),
                            add_session_middleware=False,
                            validate_session_on_each_request=False)
    app.add_middleware(SessionMiddleware, secret_key='app-owned-secret')

    installed = [m.cls.__name__ for m in app.user_middleware]
    assert installed.count('SessionMiddleware') == 1
    assert installed.index('SessionMiddleware') < installed.index('AuthMiddleware')

    @app.get('/protected')
    def protected(request: Request):
        return {'user': auth.get_userinfo(request)}

    client = TestClient(app, follow_redirects=False)
    assert client.get('/protected').headers['location'] == '/login'


def test_missing_session_middleware_raises_a_clear_error(auth_config):
    """Without any SessionMiddleware installed, the failure must be explicit."""
    app = FastAPI()
    FastAPIOIDClient(app, auth_config=auth_config,
                     session_storage=SessionHandler(mode='memory'),
                     add_session_middleware=False,
                     validate_session_on_each_request=False)

    @app.get('/protected')
    def protected():
        return {'ok': True}

    client = TestClient(app, follow_redirects=False)
    with pytest.raises(RuntimeError, match='SessionMiddleware'):
        client.get('/protected')
