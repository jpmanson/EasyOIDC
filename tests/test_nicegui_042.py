"""NiceGUI integration end-to-end against the fake IdP (0.4.2).

Builds a real NiceGUI app (``ui.run_with`` on a FastAPI app) so the
``RequestTrackingMiddleware`` and ``app.storage.user`` behave as in
production, then drives the OIDC flow with Starlette's TestClient.
"""
import pytest

nicegui = pytest.importorskip('nicegui')
pytest.importorskip('httpx')

from tests.fake_idp import CLIENT_ID, make_config  # noqa: E402


@pytest.fixture
def nicegui_app(idp, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from nicegui import app as ng_app, ui

    from EasyOIDC import SessionHandler
    from EasyOIDC.frameworks.nicegui import NiceGUIOIDClient

    def build(**kwargs):
        cfg_kwargs = kwargs.pop('config', {})
        storage = SessionHandler(mode='memory')
        auth = NiceGUIOIDClient(ng_app, auth_config=make_config(**cfg_kwargs), session_storage=storage,
                                validate_session_on_each_request=False, **kwargs)

        @ng_app.get('/protected')
        def protected():
            return {'user': auth.get_userinfo(), 'roles': auth.get_user_roles()}

        host = FastAPI()
        ui.run_with(host, storage_secret='test-secret')
        return TestClient(host, base_url='http://localhost:5000', follow_redirects=False), auth, storage

    yield build


def _login(client, idp):
    location = client.get('/login').headers['location']
    code, q = idp.authorize(location)
    return client.get(f"/authorize?code={code}&state={q['state']}")


def test_nicegui_flow(nicegui_app, idp):
    """One test: NiceGUI's global app can only be wired once per process."""
    idp.claims['resource_access'] = {CLIENT_ID: {'roles': ['app-user']}}
    client, auth, storage = nicegui_app(required_roles=['app-user'], config={'roles_source': 'client'})

    assert client.get('/protected').headers['location'] == '/login'

    login = client.get('/login').headers['location']
    assert 'code_challenge_method=S256' in login and 'nonce=' in login
    code, q = idp.authorize(login)
    response = client.get(f"/authorize?code={code}&state={q['state']}")
    assert response.status_code in (302, 307), response.text
    assert response.headers['location'] == '/protected'

    [sid] = list(storage.keys())
    assert sid != q['state']
    body = client.get('/protected').json()
    assert body['user']['sub'] == 'user-1'
    assert body['roles'] == ['app-user']

    logout = client.get('/logout').headers['location']
    assert 'client_id=cid' in logout and 'id_token_hint=' in logout
    assert list(storage.keys()) == []
    assert client.get('/protected').headers['location'] == '/login'

    idp.claims['resource_access'] = {}
    response = _login(client, idp)
    assert response.status_code == 403
    assert list(storage.keys()) == []

    client.get('/login')
    assert client.get('/authorize?error=access_denied').status_code == 400
