"""Public helpers added in 0.5.1: login_url, session_storage/count and the
provider-neutral logout URL."""
from EasyOIDC import OIDClient, SessionHandler
from tests.fake_idp import make_config


def test_login_url():
    client = OIDClient(make_config())
    assert client.login_url() == '/login'
    assert client.login_url('/') == '/login?next=/'
    assert client.login_url('/reports?id=1&x=a b') == '/login?next=/reports%3Fid%3D1%26x%3Da%20b'


def test_login_url_custom_route():
    client = OIDClient(make_config(app_login_route='/auth/login'))
    assert client.login_url('/home') == '/auth/login?next=/home'


def test_session_storage_and_count():
    assert OIDClient(make_config()).session_storage is None
    store = SessionHandler(mode='memory')
    assert store.count() == 0 and bool(store) is True
    store['a'] = {}
    store['b'] = {}
    assert store.count() == 2


def test_rp_initiated_logout_for_any_provider_with_end_session_endpoint():
    for service in ('keycloak', 'google', 'entra'):
        client = OIDClient(make_config(auth_service=service))
        url = client.get_logout_url('tok')
        assert url.startswith('https://idp.example.com/logout?client_id=cid') and 'id_token_hint=tok' in url
        assert url == client.get_rp_initiated_logout_url('tok') == client.get_keycloak_logout_url('tok')


def test_no_logout_endpoint_means_no_idp_logout():
    client = OIDClient(make_config(auth_service='google', logout_endpoint=None))
    assert client.get_logout_url('tok') is None


def test_auth0_logout_is_unchanged():
    client = OIDClient(make_config(auth_service='auth0'))
    assert client.get_logout_url('tok').startswith('https://idp.example.com/logout?returnTo=')
