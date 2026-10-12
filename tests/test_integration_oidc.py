"""Integration test for the full OIDC flow against a real server.

Uses `mock-oauth2-server` (see ../test-oidc/docker-compose.yml), a lightweight,
zero-config OIDC server. It is skipped automatically when the server isn't
reachable, so it doesn't break the suite when the mock is not running.

To run it locally:

    cd test-oidc && docker compose up -d
    pytest tests/test_integration_oidc.py -v

The discovery URL can be overridden with the MOCK_OIDC_URL environment variable
(useful in CI).
"""
import os
from urllib.parse import urlparse, parse_qs

import pytest
import requests

from EasyOIDC import Config, OIDClient

MOCK_OIDC_URL = os.environ.get(
    'MOCK_OIDC_URL',
    'http://localhost:8080/default/.well-known/openid-configuration',
)


def _mock_available() -> bool:
    try:
        return requests.get(MOCK_OIDC_URL, timeout=2).status_code == 200
    except requests.RequestException:
        return False


pytestmark = pytest.mark.skipif(
    not _mock_available(),
    reason=f'mock-oauth2-server not reachable at {MOCK_OIDC_URL}',
)


@pytest.fixture
def oidc_client() -> OIDClient:
    config = Config(
        well_known_openid_url=MOCK_OIDC_URL,
        redirect_uri='http://localhost:5000/authorize',
        client_id='easyoidc-test',
        client_secret='easyoidc-secret',
        cookie_secret_key='test-secret',
        scope=['openid', 'profile', 'email'],
    )
    return OIDClient(config)


def _complete_mock_login(session: requests.Session, authorize_uri: str,
                         username: str, claims: str) -> str:
    """Simulate the mock's interactive login and return the redirect_uri with ?code."""
    session.get(authorize_uri)  # load the mock's login screen
    response = session.post(
        authorize_uri,
        data={'username': username, 'claims': claims},
        allow_redirects=False,
    )
    assert response.status_code in (302, 303), response.text
    return response.headers['Location']


def test_discovery_resolves_endpoints(oidc_client):
    config = oidc_client.get_config()
    assert config.authorization_endpoint.startswith('http')
    assert config.token_endpoint.startswith('http')
    assert config.userinfo_endpoint.startswith('http')


def test_full_authorization_code_flow(oidc_client):
    session = requests.Session()

    # 1) Start the login and get the authorization URL + state
    authorize_uri, state = oidc_client.auth_server_login()
    assert 'client_id=easyoidc-test' in authorize_uri

    # 2) Complete the login on the mock with custom claims
    claims = '{"email":"test@example.com","realm_access":{"roles":["admin"]}}'
    redirect_url = _complete_mock_login(session, authorize_uri, 'testuser', claims)

    # 3) Verify the callback: code present and matching state
    query = parse_qs(urlparse(redirect_url).query)
    assert 'code' in query
    assert query['state'][0] == state

    # 4) Exchange the code for a token
    token, oauth_session = oidc_client.get_token(redirect_url)
    assert token['token_type'].lower() == 'bearer'
    assert token['access_token']
    assert 'id_token' in token

    # 5) Fetch userinfo and validate the claims
    userinfo = oidc_client.get_user_info(oauth_session)
    assert userinfo['sub'] == 'testuser'
    assert userinfo['email'] == 'test@example.com'
    assert userinfo['realm_access']['roles'] == ['admin']

    # 6) The session must be valid against the server
    assert oidc_client.is_valid_oidc_session(oauth_session) is True


def test_full_flow_with_pkce_nonce_and_id_token_validation(oidc_client):
    """0.4.0 flow: PKCE S256 + nonce + signed ID token checked against JWKS."""
    session = requests.Session()
    login = oidc_client.begin_login()
    assert 'code_challenge_method=S256' in login['url']
    assert f"nonce={login['nonce']}" in login['url']

    claims = '{"email":"test@example.com","email_verified":true}'
    redirect_url = _complete_mock_login(session, login['url'], 'testuser', claims)

    result = oidc_client.complete_login(redirect_url, login)
    assert result['id_claims']['sub'] == 'testuser'
    assert result['id_claims']['nonce'] == login['nonce']
    assert result['userinfo']['email'] == 'test@example.com'


def test_tampered_nonce_is_rejected(oidc_client):
    from EasyOIDC import IDTokenValidationError
    session = requests.Session()
    login = oidc_client.begin_login()
    redirect_url = _complete_mock_login(session, login['url'], 'testuser', '{}')
    with pytest.raises(IDTokenValidationError):
        oidc_client.complete_login(redirect_url, dict(login, nonce='not-the-one-sent'))
