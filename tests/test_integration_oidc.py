"""Test de integración del flujo OIDC completo contra un servidor real.

Usa `mock-oauth2-server` (ver ../test-oidc/docker-compose.yml), un OIDC
liviano y sin configuración. Se salta automáticamente si el servidor no está
accesible, así que no rompe la suite cuando el mock no está levantado.

Para correrlo localmente:

    cd test-oidc && docker compose up -d
    pytest tests/test_integration_oidc.py -v

La URL del discovery se puede sobreescribir con la variable de entorno
MOCK_OIDC_URL (útil en CI).
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
    reason=f'mock-oauth2-server no accesible en {MOCK_OIDC_URL}',
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
    """Simula el login interactivo del mock y devuelve la redirect_uri con ?code."""
    session.get(authorize_uri)  # carga la pantalla de login del mock
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

    # 1) Iniciar el login y obtener la URL de autorización + state
    authorize_uri, state = oidc_client.auth_server_login()
    assert 'client_id=easyoidc-test' in authorize_uri

    # 2) Completar el login en el mock con claims custom
    claims = '{"email":"test@example.com","realm_access":{"roles":["admin"]}}'
    redirect_url = _complete_mock_login(session, authorize_uri, 'testuser', claims)

    # 3) Verificar el callback: code presente y state que coincide
    query = parse_qs(urlparse(redirect_url).query)
    assert 'code' in query
    assert query['state'][0] == state

    # 4) Intercambiar el code por un token
    token, oauth_session = oidc_client.get_token(redirect_url)
    assert token['token_type'].lower() == 'bearer'
    assert token['access_token']
    assert 'id_token' in token

    # 5) Obtener userinfo y validar los claims
    userinfo = oidc_client.get_user_info(oauth_session)
    assert userinfo['sub'] == 'testuser'
    assert userinfo['email'] == 'test@example.com'
    assert userinfo['realm_access']['roles'] == ['admin']

    # 6) La sesión debe ser válida contra el servidor
    assert oidc_client.is_valid_oidc_session(oauth_session) is True
