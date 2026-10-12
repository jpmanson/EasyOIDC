"""Core (framework-agnostic) behaviour added in 0.4.0."""
import time
from urllib.parse import parse_qs, urlparse

import pytest

from EasyOIDC import Config, IDTokenValidationError, OIDClient
from EasyOIDC.utils import extract_roles, safe_redirect_path
from tests.fake_idp import CLIENT_ID, ISSUER, make_config


def _callback(idp, login):
    code, _ = idp.authorize(login['url'])
    return f"http://localhost:5000/authorize?code={code}&state={login['state']}"


def test_begin_login_sends_pkce_and_nonce(idp):
    client = OIDClient(make_config())
    login = client.begin_login()
    q = {k: v[0] for k, v in parse_qs(urlparse(login['url']).query).items()}
    assert q['code_challenge_method'] == 'S256'
    assert q['code_challenge'] and q['nonce'] == login['nonce']
    assert len(login['code_verifier']) >= 43


def test_complete_login_validates_signed_id_token(idp):
    client = OIDClient(make_config())
    login = client.begin_login()
    result = client.complete_login(_callback(idp, login), login)
    assert result['id_claims']['sub'] == 'user-1'
    assert result['id_claims']['nonce'] == login['nonce']
    assert result['userinfo']['email'] == 'u@example.com'
    assert idp.token_requests[-1]['code_verifier'] == login['code_verifier']


def test_pkce_wrong_verifier_is_rejected_by_idp(idp):
    client = OIDClient(make_config())
    login = client.begin_login()
    url = _callback(idp, login)
    with pytest.raises(Exception):
        client.complete_login(url, dict(login, code_verifier='x' * 64))


def test_nonce_mismatch_is_rejected(idp):
    idp.tamper_nonce = True
    client = OIDClient(make_config())
    login = client.begin_login()
    with pytest.raises(IDTokenValidationError):
        client.complete_login(_callback(idp, login), login)


@pytest.mark.parametrize('attr, value', [('issuer', 'https://evil'), ('audience', 'other-client')])
def test_wrong_iss_or_aud_is_rejected(idp, attr, value):
    setattr(idp, attr, value)
    client = OIDClient(make_config())
    login = client.begin_login()
    with pytest.raises(IDTokenValidationError):
        client.complete_login(_callback(idp, login), login)


def test_bad_signature_is_rejected(idp):
    from joserfc.jwk import KeySet, RSAKey
    client = OIDClient(make_config())
    login = client.begin_login()
    url = _callback(idp, login)
    other = KeySet([RSAKey.generate_key(2048, parameters={'kid': 'k1'})]).as_dict(private=False)
    idp.jwks = lambda: other
    with pytest.raises(IDTokenValidationError):
        client.complete_login(url, login)


def test_expired_login_is_rejected(idp):
    client = OIDClient(make_config(login_timeout_seconds=1))
    login = client.begin_login()
    login['created_at'] = time.time() - 10
    with pytest.raises(ValueError, match='expired'):
        client.complete_login(_callback(idp, login), login)


def test_pkce_and_nonce_can_be_disabled(idp):
    client = OIDClient(make_config(use_pkce=False, use_nonce=False))
    login = client.begin_login()
    assert 'code_challenge' not in login['url'] and 'nonce=' not in login['url']
    assert client.complete_login(_callback(idp, login), login)['userinfo']['sub'] == 'user-1'


def test_legacy_auth_server_login_still_works(idp):
    client = OIDClient(make_config())
    uri, state = client.auth_server_login()
    assert 'code_challenge' not in uri and f'state={state}' in uri
    code, _ = idp.authorize(uri)
    token, session = client.get_token(f'http://localhost:5000/authorize?code={code}&state={state}')
    assert client.get_user_info(session)['sub'] == 'user-1'


def test_refresh_if_needed(idp):
    client = OIDClient(make_config())
    fresh = {'access_token': 'a', 'refresh_token': 'r', 'expires_at': time.time() + 3600}
    assert client.refresh_if_needed(fresh) is None
    expired = {'access_token': 'a', 'refresh_token': 'r', 'id_token': 'idt', 'expires_at': time.time() - 5}
    new = client.refresh_if_needed(expired)
    assert new['refresh_token'] == 'rt-2' and new['id_token'] == 'idt'
    idp.refresh_ok = False
    with pytest.raises(Exception):
        client.refresh_if_needed(expired)


def test_keycloak_logout_url():
    client = OIDClient(make_config())
    url = client.get_keycloak_logout_url('a.b+c/d')
    assert 'client_id=cid' in url
    assert 'post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F' in url
    assert 'id_token_hint=a.b%2Bc%2Fd' in url
    assert 'id_token_hint' not in client.get_keycloak_logout_url(None)


@pytest.mark.parametrize('value, expected', [
    ('/ok?x=1', '/ok?x=1'), ('https://evil.com', '/'), ('//evil.com', '/'),
    ('/\\evil.com', '/'), ('', '/'), (None, '/'), ('relative', '/'), ('/a\r\nSet-Cookie:x', '/'),
])
def test_safe_redirect_path(value, expected):
    assert safe_redirect_path(value) == expected


def test_extract_roles_sources():
    claims = {'realm_access': {'roles': ['r1']},
              'resource_access': {'cid': {'roles': ['c1']}, 'other': {'roles': ['x']}}}
    assert extract_roles([claims], 'realm', 'cid') == ['r1']
    assert extract_roles([claims], 'client', 'cid') == ['c1']
    assert extract_roles([claims], 'realm+client', 'cid') == ['r1', 'c1']
    assert extract_roles([None, {}], 'client', 'cid') == []


def test_roles_from_access_token(idp):
    client = OIDClient(make_config(roles_source='client', roles_claims_from='userinfo,access_token'))
    idp.access_claims = {'resource_access': {CLIENT_ID: {'roles': ['app-user']}}}
    login = client.begin_login()
    result = client.complete_login(_callback(idp, login), login)
    assert client.roles_from_session(result) == ['app-user']


def test_config_from_env_file(tmp_path):
    env = tmp_path / '.env'
    env.write_text('\n'.join([
        'authorization_endpoint=https://idp.example.com/auth',
        'token_endpoint=https://idp.example.com/token',
        'userinfo_endpoint=https://idp.example.com/userinfo',
        'redirect_uri=http://localhost:5000/authorize',
        'client_id=cid', 'client_secret=s', 'cookie_secret_key=k', 'scope=openid,email',
        'use_pkce=false', 'roles_source=client', 'roles_claims_from=userinfo,access_token',
        'http_timeout=5',
    ]))
    cfg = Config(str(env))
    assert cfg.use_pkce is False and cfg.use_nonce is True
    assert cfg.roles_source == 'client'
    assert cfg.roles_claims_from == ['userinfo', 'access_token']
    assert cfg.http_timeout == 5.0


def test_invalid_roles_source():
    with pytest.raises(ValueError):
        make_config(roles_source='nope')


def test_issuer_constant():
    assert ISSUER.startswith('https://')
