"""0.4.2: issuer / jwks_uri are taken from discovery even when the endpoints
are configured explicitly (otherwise the ID token signature is not verified)."""
import pytest

from EasyOIDC import IDTokenValidationError, OIDClient
from tests.fake_idp import ISSUER, FakeResponse, make_config


@pytest.fixture
def discovery(idp, monkeypatch):
    import requests
    calls = []

    def fake_get(url, *args, **kwargs):
        url = str(url)
        calls.append(url)
        if url.endswith('/.well-known/openid-configuration'):
            return FakeResponse(200, {'issuer': idp.issuer_published,
                                      'jwks_uri': 'https://idp.example.com/certs'})
        if url.endswith('/certs'):
            return FakeResponse(200, idp.jwks())
        raise AssertionError(f'unexpected GET {url}')

    idp.issuer_published = ISSUER
    monkeypatch.setattr(requests, 'get', fake_get)
    return calls


def _explicit_config(**overrides):
    kwargs = dict(jwks_uri=None, issuer=None,
                  well_known_openid_url='https://idp.example.com/.well-known/openid-configuration')
    kwargs.update(overrides)
    return make_config(**kwargs)


def _login(client, idp):
    login = client.begin_login()
    code, _ = idp.authorize(login['url'])
    return client.complete_login(f"http://localhost:5000/authorize?code={code}&state={login['state']}", login)


def test_explicit_endpoints_still_get_issuer_and_jwks(idp, discovery):
    client = OIDClient(_explicit_config())
    assert client.get_config().jwks_uri is None
    assert _login(client, idp)['id_claims']['sub'] == 'user-1'
    assert client.get_config().issuer == ISSUER
    assert client.get_config().jwks_uri == 'https://idp.example.com/certs'


def test_signature_is_verified_with_explicit_endpoints(idp, discovery):
    from joserfc.jwk import KeySet, RSAKey
    other = KeySet([RSAKey.generate_key(2048, parameters={'kid': 'k1'})]).as_dict(private=False)
    idp.jwks = lambda: other
    with pytest.raises(IDTokenValidationError):
        _login(OIDClient(_explicit_config()), idp)


def test_issuer_is_checked_with_explicit_endpoints(idp, discovery):
    idp.issuer_published = 'https://other-realm'
    with pytest.raises(IDTokenValidationError):
        _login(OIDClient(_explicit_config()), idp)


def test_discovery_is_read_once(idp, discovery):
    client = OIDClient(_explicit_config())
    _login(client, idp)
    _login(client, idp)
    assert sum(u.endswith('openid-configuration') for u in discovery) == 1


def test_explicit_issuer_wins(idp, discovery):
    client = OIDClient(_explicit_config(issuer=ISSUER, jwks_uri='https://idp.example.com/certs'))
    _login(client, idp)
    assert not any(u.endswith('openid-configuration') for u in discovery)
