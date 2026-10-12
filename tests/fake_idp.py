"""In-process fake OIDC provider for the 0.4.0 tests.

It signs real RS256 ID tokens with a generated key and answers the token,
userinfo and JWKS endpoints by monkeypatching ``requests`` (used both by
EasyOIDC and by Authlib's ``requests_client``). No network or Docker needed.
"""
import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

ISSUER = 'https://idp.example.com/realms/test'
CLIENT_ID = 'cid'


class FakeResponse:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload
        self.text = json.dumps(payload)
        self.headers = {'Content-Type': 'application/json'}
        self.content = self.text.encode()

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f'{self.status_code}')


class FakeIdP:
    def __init__(self):
        self.key = RSAKey.generate_key(2048, parameters={'kid': 'k1'})
        self.keys = KeySet([self.key])
        self.codes = {}
        self.claims = {'sub': 'user-1', 'email': 'u@example.com', 'email_verified': True,
                       'name': 'User One'}
        self.access_claims = {}
        self.expires_in = 300
        self.refresh_ok = True
        self.userinfo_ok = True
        self.issued = []
        self.tamper_nonce = False
        self.issuer = ISSUER
        self.audience = CLIENT_ID
        self.token_requests = []

    def jwks(self):
        return self.keys.as_dict(private=False)

    def sign(self, claims):
        return jwt.encode({'alg': 'RS256', 'kid': 'k1'}, claims, self.keys)

    def authorize(self, authorize_url):
        q = {k: v[0] for k, v in parse_qs(urlparse(authorize_url).query).items()}
        code = f'code-{len(self.codes)}'
        self.codes[code] = q
        return code, q

    def _id_token(self, nonce):
        now = int(time.time())
        claims = dict(self.claims, iss=self.issuer, aud=self.audience, iat=now, exp=now + 300)
        if nonce:
            claims['nonce'] = 'tampered' if self.tamper_nonce else nonce
        return self.sign(claims)

    def _access_token(self):
        now = int(time.time())
        return self.sign(dict(self.access_claims, sub=self.claims['sub'], iss=self.issuer,
                              aud='account', iat=now, exp=now + self.expires_in))

    def token_endpoint(self, data):
        self.token_requests.append(dict(data))
        grant = data.get('grant_type')
        if grant == 'authorization_code':
            req = self.codes.pop(data.get('code'), None)
            if req is None:
                return FakeResponse(400, {'error': 'invalid_grant'})
            if req.get('code_challenge'):
                verifier = data.get('code_verifier') or ''
                digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
                if digest != req['code_challenge']:
                    return FakeResponse(400, {'error': 'invalid_grant', 'error_description': 'PKCE'})
            token = {'access_token': self._access_token(), 'token_type': 'Bearer',
                     'expires_in': self.expires_in, 'refresh_token': 'rt-1',
                     'id_token': self._id_token(req.get('nonce'))}
        elif grant == 'refresh_token':
            if not self.refresh_ok:
                return FakeResponse(400, {'error': 'invalid_grant'})
            token = {'access_token': self._access_token(), 'token_type': 'Bearer',
                     'expires_in': 300, 'refresh_token': 'rt-2'}
        else:
            return FakeResponse(400, {'error': 'unsupported_grant_type'})
        self.issued.append(token)
        return FakeResponse(200, token)


@pytest.fixture
def idp(monkeypatch):
    fake = FakeIdP()
    real_request = requests.Session.request

    def fake_session_request(self, method, url, *args, **kwargs):
        url = str(url)
        if url.startswith('https://idp.example.com'):
            if url.endswith('/token'):
                body = kwargs.get('data') or ''
                if isinstance(body, (bytes, str)):
                    data = {k: v[0] for k, v in parse_qs(body if isinstance(body, str) else body.decode()).items()}
                else:
                    data = dict(body)
                return fake.token_endpoint(data)
            if url.endswith('/userinfo'):
                if not fake.userinfo_ok:
                    return FakeResponse(401, {'error': 'invalid_token'})
                return FakeResponse(200, dict(fake.claims))
            if url.endswith('/certs'):
                return FakeResponse(200, fake.jwks())
        return real_request(self, method, url, *args, **kwargs)

    def fake_get(url, *args, **kwargs):
        if str(url).endswith('/certs'):
            return FakeResponse(200, fake.jwks())
        raise AssertionError(f'unexpected GET {url}')

    monkeypatch.setattr(requests.Session, 'request', fake_session_request)
    monkeypatch.setattr(requests, 'get', fake_get)
    return fake


def make_config(**overrides):
    from EasyOIDC import Config
    kwargs = dict(
        authorization_endpoint='https://idp.example.com/auth',
        token_endpoint='https://idp.example.com/token',
        userinfo_endpoint='https://idp.example.com/userinfo',
        jwks_uri='https://idp.example.com/certs',
        issuer=ISSUER,
        logout_endpoint='https://idp.example.com/logout',
        post_logout_uri='http://localhost:5000/',
        redirect_uri='http://localhost:5000/authorize',
        client_id=CLIENT_ID,
        client_secret='csecret',
        cookie_secret_key='super-secret',
        scope=['openid', 'profile', 'email'],
        unrestricted_routes=['/', '/public'],
    )
    kwargs.update(overrides)
    return Config(**kwargs)
