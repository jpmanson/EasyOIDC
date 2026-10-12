import logging
import time
from functools import wraps
from typing import Callable, Optional
from urllib.parse import quote, quote_plus

import requests
from authlib.common.security import generate_token
from authlib.integrations.requests_client import OAuth2Session

from EasyOIDC.config import Config
from EasyOIDC.utils import decode_jwt_claims_unverified, extract_roles, get_domain_from_url


class IDTokenValidationError(Exception):
    """The ID token returned by the server failed validation."""


class AccessDeniedError(Exception):
    """The authenticated user does not satisfy the access policy."""

    def __init__(self, reason: str, message: str = ''):
        self.reason = reason
        super().__init__(message or reason)


class OIDClient(object):
    logger = logging.getLogger('EasyOIDC')

    def __init__(self, config: Config, log_enabled: bool = True):
        self._config = config
        self._roles_getter = None
        self._redirector = None
        self._log_enabled = log_enabled
        self._jwks = None
        self._jwks_fetched_at = 0.0

        try:
            assert self._config.is_valid_config()
        except Exception:
            try:
                self._config.load_from_wellknown()
                assert self._config.is_valid_config()
            except Exception as e:
                raise Exception(f"Error loading configuration: {e}")
        self._discovery_loaded = False

    def _ensure_id_token_metadata(self):
        """Fill ``issuer`` / ``jwks_uri`` from discovery when they are missing.

        Configs that set the endpoints explicitly never call
        ``load_from_wellknown()`` at startup, so without this the ID token
        would be accepted without checking its signature or issuer. Explicit
        values always win; failures are logged and retried on the next login.
        """
        cfg = self._config
        if self._discovery_loaded or (cfg.issuer and cfg.jwks_uri) or not cfg.well_known_openid_url:
            return
        try:
            response = requests.get(cfg.well_known_openid_url, timeout=cfg.http_timeout)
            response.raise_for_status()
            data = response.json()
            cfg.issuer = cfg.issuer or data.get('issuer')
            cfg.jwks_uri = cfg.jwks_uri or data.get('jwks_uri')
            self._discovery_loaded = True
        except Exception as e:
            if self._log_enabled:
                self.logger.warning(f'Could not read issuer/jwks_uri from discovery: {e}')

    def set_roles_getter(self, func: callable):
        self._roles_getter = func

    def set_redirector(self, func: callable):
        self._redirector = func

    def get_config(self):
        return self._config

    # ------------------------------------------------------------------
    # OAuth2 session / login
    # ------------------------------------------------------------------
    def get_oauth_session(self, token: dict = None, update_token: Optional[Callable] = None):
        cfg = self._config
        kwargs = dict(authorization_endpoint=cfg.authorization_endpoint,
                      token_endpoint=cfg.token_endpoint,
                      scope=cfg.scope)
        if cfg.use_pkce:
            kwargs['code_challenge_method'] = 'S256'
        if cfg.http_timeout:
            kwargs['default_timeout'] = cfg.http_timeout
        if token:
            kwargs['token'] = token
        if update_token:
            kwargs['update_token'] = update_token
        return OAuth2Session(cfg.client_id, cfg.client_secret, **kwargs)

    def begin_login(self) -> dict:
        """Start the authorization code flow.

        Returns a dict with ``url`` (where to send the browser), ``state``,
        and the per-login secrets (``code_verifier``, ``nonce``) that must be
        stored server-side and passed back to :meth:`complete_login`.
        """
        cfg = self._config
        extra = {}
        code_verifier = generate_token(64) if cfg.use_pkce else None
        nonce = generate_token(32) if cfg.use_nonce else None
        if code_verifier:
            extra['code_verifier'] = code_verifier
        if nonce:
            extra['nonce'] = nonce
        uri, state = self.get_oauth_session().create_authorization_url(
            cfg.authorization_endpoint, redirect_uri=cfg.redirect_uri, **extra)
        return {'url': uri, 'state': state, 'code_verifier': code_verifier, 'nonce': nonce,
                'created_at': time.time()}

    def auth_server_login(self):
        """Backwards-compatible login start (0.3.x API).

        PKCE and nonce require keeping per-login secrets, which this tuple
        API cannot return. They are therefore not sent here; use
        :meth:`begin_login` / :meth:`complete_login` to get them.
        """
        cfg = self._config
        uri, state = self.get_oauth_session().create_authorization_url(
            cfg.authorization_endpoint, redirect_uri=cfg.redirect_uri)
        return uri, state

    def _build_callback_url(self, request_url):
        if isinstance(request_url, dict):
            url = self._config.redirect_uri + '?'
            for key, value in request_url.items():
                url += f'{key}={value}&'
            request_url = url[:-1]
        return request_url

    def get_token(self, request_url, code_verifier: Optional[str] = None):
        request_url = self._build_callback_url(request_url)
        oauth_session = self.get_oauth_session()
        params = dict(url=self._config.token_endpoint,
                      redirect_uri=self._config.redirect_uri,
                      authorization_response=request_url,
                      include_client_id=True)
        if code_verifier:
            params['code_verifier'] = code_verifier
        token = oauth_session.fetch_token(**params)
        return token, oauth_session

    def complete_login(self, request_url, login: dict) -> dict:
        """Finish the flow started by :meth:`begin_login`.

        Exchanges the code (with the PKCE verifier), validates the ID token
        (nonce included) and fetches userinfo. Returns
        ``{'token': ..., 'userinfo': ..., 'id_claims': ..., 'oauth_session': ...}``.
        """
        cfg = self._config
        created = (login or {}).get('created_at')
        if created and (time.time() - created) > cfg.login_timeout_seconds:
            raise ValueError('Login request expired')
        token, oauth_session = self.get_token(request_url, (login or {}).get('code_verifier'))
        id_claims = self.validate_id_token(token.get('id_token'), (login or {}).get('nonce'))
        userinfo = self.get_user_info(oauth_session)
        if id_claims.get('sub') and userinfo.get('sub') and id_claims['sub'] != userinfo['sub']:
            raise IDTokenValidationError('userinfo sub does not match the ID token sub')
        return {'token': dict(token), 'userinfo': userinfo, 'id_claims': id_claims,
                'oauth_session': oauth_session}

    # ------------------------------------------------------------------
    # ID token validation
    # ------------------------------------------------------------------
    def _get_jwks(self, force: bool = False):
        from joserfc.jwk import KeySet
        cfg = self._config
        if not cfg.jwks_uri:
            return None
        if self._jwks is not None and not force and (time.time() - self._jwks_fetched_at) < 3600:
            return self._jwks
        response = requests.get(cfg.jwks_uri, timeout=cfg.http_timeout)
        response.raise_for_status()
        self._jwks = KeySet.import_key_set(response.json())
        self._jwks_fetched_at = time.time()
        return self._jwks

    def validate_id_token(self, id_token: Optional[str], nonce: Optional[str] = None) -> dict:
        """Validate the ID token and return its claims.

        Signature is verified against the provider JWKS when ``jwks_uri`` is
        known (from discovery or config). ``iss``, ``aud``, ``exp`` and
        ``nonce`` are always checked when ``validate_id_token`` is on.
        """
        cfg = self._config
        if not id_token:
            if cfg.validate_id_token and 'openid' in (cfg.scope or []):
                raise IDTokenValidationError('The token response has no id_token')
            return {}
        if not cfg.validate_id_token:
            return decode_jwt_claims_unverified(id_token)

        self._ensure_id_token_metadata()

        from joserfc import jwt
        from joserfc.errors import JoseError

        try:
            if cfg.jwks_uri:
                try:
                    keys = self._get_jwks()
                    token = jwt.decode(id_token, keys, algorithms=cfg.id_token_algorithms)
                except JoseError:
                    keys = self._get_jwks(force=True)
                    token = jwt.decode(id_token, keys, algorithms=cfg.id_token_algorithms)
                claims = token.claims
            else:
                if self._log_enabled:
                    self.logger.warning('No jwks_uri configured: ID token signature is NOT verified. '
                                        'Set jwks_uri or use well_known_openid_url.')
                claims = decode_jwt_claims_unverified(id_token)

            options = {
                'aud': {'essential': True, 'value': cfg.client_id},
                'exp': {'essential': True},
                'sub': {'essential': True},
            }
            if cfg.issuer:
                options['iss'] = {'essential': True, 'value': cfg.issuer}
            if nonce:
                options['nonce'] = {'essential': True, 'value': nonce}
            jwt.JWTClaimsRegistry(leeway=cfg.id_token_leeway, **options).validate(claims)
            aud = claims.get('aud')
            if isinstance(aud, list) and len(aud) > 1 and claims.get('azp') not in (None, cfg.client_id):
                raise IDTokenValidationError('ID token azp does not match client_id')
        except IDTokenValidationError:
            raise
        except (JoseError, ValueError) as e:
            raise IDTokenValidationError(f'Invalid ID token: {e}') from e
        return dict(claims)

    # ------------------------------------------------------------------
    # Userinfo / session validity / refresh
    # ------------------------------------------------------------------
    def get_user_info(self, oauth_session):
        response = oauth_session.get(self._config.userinfo_endpoint)
        response.raise_for_status()
        return response.json()

    def is_valid_oidc_session(self, oauth_session):
        try:
            if oauth_session.token is None:
                return False
            return oauth_session.get(self._config.userinfo_endpoint).status_code == 200
        except Exception:
            return False

    def refresh_if_needed(self, token: Optional[dict], leeway: int = 30):
        """Return a fresh token dict if ``token`` is expired, else ``None``.

        Uses the refresh token when available. Raises if the refresh fails
        (e.g. revoked session), so the caller can drop the session.
        """
        if not token or not token.get('expires_at'):
            return None
        if float(token['expires_at']) - leeway > time.time():
            return None
        if not token.get('refresh_token'):
            raise ValueError('Access token expired and no refresh_token is available')
        oauth_session = self.get_oauth_session(token)
        new_token = oauth_session.refresh_token(self._config.token_endpoint,
                                                refresh_token=token['refresh_token'])
        merged = dict(new_token)
        if 'id_token' not in merged and token.get('id_token'):
            merged['id_token'] = token['id_token']
        return merged

    def token_revoke(self, oauth_session, token_type_hint: str = None):
        if oauth_session.token is None:
            return
        result = None
        if (token_type_hint is None) or (token_type_hint == 'access_token'):
            result = oauth_session.revoke_token(self._config.token_revoke_endpoint,
                                                token_type_hint='access_token',
                                                token=oauth_session.token['access_token'])
        if (token_type_hint is None) or (token_type_hint == 'refresh_token'):
            if oauth_session.token.get('refresh_token'):
                result = oauth_session.revoke_token(self._config.token_revoke_endpoint,
                                                    token_type_hint='refresh_token',
                                                    token=oauth_session.token['refresh_token'])
        return result is not None and result.status_code == 200

    # ------------------------------------------------------------------
    # Logout
    # ------------------------------------------------------------------
    def get_keycloak_logout_url(self, id_token=None):
        """RP-initiated logout URL (OIDC RP-Initiated Logout 1.0).

        Always sends ``client_id`` (required by Keycloak >= 18 when there is
        no ``id_token_hint``) and only sends ``id_token_hint`` when there is
        a token.
        """
        cfg = self._config
        url = f'{cfg.logout_endpoint}?client_id={quote(cfg.client_id or "", safe="")}'
        if cfg.post_logout_uri:
            url += f'&post_logout_redirect_uri={quote(cfg.post_logout_uri, safe="")}'
        if id_token:
            url += f'&id_token_hint={quote(id_token, safe="")}'
        return url

    def get_auth0_logout_url(self):
        post_logout_uri = self._config.post_logout_uri
        client_id = self._config.client_id
        if self._config.logout_endpoint:
            path = self._config.logout_endpoint
        else:
            path = f'https://{get_domain_from_url(self._config.authorization_endpoint)}/v2/logout'
        if post_logout_uri is None:
            post_logout_uri = ''
        url = f'{path}?returnTo={quote_plus(post_logout_uri)}&client_id={client_id}'
        return url

    def get_logout_url(self, id_token: str = ''):
        if self._config.auth_service == 'keycloak':
            return self.get_keycloak_logout_url(id_token)
        elif self._config.auth_service == 'auth0':
            return self.get_auth0_logout_url()

    def call_logout_endpoint(self, id_token: str = ''):
        url = self.get_logout_url(id_token)
        return requests.get(url, timeout=self._config.http_timeout)

    # ------------------------------------------------------------------
    # Roles / access policy
    # ------------------------------------------------------------------
    def roles_from_session(self, session_data: Optional[dict]) -> list:
        """Roles for a stored session according to ``roles_source`` and
        ``roles_claims_from``."""
        cfg = self._config
        data = session_data or {}
        claim_sets = []
        for source in cfg.roles_claims_from:
            if source == 'userinfo':
                claim_sets.append(data.get('userinfo'))
            elif source == 'id_token':
                claim_sets.append(data.get('id_claims') or
                                  decode_jwt_claims_unverified((data.get('token') or {}).get('id_token')))
            elif source == 'access_token':
                claim_sets.append(decode_jwt_claims_unverified((data.get('token') or {}).get('access_token')))
        return extract_roles(claim_sets, cfg.roles_source, cfg.roles_client_id or cfg.client_id)

    @staticmethod
    def check_access(userinfo: Optional[dict], roles: list, required_roles: Optional[list] = None,
                     require_email_verified: bool = False):
        """Raise :class:`AccessDeniedError` if the user fails the policy."""
        if require_email_verified and (userinfo or {}).get('email_verified') is not True:
            raise AccessDeniedError('email_not_verified', 'Email address is not verified')
        if required_roles and not (set(required_roles) & set(roles or [])):
            raise AccessDeniedError('missing_role',
                                    f"One of these roles is required: {', '.join(required_roles)}")

    def get_user_roles(self):
        return self._roles_getter()

    @staticmethod
    def evaluate_roles(user_roles: list, and_allow_roles: list = [], deny_roles: list = [],
                       or_allow_roles: list = []) -> bool:
        and_aroles = user_roles if and_allow_roles == ['*'] else and_allow_roles
        or_aroles = user_roles if or_allow_roles == ['*'] else or_allow_roles
        droles = user_roles if deny_roles == ['*'] else deny_roles

        is_authorized = False
        if len(and_aroles) > 0:
            is_authorized = all(x in user_roles for x in and_aroles)
        elif len(or_aroles) > 0:
            is_authorized = any(oar in user_roles for oar in or_aroles)

        for dr in droles:
            if dr in user_roles:
                is_authorized = False
                break

        return is_authorized

    def require_roles(self, access_denied_url: str, and_allow_roles: list = [], deny_roles: list = [],
                      or_allow_roles: list = []):
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                try:
                    is_authorized = self.evaluate_roles(self.get_user_roles(), and_allow_roles,
                                                        deny_roles, or_allow_roles)
                except Exception:
                    is_authorized = False

                if is_authorized:
                    response = f(*args, **kwargs)
                    return response
                else:
                    return self._redirector(access_denied_url)

            return decorated_function

        return decorator
