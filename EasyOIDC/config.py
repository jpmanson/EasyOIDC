import os
import json
import requests


def is_valid_url(url):
    if url is None:
        return False
    if url.find('http://') == 0 or url.find('https://') == 0:
        return True
    return False


def _to_bool(value, default=False):
    if value is None or value == '':
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ('1', 'true', 'yes', 'on')


def _to_list(value, default=None):
    if value is None or value == '':
        return list(default or [])
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [v.strip() for v in str(value).split(',') if v.strip()]


DEFAULT_ID_TOKEN_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512',
                               'ES256', 'ES384', 'ES512', 'EdDSA']


class Config(object):
    well_known_openid_url = None
    authorization_endpoint = None
    token_endpoint = None
    userinfo_endpoint = None
    redirect_uri = None
    client_id = None
    client_secret = None
    cookie_secret_key = None
    scope = None
    token_revoke_endpoint = None
    logout_endpoint = None
    post_logout_uri = None
    app_login_route = None
    app_logout_route = None
    app_authorize_route = None
    auth_service = None
    base_unrestricted_routes = ['/favicon.ico']

    # --- Added in 0.4.0 -----------------------------------------------------
    # Discovery metadata used to validate ID tokens.
    issuer = None
    jwks_uri = None
    # PKCE (RFC 7636, S256) on the authorization code flow.
    use_pkce = True
    # OIDC `nonce`, checked against the ID token.
    use_nonce = True
    # Validate the ID token (signature when a JWKS is available, iss, aud,
    # exp, nonce). See README "ID token validation".
    validate_id_token = True
    id_token_algorithms = None
    id_token_leeway = 60
    # Timeout (seconds) for every HTTP call to the OIDC server.
    http_timeout = 10
    # Where roles are read from: 'realm' (realm_access.roles, default and
    # 0.3.x behaviour), 'client' (resource_access.<roles_client_id>.roles) or
    # 'realm+client'.
    roles_source = 'realm'
    roles_client_id = None
    # Which claim sets are searched for roles: any of 'userinfo', 'id_token',
    # 'access_token'. Default keeps the 0.3.x behaviour (userinfo only).
    roles_claims_from = None
    # A login started at /login must be completed within this many seconds.
    login_timeout_seconds = 600

    def __init__(self, config_path=None, **kwargs):
        self.scope = ['openid', 'email', 'profile']
        self.app_login_route = '/login'
        self.app_logout_route = '/logout'
        self.app_authorize_route = '/authorize'
        self.base_unrestricted_routes = kwargs.get('base_unrestricted_routes', self.base_unrestricted_routes)
        self.unrestricted_routes = self.base_unrestricted_routes
        self.id_token_algorithms = list(DEFAULT_ID_TOKEN_ALGORITHMS)
        self.roles_claims_from = ['userinfo']

        if config_path and (os.path.exists(config_path)):
            try:
                self.load_from_json(config_path)
            except Exception:
                self.load_from_env_file(config_path)
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

        self._normalize()

        if not self.auth_service:
            self.auth_service = 'keycloak'
            authorization_endpoint = self.authorization_endpoint or ''
            if authorization_endpoint.find('https://accounts.google.com') == 0:
                self.auth_service = 'google'

    def _normalize(self):
        if isinstance(self.unrestricted_routes, str):
            self.unrestricted_routes = _to_list(self.unrestricted_routes)
        if isinstance(self.scope, str):
            self.scope = _to_list(self.scope)
        self.use_pkce = _to_bool(self.use_pkce, True)
        self.use_nonce = _to_bool(self.use_nonce, True)
        self.validate_id_token = _to_bool(self.validate_id_token, True)
        self.id_token_algorithms = _to_list(self.id_token_algorithms, DEFAULT_ID_TOKEN_ALGORITHMS)
        self.roles_claims_from = _to_list(self.roles_claims_from, ['userinfo'])
        self.http_timeout = float(self.http_timeout) if self.http_timeout else None
        self.id_token_leeway = int(self.id_token_leeway or 0)
        self.login_timeout_seconds = int(self.login_timeout_seconds or 600)
        if self.roles_source not in ('realm', 'client', 'realm+client'):
            raise ValueError("roles_source must be 'realm', 'client' or 'realm+client'")

    def _load_optional(self, getter):
        for key in ('use_pkce', 'use_nonce', 'validate_id_token', 'id_token_algorithms',
                    'id_token_leeway', 'http_timeout', 'roles_source', 'roles_client_id',
                    'roles_claims_from', 'login_timeout_seconds', 'issuer', 'jwks_uri'):
            value = getter(key)
            if value not in (None, ''):
                setattr(self, key, value)

    def load_from_json(self, json_path):
        with open(json_path, 'r') as f:
            data = json.load(f)
            self.well_known_openid_url = data.get('well_known_openid_url', None)
            self.authorization_endpoint = data.get('authorization_endpoint', None)
            self.token_endpoint = data.get('token_endpoint', None)
            self.userinfo_endpoint = data.get('userinfo_endpoint', None)
            self.redirect_uri = data['redirect_uri']
            self.client_id = data['client_id']
            self.client_secret = data['client_secret']
            self.cookie_secret_key = data['cookie_secret_key']
            self.scope = data.get('scope', '').split(',')
            self.token_revoke_endpoint = data.get('token_revoke_endpoint', None)
            self.logout_endpoint = data.get('logout_endpoint', None)
            self.post_logout_uri = data.get('post_logout_uri', None)
            self.unrestricted_routes = self.base_unrestricted_routes + data.get('unrestricted_routes', '').split(',')
            self._load_optional(data.get)

    def load_from_env_file(self, config_path):
        from decouple import Config, RepositoryEnv
        config = Config(RepositoryEnv(config_path))
        self.well_known_openid_url = config('well_known_openid_url', None)
        self.authorization_endpoint = config('authorization_endpoint', None)
        self.token_endpoint = config('token_endpoint', None)
        self.userinfo_endpoint = config('userinfo_endpoint', None)
        self.redirect_uri = config('redirect_uri')
        self.client_id = config('client_id')
        self.client_secret = config('client_secret')
        self.scope = config('scope', '').split(',')
        self.cookie_secret_key = config('cookie_secret_key')
        self.token_revoke_endpoint = config('token_revoke_endpoint', None)
        self.logout_endpoint = config('logout_endpoint', None)
        self.post_logout_uri = config('post_logout_uri', None)
        self.unrestricted_routes = self.base_unrestricted_routes + config('unrestricted_routes', '').split(',')
        self._load_optional(lambda key: config(key, None))

    def get_unrestricted_routes(self):
        return [self.app_login_route, self.app_authorize_route, self.app_logout_route] + self.unrestricted_routes

    def dump_configuration(self, hide_password=True):
        config = dict(well_known_openid_url=self.well_known_openid_url,
                      authorization_endpoint=self.authorization_endpoint,
                      token_endpoint=self.token_endpoint,
                      userinfo_endpoint=self.userinfo_endpoint,
                      redirect_uri=self.redirect_uri,
                      client_id=self.client_id,
                      client_secret=self.client_secret if not hide_password else '********',
                      scope=self.scope,
                      cookie_secret_key=self.cookie_secret_key if not hide_password else '********',
                      token_revoke_endpoint=self.token_revoke_endpoint,
                      logout_endpoint=self.logout_endpoint,
                      post_logout_uri=self.post_logout_uri,
                      issuer=self.issuer,
                      jwks_uri=self.jwks_uri,
                      use_pkce=self.use_pkce,
                      use_nonce=self.use_nonce,
                      validate_id_token=self.validate_id_token,
                      roles_source=self.roles_source)
        return json.dumps(config, indent=4)

    def load_from_wellknown(self, wellknown_url: str = None):
        url = wellknown_url or self.well_known_openid_url
        response = requests.get(url, timeout=self.http_timeout)
        if response.status_code == 200:
            data = json.loads(response.text)
            self.authorization_endpoint = data['authorization_endpoint']
            self.token_endpoint = data['token_endpoint']
            self.userinfo_endpoint = data['userinfo_endpoint']
            self.token_revoke_endpoint = data.get('revocation_endpoint')
            self.issuer = self.issuer or data.get('issuer')
            self.jwks_uri = self.jwks_uri or data.get('jwks_uri')
            # RP-initiated logout. Auth0's end_session_endpoint expects other
            # parameters than get_auth0_logout_url builds, so it is not used.
            if self.auth_service != 'auth0':
                self.logout_endpoint = self.logout_endpoint or data.get('end_session_endpoint')
            scopes_supported = data.get('scopes_supported')
            if not self.scope:
                self.scope = scopes_supported or ['openid']
            elif scopes_supported:
                for scope in self.scope:
                    if scope not in scopes_supported:
                        raise Exception(f"Scope '{scope}' not supported by the server.")
        else:
            raise Exception(f'Error loading wellknown url: {wellknown_url}')

    def __str__(self):
        return self.dump_configuration()

    def __repr__(self):
        return self.dump_configuration()

    def __getitem__(self, item):
        return getattr(self, item)

    def __setitem__(self, key, value):
        return setattr(self, key, value)

    def __contains__(self, item):
        return hasattr(self, item)

    def __iter__(self):
        return self.__dict__.items().__iter__()

    def is_valid_config(self):
        try:
            assert is_valid_url(self.authorization_endpoint)
            assert is_valid_url(self.token_endpoint)
            assert is_valid_url(self.userinfo_endpoint)
            assert is_valid_url(self.redirect_uri)
            assert self.client_id is not None
            assert self.client_secret is not None
            assert self.cookie_secret_key is not None
            assert isinstance(self.scope, list)
        except Exception as e:
            raise Exception(f"Missing configuration parameters. {e}")
        return True
