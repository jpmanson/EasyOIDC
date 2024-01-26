from authlib.integrations.requests_client import OAuth2Session
from urllib.parse import quote
from functools import wraps
from EasyOIDC.config import Config
from EasyOIDC.utils import get_domain_from_url
import requests
from urllib.parse import quote_plus, urlencode


class OIDClient(object):
    def __init__(self, config: Config, log_enabled: bool = True):
        self._config = config
        self._roles_getter = None
        self._redirector = None
        self._log_enabled = log_enabled

        try:
            assert self._config.is_valid_config()
        except Exception as e:
            try:
                self._config.load_from_wellknown()
                assert self._config.is_valid_config()
            except Exception as e:
                raise Exception(f"Error loading configuration: {e}")

    def set_roles_getter(self, func: callable):
        self._roles_getter = func

    def set_redirector(self, func: callable):
        self._redirector = func

    def get_config(self):
        return self._config

    def get_oauth_session(self, token: dict = None):
        if token:
            return OAuth2Session(self._config.client_id, self._config.client_secret,
                                 authorization_endpoint=self._config.authorization_endpoint,
                                 token_endpoint=self._config.token_endpoint,
                                 token=token, scope=self._config.scope)
        else:
            return OAuth2Session(self._config.client_id, self._config.client_secret,
                                 authorization_endpoint=self._config.authorization_endpoint,
                                 token_endpoint=self._config.token_endpoint, scope=self._config.scope)

    def auth_server_login(self):
        oauth_session = self.get_oauth_session()
        uri, state = oauth_session.create_authorization_url(self._config.authorization_endpoint,
                                                            redirect_uri=self._config.redirect_uri)
        return uri, state

    def get_token(self, request_url):
        if isinstance(request_url, dict):
            # Build the request_url from the dict
            url = self._config.redirect_uri + '?'
            for key, value in request_url.items():
                url += f'{key}={value}&'
            request_url = url[:-1]

        oauth_session = self.get_oauth_session()
        params = dict(url=self._config.token_endpoint,
                      redirect_uri=self._config.redirect_uri,
                      authorization_response=request_url,
                      include_client_id=True)
        token = oauth_session.fetch_token(**params)
        return token, oauth_session

    def get_user_info(self, oauth_session):
        return oauth_session.get(self._config.userinfo_endpoint).json()

    def is_valid_oidc_session(self, oauth_session):
        try:
            if oauth_session.token is None:
                return False
            return oauth_session.get(self._config.userinfo_endpoint).status_code == 200
        except Exception as e:
            return False

    # Revoke the token in the OIDC server
    def token_revoke(self, oauth_session, token_type_hint: str = None):
        if oauth_session.token is None:
            return
        if (token_type_hint is None) or (token_type_hint == 'access_token'):
            result = oauth_session.revoke_token(self._config.token_revoke_endpoint,
                                                token_type_hint='access_token',
                                                token=oauth_session.token['access_token'])
        if (token_type_hint is None) or (token_type_hint == 'refresh_token'):
            result = oauth_session.revoke_token(self._config.token_revoke_endpoint,
                                                token_type_hint='refresh_token',
                                                token=oauth_session.token['refresh_token'])
        return result.status_code == 200

    # Build the logout URL to send to the Keycloak server
    # id_token is required for Keycloak server
    def get_keycloak_logout_url(self, id_token):
        logout_endpoint = self._config.logout_endpoint
        post_logout_uri = self._config.post_logout_uri or ''
        url = f'{logout_endpoint}?post_logout_redirect_uri={quote(post_logout_uri)}'
        url += f'&id_token_hint={id_token}'
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

    # Send a logout request
    def call_logout_endpoint(self, id_token: str = ''):
        url = self.get_logout_url(id_token)
        return requests.get(url)

    def get_user_roles(self):
        return self._roles_getter()

    # and_allow_roles: Lista de roles que debe cumplir (todos ellos)
    # or_allow_roles: Lista de roles que puede cumplir (cualquiera de ellos)
    # deny_roles: Lista de roles que no están permitidos (cualquier de ellos)
    def require_roles(self, access_denied_url: str, and_allow_roles: list = [], deny_roles: list = [],
                      or_allow_roles: list = []):
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                try:
                    user_roles = self.get_user_roles()
                    if and_allow_roles == ['*']:
                        and_aroles = user_roles
                    else:
                        and_aroles = and_allow_roles
                    if or_allow_roles == ['*']:
                        or_aroles = user_roles
                    else:
                        or_aroles = or_allow_roles
                    if deny_roles == ['*']:
                        droles = user_roles
                    else:
                        droles = deny_roles

                    is_authorized = False
                    if len(and_aroles) > 0:
                        is_authorized = all(x in user_roles for x in and_aroles)
                    elif len(or_aroles) > 0:
                        for oar in or_aroles:
                            if oar in user_roles:
                                is_authorized = True
                                break

                    for dr in droles:
                        if dr in user_roles:
                            is_authorized = False
                            break

                except Exception as e:
                    is_authorized = False

                if is_authorized:
                    response = f(*args, **kwargs)
                    return response
                else:
                    return self._redirector(access_denied_url)

            return decorated_function

        return decorator
