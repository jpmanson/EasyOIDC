from authlib.integrations.requests_client import OAuth2Session
from urllib.parse import quote
from functools import wraps
from EasyOIDC.config import Config
import requests


class OIDClient(object):
    def __init__(self, config: Config):
        self.settings = config
        self.roles_getter = None
        self.redirector = None

    def set_roles_getter(self, func):
        self.roles_getter = func

    def set_redirector(self, func):
        self.redirector = func
        
    def get_oauth_session(self, token: dict = None):
        if token:
            return OAuth2Session(self.settings.client_id, self.settings.client_secret,
                                 authorization_endpoint=self.settings.authorization_endpoint,
                                 token_endpoint=self.settings.token_endpoint,
                                 token=token, scope=self.settings.scope)
        else:
            return OAuth2Session(self.settings.client_id, self.settings.client_secret,
                                 authorization_endpoint=self.settings.authorization_endpoint,
                                 token_endpoint=self.settings.token_endpoint, scope=self.settings.scope)

    def auth_server_login(self):
        oauth_session = self.get_oauth_session()
        uri, state = oauth_session.create_authorization_url(self.settings.authorization_endpoint,
                                                            redirect_uri=self.settings.redirect_uri)
        return uri, state

    def get_token(self, request_url):
        if isinstance(request_url, dict):
            #Build the request_url from the dict
            url = self.settings.redirect_uri + '?'
            for key, value in request_url.items():
                url += f'{key}={value}&'
            request_url = url[:-1]

        oauth_session = self.get_oauth_session()
        params = dict(url=self.settings.token_endpoint,
                      redirect_uri=self.settings.redirect_uri,
                      authorization_response=request_url,
                      include_client_id=True)
        token = oauth_session.fetch_token(**params)
        return token, oauth_session

    def get_user_info(self, oauth_session):
        return oauth_session.get(self.settings.userinfo_endpoint).json()

    def is_valid_oidc_session(self, oauth_session):
        try:
            if oauth_session.token is None:
                return False
            return oauth_session.get(self.settings.userinfo_endpoint).status_code == 200
        except Exception as e:
            return False

    # Revoke the token in the OIDC server
    def token_revoke(self, oauth_session, token_type_hint: str = None):
        if oauth_session.token is None:
            return
        if (token_type_hint is None) or (token_type_hint == 'access_token'):
            result = oauth_session.revoke_token(self.settings.token_revoke_endpoint,
                                   token_type_hint='access_token',
                                   token=oauth_session.token['access_token'])
        if (token_type_hint is None) or (token_type_hint == 'refresh_token'):
            result = oauth_session.revoke_token(self.settings.token_revoke_endpoint,
                                       token_type_hint='refresh_token',
                                       token=oauth_session.token['refresh_token'])
        return result.status_code == 200

    @staticmethod
    # Build the logout URL to send to the Keycloak server
    def get_keycloak_logout_url(oauth_session, logout_endpoint, post_logout_uri):
        if oauth_session.token is None:
            return
        if post_logout_uri is None:
            post_logout_uri = ''
        url = f'{logout_endpoint}?post_logout_redirect_uri={quote(post_logout_uri)}'
        url += f'&id_token_hint={oauth_session.token["id_token"]}'
        return url

    @staticmethod
    # Send a logout request to the Keycloak server
    def send_keycloak_logout(oauth_session, logout_endpoint):
        if oauth_session.token is None:
            return
        url = f'{logout_endpoint}?id_token_hint={oauth_session.token["id_token"]}'
        return requests.get(url)

    @staticmethod
    def nicegui_user_roles():
        from nicegui import app
        roles = []
        try:
            roles = app.storage.user['userinfo']['realm_access']['roles']
        except:
            pass
        return roles

    def get_user_roles(self):
        return self.roles_getter()

    # and_allow_roles: Lista de roles que debe cumplir (todos ellos)
    # or_allow_roles: Lista de roles que puede cumplir (cualquiera de ellos)
    # deny_roles: Lista de roles que no están permitidos (cualquier de ellos)
    def require_roles(self, access_denied_url: str, and_allow_roles: list = [], deny_roles: list = [], or_allow_roles: list = []):
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
                    return self.redirector(access_denied_url)
            return decorated_function
        return decorator
