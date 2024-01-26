from authlib.integrations.requests_client import OAuth2Session
from urllib.parse import quote, quote_plus
from functools import wraps
from EasyOIDC.config import Config
from EasyOIDC.utils import get_domain_from_url
import requests


class OIDClient(object):
    def __init__(self, config: Config, log_enabled: bool = True):
        # Initialize the OIDC Client with configuration and logging option
        self._config = config
        self._roles_getter = None  # Placeholder for a function to get user roles
        self._redirector = None  # Placeholder for a redirect function
        self._log_enabled = log_enabled

        # Validate the provided configuration
        try:
            assert self._config.is_valid_config()
        except Exception as e:
            try:
                # If initial validation fails, try loading from a well-known configuration
                self._config.load_from_wellknown()
                assert self._config.is_valid_config()
            except Exception as e:
                raise Exception(f"Error loading configuration: {e}")

    def set_roles_getter(self, func: callable):
        # Set a custom function to determine user roles
        self._roles_getter = func

    def set_redirector(self, func: callable):
        # Set a custom redirect function
        self._redirector = func

    def get_config(self):
        # Return the current configuration
        return self._config

    def get_oauth_session(self, token: dict = None):
        # Create an OAuth2 session, optionally with a provided token
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
        # Initiate the login process with the auth server and get the authorization URL
        oauth_session = self.get_oauth_session()
        uri, state = oauth_session.create_authorization_url(self._config.authorization_endpoint,
                                                            redirect_uri=self._config.redirect_uri)
        return uri, state

    def get_token(self, request_url):
        # Retrieve an authentication token using the provided request URL
        if isinstance(request_url, dict):
            # Build the request URL from the provided dictionary
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
        # Fetch user information using the provided OAuth session
        return oauth_session.get(self._config.userinfo_endpoint).json()

    def is_valid_oidc_session(self, oauth_session):
        # Check if the provided OAuth session is valid
        try:
            if oauth_session.token is None:
                return False
            return oauth_session.get(self._config.userinfo_endpoint).status_code == 200
        except Exception as e:
            return False

    # Revoke the token in the OIDC server
    def token_revoke(self, oauth_session, token_type_hint: str = None):
        # Revoke the current token in the OAuth session
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
        # Construct the logout URL for Keycloak
        logout_endpoint = self._config.logout_endpoint
        post_logout_uri = self._config.post_logout_uri or ''
        url = f'{logout_endpoint}?post_logout_redirect_uri={quote(post_logout_uri)}'
        url += f'&id_token_hint={id_token}'
        return url

    def get_auth0_logout_url(self):
        # Construct the logout URL for Auth0
        post_logout_uri = self._config.post_logout_uri
        client_id = self._config.client_id
        if self._config.logout_endpoint:
            path = self._config.logout_endpoint
        else:
            # If no specific logout endpoint, construct the URL from the auth endpoint
            path = f'https://{get_domain_from_url(self._config.authorization_endpoint)}/v2/logout'
        if post_logout_uri is None:
            post_logout_uri = ''
        url = f'{path}?returnTo={quote_plus(post_logout_uri)}&client_id={client_id}'
        return url

    def get_logout_url(self, id_token: str = ''):
        # Determine which logout URL to use based on the authentication service
        if self._config.auth_service == 'keycloak':
            return self.get_keycloak_logout_url(id_token)
        elif self._config.auth_service == 'auth0':
            return self.get_auth0_logout_url()

    # Send a logout request
    def call_logout_endpoint(self, id_token: str = ''):
        # Call the logout endpoint with the specified ID token
        url = self.get_logout_url(id_token)
        return requests.get(url)

    def get_user_roles(self):
        # Retrieve the user roles using the roles getter function
        return self._roles_getter()

    # and_allow_roles: List of roles that must be fulfilled (all of them)
    # or_allow_roles: List of roles that can be fulfilled (any of them)
    # deny_roles: List of roles that are not allowed (any of them)
    def require_roles(self, access_denied_url: str, and_allow_roles: list = [], deny_roles: list = [],
                      or_allow_roles: list = []):
        # Decorator to enforce role-based access control
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                try:
                    user_roles = self.get_user_roles()
                    # Determine the roles to be checked based on the provided parameters
                    and_aroles = user_roles if and_allow_roles == ['*'] else and_allow_roles
                    or_aroles = user_roles if or_allow_roles == ['*'] else or_allow_roles
                    droles = user_roles if deny_roles == ['*'] else deny_roles

                    is_authorized = False
                    # Check if user has the required roles
                    if len(and_aroles) > 0:
                        is_authorized = all(x in user_roles for x in and_aroles)
                    elif len(or_aroles) > 0:
                        is_authorized = any(oar in user_roles for oar in or_aroles)

                    # Check for denied roles
                    for dr in droles:
                        if dr in user_roles:
                            is_authorized = False
                            break

                except Exception as e:
                    is_authorized = False

                # Redirect to the access denied URL if unauthorized, else call the function
                if is_authorized:
                    response = f(*args, **kwargs)
                    return response
                else:
                    return self._redirector(access_denied_url)

            return decorated_function

        return decorator
