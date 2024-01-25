from flask import request, redirect, make_response, session
from werkzeug.wrappers import Request as WSGIRequest
from http.cookies import SimpleCookie
from EasyOIDC.utils import is_path_matched
from EasyOIDC import OIDClient, Config, SessionHandler
from EasyOIDC.frameworks import SESSION_STATE_VAR_NAME, REFERRER_VAR_NAME


class FlaskOIDClient(OIDClient):
    def __init__(self, app, auth_config: Config = None, session_storage: SessionHandler = None,
                 log_enabled: bool = True, **kwargs):
        if auth_config is None:
            auth_config = Config('.env')
        if session_storage is None:
            session_storage = SessionHandler(mode='redis')

        super().__init__(auth_config, log_enabled)
        self._flask_app = app
        self._auth_config = auth_config
        self._session_storage = session_storage
        self._flask_app.secret_key = auth_config.cookie_secret_key
        self._flask_app.wsgi_app = AuthenticationMiddleware(app, session_storage, self)
        self.set_redirector(lambda url: redirect(url))

        if 'unrestricted_routes' in kwargs:
            self._auth_config.unrestricted_routes = kwargs['unrestricted_routes']

        self.set_roles_getter(
            lambda: session_storage[session.get(SESSION_STATE_VAR_NAME, '')].get('userinfo', {}).get('realm_access', {}).get(
                'roles', []))

        # Add Flask route /authorize to method authorize_route_handler
        self._flask_app.add_url_rule(auth_config.app_authorize_route, 'authorize_route_handler',
                                     self._authorize_route_handler)

        # Add Flask route /login to method login_route_handler
        self._flask_app.add_url_rule(auth_config.app_login_route, 'login_route_handler', self._login_route_handler)

        # Add Flask route /logout to method logout_route_handler
        self._flask_app.add_url_rule(auth_config.app_logout_route, 'logout_route_handler', self._logout_route_handler)

    def _authorize_route_handler(self):
        try:
            # Ensure the 'state' parameter matches the one stored in the user's session
            assert request.args.get('state') == session.get(SESSION_STATE_VAR_NAME)

            token, oauth_session = self.get_token(request.url)
            userinfo = self.get_user_info(oauth_session)

            # Update the session with the new state and user info
            session.update({SESSION_STATE_VAR_NAME: request.args.get('state')})
            # Save user data in session store
            self._session_storage[request.args.get('state')] = {'userinfo': userinfo, 'token': dict(token)}
            if self._log_enabled:
                self._flask_app.logger.info(f'User {userinfo["name"]} authenticated')

        except Exception as e:
            if self._log_enabled:
                self._flask_app.logger.error(f"Authorization error: {e}")
            return redirect(self._auth_config.app_login_route)

        return redirect('/')

    def _login_route_handler(self):
        uri, state = self.auth_server_login()

        # Create a response object
        response = make_response(redirect(uri))
        session.update({SESSION_STATE_VAR_NAME: state})
        self._session_storage[state] = {'userinfo': None, 'token': None}

        # Redirect the user to the authorization server
        return response

    def _get_current_token(self):
        state = session.get(SESSION_STATE_VAR_NAME, '')
        if state in self._session_storage:
            return self._session_storage[state]['token']
        return None

    def _logout(self):
        logout_url = None
        token = self._get_current_token()
        if token:
            if self._auth_config.logout_endpoint:
                logout_url = self.get_logout_url(token.get('id_token', None))
            del self._session_storage[session.get(SESSION_STATE_VAR_NAME)]
        session.update({SESSION_STATE_VAR_NAME: None})
        return logout_url

    def _logout_route_handler(self):
        logout_url = self._logout()
        if logout_url:
            return redirect(logout_url)
        else:
            return redirect(self._auth_config.post_logout_uri)

    def is_authenticated(self):
        state = session.get(SESSION_STATE_VAR_NAME, '')
        if (state in self._session_storage) and (self._session_storage[state]['userinfo']):
            return True
        return False

    def get_userinfo(self):
        state = session.get(SESSION_STATE_VAR_NAME, '')
        if (state in self._session_storage) and (self._session_storage[state]['userinfo']):
            return self._session_storage[state]['userinfo']
        return None


class AuthenticationMiddleware:
    def __init__(self, app, session_storage: SessionHandler, oidc_client: OIDClient, log_enabled: bool = True):
        self.wsgi_app = app.wsgi_app  # Original WSGI application
        self.flask_app = app  # Flask application instance
        self.session_storage = session_storage
        self.oidc_client = oidc_client
        self.log_enabled = log_enabled

    def __call__(self, environ, start_response):
        wsgi_request = WSGIRequest(environ)

        with self.flask_app.request_context(wsgi_request.environ):
            def get_cookie(environ, key):
                cookies = SimpleCookie(environ.get('HTTP_COOKIE', ''))
                return cookies.get(key).value if key in cookies else None

            referrer_path = get_cookie(environ, REFERRER_VAR_NAME)
            unrestricted_page_routes = self.oidc_client.get_config().get_unrestricted_routes()
            login_route = self.oidc_client.get_config().app_login_route
            page_unrestricted = any(is_path_matched(request.path, pattern) for pattern in unrestricted_page_routes)
            if (not referrer_path) and page_unrestricted:
                return self.wsgi_app(environ, start_response)  # Se convierte la respuesta en un iterable para WSGI

            # Check if session is valid
            authenticated = False
            if session.get(SESSION_STATE_VAR_NAME, None) and (session.get(SESSION_STATE_VAR_NAME) in self.session_storage):
                token = self.session_storage[session.get(SESSION_STATE_VAR_NAME)]['token']

                # Check if the user is authenticated against the OIDC server
                authenticated = self.oidc_client.is_valid_oidc_session(self.oidc_client.get_oauth_session(token))

            if not authenticated:
                if not page_unrestricted:
                    response = make_response(redirect(login_route))
                    response.set_cookie(REFERRER_VAR_NAME, request.path)
                    if self.log_enabled:
                        self.flask_app.logger.debug(f'Redirecting to {login_route}...')
                    return response(environ, start_response)
            else:
                if referrer_path:
                    if self.log_enabled:
                        self.flask_app.logger.info(f'User authenticated. Redirecting to {referrer_path}')
                    # Make a redirect response and delete cookie referrer_path
                    response = make_response(redirect(referrer_path))
                    response.set_cookie(REFERRER_VAR_NAME, '', expires=0)
                    if self.log_enabled:
                        self.flask_app.logger.debug(f'Redirecting to {referrer_path}...')
                    return response(environ, start_response)  # Se convierte la respuesta en un iterable para WSGI

            # Calling original WSGI app
            return self.wsgi_app(environ, start_response)
