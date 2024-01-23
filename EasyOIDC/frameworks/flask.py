from flask import request, redirect, make_response, session
from werkzeug.wrappers import Request as WSGIRequest
from http.cookies import SimpleCookie
from EasyOIDC.utils import is_path_matched
from EasyOIDC import OIDClient, Config, SessionHandler


class FlaskOIDClient(OIDClient):
    def __init__(self, app, auth_config: Config = None, session_storage: SessionHandler = None,
                 log_enabled: bool = True):
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

        self.set_roles_getter(
            lambda: session_storage[session.get('session-state', '')].get('userinfo', {}).get('realm_access', {}).get(
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
            assert request.args.get('state') == session.get('session-state')

            token, oauth_session = self.get_token(request.url)
            userinfo = self.get_user_info(oauth_session)

            # Update the session with the new state and user info
            session.update({'session-state': request.args.get('state')})
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
        uri, state = self._auth_server_login()

        # Create a response object
        response = make_response(redirect(uri))
        session.update({'session-state': state})
        self._session_storage[state] = {'userinfo': None, 'token': None}

        # Redirect the user to the authorization server
        return response

    def _logout(self):
        if session.get('session-state', None) and (session.get('session-state') in self._session_storage):
            token = self._session_storage[session.get('session-state')]['token']
            logout_endpoint, post_logout_uri = self._auth_config.logout_endpoint, self._auth_config.post_logout_uri
            logout_url = self.get_keycloak_logout_url(self.get_oauth_session(token),
                                                      logout_endpoint, post_logout_uri)
            if session.get('session-state', '') in self._session_storage:
                del self._session_storage[session.get('session-state')]
            session.update({'session-state': None})
            return logout_url
        return None

    def _logout_route_handler(self):
        logout_url = self._logout()
        if logout_url:
            return redirect(logout_url)
        else:
            return redirect('/')

    def is_authenticated(self):
        state = session.get('session-state', '')
        if (state in self._session_storage) and (self._session_storage[state]['userinfo']):
            return True
        return False

    def get_userinfo(self):
        state = session.get('session-state', '')
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

            referrer_path = get_cookie(environ, 'referrer_path')
            unrestricted_page_routes = self.oidc_client.get_config().get_unrestricted_routes()
            login_route = self.oidc_client.get_config().app_login_route
            page_unrestricted = any(is_path_matched(request.path, pattern) for pattern in unrestricted_page_routes)
            if (not referrer_path) and page_unrestricted:
                return self.wsgi_app(environ, start_response)  # Se convierte la respuesta en un iterable para WSGI

            # Check if session is valid
            authenticated = False
            if session.get('session-state', None) and (session.get('session-state') in self.session_storage):
                token = self.session_storage[session.get('session-state')]['token']

                # Check if the user is authenticated against the OIDC server
                authenticated = self.oidc_client.is_valid_oidc_session(self.oidc_client.get_oauth_session(token))

            if not authenticated:
                if not page_unrestricted:
                    response = make_response(redirect(login_route))
                    response.set_cookie('referrer_path', request.path)
                    if self.log_enabled:
                        self.flask_app.logger.debug(f'Redirecting to {login_route}...')
                    return response(environ, start_response)
            else:
                if referrer_path:
                    if self.log_enabled:
                        self.flask_app.logger.info(f'User authenticated. Redirecting to {referrer_path}')
                    # Make a redirect response and delete cookie referrer_path
                    response = make_response(redirect(referrer_path))
                    response.set_cookie('referrer_path', '', expires=0)
                    if self.log_enabled:
                        self.flask_app.logger.debug(f'Redirecting to {referrer_path}...')
                    return response(environ, start_response)  # Se convierte la respuesta en un iterable para WSGI

            # Calling original WSGI app
            return self.wsgi_app(environ, start_response)
