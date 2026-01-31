from fastapi import Request
from fastapi.responses import RedirectResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Route
from EasyOIDC import OIDClient, Config
from EasyOIDC.utils import is_path_matched
from EasyOIDC.session import SessionHandler
from EasyOIDC.frameworks import SESSION_STATE_VAR_NAME, REFERRER_VAR_NAME
from nicegui.app import App
import logging


class NiceGUIOIDClient(OIDClient):
    logger = logging.getLogger(__name__)

    def __init__(self, nicegui_app: App, auth_config: Config = None, session_storage: SessionHandler = None,
                 log_enabled: bool = True, **kwargs):
        if auth_config is None:
            auth_config = Config('.env')
        if session_storage is None:
            session_storage = SessionHandler(mode='redis')

        super().__init__(auth_config, log_enabled)
        self._auth_config = auth_config
        self._session_storage = session_storage
        self._nicegui_app = nicegui_app

        if 'unrestricted_routes' in kwargs:
            self._auth_config.unrestricted_routes = kwargs['unrestricted_routes']
        else:
            # Get all routes from nicegui app
            nicegui_routes = ([r.path.replace('{key:path}', '*').replace('{key}/{path:path}', '*') for r in
                              nicegui_app.routes if (type(r) == Route) or (r.path.startswith('/_nicegui'))] +
                              ['/_nicegui/*'])
            self._auth_config.unrestricted_routes += nicegui_routes

        if 'logger' in kwargs:
            self.logger = kwargs['logger']

        auth_middleware = AuthMiddleware
        auth_middleware.logger = self.logger
        auth_middleware.session_storage = session_storage
        auth_middleware.oidc_client = self
        auth_middleware.log_enabled = log_enabled
        auth_middleware.nicegui_app = nicegui_app
        self._nicegui_app.add_middleware(auth_middleware)

        self.set_redirector(lambda url: RedirectResponse(url))

        self.set_roles_getter(
            lambda: self._session_storage[nicegui_app.storage.user.get(SESSION_STATE_VAR_NAME, '')].get('userinfo',
                                                                                                        {}).get(
                'realm_access', {}).get(
                'roles', []))

        # Add FastAPI route /login to method login_route_handler
        self._nicegui_app.add_route(auth_config.app_login_route, self._login_route_handler)

        # Add FastAPI route /authorize to method authorize_route_handler
        self._nicegui_app.add_route(auth_config.app_authorize_route, self._authorize_route_handler)

        # Add FastAPI route /logout to method logout_route_handler
        self._nicegui_app.add_route(auth_config.app_logout_route, self._logout_route_handler)

    def set_logger(self, logger):
        self.logger = logger

    def _authorize_route_handler(self, request: Request) -> Response:
        try:
            state = request.query_params['state']
            assert state == self._nicegui_app.storage.user.get(SESSION_STATE_VAR_NAME, None)

            token, oauth_session = self.get_token(str(request.url))
            userinfo = self.get_user_info(oauth_session)
            self._session_storage[state] = {'userinfo': userinfo, 'token': dict(token)}

            if self._log_enabled:
                self.logger.debug('Authentication successful.')
        except Exception as e:
            if self._log_enabled:
                self.logger.debug(f"Authentication error: '{e}'. Redirecting to login page...")
            return RedirectResponse(self._auth_config.app_login_route)

        referrer_path = self._nicegui_app.storage.user.get(REFERRER_VAR_NAME, '')
        if referrer_path:
            return RedirectResponse(referrer_path)
        else:
            return RedirectResponse('/')

    def _login_route_handler(self, request: Request) -> Response:
        uri, state = self.auth_server_login()
        self._nicegui_app.storage.user.update({SESSION_STATE_VAR_NAME: state})
        self._session_storage[state] = {'userinfo': None, 'token': None}
        return RedirectResponse(uri)

    def _get_current_token(self):
        state = self._nicegui_app.storage.user.get(SESSION_STATE_VAR_NAME, None)
        if state and state in self._session_storage:
            return self._session_storage[state]['token']
        return None

    def _logout(self):
        logout_url = None
        token = self._get_current_token()
        if token:
            if self._auth_config.logout_endpoint:
                logout_url = self.get_logout_url(token.get('id_token', None))
            del self._session_storage[self._nicegui_app.storage.user.get(SESSION_STATE_VAR_NAME)]
        self._nicegui_app.storage.user.update({SESSION_STATE_VAR_NAME: None, REFERRER_VAR_NAME: ''})
        return logout_url

    def _logout_route_handler(self, request: Request) -> Response:
        logout_url = self._logout()
        if logout_url:
            return RedirectResponse(logout_url)
        else:
            return RedirectResponse(self._auth_config.post_logout_uri)

    def is_authenticated(self):
        state = self._nicegui_app.storage.user.get(SESSION_STATE_VAR_NAME, None)
        if state and (state in self._session_storage) and (self._session_storage[state]['userinfo']):
            return True
        return False

    def get_userinfo(self):
        state = self._nicegui_app.storage.user.get(SESSION_STATE_VAR_NAME, None)
        if state and (state in self._session_storage) and (self._session_storage[state]['userinfo']):
            return self._session_storage[state]['userinfo']
        return None


class AuthMiddleware(BaseHTTPMiddleware):
    session_storage = None
    oidc_client = None
    log_enabled = None
    nicegui_app = None
    logger = logging.getLogger(__name__)

    async def dispatch(self, request: Request, call_next):
        authenticated = False
        config = self.oidc_client.get_config()
        session_state = self.nicegui_app.storage.user.get(SESSION_STATE_VAR_NAME, None)
        unrestricted_page_routes = self.oidc_client.get_config().get_unrestricted_routes()
        login_route = config.app_login_route
        page_unrestricted = any(is_path_matched(request.url.path, pattern) for pattern in unrestricted_page_routes)

        if session_state and (session_state in self.session_storage):
            token = self.session_storage[session_state]['token']
            # Verifica la sesión contra el servidor
            authenticated = self.oidc_client.is_valid_oidc_session(self.oidc_client.get_oauth_session(token))

        if not authenticated:
            if session_state and (session_state in self.session_storage):
                del self.session_storage[session_state]
            # Check if the requested path matches with unrestricted_page_routes.
            if not page_unrestricted:
                path_without_domain = request.url.path + ('?' + request.url.query if request.url.query else '')
                self.nicegui_app.storage.user[REFERRER_VAR_NAME] = '/' if path_without_domain is None \
                    else path_without_domain
                if self.log_enabled:
                    self.logger.debug(
                        f"After login will redirect to '{self.nicegui_app.storage.user[REFERRER_VAR_NAME]}'")
                return RedirectResponse(login_route)
        else:
            referrer_path = self.nicegui_app.storage.user.get(REFERRER_VAR_NAME, '')
            if referrer_path:
                self.nicegui_app.storage.user[REFERRER_VAR_NAME] = ''
                if self.log_enabled:
                    self.logger.debug('Redirecting to', referrer_path)
                return RedirectResponse(referrer_path)
        return await call_next(request)
