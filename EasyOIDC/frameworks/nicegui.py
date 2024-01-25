from fastapi import Request
from fastapi.responses import RedirectResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Route
from EasyOIDC import OIDClient, Config
from EasyOIDC.utils import is_path_matched
from EasyOIDC.session import SessionHandler
from nicegui.app import App
import logging

logger = logging.getLogger(__name__)


class NiceGUIOIDClient(OIDClient):
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
            nicegui_routes = [r.path.replace('{key:path}', '*').replace('{key}/{path:path}', '*') for r in nicegui_app.routes if isinstance(r, Route)]
            self._auth_config.unrestricted_routes = nicegui_routes + ['/_nicegui/*']

        auth_middleware = AuthMiddleware
        auth_middleware.session_storage = session_storage
        auth_middleware.oidc_client = self
        auth_middleware.log_enabled = log_enabled
        auth_middleware.nicegui_app = nicegui_app
        self._nicegui_app.add_middleware(auth_middleware)

        self.set_redirector(lambda url: RedirectResponse(url))

        self.set_roles_getter(
            lambda: self._session_storage[nicegui_app.storage.user.get('session-state', '')].get('userinfo', {}).get('realm_access', {}).get(
                'roles', []))

        # Add FastAPI route /login to method login_route_handler
        self._nicegui_app.add_route(auth_config.app_login_route, self._login_route_handler)

        # Add FastAPI route /authorize to method authorize_route_handler
        self._nicegui_app.add_route(auth_config.app_authorize_route, self._authorize_route_handler)

        # Add FastAPI route /logout to method logout_route_handler
        self._nicegui_app.add_route(auth_config.app_logout_route, self._logout_route_handler)

    def _authorize_route_handler(self, request: Request) -> Response:
        try:
            state = request.query_params['state']
            assert state == self._nicegui_app.storage.user.get('session-state', None)

            token, oauth_session = self.get_token(str(request.url))
            userinfo = self.get_user_info(oauth_session)
            self._session_storage[state] = {'userinfo': userinfo, 'token': dict(token)}

            if self._log_enabled:
                logger.debug('Authentication successful.')
        except Exception as e:
            if self._log_enabled:
                logger.debug(f"Authentication error: '{e}'. Redirecting to login page...")
            RedirectResponse(self._auth_config.app_login_route)

        referrer_path = self._nicegui_app.storage.user.get('referrer_path', '')
        if referrer_path:
            return RedirectResponse(referrer_path)
        else:
            return RedirectResponse('/')

    def _login_route_handler(self, request: Request) -> Response:
        uri, state = self.auth_server_login()
        self._nicegui_app.storage.user.update({'session-state': state})
        self._session_storage[state] = {'userinfo': None, 'token': None}
        return RedirectResponse(uri)

    def _get_current_token(self):
        state = self._nicegui_app.storage.user.get('session-state', '')
        if state in self._session_storage:
            return self._session_storage[state]['token']
        return None

    def _logout(self):
        logout_url = None
        token = self._get_current_token()
        if token:
            if self._auth_config.logout_endpoint:
                if self._auth_config.auth_service == 'keycloak':
                    logout_endpoint, post_logout_uri = self._auth_config.logout_endpoint, self._auth_config.post_logout_uri
                    logout_url = self.get_keycloak_logout_url(self.get_oauth_session(token),
                                                              logout_endpoint, post_logout_uri)
                elif self._auth_config.auth_service == 'auth0':
                    logout_url = self.get_auth0_logout_url()

                # Other OIDC providers here (Google, GitHub, etc.)
            del self._session_storage[self._nicegui_app.storage.user.get('session-state')]
        self._nicegui_app.storage.user.update({'session-state': None, 'referrer_path': ''})
        return logout_url

    def _logout_route_handler(self, request: Request) -> Response:
        logout_url = self._logout()
        if logout_url:
            return RedirectResponse(logout_url)
        else:
            return RedirectResponse(self._auth_config.post_logout_uri)

    def is_authenticated(self):
        state = self._nicegui_app.storage.user.get('session-state', None)
        if (state in self._session_storage) and (self._session_storage[state]['userinfo']):
            return True
        return False

    def get_userinfo(self):
        state = self._nicegui_app.storage.user.get('session-state', None)
        if (state in self._session_storage) and (self._session_storage[state]['userinfo']):
            return self._session_storage[state]['userinfo']
        return None


class AuthMiddleware(BaseHTTPMiddleware):
    session_storage = None
    oidc_client = None
    log_enabled = None
    nicegui_app = None

    async def dispatch(self, request: Request, call_next):
        authenticated = False
        config = self.oidc_client.get_config()
        session_state = self.nicegui_app.storage.user.get('session-state', None)
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
                self.nicegui_app.storage.user['referrer_path'] = '/' if request.url.path is None else request.url.path
                if self.log_enabled:
                    logger.debug(f"After login will redirect to '{request.url.path}'")
                return RedirectResponse(login_route)
        else:
            referrer_path = self.nicegui_app.storage.user.get('referrer_path', '')
            if referrer_path:
                self.nicegui_app.storage.user['referrer_path'] = ''
                if self.log_enabled:
                    logger.debug('Redirecting to', referrer_path)
                return RedirectResponse(referrer_path)
        return await call_next(request)
