from fastapi import Request
from fastapi.responses import RedirectResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from EasyOIDC import OIDClient, Config
from EasyOIDC.utils import is_path_matched
from EasyOIDC.session import SessionHandler
from nicegui.app import App


class NiceGUIOIDClient(OIDClient):
    def __init__(self, nicegui_app: App, auth_config: Config = None, session_storage: SessionHandler = None,
                 log_enabled: bool = True):
        if auth_config is None:
            auth_config = Config('.env')
        if session_storage is None:
            session_storage = SessionHandler(mode='redis')

        auth_config.unrestricted_routes = ['/_nicegui/*']

        super().__init__(auth_config, log_enabled)
        self.auth_config = auth_config
        self.session_storage = session_storage
        self.nicegui_app = nicegui_app
        auth_middleware = AuthMiddleware
        auth_middleware.session_storage = session_storage
        auth_middleware.oidc_client = self
        auth_middleware.log_enabled = log_enabled
        auth_middleware.nicegui_app = nicegui_app
        self.nicegui_app.add_middleware(auth_middleware)

        self.set_roles_getter(
            lambda: self.session_storage[nicegui_app.storage.user.get('session-state')]['userinfo']['realm_access'][
                'roles'])
        self.set_redirector(lambda url: RedirectResponse(url))

        # Add FastAPI route /login to method login_route_handler
        self.nicegui_app.add_route(auth_config.app_login_route, self.login_route_handler)

        # Add FastAPI route /authorize to method authorize_route_handler
        self.nicegui_app.add_route(auth_config.app_authorize_route, self.authorize_route_handler)

        # Add FastAPI route /logout to method logout_route_handler
        self.nicegui_app.add_route(auth_config.app_logout_route, self.logout_route_handler)

    def authorize_route_handler(self, request: Request) -> Response:
        try:
            state = request.query_params['state']
            assert state == self.nicegui_app.storage.user.get('session-state', None)

            token, oauth_session = self.get_token(str(request.url))
            userinfo = self.get_user_info(oauth_session)
            self.session_storage[state] = {'userinfo': userinfo, 'token': dict(token)}

            print('Authentication successful:', userinfo)
        except Exception as e:
            print(f"Authentication error: '{e}'. Redirecting to login page...")
            RedirectResponse(self.auth_config.app_login_route)

        referrer_path = self.nicegui_app.storage.user.get('referrer_path', '')
        if referrer_path:
            return RedirectResponse(referrer_path)
        else:
            return RedirectResponse('/')

    def login_route_handler(self, request: Request) -> Response:
        uri, state = self.auth_server_login()
        self.nicegui_app.storage.user.update({'session-state': state})
        self.session_storage[state] = {'userinfo': None, 'token': None}
        return RedirectResponse(uri)

    def logout(self):
        state = self.nicegui_app.storage.user.get('session-state', '')
        token = self.session_storage[state]['token'] if state in self.session_storage else None
        logout_endpoint, post_logout_endpoint = self.auth_config.logout_endpoint, self.auth_config.post_logout_uri
        logout_url = self.get_keycloak_logout_url(self.get_oauth_session(token),
                                                  logout_endpoint, post_logout_endpoint)
        self.nicegui_app.storage.user.update({'session-state': None, 'referrer_path': ''})
        if state in self.session_storage:
            del self.session_storage[state]
        return logout_url

    def logout_route_handler(self, request: Request) -> Response:
        return RedirectResponse(self.logout())

    def is_authenticated(self):
        state = self.nicegui_app.storage.user.get('session-state', None)
        if (state in self.session_storage) and (self.session_storage[state]['userinfo']):
            return True
        return False

    def get_userinfo(self):
        state = self.nicegui_app.storage.user.get('session-state', None)
        if (state in self.session_storage) and (self.session_storage[state]['userinfo']):
            return self.session_storage[state]['userinfo']
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
                self.nicegui_app.storage.user['referrer_path'] = request.url.path
                print(f"After login will redirect to '{request.url.path}'")
                return RedirectResponse(login_route)
        else:
            referrer_path = self.nicegui_app.storage.user.get('referrer_path', None)
            if referrer_path:
                self.nicegui_app.storage.user['referrer_path'] = ''
                print('Redirecting to', referrer_path)
                return RedirectResponse(referrer_path)
        return await call_next(request)
