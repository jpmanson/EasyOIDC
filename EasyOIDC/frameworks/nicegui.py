import html
import logging

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Route
from nicegui.app import App

from EasyOIDC import OIDClient, Config
from EasyOIDC.auth import AccessDeniedError, IDTokenValidationError
from EasyOIDC.flow import AccessPolicy, end_session, finish_login, load_session, logout_url_for, start_login
from EasyOIDC.frameworks import SESSION_STATE_VAR_NAME, REFERRER_VAR_NAME
from EasyOIDC.session import SessionHandler
from EasyOIDC.utils import is_path_matched, safe_redirect_path


def default_access_denied_handler(request: Request, error: AccessDeniedError, logout_url: str = None):
    logout = (f"<p><a href='{html.escape(logout_url, quote=True)}'>Sign out</a></p>"
              if logout_url else '')
    return HTMLResponse(f"<h1>Access denied</h1><p>{html.escape(str(error))}</p>{logout}", status_code=403)


def default_auth_error_handler(request: Request, error: Exception, login_route: str):
    return HTMLResponse(
        "<h1>Authentication error</h1><p>The sign-in could not be completed.</p>"
        f"<p><a href='{html.escape(login_route, quote=True)}'>Try again</a></p>", status_code=400)


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
        self._validate_each = kwargs.get('validate_session_on_each_request', True)

        user_roles_getter = kwargs.get('roles_getter')
        if user_roles_getter is not None:
            self._session_roles = lambda data: user_roles_getter((data or {}).get('userinfo'))
        else:
            self._session_roles = self.roles_from_session

        self._policy = AccessPolicy(required_roles=list(kwargs.get('required_roles') or []),
                                    require_email_verified=bool(kwargs.get('require_email_verified', False)))
        self._access_denied_handler = kwargs.get('access_denied_handler', default_access_denied_handler)
        self._auth_error_handler = kwargs.get('auth_error_handler', default_auth_error_handler)

        if 'unrestricted_routes' in kwargs:
            self._auth_config.unrestricted_routes = kwargs['unrestricted_routes']
        else:
            nicegui_routes = ([r.path.replace('{key:path}', '*').replace('{key}/{path:path}', '*') for r in
                              nicegui_app.routes if (type(r) is Route) or (r.path.startswith('/_nicegui'))] +
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
        self.set_roles_getter(lambda: self._roles_for_current_session())

        self._nicegui_app.add_route(auth_config.app_login_route, self._login_route_handler)
        self._nicegui_app.add_route(auth_config.app_authorize_route, self._authorize_route_handler)
        self._nicegui_app.add_route(auth_config.app_logout_route, self._logout_route_handler)

    def set_logger(self, logger):
        self.logger = logger

    @property
    def access_policy(self) -> AccessPolicy:
        return self._policy

    def _storage(self):
        return self._nicegui_app.storage.user

    def _session_data(self) -> dict:
        sid = self._storage().get(SESSION_STATE_VAR_NAME, None)
        return load_session(self, self._session_storage, sid, self._session_roles,
                            validate_with_server=False, policy=self._policy) or {}

    def _roles_for_current_session(self) -> list:
        data = self._session_data()
        if not data:
            return []
        return list(data.get('roles') or self._session_roles(data) or [])

    async def _authorize_route_handler(self, request: Request) -> Response:
        storage = self._storage()
        query = dict(request.query_params)
        try:
            new_sid, _ = await run_in_threadpool(
                finish_login, self, self._session_storage, storage.get(SESSION_STATE_VAR_NAME, None),
                str(request.url), query, self._session_roles, self._policy)
        except AccessDeniedError as e:
            storage.update({SESSION_STATE_VAR_NAME: None, REFERRER_VAR_NAME: ''})
            return self._access_denied_handler(request, e, logout_url_for(self, getattr(e, 'session', None)))
        except IDTokenValidationError as e:
            storage.update({SESSION_STATE_VAR_NAME: None})
            return self._auth_error_handler(request, e, self._auth_config.app_login_route)
        except Exception as e:
            storage.update({SESSION_STATE_VAR_NAME: None})
            if self._log_enabled:
                self.logger.debug(f"Authentication error: '{e}'. Redirecting to login page...")
            if query.get('error'):
                return self._auth_error_handler(request, e, self._auth_config.app_login_route)
            return RedirectResponse(self._auth_config.app_login_route)

        referrer_path = safe_redirect_path(storage.get(REFERRER_VAR_NAME, ''))
        storage.update({SESSION_STATE_VAR_NAME: new_sid, REFERRER_VAR_NAME: ''})
        return RedirectResponse(referrer_path)

    async def _login_route_handler(self, request: Request) -> Response:
        storage = self._storage()
        next_url = request.query_params.get('next')
        if next_url:
            storage[REFERRER_VAR_NAME] = safe_redirect_path(next_url)
        sid, uri = await run_in_threadpool(start_login, self, self._session_storage,
                                           storage.get(SESSION_STATE_VAR_NAME, None))
        storage.update({SESSION_STATE_VAR_NAME: sid})
        return RedirectResponse(uri)

    def _get_current_token(self):
        return self._session_data().get('token')

    def _logout(self):
        storage = self._storage()
        logout_url = end_session(self, self._session_storage, storage.get(SESSION_STATE_VAR_NAME, None))
        storage.update({SESSION_STATE_VAR_NAME: None, REFERRER_VAR_NAME: ''})
        return logout_url

    def _logout_route_handler(self, request: Request) -> Response:
        logout_url = self._logout()
        if logout_url:
            return RedirectResponse(logout_url)
        return RedirectResponse(self._auth_config.post_logout_uri or '/')

    def is_authenticated(self):
        return bool(self._session_data().get('userinfo'))

    def get_userinfo(self):
        return self._session_data().get('userinfo') or None

    def get_id_claims(self) -> dict:
        return self._session_data().get('id_claims') or {}


class AuthMiddleware(BaseHTTPMiddleware):
    session_storage = None
    oidc_client = None
    log_enabled = None
    nicegui_app = None
    logger = logging.getLogger(__name__)

    async def dispatch(self, request: Request, call_next):
        client = self.oidc_client
        config = client.get_config()
        oidc_routes = (config.app_login_route, config.app_authorize_route, config.app_logout_route)
        if request.url.path in oidc_routes:
            return await call_next(request)

        storage = self.nicegui_app.storage.user
        sid = storage.get(SESSION_STATE_VAR_NAME, None)
        page_unrestricted = any(is_path_matched(request.url.path, pattern)
                                for pattern in config.get_unrestricted_routes())

        data = None
        if sid:
            data = await run_in_threadpool(load_session, client, self.session_storage, sid,
                                           client._session_roles, client._validate_each, client._policy)
        authenticated = bool(data and data.get('userinfo'))

        if not authenticated and not page_unrestricted:
            path = request.url.path + ('?' + request.url.query if request.url.query else '')
            storage[REFERRER_VAR_NAME] = safe_redirect_path(path)
            if self.log_enabled:
                self.logger.debug(f"After login will redirect to '{storage[REFERRER_VAR_NAME]}'")
            return RedirectResponse(config.app_login_route)
        return await call_next(request)
