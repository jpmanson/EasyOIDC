"""FastAPI / Starlette integration for EasyOIDC.

Unlike the Flask and NiceGUI integrations -- which reach for an ambient,
context-local session object (``flask.session`` / ``app.storage.user``) --
FastAPI has no such ambient accessor. The client session lives in
``request.session``, provided by Starlette's ``SessionMiddleware``, so the
methods that inspect the current user take an explicit ``Request``:

    auth.is_authenticated(request)
    auth.get_userinfo(request)
    auth.get_user_roles(request)

For convenience the same information is also exposed as FastAPI dependencies
(``auth.current_user`` / ``auth.require_user``) and through the
``require_roles`` decorator, which injects the ``Request`` for you.

Basic usage:

    from fastapi import FastAPI
    from EasyOIDC import Config, SessionHandler
    from EasyOIDC.frameworks.fastapi import FastAPIOIDClient

    app = FastAPI()
    auth = FastAPIOIDClient(app, auth_config=Config('.env'),
                            session_storage=SessionHandler(mode='memory'))
"""
import inspect
import logging
from functools import wraps

from fastapi import Request
from fastapi.responses import RedirectResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

from EasyOIDC import OIDClient, Config, SessionHandler
from EasyOIDC.frameworks import SESSION_STATE_VAR_NAME, REFERRER_VAR_NAME
from EasyOIDC.utils import is_path_matched


def default_roles_getter(userinfo: dict) -> list:
    """Extract roles from a Keycloak-style userinfo payload."""
    return (userinfo or {}).get('realm_access', {}).get('roles', [])


class FastAPIOIDClient(OIDClient):
    """OIDC client that wires the login/authorize/logout routes and the
    authentication middleware into a FastAPI application."""

    logger = logging.getLogger(__name__)

    def __init__(self, app, auth_config: Config = None, session_storage: SessionHandler = None,
                 log_enabled: bool = True, **kwargs):
        """
        :param app: the FastAPI (or Starlette) application.
        :param auth_config: EasyOIDC Config. Defaults to ``Config('.env')``.
        :param session_storage: server-side session store. Defaults to
            ``SessionHandler(mode='memory')``.
        :param log_enabled: emit debug logs during the flow.

        Keyword arguments:
        :key unrestricted_routes: list of route patterns that skip authentication.
            Replaces the ones coming from the config.
        :key logger: custom ``logging.Logger``.
        :key roles_getter: callable receiving the ``userinfo`` dict and returning
            the list of roles. Defaults to Keycloak's ``realm_access.roles``.
        :key add_session_middleware: whether to install Starlette's
            ``SessionMiddleware`` (default ``True``). Set to ``False`` if your app
            installs it itself -- in that case add it *after* building this client,
            so it still wraps the authentication middleware.
        :key session_cookie: name of the signed session cookie
            (default ``'easyoidc_session'``).
        :key same_site: SameSite policy for the session cookie (default ``'lax'``).
        :key https_only: mark the session cookie as ``Secure`` (default ``False``).
        :key max_age: session cookie lifetime in seconds (default 14 days).
        :key validate_session_on_each_request: re-validate the token against the
            OIDC server's userinfo endpoint on every request (default ``True``).
            This matches the behaviour of the other integrations, but costs one
            HTTP round-trip per request; set to ``False`` to trust the stored
            session instead.
        """
        if auth_config is None:
            auth_config = Config('.env')
        if session_storage is None:
            session_storage = SessionHandler(mode='memory')

        super().__init__(auth_config, log_enabled)
        self._app = app
        self._auth_config = auth_config
        self._session_storage = session_storage
        self._roles_from_userinfo = kwargs.get('roles_getter', default_roles_getter)

        if 'unrestricted_routes' in kwargs:
            self._auth_config.unrestricted_routes = kwargs['unrestricted_routes']

        if 'logger' in kwargs:
            self.logger = kwargs['logger']

        self.set_redirector(lambda url: RedirectResponse(url))

        # The authentication middleware is added FIRST so that SessionMiddleware
        # ends up wrapping it: Starlette applies the last added middleware as the
        # outermost one, and `request.session` must already exist by the time the
        # authentication middleware runs.
        app.add_middleware(
            AuthMiddleware,
            oidc_client=self,
            session_storage=session_storage,
            log_enabled=log_enabled,
            logger=self.logger,
            validate_session=kwargs.get('validate_session_on_each_request', True),
        )

        if kwargs.get('add_session_middleware', True):
            if not auth_config.cookie_secret_key:
                raise ValueError(
                    "'cookie_secret_key' is required to sign the session cookie. "
                    "Set it in your configuration, or pass add_session_middleware=False "
                    "if your application already installs Starlette's SessionMiddleware."
                )
            app.add_middleware(
                SessionMiddleware,
                secret_key=auth_config.cookie_secret_key,
                session_cookie=kwargs.get('session_cookie', 'easyoidc_session'),
                same_site=kwargs.get('same_site', 'lax'),
                https_only=kwargs.get('https_only', False),
                max_age=kwargs.get('max_age', 14 * 24 * 60 * 60),
            )

        # Turn the redirect raised by the `require_user` dependency into a real
        # redirect response.
        app.add_exception_handler(
            _RedirectException,
            lambda request, exc: RedirectResponse(exc.url),
        )

        # Register the OIDC routes. They are added with `router.add_route` (rather
        # than `add_api_route`) so they stay out of the OpenAPI schema.
        app.router.add_route(auth_config.app_login_route, self._login_route_handler,
                             methods=['GET'], name='easyoidc_login')
        app.router.add_route(auth_config.app_authorize_route, self._authorize_route_handler,
                             methods=['GET'], name='easyoidc_authorize')
        app.router.add_route(auth_config.app_logout_route, self._logout_route_handler,
                             methods=['GET'], name='easyoidc_logout')

    def set_logger(self, logger):
        self.logger = logger

    # ------------------------------------------------------------------
    # Route handlers
    # ------------------------------------------------------------------
    async def _login_route_handler(self, request: Request) -> Response:
        uri, state = await run_in_threadpool(self.auth_server_login)
        request.session[SESSION_STATE_VAR_NAME] = state
        self._session_storage[state] = {'userinfo': None, 'token': None}
        return RedirectResponse(uri)

    async def _authorize_route_handler(self, request: Request) -> Response:
        try:
            state = request.query_params['state']
            if state != request.session.get(SESSION_STATE_VAR_NAME):
                raise ValueError('State mismatch between the callback and the session')

            token, oauth_session = await run_in_threadpool(self.get_token, str(request.url))
            userinfo = await run_in_threadpool(self.get_user_info, oauth_session)
            self._session_storage[state] = {'userinfo': userinfo, 'token': dict(token)}

            if self._log_enabled:
                self.logger.debug('Authentication successful.')
        except Exception as e:
            if self._log_enabled:
                self.logger.debug(f"Authentication error: '{e}'. Redirecting to login page...")
            return RedirectResponse(self._auth_config.app_login_route)

        referrer_path = request.session.pop(REFERRER_VAR_NAME, '')
        return RedirectResponse(referrer_path or '/')

    async def _logout_route_handler(self, request: Request) -> Response:
        logout_url = self._logout(request)
        if logout_url:
            return RedirectResponse(logout_url)
        return RedirectResponse(self._auth_config.post_logout_uri or '/')

    def _logout(self, request: Request):
        logout_url = None
        state = request.session.get(SESSION_STATE_VAR_NAME)
        token = self.get_current_token(request)
        if token:
            if self._auth_config.logout_endpoint:
                logout_url = self.get_logout_url(token.get('id_token', None))
            del self._session_storage[state]
        request.session.pop(SESSION_STATE_VAR_NAME, None)
        request.session.pop(REFERRER_VAR_NAME, None)
        return logout_url

    # ------------------------------------------------------------------
    # Public API (request-scoped)
    # ------------------------------------------------------------------
    def _get_session_data(self, request: Request) -> dict:
        state = request.session.get(SESSION_STATE_VAR_NAME)
        if state and (state in self._session_storage):
            return self._session_storage[state] or {}
        return {}

    def get_current_token(self, request: Request):
        """Return the OIDC token stored for the current session, or None."""
        return self._get_session_data(request).get('token')

    def is_authenticated(self, request: Request) -> bool:
        """Whether the current session holds authenticated user information."""
        return bool(self._get_session_data(request).get('userinfo'))

    def get_userinfo(self, request: Request):
        """Return the userinfo payload for the current session, or None."""
        return self._get_session_data(request).get('userinfo') or None

    def get_user_roles(self, request: Request) -> list:
        """Return the roles of the current user (empty list when anonymous)."""
        return self._roles_from_userinfo(self.get_userinfo(request)) or []

    # ------------------------------------------------------------------
    # FastAPI dependencies
    # ------------------------------------------------------------------
    def current_user(self, request: Request):
        """Dependency returning the userinfo dict, or None when not authenticated.

            @app.get('/me')
            def me(user: dict = Depends(auth.current_user)):
                ...
        """
        return self.get_userinfo(request)

    def require_user(self, request: Request):
        """Dependency returning the userinfo dict, redirecting to the login route
        when the request is not authenticated.

            @app.get('/private')
            def private(user: dict = Depends(auth.require_user)):
                ...
        """
        userinfo = self.get_userinfo(request)
        if not userinfo:
            raise _RedirectException(self._auth_config.app_login_route)
        return userinfo

    # ------------------------------------------------------------------
    # Role-based access control
    # ------------------------------------------------------------------
    def require_roles(self, access_denied_url: str, and_allow_roles: list = [], deny_roles: list = [],
                      or_allow_roles: list = []):
        """Decorator enforcing role-based access control on a FastAPI endpoint.

        Works on both sync and async endpoints. If the decorated function does
        not already declare a ``Request`` parameter, one is added to its
        signature so FastAPI injects it, and it is not forwarded to the endpoint.
        """
        def decorator(func):
            signature = inspect.signature(func)
            request_param = next(
                (name for name, param in signature.parameters.items()
                 if param.annotation is Request),
                None,
            )
            injected = request_param is None
            if injected:
                request_param = '__easyoidc_request'
                params = [p for p in signature.parameters.values()
                          if p.kind is not inspect.Parameter.VAR_KEYWORD]
                var_kw = [p for p in signature.parameters.values()
                          if p.kind is inspect.Parameter.VAR_KEYWORD]
                params.append(inspect.Parameter(request_param, inspect.Parameter.KEYWORD_ONLY,
                                                annotation=Request))
                new_signature = signature.replace(parameters=params + var_kw)

            def authorize(kwargs):
                """Whether the current user passes the role check. Removes the
                injected Request so it is not forwarded to the endpoint."""
                request = kwargs.pop(request_param, None) if injected else kwargs.get(request_param)
                try:
                    is_authorized = self.evaluate_roles(self.get_user_roles(request),
                                                        and_allow_roles, deny_roles, or_allow_roles)
                except Exception:
                    is_authorized = False
                return is_authorized

            if inspect.iscoroutinefunction(func):
                @wraps(func)
                async def wrapper(*args, **kwargs):
                    if not authorize(kwargs):
                        return self._redirector(access_denied_url)
                    return await func(*args, **kwargs)
            else:
                @wraps(func)
                def wrapper(*args, **kwargs):
                    if not authorize(kwargs):
                        return self._redirector(access_denied_url)
                    return func(*args, **kwargs)

            if injected:
                wrapper.__signature__ = new_signature
            return wrapper

        return decorator


class _RedirectException(Exception):
    """Internal exception raised by the require_user dependency. It is turned
    into a redirect response by an exception handler registered on the app."""

    def __init__(self, url: str):
        self.url = url
        super().__init__(url)


class AuthMiddleware(BaseHTTPMiddleware):
    """Redirects unauthenticated requests to the login route, remembering the
    originally requested path so the user is sent back after logging in."""

    def __init__(self, app, oidc_client: FastAPIOIDClient, session_storage: SessionHandler,
                 log_enabled: bool = True, logger: logging.Logger = None,
                 validate_session: bool = True):
        super().__init__(app)
        self.oidc_client = oidc_client
        self.session_storage = session_storage
        self.log_enabled = log_enabled
        self.logger = logger or logging.getLogger(__name__)
        self.validate_session = validate_session

    async def dispatch(self, request: Request, call_next):
        if 'session' not in request.scope:
            raise RuntimeError(
                "No session found on the request. EasyOIDC's FastAPI integration "
                "requires Starlette's SessionMiddleware to wrap it. Either let "
                "EasyOIDC install it (the default), or, when using "
                "add_session_middleware=False, call app.add_middleware(SessionMiddleware, ...) "
                "AFTER building the FastAPIOIDClient so it becomes the outer layer."
            )

        config = self.oidc_client.get_config()
        login_route = config.app_login_route
        page_unrestricted = any(is_path_matched(request.url.path, pattern)
                                for pattern in config.get_unrestricted_routes())

        session_state = request.session.get(SESSION_STATE_VAR_NAME)
        authenticated = False
        if session_state and (session_state in self.session_storage):
            stored = self.session_storage[session_state] or {}
            token = stored.get('token')
            if self.validate_session:
                # `is_valid_oidc_session` performs a blocking HTTP request, so it
                # runs in a threadpool to avoid stalling the event loop.
                authenticated = await run_in_threadpool(
                    self.oidc_client.is_valid_oidc_session,
                    self.oidc_client.get_oauth_session(token),
                )
            else:
                authenticated = bool(stored.get('userinfo'))

        if not authenticated and not page_unrestricted:
            # Only discard the stored session when the request is actually being
            # bounced to the login route. Unrestricted routes are left untouched:
            # the /login -> /authorize callback keeps a not-yet-authenticated
            # session entry that the authorize handler still needs.
            if session_state and (session_state in self.session_storage):
                del self.session_storage[session_state]
            referrer = request.url.path + (f'?{request.url.query}' if request.url.query else '')
            request.session[REFERRER_VAR_NAME] = referrer or '/'
            if self.log_enabled:
                self.logger.debug(f"After login will redirect to '{referrer}'")
            return RedirectResponse(login_route)

        return await call_next(request)
