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
import html
import inspect
import logging
from functools import wraps

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

from EasyOIDC import OIDClient, Config, SessionHandler
from EasyOIDC.auth import AccessDeniedError, IDTokenValidationError
from EasyOIDC.flow import AccessPolicy, end_session, finish_login, load_session, logout_url_for, start_login
from EasyOIDC.frameworks import SESSION_STATE_VAR_NAME, REFERRER_VAR_NAME
from EasyOIDC.utils import is_path_matched, safe_redirect_path


def default_roles_getter(userinfo: dict) -> list:
    """Extract roles from a Keycloak-style userinfo payload (0.3.x default)."""
    return (userinfo or {}).get('realm_access', {}).get('roles', [])


def default_access_denied_handler(request: Request, error: AccessDeniedError, logout_url: str = None):
    logout = (f"<p><a href='{html.escape(logout_url, quote=True)}'>Sign out</a></p>"
              if logout_url else '')
    return HTMLResponse(
        f"<h1>Access denied</h1><p>{html.escape(str(error))}</p>{logout}",
        status_code=403,
    )


def default_auth_error_handler(request: Request, error: Exception, login_route: str):
    return HTMLResponse(
        "<h1>Authentication error</h1>"
        "<p>The sign-in could not be completed.</p>"
        f"<p><a href='{html.escape(login_route, quote=True)}'>Try again</a></p>",
        status_code=400,
    )


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
            the list of roles. When omitted, roles are resolved from the config
            (``roles_source`` / ``roles_claims_from``), which defaults to
            Keycloak's ``realm_access.roles`` in userinfo.
        :key required_roles: list of roles; a user needs at least one of them
            to get a session. Others get ``access_denied_handler``'s response.
        :key require_email_verified: reject users whose ``email_verified``
            claim is not ``True`` (default ``False``).
        :key access_denied_handler: ``(request, error, logout_url) -> Response``.
        :key auth_error_handler: ``(request, error, login_route) -> Response``,
            used when the IdP returns an error or the ID token is invalid.
        :key add_session_middleware: whether to install Starlette's
            ``SessionMiddleware`` (default ``True``).
        :key session_cookie: name of the signed session cookie
            (default ``'easyoidc_session'``).
        :key same_site: SameSite policy for the session cookie (default ``'lax'``).
        :key https_only: mark the session cookie as ``Secure`` (default ``False``).
        :key max_age: session cookie lifetime in seconds (default 14 days).
        :key validate_session_on_each_request: re-validate the token against the
            OIDC server's userinfo endpoint on every request (default ``True``).
            With ``False`` the stored session is trusted until the access token
            expires; it is then refreshed (or the session dropped).
        """
        if auth_config is None:
            auth_config = Config('.env')
        if session_storage is None:
            session_storage = SessionHandler(mode='memory')

        super().__init__(auth_config, log_enabled)
        self._app = app
        self._auth_config = auth_config
        self._session_storage = session_storage
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

        if 'logger' in kwargs:
            self.logger = kwargs['logger']

        self.set_redirector(lambda url: RedirectResponse(url))

        app.add_middleware(
            AuthMiddleware,
            oidc_client=self,
            session_storage=session_storage,
            log_enabled=log_enabled,
            logger=self.logger,
            validate_session=self._validate_each,
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

        app.add_exception_handler(
            _RedirectException,
            lambda request, exc: RedirectResponse(exc.url),
        )

        app.router.add_route(auth_config.app_login_route, self._login_route_handler,
                             methods=['GET'], name='easyoidc_login')
        app.router.add_route(auth_config.app_authorize_route, self._authorize_route_handler,
                             methods=['GET'], name='easyoidc_authorize')
        app.router.add_route(auth_config.app_logout_route, self._logout_route_handler,
                             methods=['GET'], name='easyoidc_logout')

    def set_logger(self, logger):
        self.logger = logger

    @property
    def access_policy(self) -> AccessPolicy:
        return self._policy

    # ------------------------------------------------------------------
    # Route handlers
    # ------------------------------------------------------------------
    async def _login_route_handler(self, request: Request) -> Response:
        next_url = request.query_params.get('next')
        if next_url:
            request.session[REFERRER_VAR_NAME] = safe_redirect_path(next_url)
        sid, uri = await run_in_threadpool(start_login, self, self._session_storage,
                                           request.session.get(SESSION_STATE_VAR_NAME))
        request.session[SESSION_STATE_VAR_NAME] = sid
        return RedirectResponse(uri)

    async def _authorize_route_handler(self, request: Request) -> Response:
        sid = request.session.get(SESSION_STATE_VAR_NAME)
        query = dict(request.query_params)
        try:
            new_sid, _ = await run_in_threadpool(
                finish_login, self, self._session_storage, sid, str(request.url), query,
                self._session_roles, self._policy)
        except AccessDeniedError as e:
            request.session.pop(SESSION_STATE_VAR_NAME, None)
            request.session.pop(REFERRER_VAR_NAME, None)
            if self._log_enabled:
                self.logger.info(f'Access denied after login: {e.reason}')
            return self._access_denied_handler(request, e, logout_url_for(self, getattr(e, 'session', None)))
        except (IDTokenValidationError,) as e:
            request.session.pop(SESSION_STATE_VAR_NAME, None)
            if self._log_enabled:
                self.logger.warning(f'Invalid ID token: {e}')
            return self._auth_error_handler(request, e, self._auth_config.app_login_route)
        except Exception as e:
            request.session.pop(SESSION_STATE_VAR_NAME, None)
            if self._log_enabled:
                self.logger.debug(f"Authentication error: '{e}'.")
            if query.get('error'):
                return self._auth_error_handler(request, e, self._auth_config.app_login_route)
            return RedirectResponse(self._auth_config.app_login_route)

        request.session[SESSION_STATE_VAR_NAME] = new_sid
        referrer_path = safe_redirect_path(request.session.pop(REFERRER_VAR_NAME, ''))
        return RedirectResponse(referrer_path)

    async def _logout_route_handler(self, request: Request) -> Response:
        logout_url = self._logout(request)
        if logout_url:
            return RedirectResponse(logout_url)
        return RedirectResponse(self._auth_config.post_logout_uri or '/')

    def _logout(self, request: Request):
        logout_url = end_session(self, self._session_storage, request.session.get(SESSION_STATE_VAR_NAME))
        request.session.pop(SESSION_STATE_VAR_NAME, None)
        request.session.pop(REFERRER_VAR_NAME, None)
        return logout_url

    # ------------------------------------------------------------------
    # Public API (request-scoped)
    # ------------------------------------------------------------------
    def _get_session_data(self, request: Request) -> dict:
        cached = request.scope.get('easyoidc.session')
        if cached is not None:
            return cached
        data = load_session(self, self._session_storage, request.session.get(SESSION_STATE_VAR_NAME),
                            self._session_roles, validate_with_server=False, policy=self._policy) or {}
        request.scope['easyoidc.session'] = data
        return data

    def get_current_token(self, request: Request):
        """Return the OIDC token stored for the current session, or None."""
        return self._get_session_data(request).get('token')

    def is_authenticated(self, request: Request) -> bool:
        """Whether the current session holds authenticated user information."""
        return bool(self._get_session_data(request).get('userinfo'))

    def get_userinfo(self, request: Request):
        """Return the userinfo payload for the current session, or None."""
        return self._get_session_data(request).get('userinfo') or None

    def get_id_claims(self, request: Request) -> dict:
        """Return the validated ID token claims of the current session."""
        return self._get_session_data(request).get('id_claims') or {}

    def get_user_roles(self, request: Request) -> list:
        """Return the roles of the current user (empty list when anonymous)."""
        data = self._get_session_data(request)
        if not data:
            return []
        return list(data.get('roles') or self._session_roles(data) or [])

    # ------------------------------------------------------------------
    # FastAPI dependencies
    # ------------------------------------------------------------------
    def current_user(self, request: Request):
        """Dependency returning the userinfo dict, or None when not authenticated."""
        return self.get_userinfo(request)

    def require_user(self, request: Request):
        """Dependency returning the userinfo dict, redirecting to the login route
        when the request is not authenticated."""
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
    """Internal exception raised by the require_user dependency."""

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

        client = self.oidc_client
        config = client.get_config()
        login_route = config.app_login_route
        oidc_routes = (config.app_login_route, config.app_authorize_route, config.app_logout_route)
        if request.url.path in oidc_routes:
            return await call_next(request)

        page_unrestricted = any(is_path_matched(request.url.path, pattern)
                                for pattern in config.get_unrestricted_routes())

        sid = request.session.get(SESSION_STATE_VAR_NAME)
        data = None
        if sid:
            data = await run_in_threadpool(
                load_session, client, self.session_storage, sid, client._session_roles,
                self.validate_session, client._policy)
        request.scope['easyoidc.session'] = data or {}
        authenticated = bool(data and data.get('userinfo'))

        if not authenticated and not page_unrestricted:
            if sid and not (data or {}).get('userinfo'):
                stored = self.session_storage[sid] if sid in self.session_storage else None
                if not (stored or {}).get('login'):
                    request.session.pop(SESSION_STATE_VAR_NAME, None)
            referrer = request.url.path + (f'?{request.url.query}' if request.url.query else '')
            request.session[REFERRER_VAR_NAME] = safe_redirect_path(referrer)
            if self.log_enabled:
                self.logger.debug(f"After login will redirect to '{referrer}'")
            return RedirectResponse(login_route)

        return await call_next(request)
