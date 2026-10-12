import html

from flask import request, redirect, make_response, session
from werkzeug.wrappers import Request as WSGIRequest

from EasyOIDC import OIDClient, Config, SessionHandler
from EasyOIDC.auth import AccessDeniedError, IDTokenValidationError
from EasyOIDC.flow import AccessPolicy, end_session, finish_login, load_session, logout_url_for, start_login
from EasyOIDC.frameworks import SESSION_STATE_VAR_NAME, REFERRER_VAR_NAME
from EasyOIDC.utils import is_path_matched, safe_redirect_path


def default_access_denied_handler(error: AccessDeniedError, logout_url: str = None):
    logout = (f"<p><a href='{html.escape(logout_url, quote=True)}'>Sign out</a></p>"
              if logout_url else '')
    return make_response(f"<h1>Access denied</h1><p>{html.escape(str(error))}</p>{logout}", 403)


def default_auth_error_handler(error: Exception, login_route: str):
    return make_response(
        "<h1>Authentication error</h1><p>The sign-in could not be completed.</p>"
        f"<p><a href='{html.escape(login_route, quote=True)}'>Try again</a></p>", 400)


class FlaskOIDClient(OIDClient):
    def __init__(self, app, auth_config: Config = None, session_storage: SessionHandler = None,
                 log_enabled: bool = True, **kwargs):
        """
        Keyword arguments (all optional, added in 0.4.0 unless noted):

        :key unrestricted_routes: route patterns that skip authentication.
        :key roles_getter: ``(userinfo) -> list``. Defaults to the config's
            ``roles_source`` (``realm_access.roles`` unless configured).
        :key required_roles: a user needs at least one of these roles.
        :key require_email_verified: reject unverified emails.
        :key access_denied_handler: ``(error, logout_url) -> Response``.
        :key auth_error_handler: ``(error, login_route) -> Response``.
        :key validate_session_on_each_request: re-check the token with the
            userinfo endpoint on every request (default ``True``, 0.3.x
            behaviour).
        """
        if auth_config is None:
            auth_config = Config('.env')
        if session_storage is None:
            session_storage = SessionHandler(mode='redis')

        super().__init__(auth_config, log_enabled)
        self._flask_app = app
        self._auth_config = auth_config
        self._session_storage = session_storage
        self._flask_app.secret_key = auth_config.cookie_secret_key
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

        self._flask_app.wsgi_app = AuthenticationMiddleware(app, session_storage, self)
        self.set_redirector(lambda url: redirect(url))

        if 'unrestricted_routes' in kwargs:
            self._auth_config.unrestricted_routes = kwargs['unrestricted_routes']

        self.set_roles_getter(lambda: self._roles_for_current_session())

        self._flask_app.add_url_rule(auth_config.app_authorize_route, 'authorize_route_handler',
                                     self._authorize_route_handler)
        self._flask_app.add_url_rule(auth_config.app_login_route, 'login_route_handler', self._login_route_handler)
        self._flask_app.add_url_rule(auth_config.app_logout_route, 'logout_route_handler', self._logout_route_handler)

    @property
    def access_policy(self) -> AccessPolicy:
        return self._policy

    def _session_data(self) -> dict:
        from flask import g
        cached = getattr(g, '_easyoidc_session', None)
        if cached is not None:
            return cached
        data = load_session(self, self._session_storage, session.get(SESSION_STATE_VAR_NAME),
                            self._session_roles, validate_with_server=False, policy=self._policy) or {}
        g._easyoidc_session = data
        return data

    def _roles_for_current_session(self) -> list:
        data = self._session_data()
        if not data:
            return []
        return list(data.get('roles') or self._session_roles(data) or [])

    def _authorize_route_handler(self):
        query = request.args.to_dict()
        try:
            new_sid, data = finish_login(self, self._session_storage, session.get(SESSION_STATE_VAR_NAME),
                                         request.url, query, self._session_roles, self._policy)
        except AccessDeniedError as e:
            session.pop(SESSION_STATE_VAR_NAME, None)
            if self._log_enabled:
                self._flask_app.logger.info(f'Access denied after login: {e.reason}')
            return self._access_denied_handler(e, logout_url_for(self, getattr(e, 'session', None)))
        except IDTokenValidationError as e:
            session.pop(SESSION_STATE_VAR_NAME, None)
            if self._log_enabled:
                self._flask_app.logger.warning(f'Invalid ID token: {e}')
            return self._auth_error_handler(e, self._auth_config.app_login_route)
        except Exception as e:
            session.pop(SESSION_STATE_VAR_NAME, None)
            if self._log_enabled:
                self._flask_app.logger.error(f"Authorization error: {e}")
            if query.get('error'):
                return self._auth_error_handler(e, self._auth_config.app_login_route)
            return redirect(self._auth_config.app_login_route)

        session[SESSION_STATE_VAR_NAME] = new_sid
        if self._log_enabled:
            self._flask_app.logger.debug(f"User {(data.get('userinfo') or {}).get('sub')} authenticated")

        referrer_path = safe_redirect_path(request.cookies.get(REFERRER_VAR_NAME, '/'))
        response = make_response(redirect(referrer_path))
        response.delete_cookie(REFERRER_VAR_NAME)
        return response

    def _login_route_handler(self):
        sid, uri = start_login(self, self._session_storage, session.get(SESSION_STATE_VAR_NAME))
        session[SESSION_STATE_VAR_NAME] = sid
        response = make_response(redirect(uri))
        next_url = request.args.get('next')
        if next_url:
            response.set_cookie(REFERRER_VAR_NAME, safe_redirect_path(next_url), httponly=True, samesite='Lax')
        return response

    def _get_current_token(self):
        return self._session_data().get('token')

    def _logout(self):
        logout_url = end_session(self, self._session_storage, session.get(SESSION_STATE_VAR_NAME))
        session.pop(SESSION_STATE_VAR_NAME, None)
        return logout_url

    def _logout_route_handler(self):
        logout_url = self._logout()
        if logout_url:
            return redirect(logout_url)
        return redirect(self._auth_config.post_logout_uri or '/')

    def is_authenticated(self):
        return bool(self._session_data().get('userinfo'))

    def get_userinfo(self):
        return self._session_data().get('userinfo') or None

    def get_id_claims(self) -> dict:
        return self._session_data().get('id_claims') or {}


class AuthenticationMiddleware:
    def __init__(self, app, session_storage: SessionHandler, oidc_client: FlaskOIDClient, log_enabled: bool = True):
        self.wsgi_app = app.wsgi_app
        self.flask_app = app
        self.session_storage = session_storage
        self.oidc_client = oidc_client
        self.log_enabled = log_enabled

    def __call__(self, environ, start_response):
        wsgi_request = WSGIRequest(environ)
        client = self.oidc_client
        config = client.get_config()

        with self.flask_app.request_context(wsgi_request.environ):
            from flask import g

            oidc_routes = (config.app_login_route, config.app_authorize_route, config.app_logout_route)
            if request.path in oidc_routes:
                return self.wsgi_app(environ, start_response)

            page_unrestricted = any(is_path_matched(request.path, pattern)
                                    for pattern in config.get_unrestricted_routes())

            sid = session.get(SESSION_STATE_VAR_NAME)
            data = None
            if sid:
                data = load_session(client, self.session_storage, sid, client._session_roles,
                                    validate_with_server=client._validate_each, policy=client._policy)
            authenticated = bool(data and data.get('userinfo'))
            g._easyoidc_session = data or {}

            if not authenticated and not page_unrestricted:
                path = request.full_path if request.query_string else request.path
                response = make_response(redirect(config.app_login_route))
                response.set_cookie(REFERRER_VAR_NAME, safe_redirect_path(path), httponly=True, samesite='Lax')
                self.flask_app.session_interface.save_session(self.flask_app, session, response)
                if self.log_enabled:
                    self.flask_app.logger.debug(f'Redirecting to {config.app_login_route}...')
                return response(environ, start_response)

        return self.wsgi_app(environ, start_response)
