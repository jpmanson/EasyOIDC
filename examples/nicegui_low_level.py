from typing import Optional
from fastapi import Request
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from EasyOIDC import OIDClient, Config
from EasyOIDC.utils import is_path_matched
from EasyOIDC.session import SessionHandler
from nicegui import Client, app, ui

session_store = SessionHandler(mode='redis')

auth_config = Config('.env')
auth = OIDClient(auth_config)
# Set callbacks that dependes on the web framework.
auth.set_roles_getter(lambda: session_store[app.storage.user.get('session-state')]['userinfo']['realm_access']['roles'])
auth.set_redirector(lambda url: RedirectResponse(url))

LOGIN_PATH = '/login'
LOGOUT_PATH = '/logout'
AUTHORIZE_PATH = '/authorize'
unrestricted_page_routes = [LOGIN_PATH, AUTHORIZE_PATH, '/', LOGOUT_PATH, '/_nicegui/*', '/favicon.ico']


class AuthMiddleware(BaseHTTPMiddleware):
    """This middleware restricts access to all NiceGUI pages.
    It redirects the user to the login page if they are not authenticated.
    """
    async def dispatch(self, request: Request, call_next):
        authenticated = False
        session_state = app.storage.user.get('session-state', None)
        if session_state and (session_state in session_store):
            token = session_store[session_state]['token']
            # Verifica la sesión contra el servidor
            authenticated = auth.is_valid_oidc_session(auth.get_oauth_session(token))

        if not authenticated:
            if session_state and (session_state in session_store):
                del session_store[session_state]
            # Check if the requested path matches with unrestricted_page_routes.
            if not any(is_path_matched(request.url.path, pattern) for pattern in unrestricted_page_routes):
                app.storage.user['referrer_path'] = request.url.path
                print(f"After login will redirect to '{request.url.path}'")
                return RedirectResponse(LOGIN_PATH)
        else:
            referrer_path = app.storage.user.get('referrer_path', None)
            if referrer_path:
                app.storage.user['referrer_path'] = ''
                print('Redirecting to', referrer_path)
                return RedirectResponse(referrer_path)
        return await call_next(request)


app.add_middleware(AuthMiddleware)


@ui.page('/')
def main_page() -> None:
    if app.storage.user.get('session-state', None) and (app.storage.user.get('session-state') in session_store):
        auth_txt = f'User authenticated={session_store[app.storage.user.get("session-state")]["authenticated"]}'
        userinfo = session_store[app.storage.user.get('session-state')]['userinfo']
        ui.html(f"Welcome to the Flask app with Middleware!.<br>{auth_txt}<br>{userinfo}<br><a href='/logout'>Logout</a>")
    else:
        ui.html(f"Welcome to the Flask app with Middleware!.<br><a href='/login'>Login</a>")


@ui.page('/protected')
@auth.require_roles('/access-forbidden', and_allow_roles=['intranet-home'])
def home_page() -> None:
    with ui.column().classes('absolute-center items-center'):
        ui.label(f'Hello!').classes('text-2xl')


@ui.page('/access-forbidden')
def access_forbidden() -> None:
    with ui.column().classes('absolute-center items-center'):
        ui.label(f'Lo lamento. Acceso denegado!').classes('text-2xl')


def logout():
    state = app.storage.user.get('session-state', '')
    token = session_store[state]['token'] if state in session_store else None
    logout_endpoint, post_logout_endpoint = auth_config.logout_endpoint, auth_config.post_logout_uri
    logout_url = auth.get_keycloak_logout_url(auth.get_oauth_session(token),
                                              logout_endpoint, post_logout_endpoint)
    app.storage.user.update({'session-state': None, 'referrer_path': ''})
    if state in session_store:
        del session_store[state]
    return logout_url


@ui.page(LOGOUT_PATH)
def logout_page() -> Optional[RedirectResponse]:
    return RedirectResponse(logout())


@ui.page(AUTHORIZE_PATH)
def authorize_page(request: Request) -> Optional[RedirectResponse]:
    try:
        state = request.query_params['state']
        assert state == app.storage.user.get('session-state', None)

        token, oauth_session = auth.get_token(str(request.url))
        userinfo = auth.get_user_info(oauth_session)
        session_store[state] = {'userinfo': userinfo, 'token': dict(token)}

        print('Authentication successful:', userinfo)
    except Exception as e:
        print(f"Authentication error: '{e}'. Redirecting to login page...")
        RedirectResponse(LOGIN_PATH)

    referrer_path = app.storage.user.get('referrer_path', '')
    if referrer_path:
        return RedirectResponse(referrer_path)
    else:
        return RedirectResponse('/')


@ui.page(LOGIN_PATH)
def login() -> Optional[RedirectResponse]:
    uri, state = auth.auth_server_login()
    app.storage.user.update({'session-state': state})
    session_store[state] = {'userinfo': None, 'token': None}
    return RedirectResponse(uri)


ui.run(storage_secret=auth_config.cookie_secret_key, port=5000)
