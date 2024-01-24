from flask import Flask, request, redirect, make_response, session, Response
from werkzeug.wrappers import Request as WSGIRequest
from http.cookies import SimpleCookie
from EasyOIDC.auth import OIDClient, Config
from EasyOIDC.utils import is_path_matched
from EasyOIDC.session import SessionHandler
from taipy import Gui
import taipy as tp
import taipy.gui.builder as tgb
from taipy.gui import Markdown


"""
session_store = shelve.open("session_data/sessions.db")
# Clean session store
for key in session_store.keys():
    del session_store[key]
"""
session_store = SessionHandler(mode='redis')

auth_config = Config('.env')
auth = OIDClient(auth_config)
auth.set_roles_getter(lambda: session_store[session.get('session-state')]['userinfo']['realm_access']['roles'])
auth.set_redirector(lambda url: redirect(url))


LOGIN_PATH = '/login'
LOGOUT_PATH = '/logout'
AUTHORIZE_PATH = '/authorize'
unrestricted_page_routes = [LOGIN_PATH, AUTHORIZE_PATH, LOGOUT_PATH, '/favicon.ico',
                            '/taipy-*', '/stylekit/*', '/manifest.json', '/227.taipy-gui.js',
                            '/taipy.status.json']


class AuthenticationMiddleware:
    def __init__(self, app):
        self.wsgi_app = app.wsgi_app  # Original WSGI application
        self.flask_app = app  # Flask application instance

    def __call__(self, environ, start_response):
        wsgi_request = WSGIRequest(environ)

        with self.flask_app.request_context(wsgi_request.environ):
            def get_cookie(environ, key):
                cookies = SimpleCookie(environ.get('HTTP_COOKIE', ''))
                return cookies.get(key).value if key in cookies else None

            referrer_path = get_cookie(environ, 'referrer_path')
            page_unrestricted = any(is_path_matched(request.path, pattern) for pattern in unrestricted_page_routes)
            if (not referrer_path) and page_unrestricted:
                return self.wsgi_app(environ, start_response)  # Se convierte la respuesta en un iterable para WSGI

            # Check if session is valid
            authenticated = False
            if session.get('session-state', None) and (session.get('session-state') in session_store):
                token = session_store[session.get('session-state')]['token']

                # Check if the user is authenticated against the OIDC server
                authenticated = auth.is_valid_oidc_session(auth.get_oauth_session(token))
                session_store[session.get('session-state')]['authenticated'] = authenticated

            if not authenticated:
                if not page_unrestricted:
                    response = make_response(redirect(LOGIN_PATH))
                    response.set_cookie('referrer_path', request.path)
                    app.logger.debug(f'Redirecting to {LOGIN_PATH}...')
                    return response(environ, start_response)
            else:
                if referrer_path:
                    app.logger.info(f'User authenticated. Redirecting to {referrer_path}')
                    # Make a redirect response and delete cookie referrer_path
                    response = make_response(redirect(referrer_path))
                    response.set_cookie('referrer_path', '', expires=0)
                    app.logger.debug(f'Redirecting to {referrer_path}...')
                    return response(environ, start_response)  # Se convierte la respuesta en un iterable para WSGI

            # Calling original WSGI app
            return self.wsgi_app(environ, start_response)


app = Flask(__name__)
app.secret_key = auth_config.cookie_secret_key
app.wsgi_app = AuthenticationMiddleware(app)


# Define a protected route for the Flask app
@app.route('/protected')
@auth.require_roles(access_denied_url='/access-forbidden', and_allow_roles=['intranet-home'])
def protected():
    return "You have accessed a protected route."


@app.route('/access-forbidden')
def access_forbidden():
    return "Sorry, you are not allowed to access this route."


# Define a route for the Flask app
@app.route('/sdfsd')
def root():
    if session.get('session-state', None) and (session.get('session-state') in session_store):
        auth_txt = f'User authenticated={session_store[session.get("session-state")]["authenticated"]}'
        userinfo = session_store[session.get('session-state')]['userinfo']
        return f"Welcome to the Flask app with Middleware!.<br>{auth_txt}<br>{userinfo}<br><a href='/logout'>Logout</a>"
    else:
        return f"Welcome to the Flask app with Middleware!.<br><a href='/login'>Login</a>"


@app.route('/authorize')
def authorize_page():
    try:
        # Ensure the 'state' parameter matches the one stored in the user's session
        assert request.args.get('state') == session.get('session-state')

        token, oauth_session = auth.get_token(request.url)
        userinfo = auth.get_user_info(oauth_session)

        # Update the session with the new state and user info
        session.update({'session-state': request.args.get('state')})
        # Save user data in session store
        session_store[request.args.get('state')] = {'userinfo': userinfo, 'token': dict(token), 'authenticated': True}
        app.logger.info(f'User {userinfo["name"]} authenticated')

    except Exception as e:
        app.logger.error(f"Authorization error: {e}")
        return redirect('/login')

    referrer_path = session.get('referrer_path', '/')
    app.logger.debug(f'Redirecting to {referrer_path}...')
    return redirect(referrer_path)


@app.route('/login')
def login():
    uri, state = auth.auth_server_login()

    # Create a response object
    response = make_response(redirect(uri))
    session.update({'session-state': state})
    session_store[state] = {'userinfo': None, 'token': None, 'authenticated': False}

    # Redirect the user to the authorization server
    return response


def logout():
    if session.get('session-state', None) and (session.get('session-state') in session_store):
        token = session_store[session.get('session-state')]['token']
        logout_endpoint, post_logout_uri = auth_config.logout_endpoint, auth_config.post_logout_uri
        logout_url = auth.get_keycloak_logout_url(auth.get_oauth_session(token),
                                                  logout_endpoint, post_logout_uri)
        if session.get('session-state', '') in session_store:
            del session_store[session.get('session-state')]
        session.update({'session-state': None})
        return logout_url
    return None


@app.route('/logout')
def logout_page():
    logout_url = logout()
    if logout_url:
        return redirect(logout_url)
    else:
        return redirect('/')


with tgb.Page() as home_page:
    tgb.text("Name:")
    tgb.input("{input_name}")
    tgb.button("Submit")
    tgb.text("Message {message}")


pages = {
    "page1": Markdown("#HolaPage1"),
	"page2": Markdown("#HolaPage2"),
    "/": Markdown("<center><|navbar|></center>")
}

gui = Gui(pages=pages, flask=app)
gui.run()