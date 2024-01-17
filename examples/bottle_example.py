from bottle import request, redirect, response, run
import bottle
import settings
from EasyOIDC.auth import OIDClient
from beaker.middleware import SessionMiddleware

session_opts = {
    'session.type': 'file',
    'session.cookie_expires': 300,
    'session.data_dir': './data',
    'session.auto': True
}
app = SessionMiddleware(bottle.app(), session_opts)
auth = OIDClient()


@bottle.route('/')
def home():
    # validate_cookie()
    return 'Inicio de la aplicación'


@bottle.route('/login')
def login():
    uri, state = auth.auth_server_login()
    response.set_cookie('session-cookie', dict(state=state), secret=settings.COOKIE_SECRET_KEY)
    redirect(uri)


def validate_cookie(state: str = None):
    if state is None:
        state = request.query.state
    oauth_state = request.get_cookie('session-cookie', secret=settings.COOKIE_SECRET_KEY)
    assert oauth_state['state'] == state


@bottle.route('/authorize')
def authorize():
    validate_cookie()

    token, oauth_session = auth.get_token(request.url)
    # userinfo = auth.get_user_info(oauth_session)

    session = bottle.request.environ.get('beaker.session')
    session['tokens'] = {
        'access_token': token['access_token'],
        'refresh_token': token.get('refresh_token')
    }
    session.save()

    redirect('/')


@bottle.route('/protected')
def protected():
    session = bottle.request.environ.get('beaker.session')
    tokens = session.get('tokens')
    print("Tokens recuperados de la sesión:", tokens)  # Depuración

    if not tokens or 'access_token' not in tokens:
        redirect('/login')

    # Aquí podrías añadir lógica para validar o refrescar el token si es necesario
    # ...

    return 'Contenido protegido'


if __name__ == "__main__":
    run(app=app, host='localhost', port=5000)