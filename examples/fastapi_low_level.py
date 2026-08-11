"""FastAPI example wiring the OIDC flow by hand with the base OIDClient.

Nothing here is FastAPI-specific inside EasyOIDC: `OIDClient` only speaks OIDC,
so the routes and the session handling are yours to write. Use this when you
want full control; for the batteries-included version see
`fastapi_high_level.py`.

Note that `OIDClient`'s network calls are blocking, so the handlers below are
declared as plain `def`: Starlette then runs them in a threadpool and the event
loop is never stalled. If you make them `async def`, wrap those calls with
`starlette.concurrency.run_in_threadpool`.

Run with:
    uv add "easyoidc[fastapi]"
    uv run uvicorn fastapi_low_level:app --port 5000
"""
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from EasyOIDC import Config, OIDClient, SessionHandler

LOGIN_PATH = '/login'
LOGOUT_PATH = '/logout'
AUTHORIZE_PATH = '/authorize'
SESSION_STATE = 'session-state'

auth_config = Config('.env')
auth = OIDClient(auth_config)
session_store = SessionHandler(mode='memory')

app = FastAPI()
# Signed cookie holding the session state. Required to correlate the OIDC
# callback with the browser that started the login.
app.add_middleware(SessionMiddleware, secret_key=auth_config.cookie_secret_key)


def _current_userinfo(request: Request):
    state = request.session.get(SESSION_STATE)
    if state and (state in session_store):
        return (session_store[state] or {}).get('userinfo')
    return None


@app.get('/', response_class=HTMLResponse)
def root(request: Request):
    userinfo = _current_userinfo(request)
    if userinfo:
        return f"Welcome!<br>{userinfo}<br><a href='{LOGOUT_PATH}'>Logout</a>"
    return f"FastAPI low-level demo.<br><a href='{LOGIN_PATH}'>Login</a>"


@app.get(LOGIN_PATH)
def login(request: Request):
    uri, state = auth.auth_server_login()
    request.session[SESSION_STATE] = state
    session_store[state] = {'userinfo': None, 'token': None}
    return RedirectResponse(uri)


@app.get(AUTHORIZE_PATH)
def authorize(request: Request):
    try:
        state = request.query_params['state']
        # Reject a callback that doesn't match the state we handed out
        assert state == request.session.get(SESSION_STATE)

        token, oauth_session = auth.get_token(str(request.url))
        userinfo = auth.get_user_info(oauth_session)
        session_store[state] = {'userinfo': userinfo, 'token': dict(token)}
    except Exception:
        return RedirectResponse(LOGIN_PATH)

    return RedirectResponse('/')


@app.get(LOGOUT_PATH)
def logout(request: Request):
    logout_url = None
    state = request.session.get(SESSION_STATE)
    if state and (state in session_store):
        token = (session_store[state] or {}).get('token') or {}
        if auth_config.logout_endpoint:
            logout_url = auth.get_logout_url(token.get('id_token'))
        del session_store[state]
    request.session.pop(SESSION_STATE, None)
    return RedirectResponse(logout_url or '/')


@app.get('/protected')
def protected(request: Request):
    # No middleware here: guard the route yourself.
    userinfo = _current_userinfo(request)
    if not userinfo:
        return RedirectResponse(LOGIN_PATH)
    return {'message': 'You have accessed a protected route', 'user': userinfo}


if __name__ == '__main__':
    import uvicorn
    # host/port must match the redirect_uri configured in .env
    uvicorn.run(app, host='localhost', port=5000)
