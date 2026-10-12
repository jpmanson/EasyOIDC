"""FastAPI example wiring the OIDC flow by hand with the base OIDClient.

Nothing here is FastAPI-specific inside EasyOIDC: `OIDClient` only speaks OIDC,
so the routes and the session handling are yours to write. Use this when you
want full control; for the batteries-included version see
`fastapi_high_level.py`.

Since 0.4.0 the recommended low-level calls are `begin_login()` /
`complete_login()`: they add PKCE (S256), a nonce and ID token validation.
The per-login secrets they return must be kept server-side until the
callback arrives.

Note that `OIDClient`'s network calls are blocking, so the handlers below are
declared as plain `def`: Starlette then runs them in a threadpool and the event
loop is never stalled.

Run with:
    uv add "easyoidc[fastapi]"
    uv run uvicorn fastapi_low_level:app --port 5000
"""
import secrets

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from EasyOIDC import Config, OIDClient, SessionHandler

LOGIN_PATH = '/login'
LOGOUT_PATH = '/logout'
AUTHORIZE_PATH = '/authorize'
SESSION_ID = 'session-id'

auth_config = Config('.env')
auth = OIDClient(auth_config)
session_store = SessionHandler(mode='memory')

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=auth_config.cookie_secret_key)


def _current_userinfo(request: Request):
    sid = request.session.get(SESSION_ID)
    if sid and (sid in session_store):
        return (session_store[sid] or {}).get('userinfo')
    return None


@app.get('/', response_class=HTMLResponse)
def root(request: Request):
    userinfo = _current_userinfo(request)
    if userinfo:
        return f"Welcome!<br>{userinfo}<br><a href='{LOGOUT_PATH}'>Logout</a>"
    return f"FastAPI low-level demo.<br><a href='{LOGIN_PATH}'>Login</a>"


@app.get(LOGIN_PATH)
def login(request: Request):
    login = auth.begin_login()
    sid = secrets.token_urlsafe(32)
    request.session[SESSION_ID] = sid
    session_store[sid] = {'login': login, 'userinfo': None, 'token': None}
    return RedirectResponse(login['url'])


@app.get(AUTHORIZE_PATH)
def authorize(request: Request):
    sid = request.session.get(SESSION_ID)
    pending = (session_store[sid] or {}).get('login') if sid and sid in session_store else None
    if not pending or request.query_params.get('state') != pending['state']:
        return RedirectResponse(LOGIN_PATH)
    if request.query_params.get('error'):
        return HTMLResponse(f"Login failed: {request.query_params['error']}", status_code=400)
    try:
        result = auth.complete_login(str(request.url), pending)
    except Exception:
        del session_store[sid]
        return RedirectResponse(LOGIN_PATH)

    del session_store[sid]
    new_sid = secrets.token_urlsafe(32)
    session_store[new_sid] = {'userinfo': result['userinfo'], 'token': result['token']}
    request.session[SESSION_ID] = new_sid
    return RedirectResponse('/')


@app.get(LOGOUT_PATH)
def logout(request: Request):
    logout_url = None
    sid = request.session.get(SESSION_ID)
    if sid and (sid in session_store):
        token = (session_store[sid] or {}).get('token') or {}
        if auth_config.logout_endpoint:
            logout_url = auth.get_logout_url(token.get('id_token'))
        del session_store[sid]
    request.session.pop(SESSION_ID, None)
    return RedirectResponse(logout_url or '/')


@app.get('/protected')
def protected(request: Request):
    userinfo = _current_userinfo(request)
    if not userinfo:
        return RedirectResponse(LOGIN_PATH)
    return {'message': 'You have accessed a protected route', 'user': userinfo}


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='localhost', port=5000)
