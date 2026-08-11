"""FastAPI example using the high-level EasyOIDC integration.

EasyOIDC registers the /login, /authorize and /logout routes and installs an
authentication middleware that redirects anonymous users to the login page.

Run with:
    uv add "easyoidc[fastapi]"
    uv run uvicorn fastapi_high_level:app --port 5000
"""
from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse

from EasyOIDC import Config, SessionHandler
from EasyOIDC.frameworks.fastapi import FastAPIOIDClient

app = FastAPI()

auth_config = Config('.env')
session_storage = SessionHandler(mode='redis', namespace=__name__)

# `unrestricted_routes` lists everything reachable without a session. FastAPI's
# own documentation routes are ordinary routes, so add them here if you want
# them public.
auth = FastAPIOIDClient(
    app,
    auth_config=auth_config,
    session_storage=session_storage,
    unrestricted_routes=['/', '/access-forbidden', '/docs', '/openapi.json'],
)


@app.get('/', response_class=HTMLResponse)
def root(request: Request):
    if auth.is_authenticated(request):
        userinfo = auth.get_userinfo(request)
        return (
            "User authenticated!<br>"
            f"Name: {userinfo.get('name')}<br>"
            f"Email: {userinfo.get('email')}<br>"
            f"Roles: {auth.get_user_roles(request)}<br>"
            "<a href='/logout'>Logout</a>"
        )
    return "FastAPI demo.<br><a href='/login'>Login</a>"


@app.get('/protected')
def protected(request: Request):
    # The middleware already guarantees a valid session here.
    return {'message': 'You reached a protected route', 'user': auth.get_userinfo(request)}


@app.get('/me')
def me(user: dict = Depends(auth.require_user)):
    """Same thing through a dependency: anonymous requests are sent to /login."""
    return {'user': user}


@app.get('/admin')
@auth.require_roles('/access-forbidden', and_allow_roles=['intranet-home'])
def admin():
    """Only users holding the 'intranet-home' role get through."""
    return {'message': 'Welcome, admin'}


@app.get('/access-forbidden', response_class=HTMLResponse)
def access_forbidden():
    return "Sorry. Access denied!"


if __name__ == '__main__':
    import uvicorn
    # host/port must match the redirect_uri configured in .env
    uvicorn.run(app, host='localhost', port=5000)
