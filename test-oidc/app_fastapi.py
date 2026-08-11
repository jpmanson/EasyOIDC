"""Minimal FastAPI example to test EasyOIDC against a real (local) OIDC server.

Usage:
    1) docker compose up                    # starts mock-oauth2-server on :8080
    2) python app_fastapi.py                # starts this FastAPI app on :5000
    3) Open http://localhost:5000 and click "Login"

Uses SessionHandler in 'memory' mode so it doesn't depend on Redis.
"""
import os

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse

from EasyOIDC import Config, SessionHandler
from EasyOIDC.frameworks.fastapi import FastAPIOIDClient

# Load the .env.mock sitting next to this file (regardless of the cwd)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, '.env.mock')

app = FastAPI()

# In-memory store (thread-safe, no dependencies). For production: mode='redis'.
session_storage = SessionHandler(mode='memory')

# When the client is built, EasyOIDC fetches the mock's discovery document
# and resolves authorization/token/userinfo automatically.
auth_config = Config(ENV_PATH)
auth = FastAPIOIDClient(
    app,
    auth_config=auth_config,
    session_storage=session_storage,
    # FastAPI's docs are ordinary routes: list them to keep them public.
    unrestricted_routes=['/', '/docs', '/openapi.json'],
)


@app.get('/protected', response_class=HTMLResponse)
def protected():
    # The middleware already requires a valid session to reach here.
    return "You reached a protected route ✅ <br><a href='/'>Back</a>"


@app.get('/me')
def me(user: dict = Depends(auth.require_user)):
    """Same protection, expressed as a dependency."""
    return {'user': user}


@app.get('/', response_class=HTMLResponse)
def root(request: Request):
    if auth.is_authenticated(request):
        userinfo = auth.get_userinfo(request)
        return (
            "Welcome 👋<br>"
            f"Authenticated as: <b>{userinfo.get('sub')}</b><br>"
            f"<pre>{userinfo}</pre>"
            "<a href='/protected'>Go to protected route</a> | "
            "<a href='/me'>/me (dependency)</a> | "
            "<a href='/logout'>Logout</a>"
        )
    return "Not authenticated.<br><a href='/login'>Login</a>"


if __name__ == '__main__':
    import uvicorn
    # host/port match the redirect_uri in .env.mock
    uvicorn.run(app, host='localhost', port=5000)
