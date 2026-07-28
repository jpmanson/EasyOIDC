"""Minimal example to test EasyOIDC against a real (local) OIDC server.

Usage:
    1) docker compose up          # starts mock-oauth2-server on :8080
    2) python app.py              # starts this Flask app on :5000
    3) Open http://localhost:5000 and click "Login"

Uses SessionHandler in 'memory' mode so it doesn't depend on Redis.
"""
import os
from flask import Flask
from EasyOIDC import Config, SessionHandler
from EasyOIDC.frameworks.flask import FlaskOIDClient

# Load the .env.mock sitting next to this file (regardless of the cwd)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, '.env.mock')

app = Flask(__name__)

# In-memory store (thread-safe, no dependencies). For production: mode='redis'.
session_storage = SessionHandler(mode='memory')

# When the client is built, EasyOIDC fetches the mock's discovery document
# and resolves authorization/token/userinfo automatically.
auth_config = Config(ENV_PATH)
auth = FlaskOIDClient(app, auth_config=auth_config, session_storage=session_storage)


@app.route('/protected')
def protected():
    # The middleware already requires a valid session to reach here.
    return "You reached a protected route ✅ <br><a href='/'>Back</a>"


@app.route('/')
def root():
    if auth.is_authenticated():
        userinfo = auth.get_userinfo()
        return (
            "Welcome 👋<br>"
            f"Authenticated as: <b>{userinfo.get('sub')}</b><br>"
            f"<pre>{userinfo}</pre>"
            "<a href='/protected'>Go to protected route</a> | "
            "<a href='/logout'>Logout</a>"
        )
    return "Not authenticated.<br><a href='/login'>Login</a>"


if __name__ == "__main__":
    # host/port match the redirect_uri in .env.mock
    app.run(host="localhost", port=5000, debug=True)
