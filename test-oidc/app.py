"""Ejemplo mínimo para probar EasyOIDC contra un servidor OIDC real (local).

Uso:
    1) docker compose up          # levanta el mock-oauth2-server en :8080
    2) python app.py              # levanta esta app Flask en :5000
    3) Abrí http://localhost:5000 y hacé click en "Login"

Usa SessionHandler en modo 'memory' para no depender de Redis.
"""
import os
from flask import Flask
from EasyOIDC import Config, SessionHandler
from EasyOIDC.frameworks.flask import FlaskOIDClient

# Carga el .env.mock que está junto a este archivo (sin importar el cwd)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, '.env.mock')

app = Flask(__name__)

# Store en memoria (thread-safe, sin dependencias). Para producción: mode='redis'.
session_storage = SessionHandler(mode='memory')

# Al construir el cliente, EasyOIDC descarga el discovery del mock
# y resuelve authorization/token/userinfo automáticamente.
auth_config = Config(ENV_PATH)
auth = FlaskOIDClient(app, auth_config=auth_config, session_storage=session_storage)


@app.route('/protected')
def protected():
    # El middleware ya exige sesión válida para llegar acá.
    return "Accediste a una ruta protegida ✅ <br><a href='/'>Volver</a>"


@app.route('/')
def root():
    if auth.is_authenticated():
        userinfo = auth.get_userinfo()
        return (
            "Bienvenido 👋<br>"
            f"Autenticado como: <b>{userinfo.get('sub')}</b><br>"
            f"<pre>{userinfo}</pre>"
            "<a href='/protected'>Ir a ruta protegida</a> | "
            "<a href='/logout'>Logout</a>"
        )
    return "No autenticado.<br><a href='/login'>Login</a>"


if __name__ == "__main__":
    # host/port coinciden con redirect_uri del .env.mock
    app.run(host="localhost", port=5000, debug=True)
