from flask import Flask
from EasyOIDC import Config, SessionHandler
from EasyOIDC.frameworks.flask import FlaskOIDClient

app = Flask(__name__)
session_storage = SessionHandler(mode='redis', namespace=__name__)
auth_config = Config('.env')
auth = FlaskOIDClient(app, auth_config=auth_config, session_storage=session_storage)

@app.route('/')
def root():
    is_authenticated = auth.is_authenticated()
    if is_authenticated:
        userinfo = auth.get_userinfo()
        return f"Welcome to the Flask app with Middleware!.<br>User authenticated={is_authenticated}<br>{userinfo}<br><a href='/logout'>Logout</a>"
    else:
        return f"Welcome to the Flask app with Middleware!.<br><a href='/login'>Login</a>"


if __name__ == "__main__":
    app.run()
