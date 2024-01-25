## Introduction

EasyOIDC is a Python library that provides a simple interface to the OpenID Connect protocol. It is designed to be easy to use and to integrate into existing applications. It is built on top of the Authlib library.

EasyOIDC can basically adapt to any web framework that supports session variables, route definition, and redirection. As an example, integration examples with Flask, NiceGUI, Streamlit and Taipy are provided.

In addition, the library has high-level classes, to integrate even more easily with Flask, NiceGUI and Taipy. The idea of the project is to gradually incorporate high-level support for new web frameworks from the Python world.

EasyOIDC has been tested with OIDC backends such as Keycloak, Google and Auth0, and could connect to virtually any [OpenID Connect](https://en.wikipedia.org/wiki/OpenID#OpenID_Connect_(OIDC)) compatible server.

## Installation

```bash
pip install easyoidc
```

## Usage

This is an example of how to integrate EasyOIDC with Flask:

```python
from flask import Flask
from EasyOIDC import Config, SessionHandler
from EasyOIDC.frameworks.flask import FlaskOIDClient

app = Flask(__name__)
session_storage = SessionHandler(mode='redis')
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
```

The configuration can be provided from json and .env files. The .env file. The following is an example of a .env file:

```bash
# Auth0 example configuration

# Secret keys
client_id = RqtJHUjAyEMXdgT4j2ScdOfjUhFACS9G
client_secret = diylwTR8O_Y4B8_4AFXPYRPft3z_Im14hD8suAG8OiLCRtJPuCT6yHqlELQn_Yf
cookie_secret_key = some-secret-key

# OIDC
well_known_openid_url = https://myapplication.us.auth0.com/.well-known/openid-configuration
redirect_uri = http://localhost:5000/authorize

# Application routes
app_login_route = /login
app_logout_route = /logout
app_authorize_route = /authorize
unrestricted_routes = /
post_logout_uri = http://localhost:5000
```

In that case, EasyOIDC will get the server endpoints from the well-known url. If you want to provide the endpoints manually, you can do it as follows:

```bash
# Google endpoints configuration example: 

# OIDC
well_known_openid_url = https://accounts.google.com/.well-known/openid-configuration
authorization_endpoint = https://accounts.google.com/o/oauth2/auth
token_endpoint = https://oauth2.googleapis.com/token
userinfo_endpoint = https://openidconnect.googleapis.com/v1/userinfo
token_revoke_endpoint = https://oauth2.googleapis.com/revoke
redirect_uri = http://localhost:5000/authorize
scope = openid,profile,email
```
