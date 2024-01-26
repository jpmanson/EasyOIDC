## Introduction

EasyOIDC is a Python library that provides a simple interface to the [OpenID Connect](https://en.wikipedia.org/wiki/OpenID#OpenID_Connect_(OIDC)) protocol. It is designed to be easy to use and to integrate into existing applications. It is built on top of the Authlib library.

EasyOIDC can basically adapt to any web framework that supports session variables, route definition, and redirection. As an example, integration examples with [Flask](https://github.com/pallets/flask), [NiceGUI](https://github.com/zauberzeug/nicegui/), [Streamlit](https://github.com/streamlit/streamlit) and [Taipy](https://github.com/Avaiga/taipy) are provided.

In addition, the library has high-level classes, to integrate even more easily with [Flask](https://github.com/pallets/flask), [NiceGUI](https://github.com/zauberzeug/nicegui/) and [Taipy](https://github.com/Avaiga/taipy). The idea of the project is to gradually incorporate high-level support for new web frameworks from the Python world.

EasyOIDC has been tested with OIDC backends such as [Keycloak](https://www.keycloak.org/), [Google](https://developers.google.com/identity/openid-connect/openid-connect?hl=es-419) and [Auth0](https://auth0.com/), and could connect to virtually any [OpenID Connect](https://en.wikipedia.org/wiki/OpenID#OpenID_Connect_(OIDC)) compatible server.

## Installation

```bash
pip install easyoidc
```

If you are going to use it with a specific web framework, you can install it like this: 
```bash
pip install easyoidc[flask]
pip install easyoidc[nicegui]
pip install easyoidc[taipy]
```

## Usage

### Flask
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

### NiceGUI
This is an example of how you can integrate EasyOIDC with NiceGUI:

```python
from EasyOIDC import Config, SessionHandler
from EasyOIDC.frameworks.nicegui import NiceGUIOIDClient
from nicegui import app, ui

session_storage = SessionHandler(mode='shelve')
auth_config = Config('.env')
auth = NiceGUIOIDClient(app, auth_config=auth_config, session_storage=session_storage)

@ui.page('/')
def root():
    is_authenticated = auth.is_authenticated()
    with ui.column().classes('absolute-center '):
        if is_authenticated:
            ui.markdown(f"User authenticated!")
            ui.markdown(f"Name: {auth.get_userinfo()['name']}")
            ui.markdown(f"Email: {auth.get_userinfo()['email']}")
            ui.markdown(f"Roles: {auth.get_user_roles()}")
            ui.markdown(f"<a href='/logout'>Logout</a>").classes('text-2xl')
        else:
            ui.markdown(f"NiceGUI demo.<br><a href='/login'>Login</a>").classes('text-2xl')


if __name__ in {"__main__", "__mp_main__"}:
    ui.run(storage_secret=auth_config.cookie_secret_key, port=5000)

```

## Configuration
Your app routes and server endpoints, can be provided from json and .env files, or via a dict or code of course.

The following is an example of a .env file:

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

In that case, EasyOIDC will get the server endpoints from the well-known url. You can also adapt the file examples/.env.google to your needs.

If you want to provide the endpoints manually, you can do it as follows:

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

And more examples via code:
```python
from EasyOIDC import Config
config = Config(client_id='my_client_id',
                client_secret='my_client_secret',
                cookie_secret_key='some-secret-key',
                redirect_uri='http://localhost:5000/authorize',
                well_known_openid_url='https://myapplication.us.auth0.com/.well-known/openid-configuration',
                app_login_route='/login',
                app_logout_route='/logout',
                app_authorize_route='/authorize',
                unrestricted_routes='/',
                post_logout_uri='http://localhost:5000')

```

### Server session data storage

EasyOIDC needs to store some data in the server session, like tokens and authenticated user information. The library provides a SessionHandler class that can be used to store the session data in memory, in a file or in a Redis database. The SessionHandler class is initialized as follows:

```python
from EasyOIDC import SessionHandler

# Redis memory storage
session_storage = SessionHandler(mode='redis')

# or for file storage
session_storage = SessionHandler(mode='shelve')

```