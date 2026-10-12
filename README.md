## Introduction

EasyOIDC is a Python library that provides a simple interface to the [OpenID Connect](https://en.wikipedia.org/wiki/OpenID#OpenID_Connect_(OIDC)) protocol. It is designed to be easy to use and to integrate into existing applications. It is built on top of the [Authlib library](https://github.com/authlib/authlib).

EasyOIDC can basically adapt to any web framework that supports session variables, route definition, and redirection. As an example, integration examples with [Flask](https://github.com/pallets/flask), [FastAPI](https://github.com/fastapi/fastapi), [NiceGUI](https://github.com/zauberzeug/nicegui/), [Streamlit](https://github.com/streamlit/streamlit), [Taipy](https://github.com/Avaiga/taipy) and [Bottle](https://github.com/bottlepy/bottle) are provided.

In addition, the library has high-level classes, to integrate even more easily with [Flask](https://github.com/pallets/flask), [FastAPI](https://github.com/fastapi/fastapi), [NiceGUI](https://github.com/zauberzeug/nicegui/) and [Taipy](https://github.com/Avaiga/taipy). The idea of the project is to gradually incorporate high-level support for new web frameworks from the Python world.

EasyOIDC has been tested with OIDC backends such as [Keycloak](https://www.keycloak.org/), [Google](https://developers.google.com/identity/openid-connect/openid-connect?hl=es-419) and [Auth0](https://auth0.com/), and could connect to virtually any [OpenID Connect](https://en.wikipedia.org/wiki/OpenID#OpenID_Connect_(OIDC)) compatible server.

## Installation

The library is available via PyPi (https://pypi.org/project/EasyOIDC/)

```bash
uv add easyoidc
```

If you are going to use it with a specific web framework, you can install it like this: 
```bash
uv add "easyoidc[flask]"
uv add "easyoidc[fastapi]"
uv add "easyoidc[nicegui]"
uv add "easyoidc[taipy]"
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

### FastAPI
This is an example of how to integrate EasyOIDC with FastAPI:

```python
from fastapi import Depends, FastAPI, Request
from EasyOIDC import Config, SessionHandler
from EasyOIDC.frameworks.fastapi import FastAPIOIDClient

app = FastAPI()
session_storage = SessionHandler(mode='redis')
auth_config = Config('.env')
auth = FastAPIOIDClient(app, auth_config=auth_config, session_storage=session_storage)

@app.get('/')
def root(request: Request):
    if auth.is_authenticated(request):
        userinfo = auth.get_userinfo(request)
        return f"User authenticated. {userinfo}"
    return "Not authenticated. Go to /login"

@app.get('/me')
def me(user: dict = Depends(auth.require_user)):
    return {'user': user}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host='localhost', port=5000)
```

FastAPI has no ambient (context-local) session object like `flask.session` or
NiceGUI's `app.storage.user`, so the methods that inspect the current user take
an explicit `Request`: `auth.is_authenticated(request)`,
`auth.get_userinfo(request)` and `auth.get_user_roles(request)`. The same
information is also available as dependencies:

- `Depends(auth.current_user)` returns the userinfo dict, or `None` when anonymous.
- `Depends(auth.require_user)` returns the userinfo dict, redirecting to the login route when anonymous.

Role-based access control works as in the other integrations. The `Request` is
injected automatically when the endpoint doesn't declare one:

```python
@app.get('/admin')
@auth.require_roles('/access-forbidden', and_allow_roles=['intranet-home'])
def admin():
    return {'message': 'Welcome, admin'}
```

A few things worth knowing:

- The client session is stored in a signed cookie via Starlette's
  `SessionMiddleware`, which EasyOIDC installs for you using
  `cookie_secret_key`. If your app installs it itself, pass
  `add_session_middleware=False` and add it **after** building the client, so it
  still wraps the authentication middleware.
- FastAPI's `/docs`, `/redoc` and `/openapi.json` are ordinary routes, so the
  middleware protects them too. List them in `unrestricted_routes` to keep them
  public. The OIDC routes themselves (`/login`, `/authorize`, `/logout`) are
  registered outside the OpenAPI schema.
- By default every request re-validates the token against the OIDC server's
  userinfo endpoint, matching the behaviour of the other integrations. That
  costs one HTTP round-trip per request; pass
  `validate_session_on_each_request=False` to trust the stored session instead.
  The blocking calls always run in a threadpool, so the event loop is never
  stalled.

See `examples/fastapi_high_level.py` and `examples/fastapi_low_level.py`.

### Access policy, Keycloak client roles and security defaults (0.4.0)

The high-level clients (FastAPI, Flask, NiceGUI, Taipy) accept an access
policy, so you don't have to re-implement "authenticated is not enough" in
every app:

```python
auth = FastAPIOIDClient(
    app,
    auth_config=Config('.env', roles_source='client'),  # resource_access.<client_id>.roles
    session_storage=SessionHandler(mode='redis'),
    required_roles=['my-app-user', 'my-app-admin'],     # at least one of them
    require_email_verified=True,
    validate_session_on_each_request=False,             # trust the store, refresh on expiry
)
```

A user that authenticates but fails the policy gets a 403 page with an IdP
logout link (override it with `access_denied_handler`). Errors returned by the
IdP (`?error=...`) or an invalid ID token render an error page instead of
bouncing back to `/login` (override with `auth_error_handler`).

**Where roles come from** is configurable on `Config`:

| Setting | Values | Default |
|---|---|---|
| `roles_source` | `realm` (`realm_access.roles`), `client` (`resource_access.<roles_client_id or client_id>.roles`), `realm+client` | `realm` |
| `roles_claims_from` | any of `userinfo`, `id_token`, `access_token` | `userinfo` |
| `roles_client_id` | client whose roles are read | `client_id` |

Keycloak clients with *Full scope allowed* off do not put `realm_access` in
their tokens; use `roles_source='client'`. If the client roles mapper only
adds them to the access token, add `access_token` to `roles_claims_from`.
A custom `roles_getter=(userinfo) -> list` still wins over all of this.

**Security defaults**

| Setting | Default | What it does |
|---|---|---|
| `use_pkce` | `True` | PKCE S256 on the authorization code flow |
| `use_nonce` | `True` | sends a `nonce` and checks it in the ID token |
| `validate_id_token` | `True` | verifies the ID token signature (JWKS from discovery), `iss`, `aud`, `exp`, `nonce` |
| `http_timeout` | `10` | timeout (s) for every call to the OIDC server |
| `login_timeout_seconds` | `600` | a started login must finish within this time |

Other behaviour of the high-level clients:

- The browser cookie carries a random session id, not the OAuth `state`, and
  the id is rotated after login.
- Expired access tokens are refreshed with the refresh token and the new token
  is persisted; userinfo is re-read and the policy re-checked, so a role
  removed in the IdP takes effect at the next refresh. A failed refresh drops
  the session.
- `?next=/path` is accepted on the login route; only local paths are honoured.
- Logout sends `client_id`, `post_logout_redirect_uri` and (when available)
  `id_token_hint`, as required by Keycloak 18+.

See [`CHANGELOG.md`](CHANGELOG.md) for the upgrade notes.

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

# In-memory storage (thread-safe, no external dependencies). Default mode.
# Sessions are lost when the process restarts. Great for development/testing.
session_storage = SessionHandler(mode='memory')

# File storage
session_storage = SessionHandler(mode='shelve')

# Redis storage (requires the optional extra: uv add "easyoidc[redis]")
session_storage = SessionHandler(mode='redis')
```

#### Choosing a backend

| Mode | Persistence | Thread-safe | Multi-process | Dependencies | Best for |
|------|-------------|-------------|---------------|--------------|----------|
| `memory` *(default)* | No — lost on restart | ✅ Yes | ❌ No (per-process state) | None | Development, testing, single-process apps |
| `shelve` | ✅ On disk | ⚠️ No (see note) | ❌ No | None (stdlib) | Simple single-process apps needing persistence across restarts |
| `redis` | ✅ In Redis | ✅ Yes | ✅ Yes (shared store) | `easyoidc[redis]` + a Redis server | Production, multi-worker/multi-process deployments |

**Pros & cons**

- **`memory`** — zero setup, thread-safe, fastest. But sessions vanish on
  restart and are **not shared** between processes/workers, so a multi-worker
  server (e.g. Gunicorn with several workers) will see inconsistent logins.
- **`shelve`** — persists to a local file with no external service. But the
  default Python 3.13+ backend (`dbm.sqlite3`) is **not thread-safe** and it is
  single-host/single-process only, so it's unsuitable for multi-threaded WSGI
  servers or auto-reloading frameworks like `nicegui`.
- **`redis`** — the only option that is both thread-safe **and** shared across
  processes/hosts, making it the right choice for production and horizontally
  scaled deployments. It requires the optional extra and a running Redis. Uses
  `redis-py` directly (no version cap); sessions are stored as fields of a
  single Redis hash (one key per `namespace`), serialized with `pickle`.

**Redis is optional** and kept out of the core dependencies, so projects using
`memory` or `shelve` don't pull Redis in. Install it with
`uv add "easyoidc[redis]"`.

**Rule of thumb:** use `memory` for development and single-process apps,
`shelve` when you need on-disk persistence in a single process, and `redis` for
anything multi-process or production.

## Testing against a real OIDC server

The [`test-oidc/`](test-oidc/) directory contains a self-contained setup to test
the full OIDC flow (login → token → userinfo → protected routes → logout)
against a real but lightweight OpenID Connect server
([`mock-oauth2-server`](https://github.com/navikt/mock-oauth2-server)), with no
Keycloak configuration required:

```bash
cd test-oidc
docker compose up                     # starts the OIDC server on :8080
uv run python app.py                  # starts the Flask example on :5000
# or:  uv run python app_fastapi.py   # starts the FastAPI example on :5000
# open http://localhost:5000 and click "Login"
```

See [`test-oidc/README.md`](test-oidc/README.md) for details.

### Automated tests

```bash
# `uv sync` matches the environment exactly to the lockfile, so pass every extra
# you want to keep installed (add --extra nicegui / --extra taipy if you use them).
uv sync --extra flask --extra fastapi --extra redis
uv run pytest                # unit tests (integration tests auto-skip if the mock is down)

# to also run the integration tests, start the mock first:
cd test-oidc && docker compose up -d
uv run pytest
```

The integration suite (`tests/test_integration_oidc.py`) exercises the full
authorization-code flow against the mock and is skipped automatically when the
server isn't reachable. CI runs the whole suite with the mock and Redis as
service containers (see `.github/workflows/tests.yml`).