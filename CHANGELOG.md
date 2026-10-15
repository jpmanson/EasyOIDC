# Changelog

## 0.5.0

### Changed (breaking for `mode='redis'`)

- **Redis sessions expire.** Each session is now its own key,
  `{namespace}:{session id}`, written with `SET ... EX ttl`. Before, all
  sessions were fields of one hash, which can't expire, so sessions without a
  logout stayed in Redis forever with their tokens. `ttl` defaults to 14 days
  (the FastAPI cookie lifetime) and is renewed on every write (token refresh);
  `ttl=None` disables it. `keys()` and `reset_keys()` use `SCAN`.
- **JSON instead of pickle.** Values are stored as JSON. With pickle, whoever
  could write to Redis could run code in the app.
- **Migration:** sessions from earlier versions (the `{namespace}` hash) are
  ignored, so users log in again, and a warning is logged at startup. To keep
  them, start once with `SessionHandler(mode='redis', allow_pickle=True)`:
  each one is moved to the new format when read. Remove the option afterwards.

### Added

- `SessionHandler(mode='redis', url=...)` (`redis://`, `rediss://`, ACL
  users). Any other keyword (`username`, `ssl`, `socket_timeout`,
  `health_check_interval`, ...) is passed to `redis.Redis`; before, only
  `host`, `port`, `db` and `password` were used and the rest was ignored.
- `socket_timeout` and `socket_connect_timeout` default to 5 seconds. Without
  them a Redis outage hung every request.
- `SessionHandler.ping()` for health checks.
- `redis_client` accepts any object with `get`, `set`, `delete`, `exists`,
  `scan_iter` and `ping` (e.g. wrappers). Before, a client that was
  not a `redis.Redis` was silently ignored and a default client was created;
  now an incompatible object raises `TypeError`.

### Tests

- Redis tests against a real server (`EASYOIDC_TEST_REDIS_URL`, default
  `redis://localhost:6379/15`, namespace `easyoidc-test`), including a full
  login/logout. The old Redis test no longer touches the default `sessions`
  namespace in db 0.

## 0.4.3

### Fixed

- **Logout did not close the IdP session when the server-side session was
  lost.** If the session id in the cookie was not in the store (`memory`
  storage after a restart or `--reload`, several processes with `memory`
  storage, expired or deleted entry), `/logout` only redirected to
  `post_logout_uri`. The Keycloak SSO session stayed alive and the next login
  was silent, so "Logout" seemed not to work. `/logout` now redirects to the
  IdP logout with `client_id` and `post_logout_redirect_uri`, without
  `id_token_hint` (Keycloak 18+ shows a confirmation page). Applies to
  FastAPI, Flask and NiceGUI.
- A warning is logged (logger `EasyOIDC`) when `/logout` gets a session id
  that is not in the store.
- `SessionHandler(mode='memory')` logs a warning when the app seems to run
  in several processes (`WEB_CONCURRENCY > 1`, or `--workers N > 1` /
  `-w N > 1` on the command line). Sessions in memory are not shared between
  processes; use `mode='redis'`.

### Added

- `logout_without_token` setting: `'idp'` (default, new behaviour) or
  `'local'` (only clear the local session, as before 0.4.3).

## 0.4.2

### Fixed

- **ID token signature and issuer were not verified** when the endpoints
  (`authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`) are set
  explicitly together with `well_known_openid_url`. In that case
  `load_from_wellknown()` is never called at startup, so `jwks_uri` and
  `issuer` stayed empty and `validate_id_token()` only checked `aud`, `exp`
  and `nonce`. The client now reads `issuer` / `jwks_uri` from discovery on
  the first login when they are missing (once per process; explicit values
  win). Affects 0.4.0 and 0.4.1.

  Apps that only configure endpoints, without `well_known_openid_url`, should
  set `issuer` and `jwks_uri` explicitly; otherwise a warning is logged and
  the signature is not verified.

### Tests

- End-to-end test of the NiceGUI integration against the in-process IdP
  (login, client roles, 403, logout, IdP error).

## 0.4.1

### Fixed

- `Config.load_from_wellknown()` now takes `logout_endpoint` from the
  discovery document's `end_session_endpoint` when it is not set explicitly.
  Before, configs that only set `well_known_openid_url` got a local-only
  logout: the IdP session stayed open and the next login was silent. Not
  applied when `auth_service='auth0'`.

  **Behaviour change:** these apps now redirect to the IdP on logout, so
  `post_logout_uri` must be registered as a valid post-logout redirect URI
  in the provider (Keycloak rejects unregistered ones).

## 0.4.0

Security release. Fixes gaps that every Keycloak-backed app had to patch by
hand: PKCE, ID token validation, client roles, Keycloak 18+ logout, token
refresh and the OAuth `state` being reused as a session id.

The public API is backwards compatible: existing code keeps working without
changes. Some **defaults change** (PKCE, nonce, ID token validation), which
can surface as login failures against misconfigured or non-compliant
providers. Read "Behaviour changes" before upgrading.

### Added

- **PKCE (S256)** on the authorization code flow (`Config.use_pkce`, default
  `True`). Required by Keycloak clients with *PKCE method = S256*.
- **Nonce + ID token validation** (`use_nonce`, `validate_id_token`, default
  `True`): signature against the provider JWKS (`jwks_uri`, taken from
  discovery), `iss`, `aud`, `exp`, `nonce`, `azp` and `sub` consistency with
  userinfo. Uses `joserfc` (new dependency, already required by Authlib 1.7+).
- `OIDClient.begin_login()` / `complete_login()`: low-level API that returns
  and consumes the per-login secrets (verifier, nonce).
- **Access policy** on the FastAPI, Flask, NiceGUI and Taipy clients:
  `required_roles=[...]`, `require_email_verified=True`,
  `access_denied_handler`, `auth_error_handler`.
- **Configurable roles source**: `Config.roles_source` (`realm`, `client`,
  `realm+client`), `roles_claims_from` (`userinfo`, `id_token`,
  `access_token`), `roles_client_id`. `roles_getter=` is now also accepted by
  `FlaskOIDClient` and `NiceGUIOIDClient`.
- **Token refresh**: expired access tokens are refreshed and the new token is
  persisted; userinfo and the policy are re-checked after a refresh.
- `?next=/path` on the login route (local paths only).
- `get_id_claims()` on the high-level clients.
- `http_timeout` (default 10 s) on discovery, JWKS, token, userinfo, logout.
- `login_timeout_seconds` (default 600) for abandoned logins.
- `EasyOIDC.utils.safe_redirect_path`, `extract_roles`.
- `AccessDeniedError`, `IDTokenValidationError` exported from `EasyOIDC`.
- `.env` / JSON keys for every new `Config` option.

### Fixed

- Keycloak 18+ logout: `client_id` is always sent, `id_token_hint` is
  URL-encoded and omitted when there is no token (it used to be the literal
  string `None`), and an empty `post_logout_uri` is no longer sent.
- Callback errors from the IdP (`?error=...`) rendered as an error page
  instead of a redirect loop to `/login`.
- Open redirect: the post-login redirect only accepts local paths.
- Flask: `KeyError` / `AttributeError` on `get_user_roles()`,
  `is_authenticated()` and `get_userinfo()` for anonymous users (same bug as
  issue #4, fixed for NiceGUI in 0.1.x).
- Flask: the referrer cookie is now `HttpOnly` / `SameSite=Lax` and is cleared
  after login.
- NiceGUI: blocking OIDC calls moved to a threadpool.
- `StreamlitODICClient` did not inherit from `OIDClient` and failed on
  instantiation.
- `TaipyOIDClient` overwrote the user's `unrestricted_routes` instead of
  extending them, and crashed with `auth_config=None`.
- `token_revoke()` crashed when the token had no refresh token.
- `dump_configuration()` no longer prints `cookie_secret_key` when
  `hide_password=True`.

### Behaviour changes (read before upgrading)

| Change | Who is affected | How to keep 0.3.x behaviour |
|---|---|---|
| PKCE S256 sent by default | Providers that reject `code_challenge` (rare; Keycloak, Auth0, Google, Entra accept it) | `use_pkce=False` |
| `nonce` sent and checked by default | Providers that don't echo `nonce` in the ID token | `use_nonce=False` |
| ID token validated by default | Providers whose ID token `iss`/`aud` don't match discovery/`client_id`, or apps using `openid` scope with a provider that omits `id_token` | `validate_id_token=False` |
| The session cookie holds a random id, not the OAuth state | Code that read `session['easyoidc-session-state']` and used it as the OAuth state | Use `get_userinfo()` / `get_current_token()`; the key name is unchanged |
| Session store entries gain `login`, `id_claims`, `roles` keys | Code that compared store entries for equality | Read the keys you need; 0.3.x entries are still accepted, existing sessions survive the upgrade |
| Callback with `?error=` returns HTTP 400 instead of a redirect to `/login` | Apps relying on the loop | Pass `auth_error_handler=` returning your redirect |
| Flask / NiceGUI: an authenticated request with a pending referrer no longer gets an extra redirect; the redirect happens in `/authorize` | None visible | — |
| Users without `email_verified` / required role get a 403 | Only if you opt in with `required_roles` / `require_email_verified` | Don't pass them |

Not changed: default roles source (`realm_access.roles` from userinfo),
route names, `SESSION_STATE_VAR_NAME`, the `require_roles` decorator,
`validate_session_on_each_request` default (`True`), `SessionHandler`.

`OIDClient.auth_server_login()` / `get_token()` are kept for compatibility
and do **not** add PKCE or nonce (they can't return the per-login secrets).
Low-level integrations should move to `begin_login()` / `complete_login()`.

### Upgrade checklist

1. `pip install -U easyoidc` (pulls `joserfc`).
2. Keycloak clients with *Full scope allowed* off: set `roles_source='client'`
   (and `roles_claims_from='userinfo,access_token'` if the client roles mapper
   only targets the access token).
3. If your app checks roles or `email_verified` after login, replace that code
   with `required_roles=` / `require_email_verified=`.
4. If you subclassed a client only to add PKCE, `?next=`, or fix logout,
   remove the subclass.
5. Test login and logout once against your IdP. If it fails with an ID token
   error, check `issuer` and `client_id`; as a last resort disable the new
   check with the setting in the table above and open an issue.
