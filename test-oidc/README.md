# Local EasyOIDC testing against a real OIDC server

A minimal, reproducible environment to test the full OIDC flow (login → token →
userinfo → protected routes → logout) against a **real but lightweight** OpenID
Connect server, without having to configure Keycloak.

It uses [`mock-oauth2-server`](https://github.com/navikt/mock-oauth2-server): a
single, **zero-config** container that exposes the standard discovery document
and an **interactive login page** where you can type any user.

## Requirements

- Docker (for the OIDC server)
- Python with EasyOIDC + Flask installed:

  ```bash
  pip install -e ..[flask]      # or: pip install easyoidc[flask]
  ```

## Steps

1. Start the OIDC server:

   ```bash
   cd test-oidc
   docker compose up          # or, with Compose v1:  docker-compose up
   ```

   Discovery is served at
   `http://localhost:8080/default/.well-known/openid-configuration`.

2. In another terminal, start the example app:

   ```bash
   cd test-oidc
   python app.py
   ```

3. Open <http://localhost:5000> and click **Login**.

4. On the mock's login screen, type any **user** (for example `testuser`) and
   submit. The mock signs a valid token and sends you back to the app already
   authenticated.

   > Want custom claims (email, roles, etc.)? The mock lets you paste a claims
   > JSON in its login form, for example:
   > `{"email":"test@example.com","realm_access":{"roles":["admin"]}}`

## Shutting down

```bash
docker compose down
```

## Notes

- The example uses `SessionHandler(mode='memory')` (in-memory, thread-safe
  store), so **you don't need Redis** or any extra service. Sessions are lost
  when the app restarts (fine for a demo). In production use
  `SessionHandler(mode='redis')` (requires `pip install easyoidc[redis]`).
  > Note: `SessionHandler(mode='shelve')` is not thread-safe under the Flask
  > development server on Python 3.13+ (the `dbm.sqlite3` backend fails across
  > threads), which is why the demo uses `memory`.
- The mock accepts any `client_id` / `client_secret`; the values live in
  `.env.mock`.
- To test against **Keycloak, Auth0 or Google** instead of the mock, just change
  `well_known_openid_url` (and the credentials) in `.env.mock`.
- The mock lets you inject claims (email, roles, etc.) from the **claims** field
  of its login form, for example:
  `{"email":"test@example.com","realm_access":{"roles":["admin"]}}`.
