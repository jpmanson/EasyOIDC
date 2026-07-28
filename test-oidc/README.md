# Prueba local de EasyOIDC contra un OIDC real

Entorno mínimo y reproducible para probar el flujo OIDC completo (login →
token → userinfo → rutas protegidas → logout) contra un servidor OpenID
Connect **real pero liviano**, sin tener que configurar Keycloak.

Usa [`mock-oauth2-server`](https://github.com/navikt/mock-oauth2-server):
un único contenedor, **sin configuración**, que expone el discovery estándar
y una **página de login interactiva** donde podés escribir cualquier usuario.

## Requisitos

- Docker (para el servidor OIDC)
- Python con EasyOIDC + Flask instalados:

  ```bash
  pip install -e ..[flask]      # o: pip install easyoidc[flask]
  ```

## Pasos

1. Levantá el servidor OIDC:

   ```bash
   cd test-oidc
   docker compose up          # o, con Compose v1:  docker-compose up
   ```

   El discovery queda en
   `http://localhost:8080/default/.well-known/openid-configuration`.

2. En otra terminal, levantá la app de ejemplo:

   ```bash
   cd test-oidc
   python app.py
   ```

3. Abrí <http://localhost:5000> y hacé click en **Login**.

4. En la pantalla del mock, escribí cualquier **usuario** (por ejemplo
   `testuser`) y enviá. El mock te firma un token válido y te devuelve a la app
   ya autenticado.

   > ¿Querés claims custom (email, roles, etc.)? El mock permite pegar un JSON
   > de claims en su formulario de login, por ejemplo:
   > `{"email":"test@example.com","realm_access":{"roles":["admin"]}}`

## Cómo apagar

```bash
docker compose down
```

## Notas

- El ejemplo usa `SessionHandler(mode='memory')` (store en memoria,
  thread-safe), así que **no necesitás Redis** ni ningún servicio extra. Las
  sesiones se pierden al reiniciar la app (aceptable para un demo). En
  producción usá `SessionHandler(mode='redis')` (requiere `pip install
  easyoidc[redis]`).
  > Nota: `SessionHandler(mode='shelve')` no es thread-safe bajo el servidor de
  > desarrollo de Flask en Python 3.13+ (el backend `dbm.sqlite3` falla entre
  > hilos), por eso el demo usa `memory`.
- El mock acepta cualquier `client_id` / `client_secret`; los valores están en
  `.env.mock`.
- Para probar contra **Keycloak, Auth0 o Google** en lugar del mock, solo cambiá
  `well_known_openid_url` (y las credenciales) en `.env.mock`.
- El mock permite inyectar claims (email, roles, etc.) desde el campo **claims**
  de su formulario de login, por ejemplo:
  `{"email":"test@example.com","realm_access":{"roles":["admin"]}}`.
