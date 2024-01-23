from EasyOIDC.auth import Config
from EasyOIDC.nicegui import NiceGUIOIDClient
from EasyOIDC.session import SessionHandler
from nicegui import Client, app, ui


session_storage = SessionHandler(mode='redis', namespace=__name__)
auth_config = Config('.env')
auth = NiceGUIOIDClient(app, auth_config=auth_config, session_storage=session_storage)


@ui.page('/protected')
@auth.require_roles('/access-forbidden', and_allow_roles=['intranet-home'])
def home_page() -> None:
    with ui.column().classes('absolute-center items-center'):
        ui.label(f'Hello!').classes('text-2xl')


@ui.page('/access-forbidden')
def access_forbidden() -> None:
    with ui.column().classes('absolute-center items-center'):
        ui.label(f'Lo lamento. Acceso denegado!').classes('text-2xl')


@ui.page('/')
def root():
    is_authenticated = auth.is_authenticated()
    if is_authenticated:
        userinfo = auth.get_userinfo()
        return f"Welcome to the Flask app with Middleware!.<br>User authenticated={is_authenticated}<br>{userinfo}<br><a href='/logout'>Logout</a>"
    else:
        return f"Welcome to the Flask app with Middleware!.<br><a href='/login'>Login</a>"


if __name__ in {"__main__", "__mp_main__"}:
    ui.run(storage_secret=auth_config.cookie_secret_key, port=5000)
