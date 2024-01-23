from EasyOIDC import Config, SessionHandler
from EasyOIDC.frameworks.nicegui import NiceGUIOIDClient
from nicegui import app, ui


session_storage = SessionHandler(mode='redis', namespace=__name__)
auth_config = Config('.env')
auth = NiceGUIOIDClient(app, auth_config=auth_config, session_storage=session_storage)


@ui.page('/protected')
@auth.require_roles('/access-forbidden', and_allow_roles=['intranet-home'])
def protected_page() -> None:
    with ui.column().classes('absolute-center items-center'):
        ui.label(f'Hello!').classes('text-2xl')


@ui.page('/access-forbidden')
def access_forbidden() -> None:
    with ui.column().classes('absolute-center items-center'):
        ui.label(f'Lo lamento. Acceso denegado!').classes('text-2xl')


@ui.page('/')
def root():
    is_authenticated = auth.is_authenticated()
    with ui.column().classes('absolute-center items-center'):
        if is_authenticated:
            ui.markdown(f"NiceGUI demo.<br>User authenticated={is_authenticated}<br>{auth.get_userinfo()}<br><a href='/logout'>Logout</a>").classes('text-2xl')
        else:
            ui.markdown(f"NiceGUI demo.<br><a href='/login'>Login</a>").classes('text-2xl')


if __name__ in {"__main__", "__mp_main__"}:
    ui.run(storage_secret=auth_config.cookie_secret_key, port=5000)
