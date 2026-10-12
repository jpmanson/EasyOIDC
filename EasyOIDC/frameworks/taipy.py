from EasyOIDC.frameworks.flask import FlaskOIDClient
from EasyOIDC import Config, SessionHandler

TAIPY_UNRESTRICTED_ROUTES = ['/taipy-*', '/stylekit/*', '/manifest.json', '/227.taipy-gui.js',
                             '/taipy.status.json']


class TaipyOIDClient(FlaskOIDClient):
    def __init__(self, flask_app, auth_config: Config = None, session_storage: SessionHandler = None,
                 log_enabled: bool = True, **kwargs):
        if auth_config is None:
            auth_config = Config('.env')
        extra = [r for r in TAIPY_UNRESTRICTED_ROUTES if r not in (auth_config.unrestricted_routes or [])]
        auth_config.unrestricted_routes = list(auth_config.unrestricted_routes or []) + extra
        super().__init__(flask_app, auth_config, session_storage, log_enabled, **kwargs)
