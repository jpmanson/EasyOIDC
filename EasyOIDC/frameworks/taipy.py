from EasyOIDC.frameworks.flask import FlaskOIDClient
from EasyOIDC import OIDClient, Config, SessionHandler


class TaipyOIDClient(FlaskOIDClient):
    def __init__(self, flask_app, auth_config: Config = None, session_storage: SessionHandler = None,
                 log_enabled: bool = True, **kwargs):
        auth_config.unrestricted_routes = ['/taipy-*', '/stylekit/*', '/manifest.json', '/227.taipy-gui.js', '/taipy.status.json']
        super().__init__(flask_app, auth_config, session_storage, log_enabled, **kwargs)
