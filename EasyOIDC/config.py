import os


class Config(object):
    base_auth_url = None
    well_known_openid_url = None
    authorization_endpoint = None
    token_endpoint = None
    userinfo_endpoint = None
    redirect_uri = None
    client_id = None
    client_secret = None
    cookie_secret_key = None
    scope = None
    token_revoke_endpoint = None
    logout_endpoint = None
    post_logout_uri = None
    app_login_route = None
    app_logout_route = None
    app_authorize_route = None
    auth_service = None

    def __init__(self, config_path=None, **kwargs):
        # Defaults
        self.scope = ['openid', 'email', 'profile']
        self.app_login_route = '/login'
        self.app_logout_route = '/logout'
        self.app_authorize_route = '/authorize'
        self.unrestricted_routes = ['/', '/favicon.ico']

        if config_path and (os.path.exists(config_path)):
            try:
                self.load_from_json(config_path)
            except:
                self.load_from_env_file(config_path)
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

        if not self.auth_service:
            self.auth_service = 'keycloak'     # Default service provider
            if self.authorization_endpoint.find('https://accounts.google.com') == 0:
                self.auth_service = 'google'

    def load_from_json(self, json_path):
        import json
        with open(json_path, 'r') as f:
            data = json.load(f)
            self.base_auth_url = data['base_auth_url']
            self.well_known_openid_url = data.get('well_known_openid_url', None)
            self.authorization_endpoint = data['authorization_endpoint']
            self.token_endpoint = data['token_endpoint']
            self.userinfo_endpoint = data['userinfo_endpoint']
            self.redirect_uri = data['redirect_uri']
            self.client_id = data['client_id']
            self.client_secret = data['client_secret']
            self.cookie_secret_key = data['cookie_secret_key']
            self.scope = data['scope']
            self.token_revoke_endpoint = data.get('token_revoke_endpoint', None)
            self.logout_endpoint = data.get('logout_endpoint', None)
            self.post_logout_uri = data.get('post_logout_uri', None)

    def load_from_env_file(self, config_path):
        from decouple import Config, RepositoryEnv
        config = Config(RepositoryEnv(config_path))
        self.base_auth_url = config('base_auth_url')
        self.well_known_openid_url = config('well_known_openid_url', None)
        self.authorization_endpoint = config('authorization_endpoint')
        self.token_endpoint = config('token_endpoint')
        self.userinfo_endpoint = config('userinfo_endpoint')
        self.redirect_uri = config('redirect_uri')
        self.client_id = config('client_id')
        self.client_secret = config('client_secret')
        self.scope = config('scope').split(',')
        self.cookie_secret_key = config('cookie_secret_key')
        self.token_revoke_endpoint = config('token_revoke_endpoint', None)
        self.logout_endpoint = config('logout_endpoint', None)
        self.post_logout_uri = config('post_logout_uri', None)

    def get_unrestricted_routes(self):
        return [self.app_login_route, self.app_authorize_route, self.app_logout_route] + self.unrestricted_routes

    def update_automatic_settings(self):
        self._auth_service = 'keycloak'
        if self._config.authorization_endpoint.find('https://accounts.google.com') == 0:
            self._auth_service = 'google'




