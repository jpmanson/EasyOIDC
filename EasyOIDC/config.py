import os
import json
import requests


def is_valid_url(url):
    if url is None:
        return False
    if url.find('http://') == 0 or url.find('https://') == 0:
        return True
    return False


class Config(object):
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
        self.unrestricted_routes = ['/favicon.ico']

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
            authorization_endpoint = self.authorization_endpoint or ''
            if authorization_endpoint.find('https://accounts.google.com') == 0:
                self.auth_service = 'google'

    def load_from_json(self, json_path):
        with open(json_path, 'r') as f:
            data = json.load(f)
            self.well_known_openid_url = data.get('well_known_openid_url', None)
            self.authorization_endpoint = data.get('authorization_endpoint', None)
            self.token_endpoint = data.get('token_endpoint', None)
            self.userinfo_endpoint = data.get('userinfo_endpoint', None)
            self.redirect_uri = data['redirect_uri']
            self.client_id = data['client_id']
            self.client_secret = data['client_secret']
            self.cookie_secret_key = data['cookie_secret_key']
            self.scope = data.get('scope', '').split(',')
            self.token_revoke_endpoint = data.get('token_revoke_endpoint', None)
            self.logout_endpoint = data.get('logout_endpoint', None)
            self.post_logout_uri = data.get('post_logout_uri', None)

    def load_from_env_file(self, config_path):
        from decouple import Config, RepositoryEnv
        config = Config(RepositoryEnv(config_path))
        self.well_known_openid_url = config('well_known_openid_url', None)
        self.authorization_endpoint = config('authorization_endpoint', None)
        self.token_endpoint = config('token_endpoint', None)
        self.userinfo_endpoint = config('userinfo_endpoint', None)
        self.redirect_uri = config('redirect_uri')
        self.client_id = config('client_id')
        self.client_secret = config('client_secret')
        self.scope = config('scope', '').split(',')
        self.cookie_secret_key = config('cookie_secret_key')
        self.token_revoke_endpoint = config('token_revoke_endpoint', None)
        self.logout_endpoint = config('logout_endpoint', None)
        self.post_logout_uri = config('post_logout_uri', None)

    def get_unrestricted_routes(self):
        return [self.app_login_route, self.app_authorize_route, self.app_logout_route] + self.unrestricted_routes

    def dump_configuration(self, hide_password=True):
        config = dict(well_known_openid_url=self.well_known_openid_url,
                      authorization_endpoint=self.authorization_endpoint,
                      token_endpoint=self.token_endpoint,
                      userinfo_endpoint=self.userinfo_endpoint,
                      redirect_uri=self.redirect_uri,
                      client_id=self.client_id,
                      client_secret=self.client_secret if not hide_password else '********',
                      scope=self.scope,
                      cookie_secret_key=self.cookie_secret_key,
                      token_revoke_endpoint=self.token_revoke_endpoint,
                      logout_endpoint=self.logout_endpoint,
                      post_logout_uri=self.post_logout_uri)
        return json.dumps(config, indent=4)

    def load_from_wellknown(self, wellknown_url: str = None):
        url = wellknown_url or self.well_known_openid_url
        response = requests.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            self.authorization_endpoint = data['authorization_endpoint']
            self.token_endpoint = data['token_endpoint']
            self.userinfo_endpoint = data['userinfo_endpoint']
            self.token_revoke_endpoint = data['revocation_endpoint']
            self.scope = data['scopes_supported']
        else:
            raise Exception(f'Error loading wellknown url: {wellknown_url}')

    def __str__(self):
        return self.dump_configuration()

    def __repr__(self):
        return self.dump_configuration()

    def __getitem__(self, item):
        return getattr(self, item)

    def __setitem__(self, key, value):
        return setattr(self, key, value)

    def __contains__(self, item):
        return hasattr(self, item)

    def __iter__(self):
        return self.__dict__.items().__iter__()

    def is_valid_config(self):
        try:
            assert is_valid_url(self.authorization_endpoint)
            assert is_valid_url(self.token_endpoint)
            assert is_valid_url(self.userinfo_endpoint)
            assert is_valid_url(self.redirect_uri)
            assert self.client_id is not None
            assert self.client_secret is not None
            assert self.cookie_secret_key is not None
            assert isinstance(self.scope, list)
        except Exception as e:
            raise Exception(f"Missing configuration parameters. {e}")
        return True





