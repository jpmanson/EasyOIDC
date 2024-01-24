from EasyOIDC import OIDClient, Config
from EasyOIDC.utils import streamlit_nav_to
from EasyOIDC.session import SessionHandler
import streamlit as st
from streamlit_cookies_manager import EncryptedCookieManager


def remove_path_from_url(url: str) -> str:
    url = url.split('?')[0]
    url = url.split('#')[0]
    url = url.split('/')
    url = '/'.join(url[:3])
    return url


class StreamlitODICClient:
    def __init__(self, dummy_app=None, auth_config: Config = None, session_storage: SessionHandler = None,
                 log_enabled: bool = True, **kwargs):
        if auth_config is None:
            auth_config = Config('.env')
        if session_storage is None:
            session_storage = SessionHandler(mode='redis')

        auth_config.redirect_uri = remove_path_from_url(auth_config.redirect_uri)
        super().__init__(auth_config, log_enabled)
        self._auth_config = auth_config
        self._session_storage = session_storage

        if 'unrestricted_routes' in kwargs:
            self._auth_config.unrestricted_routes = kwargs['unrestricted_routes']

        self.cookies = EncryptedCookieManager(prefix="EasyOIDC/", password=auth_config.cookie_secret_key)