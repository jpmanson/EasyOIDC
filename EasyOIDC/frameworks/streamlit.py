from EasyOIDC import OIDClient, Config
from EasyOIDC.session import SessionHandler

try:
    import streamlit as st  # noqa: F401
    from streamlit_cookies_manager import EncryptedCookieManager
except ImportError:  # pragma: no cover
    EncryptedCookieManager = None


def remove_path_from_url(url: str) -> str:
    url = url.split('?')[0]
    url = url.split('#')[0]
    url = url.split('/')
    url = '/'.join(url[:3])
    return url


class StreamlitODICClient(OIDClient):
    """Experimental Streamlit helper (unchanged API since 0.1.x).

    0.4.0 fixes the base class: it previously did not inherit from
    ``OIDClient`` and failed on instantiation.
    """

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

        if EncryptedCookieManager is None:
            raise ImportError('StreamlitODICClient requires streamlit and streamlit-cookies-manager')
        self.cookies = EncryptedCookieManager(prefix="EasyOIDC/", password=auth_config.cookie_secret_key)
