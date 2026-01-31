"""Basic import tests to catch syntax errors early."""
import pytest


def test_import_main_module():
    """Test that main EasyOIDC module can be imported."""
    from EasyOIDC import Config, SessionHandler, OIDClient
    assert Config is not None
    assert SessionHandler is not None
    assert OIDClient is not None


def test_import_config():
    """Test that config module can be imported."""
    from EasyOIDC.config import Config, is_valid_url
    assert Config is not None
    assert is_valid_url is not None


def test_import_auth():
    """Test that auth module can be imported."""
    from EasyOIDC.auth import OIDClient
    assert OIDClient is not None


def test_import_session():
    """Test that session module can be imported."""
    from EasyOIDC.session import SessionHandler
    assert SessionHandler is not None


def test_import_flask_framework():
    """Test that Flask framework module can be imported."""
    pytest.importorskip("flask")
    from EasyOIDC.frameworks.flask import FlaskOIDClient
    assert FlaskOIDClient is not None


def test_import_nicegui_framework():
    """Test that NiceGUI framework module can be imported."""
    pytest.importorskip("nicegui")
    from EasyOIDC.frameworks.nicegui import NiceGUIOIDClient
    assert NiceGUIOIDClient is not None


def test_config_instantiation():
    """Test that Config can be instantiated without file."""
    from EasyOIDC.config import Config
    config = Config()
    assert config.scope == ['openid', 'email', 'profile']
    assert config.app_login_route == '/login'
    assert config.app_logout_route == '/logout'
    assert config.app_authorize_route == '/authorize'


def test_is_valid_url():
    """Test URL validation function."""
    from EasyOIDC.config import is_valid_url
    assert is_valid_url('https://example.com') is True
    assert is_valid_url('http://example.com') is True
    assert is_valid_url('ftp://example.com') is False
    assert is_valid_url(None) is False
    assert is_valid_url('') is False
