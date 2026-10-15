"""Logout when the session is no longer in the store (0.4.3)."""
import logging

import pytest

from EasyOIDC import OIDClient, SessionHandler
from EasyOIDC.flow import end_session
from tests.fake_idp import make_config

pytest.importorskip('fastapi')
pytest.importorskip('httpx')
pytest.importorskip('flask')

from tests.test_frameworks_040 import _fastapi_app, _fastapi_login, _flask_app, _flask_login  # noqa: E402


def test_lost_session_still_goes_to_idp(idp, caplog):
    """The store lost the session (restart, another worker with memory
    storage): /logout must still close the IdP SSO session."""
    client, _, storage = _fastapi_app()
    _fastapi_login(client, idp)
    storage.reset_keys()
    with caplog.at_level(logging.WARNING, logger='EasyOIDC'):
        location = client.get('/logout').headers['location']
    assert location.startswith('https://idp.example.com/logout?client_id=cid')
    assert 'post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F' in location
    assert 'id_token_hint' not in location
    assert 'session not found' in caplog.text


def test_lost_session_local_mode_keeps_old_behaviour(idp):
    client, _, storage = _fastapi_app(config={'logout_without_token': 'local'})
    _fastapi_login(client, idp)
    storage.reset_keys()
    assert client.get('/logout').headers['location'] == 'http://localhost:5000/'


def test_flask_lost_session_still_goes_to_idp(idp):
    client, _, storage = _flask_app()
    _flask_login(client, idp)
    storage.reset_keys()
    location = client.get('/logout').headers['location']
    assert location.startswith('https://idp.example.com/logout?client_id=cid')
    assert 'id_token_hint' not in location


def test_end_session_without_logout_endpoint_is_local():
    client = OIDClient(make_config(logout_endpoint=None))
    storage = SessionHandler(mode='memory')
    assert end_session(client, storage, 'missing-sid') is None


def test_end_session_without_cookie_does_not_warn(caplog):
    client = OIDClient(make_config())
    storage = SessionHandler(mode='memory')
    with caplog.at_level(logging.WARNING, logger='EasyOIDC'):
        url = end_session(client, storage, None)
    assert url.startswith('https://idp.example.com/logout?client_id=cid')
    assert caplog.text == ''


def test_invalid_logout_without_token_is_rejected():
    with pytest.raises(ValueError, match='logout_without_token'):
        make_config(logout_without_token='nope')
