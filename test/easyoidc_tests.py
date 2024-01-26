import pytest
from EasyOIDC import OIDClient, SessionHandler, Config


def test_validate_config():
    # Setup a complete and valid configuration
    valid_config = Config()
    valid_config.authorization_endpoint = 'https://example.com/auth'
    valid_config.token_endpoint = 'https://example.com/token'
    valid_config.userinfo_endpoint = 'https://example.com/userinfo'
    valid_config.redirect_uri = 'https://example.com/redirect'
    valid_config.client_id = 'client-id'
    valid_config.client_secret = 'client-secret'
    valid_config.cookie_secret_key = 'secret-key'
    valid_config.scope = ['openid']

    client = OIDClient(valid_config)
    # No exception should be raised
    valid_config.is_valid_config()

    # Setup an invalid configuration (missing client_id)
    invalid_config = Config()
    invalid_config.authorization_endpoint = 'https://example.com/auth'
    # ... other configurations except client_id

    with pytest.raises(Exception):
        client = OIDClient(invalid_config)

    valid_config = Config(well_known_openid_url='https://accounts.google.com/.well-known/openid-configuration',
                          redirect_uri='https://example.com/redirect',
                          client_id='client-id',
                          client_secret='client-secret',
                          cookie_secret_key='secret-key')
    client = OIDClient(valid_config)


def test_session_storage():
    session_store = SessionHandler(mode='redis')
    session_store.get('test', 'default')
    session_store.set('test', 'other')
    assert session_store.get('test', 'default') == 'other'

    session_store = SessionHandler(mode='shelve')
    session_store.get('test', 'default')
    session_store.set('test', 'other')
    assert session_store.get('test', 'default') == 'other'