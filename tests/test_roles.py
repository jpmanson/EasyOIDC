"""Tests for the role-checking logic shared by every framework integration.

`OIDClient.evaluate_roles` backs both the generic `require_roles` decorator
(Flask, NiceGUI, Taipy) and the FastAPI one, so its semantics are pinned here.
"""
import pytest

from EasyOIDC import Config, OIDClient


@pytest.fixture
def client() -> OIDClient:
    config = Config(
        authorization_endpoint='https://oidc.example.com/auth',
        token_endpoint='https://oidc.example.com/token',
        userinfo_endpoint='https://oidc.example.com/userinfo',
        redirect_uri='http://localhost:5000/authorize',
        client_id='cid',
        client_secret='csecret',
        cookie_secret_key='secret',
        scope=['openid'],
    )
    return OIDClient(config)


@pytest.mark.parametrize('user_roles, kwargs, expected', [
    # and_allow_roles: every role is required
    (['a', 'b', 'c'], {'and_allow_roles': ['a', 'b']}, True),
    (['a'], {'and_allow_roles': ['a', 'b']}, False),
    ([], {'and_allow_roles': ['a']}, False),
    # or_allow_roles: any role is enough
    (['a'], {'or_allow_roles': ['x', 'a']}, True),
    (['z'], {'or_allow_roles': ['x', 'a']}, False),
    # deny_roles wins over an otherwise successful match
    (['a', 'bad'], {'or_allow_roles': ['a'], 'deny_roles': ['bad']}, False),
    (['a'], {'or_allow_roles': ['a'], 'deny_roles': ['bad']}, True),
    # '*' wildcards
    (['a', 'b'], {'and_allow_roles': ['*']}, True),
    ([], {'and_allow_roles': ['*']}, False),
    (['a'], {'or_allow_roles': ['a'], 'deny_roles': ['*']}, False),
    # No criteria at all denies by default
    (['a'], {}, False),
])
def test_evaluate_roles(client, user_roles, kwargs, expected):
    assert client.evaluate_roles(user_roles, **kwargs) is expected


def test_require_roles_calls_the_endpoint_when_authorized(client):
    client.set_roles_getter(lambda: ['admin'])
    client.set_redirector(lambda url: f'redirected:{url}')

    @client.require_roles('/denied', and_allow_roles=['admin'])
    def endpoint():
        return 'allowed'

    assert endpoint() == 'allowed'


def test_require_roles_redirects_when_unauthorized(client):
    client.set_roles_getter(lambda: ['guest'])
    client.set_redirector(lambda url: f'redirected:{url}')

    @client.require_roles('/denied', and_allow_roles=['admin'])
    def endpoint():
        return 'allowed'

    assert endpoint() == 'redirected:/denied'


def test_require_roles_redirects_when_roles_getter_fails(client):
    def boom():
        raise RuntimeError('no session')

    client.set_roles_getter(boom)
    client.set_redirector(lambda url: f'redirected:{url}')

    @client.require_roles('/denied', or_allow_roles=['admin'])
    def endpoint():
        return 'allowed'

    assert endpoint() == 'redirected:/denied'


def test_require_roles_preserves_function_metadata(client):
    client.set_roles_getter(lambda: ['admin'])
    client.set_redirector(lambda url: url)

    @client.require_roles('/denied', and_allow_roles=['admin'])
    def my_endpoint(a, b=2):
        """Docstring kept."""
        return a + b

    assert my_endpoint.__name__ == 'my_endpoint'
    assert my_endpoint.__doc__ == 'Docstring kept.'
    assert my_endpoint(1) == 3
