"""Framework-agnostic session flow shared by the high-level integrations.

The integrations (FastAPI, Flask, NiceGUI) only deal with cookies, requests
and responses. Everything that touches the OIDC server or the server-side
session store lives here, so the security rules are identical everywhere:

- the browser cookie holds a random **session id**, never the OAuth ``state``;
- each login keeps its own PKCE ``code_verifier`` and ``nonce`` server-side;
- the session id is rotated after a successful login (no session fixation);
- expired access tokens are refreshed and the new token is persisted;
- the access policy (required roles, verified email) is enforced at login and
  re-checked after every refresh.

Store layout (one entry per session id)::

    {'userinfo': dict | None, 'token': dict | None, 'id_claims': dict,
     'login': {'state', 'code_verifier', 'nonce', 'created_at'} | absent,
     'roles': list}

0.3.x entries (``{'userinfo', 'token'}`` keyed by the OAuth state) are still
readable, so existing sessions survive the upgrade.
"""
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from authlib.common.security import generate_token

from EasyOIDC.auth import AccessDeniedError, OIDClient

logger = logging.getLogger('EasyOIDC')


@dataclass
class AccessPolicy:
    """Who may hold a session.

    :param required_roles: the user needs at least one of these roles
        (as resolved by the client's roles getter). Empty = any user.
    :param require_email_verified: reject users whose ``email_verified``
        claim is not ``True``.
    """
    required_roles: list = field(default_factory=list)
    require_email_verified: bool = False

    @property
    def active(self) -> bool:
        return bool(self.required_roles) or self.require_email_verified


def new_session_id() -> str:
    return generate_token(48)


def _store_get(storage, sid):
    if not sid:
        return None
    try:
        if sid not in storage:
            return None
        return storage[sid]
    except Exception:
        return None


def _store_del(storage, sid):
    if not sid:
        return
    try:
        if sid in storage:
            del storage[sid]
    except Exception:
        pass


def start_login(client: OIDClient, storage, current_sid: Optional[str] = None) -> tuple:
    """Begin a login. Returns ``(sid, authorization_url)``.

    Any previous session for ``current_sid`` is discarded.
    """
    _store_del(storage, current_sid)
    login = client.begin_login()
    sid = new_session_id()
    storage[sid] = {'userinfo': None, 'token': None,
                    'login': {k: login[k] for k in ('state', 'code_verifier', 'nonce', 'created_at')}}
    return sid, login['url']


def finish_login(client: OIDClient, storage, sid: Optional[str], request_url: str,
                 query: dict, roles_getter, policy: Optional[AccessPolicy] = None) -> tuple:
    """Complete a login from the authorization callback.

    Returns ``(new_sid, session_data)``. Raises:

    - ``ValueError`` for protocol errors (IdP ``error``, state mismatch,
      expired or unknown login);
    - ``IDTokenValidationError`` when the ID token is invalid;
    - ``AccessDeniedError`` when the user fails ``policy``. In that case the
      exception carries ``session_data`` (token included) on ``.session``,
      so the caller can offer an IdP logout, but nothing is stored.
    """
    error = query.get('error')
    if error:
        raise ValueError(f"Authorization server error: {error} {query.get('error_description', '')}".strip())

    stored = _store_get(storage, sid) or {}
    login = stored.get('login')
    if not login:
        raise ValueError('No pending login for this session')
    if query.get('state') != login.get('state'):
        raise ValueError('State mismatch between the callback and the session')

    try:
        result = client.complete_login(request_url, login)
    finally:
        _store_del(storage, sid)

    data = {'userinfo': result['userinfo'], 'token': result['token'],
            'id_claims': result['id_claims']}
    data['roles'] = list(roles_getter(data) or [])

    if policy and policy.active:
        try:
            client.check_access(data['userinfo'], data['roles'], policy.required_roles,
                                policy.require_email_verified)
        except AccessDeniedError as e:
            e.session = data
            raise

    new_sid = new_session_id()
    storage[new_sid] = data
    return new_sid, data


def load_session(client: OIDClient, storage, sid: Optional[str], roles_getter,
                 validate_with_server: bool = False, policy: Optional[AccessPolicy] = None,
                 refresh: bool = True) -> Optional[dict]:
    """Return the authenticated session data for ``sid`` or ``None``.

    Expired tokens are refreshed (and persisted); userinfo is re-fetched
    after a refresh so role changes are picked up, and the policy is
    re-checked. Any failure drops the session.
    """
    data = _store_get(storage, sid)
    if not data:
        return None
    if data.get('login') and not data.get('userinfo'):
        created = data['login'].get('created_at') or 0
        if time.time() - created > client.get_config().login_timeout_seconds:
            _store_del(storage, sid)
        return None
    if not data.get('userinfo'):
        return None

    token = data.get('token')
    try:
        if refresh and token:
            new_token = client.refresh_if_needed(token)
            if new_token:
                session = client.get_oauth_session(new_token)
                data = dict(data, token=new_token, userinfo=client.get_user_info(session))
                data['roles'] = list(roles_getter(data) or [])
                if policy and policy.active:
                    client.check_access(data['userinfo'], data['roles'], policy.required_roles,
                                        policy.require_email_verified)
                storage[sid] = data
                return data
        if validate_with_server:
            if not client.is_valid_oidc_session(client.get_oauth_session(data.get('token'))):
                raise ValueError('Session rejected by the OIDC server')
    except Exception as e:
        logger.debug(f'Dropping session: {e}')
        _store_del(storage, sid)
        return None

    if 'roles' not in data:
        data = dict(data, roles=list(roles_getter(data) or []))
    if policy and policy.active:
        try:
            client.check_access(data['userinfo'], data['roles'], policy.required_roles,
                                policy.require_email_verified)
        except AccessDeniedError:
            _store_del(storage, sid)
            return None
    return data


def end_session(client: OIDClient, storage, sid: Optional[str]) -> Optional[str]:
    """Drop the session and return the IdP logout URL (or ``None``).

    When the session is not in the store (process restart, another worker
    with ``memory`` storage, expired entry) there is no ID token, but the
    IdP SSO session may still be alive. With ``logout_without_token='idp'``
    (default) the user is still sent to the IdP logout, without
    ``id_token_hint``; with ``'local'`` only the local session is cleared.
    """
    data = _store_get(storage, sid)
    _store_del(storage, sid)
    if sid and data is None:
        logger.warning('Logout: session not found in the store (restart, another process '
                       'with memory storage, or expired); there is no ID token for the IdP logout')
    cfg = client.get_config()
    if not cfg.logout_endpoint:
        return None
    token = (data or {}).get('token') or {}
    if token:
        return client.get_logout_url(token.get('id_token'))
    if cfg.logout_without_token == 'idp':
        return client.get_logout_url(None)
    return None


def logout_url_for(client: OIDClient, session_data: Optional[dict]) -> Optional[str]:
    token = (session_data or {}).get('token') or {}
    if token and client.get_config().logout_endpoint:
        return client.get_logout_url(token.get('id_token'))
    return None
