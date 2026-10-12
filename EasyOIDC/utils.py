import base64
import json
import re
from typing import Iterable, Optional


def is_path_matched(path, pattern):
    if '*' in pattern:
        pattern = '^' + re.escape(pattern).replace('\\*', '.*') + '$'
        return re.match(pattern, path) is not None
    else:
        return path == pattern


def get_domain_from_url(url):
    from urllib.parse import urlparse
    parsed_url = urlparse(url)
    return parsed_url.netloc


def streamlit_nav_to(url):
    import streamlit as st
    nav_script = f"""<meta http-equiv="refresh" content="0; url='{url}'">"""
    st.write(nav_script, unsafe_allow_html=True)


def safe_redirect_path(path: Optional[str], default: str = '/') -> str:
    """Return ``path`` only if it is a local, relative path.

    Rejects absolute URLs (``https://evil``), scheme-relative URLs (``//evil``)
    and backslash tricks (``/\\evil``) so post-login redirects can't be turned
    into an open redirect.
    """
    if not path or not isinstance(path, str):
        return default
    if not path.startswith('/') or path.startswith('//') or path.startswith('/\\'):
        return default
    if any(c in path for c in ('\r', '\n', '\t')):
        return default
    return path


def decode_jwt_claims_unverified(token: Optional[str]) -> dict:
    """Decode a JWT payload WITHOUT verifying its signature.

    Only use this for tokens received directly from the token endpoint over
    TLS (e.g. to read roles from a Keycloak access token). Returns ``{}`` for
    anything that isn't a decodable JWT.
    """
    if not token or not isinstance(token, str) or token.count('.') != 2:
        return {}
    try:
        payload = token.split('.')[1]
        payload += '=' * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload.encode('ascii')))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _as_list(value) -> list:
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return []


def extract_roles(claim_sets: Iterable[Optional[dict]], source: str = 'realm',
                  client_id: Optional[str] = None) -> list:
    """Collect Keycloak-style roles from one or more claim sets.

    :param source: ``'realm'`` (``realm_access.roles``), ``'client'``
        (``resource_access.<client_id>.roles``) or ``'realm+client'``.
    """
    want_realm = source in ('realm', 'realm+client')
    want_client = source in ('client', 'realm+client')
    roles = []
    for claims in claim_sets:
        if not isinstance(claims, dict):
            continue
        if want_realm:
            roles += _as_list((claims.get('realm_access') or {}).get('roles'))
        if want_client and client_id:
            roles += _as_list(((claims.get('resource_access') or {}).get(client_id) or {}).get('roles'))
    seen = set()
    return [r for r in roles if not (r in seen or seen.add(r))]
