from EasyOIDC import OIDClient, Config
from EasyOIDC.utils import streamlit_nav_to
from EasyOIDC.session import SessionHandler
import streamlit as st
from streamlit_cookies_manager import EncryptedCookieManager

session_store = SessionHandler(mode='redis')

auth_config = Config('.env')
auth_config.redirect_uri = 'http://localhost:5000'
auth = OIDClient(auth_config)

cookies = EncryptedCookieManager(prefix="jpmanson/EasyODIC/", password=auth_config.cookie_secret_key)
if not cookies.ready():
    st.stop()


def logout():
    state = cookies.get('state', '')
    token = get_current_token()
    cookies.pop('state')
    cookies.save()
    if token:
        logout_endpoint, post_logout_endpoint = auth_config.logout_endpoint, auth_config.post_logout_uri
        logout_url = auth.get_keycloak_logout_url(auth.get_oauth_session(token),
                                                  logout_endpoint, post_logout_endpoint)
        session_store[state] = {'userinfo': None, 'token': None}
        streamlit_nav_to(logout_url)
    else:
        streamlit_nav_to('/')


def login_request():
    uri, state = auth.auth_server_login()
    cookies['state'] = state
    cookies.save()
    session_store[state] = {'userinfo': None, 'token': None}
    streamlit_nav_to(uri)


def get_current_token():
    try:
        state = cookies.get('state', '')
        return session_store.get(state, {}).get('token', {})
    except:
        return None


def validate_user_session():
    token = get_current_token()
    authenticated = False
    if token:
        authenticated = auth.is_valid_oidc_session(auth.get_oauth_session(token))
        # Si tiene un token inválido, lo borramos
        if not authenticated:
            login_request()
    return authenticated


def authenticate():
    try:
        state = st.query_params.to_dict().get('state', '')
        token, oauth_session = auth.get_token(st.query_params.to_dict())
        userinfo = auth.get_user_info(oauth_session)
        session_store.set(state, {'userinfo': userinfo, 'token': dict(token)})
    except Exception as e:
        print(f"Authentication error: '{e}'. Redirecting to login page...")
    streamlit_nav_to('/')


def main():
    state = cookies.get('state', None)
    authorizing = ('state' in st.query_params.to_dict()) and ('code' in st.query_params.to_dict())
    session_data_found = state in session_store

    authenticated = False
    if not authorizing:
        if 'state' not in cookies:
            login_request()
        else:
            authenticated = validate_user_session()
    else:
        authenticate()

    if authorizing:
        st.stop()

    st.title("EasyOIDC")
    st.markdown("This is an streamlit example")

    if authenticated:
        st.write(f"Hello {session_store[state]['userinfo']['name']}")
        st.button('Logout', on_click=logout)
    else:
        st.button('Login', on_click=login_request)


if __name__ == "__main__":
    main()