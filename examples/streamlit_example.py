from EasyOIDC import OIDClient, Config
from EasyOIDC.utils import streamlit_nav_to
from EasyOIDC.session import SessionHandler
import streamlit as st
from streamlit_cookies_manager import EncryptedCookieManager
st.set_page_config(page_title="EasyOIDC", page_icon=":lock:", initial_sidebar_state="collapsed", layout="wide", menu_items=None)
session_store = SessionHandler(mode='redis')

auth_config = Config('.env')
auth_config.redirect_uri = 'http://localhost:5000'
auth = OIDClient(auth_config)

cookies = EncryptedCookieManager(prefix="jpmanson/EasyODIC/", password=auth_config.cookie_secret_key)
if not cookies.ready():
    st.stop()


def logout(reload=False):
    state = cookies.get('state', '')
    token = get_current_token()
    cookies.pop('state')
    cookies.save()
    session_store[state] = {'userinfo': None, 'token': None}
    if reload:
        if token:
            logout_endpoint, post_logout_endpoint = auth_config.logout_endpoint, auth_config.post_logout_uri
            logout_url = auth.get_keycloak_logout_url(auth.get_oauth_session(token),
                                                      logout_endpoint, post_logout_endpoint)
            streamlit_nav_to(logout_url)
        else:
            streamlit_nav_to('/')
    else:
        if token:
            auth.send_keycloak_logout(auth.get_oauth_session(token), auth_config.logout_endpoint)


def login_request():
    uri, state = auth._auth_server_login()
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



style = "<style>"
style += "div[data-testid='collapsedControl'] {transition: none; display: none;}"
style += "section[data-testid='stSidebar'] {transition: none; display: none;}"
style += "div[data-testid='stSidebarNav'] {transition: none; display: none;}"
style += "footer {visibility: hidden;}"
style += "div[data-testid='stDecoration'] {display: none;}"
style += "#MainMenu, header, footer {visibility: hidden;}"
style += ".stDeployButton {display:none;}"
style += "#stDecoration {display:none;}"
style += ".st-emotion-cache-z5fcl4 {padding-top: 0}"
style += "</style>"
st.markdown(style, unsafe_allow_html=True)

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

    if len(st.query_params.to_dict().keys()):
        st.stop()

    st.title("EasyOIDC")
    st.markdown("This is an streamlit example")

    if authenticated:
        #st.write(f"Hello {session_store[state]['userinfo']['name']}")
        st.button('Logout', on_click=logout)
    else:
        st.button('Login', on_click=login_request)


if __name__ == "__main__":
    main()