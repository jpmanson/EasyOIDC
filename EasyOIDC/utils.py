import re


def is_path_matched(path, pattern):
    if '*' in pattern:
        # Convertimos el patrón con wildcard a una expresión regular
        pattern = '^' + re.escape(pattern).replace('\\*', '.*') + '$'
        return re.match(pattern, path) is not None
    else:
        # Comparación directa para rutas exactas
        return path == pattern


def streamlit_nav_to(url):
    import streamlit as st
    nav_script = f"""<meta http-equiv="refresh" content="0; url='{url}'">"""
    st.write(nav_script, unsafe_allow_html=True)
