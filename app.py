import streamlit as st
from openai import OpenAI

from core.config import get_settings
from core.auth import (
    build_linkedin_auth_url,
    exchange_code_for_tokens,
    fetch_userinfo,
    make_signed_state,
    verify_signed_state,
)
from core.sheets import persist_signin_row
from core.utils import stringify_locale
from features.chat import render_chat
from ui.components import render_linkedin_button

st.set_page_config(
    page_title="Get Better at Flatter - LinkedIn",
    page_icon="💬",
    layout="centered",
)
st.title("Get Better at Flatter Chatbot")

# --- Load settings & OpenAI client ---
cfg = get_settings()
client = OpenAI(api_key=cfg.openai_api_key)

# --- Session bootstrap ---
st.session_state.setdefault("li_authed", False)
st.session_state.setdefault("li_profile", None)
st.session_state.setdefault("logged_ids_this_session", set())

# --- Read & clear query params (supports old/new Streamlit) ---
try:
    params = st.query_params
    qp_code = params.get("code")
    qp_state = params.get("state")

    def _clear_qp():
        try:
            st.query_params.clear()
        except Exception:
            st.experimental_set_query_params()
except Exception:
    qp = st.experimental_get_query_params()
    qp_code = qp.get("code", [None])[0] if qp.get("code") else None
    qp_state = qp.get("state", [None])[0] if qp.get("state") else None

    def _clear_qp():
        st.experimental_set_query_params()

# --- OAuth callback (stateless signed CSRF) ---
if qp_code and not st.session_state["li_authed"]:
    if qp_state and verify_signed_state(cfg.app_state_secret, qp_state, max_age_seconds=900):
        try:
            access_token, id_token = exchange_code_for_tokens(
                cfg.li_client_id, cfg.li_client_secret, cfg.li_redirect_uri, qp_code
            )
            if access_token:
                ui = fetch_userinfo(access_token) or {}
                locale_str = stringify_locale(ui.get("locale"))

                st.session_state["li_authed"] = True
                st.session_state["li_profile"] = {
                    "sub": ui.get("sub"),
                    "first_name": ui.get("given_name"),
                    "last_name": ui.get("family_name"),
                    "full_name": ui.get("name"),
                    "email": ui.get("email"),
                    "email_verified": ui.get("email_verified"),
                    "locale": locale_str,
                }

                uid = ui.get("sub")
                if uid and uid not in st.session_state["logged_ids_this_session"]:
                    persist_signin_row(ui, cfg)
                    st.session_state["logged_ids_this_session"].add(uid)
        except Exception as e:
            st.error(f"LinkedIn sign-in failed: {e}")
        finally:
            _clear_qp()
    else:
        st.error("CSRF state mismatch. Please try signing in again.")
        _clear_qp()

# --- Main view: gate chat on login; centered LinkedIn button in #0077B5 ---
if not st.session_state.get("li_authed"):
    st.write("")  # spacer
    left, center, right = st.columns([1, 2, 1])
    with center:
        state_token = make_signed_state(cfg.app_state_secret)
        auth_url = build_linkedin_auth_url(
            cfg.li_client_id, cfg.li_redirect_uri, cfg.oidc_scope, state_token
        )
        render_linkedin_button(auth_url)
else:
    render_chat(client, cfg.model, cfg.vector_store_id)
