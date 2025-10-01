# streamlit_app/ui/components.py
import streamlit as st

def render_linkedin_button() -> bool:
    """
    Render a LinkedIn-styled button using Streamlit's native st.button.
    Returns True when clicked. The caller handles the actual redirect
    (so we can force a same-tab navigation).
    """
    # Style all buttons on this page (safe here because the login view has only one)
    st.markdown(
        """
        <style>
        div.stButton > button {
            background: #0077B5 !important;
            color: #ffffff !important;
            border: 0 !important;
            border-radius: 10px !important;
            font-weight: 700 !important;
            box-shadow: 0 2px 8px rgba(0,0,0,0.15) !important;
            padding: 0.6rem 1.1rem !important;
        }
        div.stButton > button:hover { filter: brightness(0.95); }
        </style>
        """,
        unsafe_allow_html=True,
    )
    return st.button("Sign in with LinkedIn", key="li_signin_btn")
