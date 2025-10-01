import streamlit as st

def render_linkedin_button(auth_url: str):
    st.markdown(
        f"""
        <style>
        .li-btn {{
            display: inline-flex; align-items: center; gap: 10px;
            padding: 12px 18px; border-radius: 10px;
            background: #0077B5; color: #ffffff !important; text-decoration: none;
            font-weight: 700; font-family: system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        }}
        .li-btn:hover {{ filter: brightness(0.95); }}
        .li-icon {{ width: 18px; height: 18px; display: inline-block; }}
        </style>
        <a class="li-btn" href="{auth_url}">
            <svg class="li-icon" viewBox="0 0 24 24" aria-hidden="true">
                <path fill="#ffffff" d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.447-2.136 2.942v5.664H9.351V9h3.414v1.561h.049c.476-.9 1.637-1.85 3.366-1.85 3.6 0 4.265 2.37 4.265 5.455v6.286zM5.337 7.433a2.06 2.06 0 1 1 0-4.12 2.06 2.06 0 0 1 0 4.12zM6.994 20.452H3.677V9h3.317v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.226.792 24 1.771 24h20.451C23.2 24 24 23.226 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
            </svg>
            Sign in with LinkedIn
        </a>
        """,
        unsafe_allow_html=True,
    )
