from dataclasses import dataclass
import streamlit as st

@dataclass(frozen=True)
class Settings:
    openai_api_key: str
    model: str
    vector_store_id: str
    # LinkedIn
    li_client_id: str
    li_client_secret: str
    li_redirect_uri: str
    oidc_scope: str
    app_state_secret: str
    # Google Sheets
    sheet_id: str | None
    worksheet: str
    service_account_info: dict | None

def get_settings() -> Settings:
    API_KEY = st.secrets.get("OPENAI_API_KEY")
    MODEL = st.secrets.get("OPENAI_MODEL", "gpt-4o-mini")
    VSTORE = st.secrets.get("OPENAI_VECTOR_STORE_ID", "")

    LI = st.secrets.get("linkedin", {})
    GS = st.secrets.get("google_sheets", {})
    SA = st.secrets.get("gcp_service_account")

    if not API_KEY:
        st.error("Missing OPENAI_API_KEY in .streamlit/secrets.toml"); st.stop()
    if not VSTORE:
        st.error("Missing OPENAI_VECTOR_STORE_ID in .streamlit/secrets.toml (required for file_search)."); st.stop()
    if not (LI.get("client_id") and LI.get("client_secret") and LI.get("redirect_uri")):
        st.error("LinkedIn OIDC not configured: add [linkedin] client_id, client_secret, redirect_uri."); st.stop()

    app_state_secret = st.secrets.get("APP_STATE_SECRET", LI.get("client_secret") or "dev-secret")

    return Settings(
        openai_api_key=API_KEY,
        model=MODEL,
        vector_store_id=VSTORE,
        li_client_id=LI["client_id"],
        li_client_secret=LI["client_secret"],
        li_redirect_uri=LI["redirect_uri"],
        oidc_scope="openid profile email",
        app_state_secret=app_state_secret,
        sheet_id=GS.get("sheet_id"),
        worksheet=GS.get("worksheet", "linkedin_signins"),
        service_account_info=SA,
    )
