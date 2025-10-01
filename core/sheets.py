from datetime import datetime
import streamlit as st

try:
    import gspread
    from google.oauth2.service_account import Credentials
except Exception:
    gspread = None
    Credentials = None

from .utils import coerce_cell, stringify_locale

@st.cache_resource(show_spinner=False)
def _get_ws(sheet_id: str | None, worksheet: str, service_account_info: dict | None):
    if gspread is None or Credentials is None:
        return None
    if not (sheet_id and service_account_info):
        return None
    scope = ["https://www.googleapis.com/auth/spreadsheets"]
    creds = Credentials.from_service_account_info(service_account_info, scopes=scope)
    gc = gspread.authorize(creds)
    sh = gc.open_by_key(sheet_id)
    try:
        ws = sh.worksheet(worksheet)
    except gspread.WorksheetNotFound:
        ws = sh.add_worksheet(title=worksheet, rows=1000, cols=20)
        ws.append_row(["timestamp_iso","sub","name","given_name","family_name","email","email_verified","locale"])
    # Ensure header exists
    try:
        hdr = [h.strip().lower() for h in (ws.row_values(1) or [])]
        want = ["timestamp_iso","sub","name","given_name","family_name","email","email_verified","locale"]
        if hdr != want:
            ws.insert_row(["timestamp_iso","sub","name","given_name","family_name","email","email_verified","locale"], 1)
    except Exception:
        pass
    return ws

def persist_signin_row(userinfo: dict, cfg) -> None:
    ws = _get_ws(cfg.sheet_id, cfg.worksheet, cfg.service_account_info)
    if ws is None:
        return
    try:
        row = [
            datetime.utcnow().isoformat(),
            coerce_cell(userinfo.get("sub")),
            coerce_cell(userinfo.get("name")),
            coerce_cell(userinfo.get("given_name")),
            coerce_cell(userinfo.get("family_name")),
            coerce_cell(userinfo.get("email")),
            coerce_cell(userinfo.get("email_verified")),
            stringify_locale(userinfo.get("locale")),
        ]
        ws.append_row(row, value_input_option="USER_ENTERED")
    except Exception as e:
        st.warning(f"Could not write to Google Sheets: {e}")
