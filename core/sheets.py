# streamlit_app/core/sheets.py
from datetime import datetime
import streamlit as st
try:
    import gspread
    from google.oauth2.service_account import Credentials
except Exception:
    gspread = None
    Credentials = None

from .config import Settings
from .utils import coerce_cell, stringify_locale

@st.cache_resource(show_spinner=False)
def _get_ws(cfg: Settings):
    if gspread is None or Credentials is None: return None
    if not (cfg.sheet_id and cfg.service_account_info): return None
    scope = ["https://www.googleapis.com/auth/spreadsheets"]
    creds = Credentials.from_service_account_info(cfg.service_account_info, scopes=scope)
    gc = gspread.authorize(creds)
    sh = gc.open_by_key(cfg.sheet_id)
    try:
        ws = sh.worksheet(cfg.worksheet)
    except gspread.WorksheetNotFound:
        ws = sh.add_worksheet(title=cfg.worksheet, rows=1000, cols=20)
        ws.append_row(["timestamp_iso","sub","name","given_name","family_name","email","email_verified","locale"])
    # ensure header exists
    try:
        hdr = [h.strip().lower() for h in (ws.row_values(1) or [])]
        want = ["timestamp_iso","sub","name","given_name","family_name","email","email_verified","locale"]
        if hdr != want:
            ws.insert_row(["timestamp_iso","sub","name","given_name","family_name","email","email_verified","locale"], 1)
    except Exception:
        pass
    return ws

def persist_signin_row(userinfo: dict, cfg: Settings):
    ws = _get_ws(cfg)
    if ws is None: return
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
