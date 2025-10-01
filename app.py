import re
import os
import requests
import urllib.parse as urlparse
import secrets as pysecrets
from datetime import datetime

import streamlit as st
from openai import OpenAI

# Optional (Sheets)
try:
    import gspread
    from google.oauth2.service_account import Credentials
except Exception:
    gspread = None
    Credentials = None

st.set_page_config(page_title="Chat (Responses API + Vector Store + Plotly)", page_icon="💬", layout="centered")

# --- Secrets / Config ---
API_KEY = st.secrets.get("OPENAI_API_KEY")
MODEL = st.secrets.get("OPENAI_MODEL", "gpt-4o-mini")
VECTOR_STORE_ID = st.secrets.get("OPENAI_VECTOR_STORE_ID", "")

# LinkedIn OIDC
LINKEDIN = st.secrets.get("linkedin", {})
LINKEDIN_CLIENT_ID = LINKEDIN.get("client_id")
LINKEDIN_CLIENT_SECRET = LINKEDIN.get("client_secret")
LINKEDIN_REDIRECT_URI = LINKEDIN.get("redirect_uri")

# Google Sheets
GS_CONF = st.secrets.get("google_sheets", {})
SA_INFO = st.secrets.get("gcp_service_account")

if not API_KEY:
    st.error("Missing OPENAI_API_KEY in .streamlit/secrets.toml")
    st.stop()

if not VECTOR_STORE_ID:
    st.error("Missing OPENAI_VECTOR_STORE_ID in .streamlit/secrets.toml (required for file_search).")
    st.stop()

if not (LINKEDIN_CLIENT_ID and LINKEDIN_CLIENT_SECRET and LINKEDIN_REDIRECT_URI):
    st.error("LinkedIn OIDC not configured. Add [linkedin] client_id, client_secret, redirect_uri to secrets.toml.")
    st.stop()

client = OpenAI(api_key=API_KEY)

st.title("Get Better at Flatter Chatbot")

# --- Chat history in session state ---
# Entries can be:
#   {"role": "user"|"assistant", "content": "text"}  OR
#   {"role": "assistant", "plot": <plotly_figure>, "caption": "..."}
if "messages" not in st.session_state:
    st.session_state.messages = []

# ================= LinkedIn OIDC helpers =================
AUTH_URL = "https://www.linkedin.com/oauth/v2/authorization"
TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
USERINFO_URL = "https://api.linkedin.com/v2/userinfo"
OIDC_SCOPE = "openid profile email"

def build_linkedin_auth_url(state: str, scope: str = OIDC_SCOPE) -> str:
    params = {
        "response_type": "code",
        "client_id": LINKEDIN_CLIENT_ID,
        "redirect_uri": LINKEDIN_REDIRECT_URI,
        "state": state,
        "scope": scope,
    }
    return f"{AUTH_URL}?{urlparse.urlencode(params)}"

def exchange_code_for_tokens(code: str):
    """Return (access_token, id_token or None)"""
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": LINKEDIN_REDIRECT_URI,
        "client_id": LINKEDIN_CLIENT_ID,
        "client_secret": LINKEDIN_CLIENT_SECRET,
    }
    r = requests.post(TOKEN_URL, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=15)
    r.raise_for_status()
    js = r.json()
    return js.get("access_token"), js.get("id_token")

def fetch_userinfo(access_token: str) -> dict | None:
    """OpenID Connect userinfo → standard claims"""
    try:
        r = requests.get(USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"}, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"Fetching LinkedIn userinfo failed: {e}")
        return None

# ================= Google Sheets helpers =================
@st.cache_resource(show_spinner=False)
def _get_gsheet_worksheet():
    """
    Returns a gspread Worksheet or None if Sheets isn't configured.
    Ensures the worksheet exists and has a header row.
    """
    if gspread is None or Credentials is None:
        return None
    if not GS_CONF or not SA_INFO:
        return None
    try:
        scope = ["https://www.googleapis.com/auth/spreadsheets"]
        creds = Credentials.from_service_account_info(SA_INFO, scopes=scope)
        gc = gspread.authorize(creds)
        sheet_id = GS_CONF.get("sheet_id")
        if not sheet_id:
            return None
        sh = gc.open_by_key(sheet_id)
        ws_title = GS_CONF.get("worksheet", "linkedin_signins")
        try:
            ws = sh.worksheet(ws_title)
        except gspread.WorksheetNotFound:
            ws = sh.add_worksheet(title=ws_title, rows=1000, cols=20)
            ws.append_row([
                "timestamp_iso", "sub", "name", "given_name", "family_name",
                "email", "email_verified", "picture", "locale"
            ])
        # Ensure header exists (don’t overwrite existing data)
        try:
            hdr = ws.row_values(1)
            want = ["timestamp_iso","sub","name","given_name","family_name","email","email_verified","picture","locale"]
            if [h.strip().lower() for h in hdr] != want:
                ws.insert_row([
                    "timestamp_iso", "sub", "name", "given_name", "family_name",
                    "email", "email_verified", "picture", "locale"
                ], 1)
        except Exception:
            pass
        return ws
    except Exception as e:
        st.warning(f"Google Sheets setup issue: {e}")
        return None

def persist_signin_row(userinfo: dict):
    """
    Append sign-in claims to Google Sheets (if configured).
    Schema: timestamp_iso, sub, name, given_name, family_name, email, email_verified, picture, locale
    """
    ws = _get_gsheet_worksheet()
    if ws is None:
        st.warning("Google Sheets logging not configured; skipping persistent write.")
        return
    try:
        ws.append_row([
            datetime.utcnow().isoformat(),
            userinfo.get("sub"),
            userinfo.get("name"),
            userinfo.get("given_name"),
            userinfo.get("family_name"),
            userinfo.get("email"),
            userinfo.get("email_verified"),
            userinfo.get("picture"),
            userinfo.get("locale"),
        ], value_input_option="USER_ENTERED")
    except Exception as e:
        st.warning(f"Could not write to Google Sheets: {e}")

# ================= Auth state & callback handling =================
st.session_state.setdefault("oauth_state", pysecrets.token_urlsafe(16))
st.session_state.setdefault("li_authed", False)
st.session_state.setdefault("li_profile", None)
st.session_state.setdefault("li_access_token", None)
st.session_state.setdefault("li_id_token", None)
st.session_state.setdefault("logged_ids_this_session", set())

# Read query params (new + fallback)
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

# Handle OAuth callback
if qp_code and not st.session_state["li_authed"]:
    if qp_state and qp_state == st.session_state["oauth_state"]:
        try:
            access_token, id_token = exchange_code_for_tokens(qp_code)
            if access_token:
                ui = fetch_userinfo(access_token) or {}
                # Normalize & store minimal profile
                st.session_state["li_authed"] = True
                st.session_state["li_access_token"] = access_token
                st.session_state["li_id_token"] = id_token
                st.session_state["li_profile"] = {
                    "sub": ui.get("sub"),
                    "first_name": ui.get("given_name"),
                    "last_name": ui.get("family_name"),
                    "full_name": ui.get("name"),
                    "email": ui.get("email"),
                    "email_verified": ui.get("email_verified"),
                    "picture": ui.get("picture"),
                    "locale": ui.get("locale"),
                }
                # Persist once per session (unique by sub)
                uid = ui.get("sub")
                if uid and uid not in st.session_state["logged_ids_this_session"]:
                    persist_signin_row(ui)
                    st.session_state["logged_ids_this_session"].add(uid)
        except Exception as e:
            st.error(f"LinkedIn sign-in failed: {e}")
        finally:
            _clear_qp()
    else:
        st.error("CSRF state mismatch. Please try signing in again.")
        _clear_qp()

# ================= Sidebar: Identity & Sheets status =================
with st.sidebar:
    st.subheader("Identity")
    if st.session_state["li_authed"] and st.session_state["li_profile"]:
        p = st.session_state["li_profile"]
        name_line = p.get("full_name") or f"{p.get('first_name','')} {p.get('last_name','')}".strip()
        st.success(f"Signed in as **{name_line}** (LinkedIn)")
        if p.get("email"):
            st.caption(f"Email: {p['email']} {'(verified)' if p.get('email_verified') else ''}")
        if p.get("picture"):
            st.image(p["picture"], width=72)
        # Sheets indicator
        ws_ok = _get_gsheet_worksheet() is not None
        if ws_ok:
            st.caption("✓ Google Sheets logging enabled")
        else:
            st.caption("∙ Sheets logging not configured")
            try:
                svc_email = SA_INFO.get("client_email") if SA_INFO else "service-account"
                st.caption(f"(Share your Sheet with: {svc_email})")
            except Exception:
                pass
        if st.button("Sign out"):
            for k in ["li_authed","li_profile","li_access_token","li_id_token"]:
                st.session_state[k] = None if k == "li_profile" else False
            st.rerun()
    else:
        auth_url = build_linkedin_auth_url(st.session_state["oauth_state"], scope=OIDC_SCOPE)
        st.link_button("Sign in with LinkedIn", auth_url)

# ================= Utilities (unchanged) =================
def build_transcript(history):
    """Compile chat history into a single text transcript for Responses 'input'."""
    lines = []
    for m in history:
        if "plot" in m:
            lines.append("Assistant: [chart]")
        else:
            speaker = "User" if m["role"] == "user" else "Assistant"
            lines.append(f"{speaker}: {m['content']}")
    return "\n".join(lines)

def extract_python_code(text: str):
    """
    Extract a Python code block wrapped as:
    ```python
    <code>
    ```
    Returns the inner code or None.
    """
    pattern = r"```python\s(.*?)```"
    matches = re.findall(pattern, text, re.DOTALL)
    return matches[0] if matches else None

def remove_python_blocks(text: str):
    """Remove all ```python ...``` fenced code blocks from the text."""
    return re.sub(r"```python\s.*?```", "", text, flags=re.DOTALL).strip()

# --- Render previous turns (including persistent plots) ---
for m in st.session_state.messages:
    with st.chat_message(m["role"]):
        if "plot" in m:
            st.plotly_chart(m["plot"], theme="streamlit", use_container_width=True)
            if m.get("caption"):
                st.caption(m["caption"])
        else:
            st.markdown(m["content"])

# --- Input box (disabled until LinkedIn sign-in) ---
chat_disabled = not st.session_state.get("li_authed", False)
user_input = st.chat_input(
    "Type your question… (e.g., “visualize…”, “plot…”, “show a chart of…”)",
    disabled=chat_disabled
)

if chat_disabled:
    st.info("Please sign in with LinkedIn to use the chatbot. We’ll store your name and basic profile claims (name/email/picture/locale) in our Google Sheet.")

if user_input and not chat_disabled:
    # Show user message
    st.session_state.messages.append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.markdown(user_input)

    transcript = build_transcript(st.session_state.messages)

    # --- Instructions ---
    base_instructions = (
        "You are a careful, concise assistant providing individual information on Prof. Markus Reitzig's Book 'Get Better at Flatter'. "
        "Use ONLY the information retrieved from the file_search tool. "
        "If a retrieved chunk contains a page marker like '{:.page-1}', translate it into a citation in the following format:\n\n"
        "Reitzig, M. (2022). Get better at flatter. Springer International Publishing., p. <page number>\n\n"
        "Example: If the marker is '{:.page-3}', cite it as 'Reitzig, M. (2022). Get better at flatter. Springer International Publishing., p. 3'. "
        "If no page marker is present, omit the page reference. "
        "If the knowledge base does not contain the answer, reply with: "
        "\"I don't know based on the provided knowledge base.\" "
        "Do not rely on outside or general knowledge. Do not fabricate facts."
    )

    plotting_guidance = (
        "If the user asks to visualize, chart, graph, plot, or show a figure, produce Plotly-only Python code. "
        "Return the code wrapped in a single fenced block exactly like:\n"
        "```python\n"
        "# (imports if needed)\n"
        "# construct data from the retrieved context\n"
        "# create a Plotly figure assigned to the variable `fig`\n"
        "```\n"
        "Requirements:\n"
        "- Use Plotly only (no matplotlib).\n"
        "- Name the resulting figure variable `fig`.\n"
        "- Do NOT call fig.show().\n"
        "- You may include a brief natural-language explanation before the code block."
    )

    instructions = f"{base_instructions}\n\n{plotting_guidance}"

    req = {
        "model": MODEL,
        "input": transcript,
        "instructions": instructions,
        "tools": [{
            "type": "file_search",
            "vector_store_ids": [VECTOR_STORE_ID],
        }],
    }

    # Call the API
    try:
        resp = client.responses.create(**req)
        assistant_text = resp.output_text or ""
    except Exception as e:
        assistant_text = f"Sorry, there was an error calling the API:\n\n```\n{e}\n```"
        resp = None

    # Assistant bubble
    with st.chat_message("assistant"):
        # Try to find a plot code block (the LLM decides if one is needed)
        code = extract_python_code(assistant_text)
        if code:
            # 1) Show any explanatory text (minus code)
            explanation = remove_python_blocks(assistant_text)
            if explanation:
                st.markdown(explanation)

            # 2) Exec the code (hide the code itself). Expect a variable `fig`.
            try:
                # Strip any fig.show() just in case
                safe_code = code.replace("fig.show()", "").strip()
                exec_globals = {"st": st}
                exec_locals = {}
                exec(safe_code, exec_globals, exec_locals)

                # Retrieve the figure
                fig = None
                if "fig" in exec_locals:
                    fig = exec_locals["fig"]
                elif "fig" in exec_globals:
                    fig = exec_globals["fig"]

                if fig is not None and hasattr(fig, "to_dict"):
                    st.plotly_chart(fig, theme="streamlit", use_container_width=True)
                    # Persist the plot in history so it stays visible
                    st.session_state.messages.append({
                        "role": "assistant",
                        "plot": fig,
                        "caption": None  # optional caption string
                    })
                else:
                    st.info("I generated code but couldn't detect a Plotly figure named 'fig'.")
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": "Chart generation attempted, but no figure was detected."
                    })
            except Exception as ex:
                st.error(f"Plot execution error:\n{ex}")
                st.session_state.messages.append({"role": "assistant", "content": f"Plot execution error: {ex}"})
        else:
            # No code -> regular text answer
            st.markdown(assistant_text)
            st.session_state.messages.append({"role": "assistant", "content": assistant_text})
