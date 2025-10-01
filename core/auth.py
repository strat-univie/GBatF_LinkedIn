# streamlit_app/core/auth.py
import json, time, base64, hmac, hashlib, requests, urllib.parse as urlparse
from typing import Tuple, Optional
from .config import Settings

AUTH_URL = "https://www.linkedin.com/oauth/v2/authorization"
TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
USERINFO_URL = "https://api.linkedin.com/v2/userinfo"

def build_linkedin_auth_url(cfg: Settings, state: str) -> str:
    params = {
        "response_type": "code",
        "client_id": cfg.li_client_id,
        "redirect_uri": cfg.li_redirect_uri,
        "state": state,
        "scope": cfg.oidc_scope,
    }
    return f"{AUTH_URL}?{urlparse.urlencode(params)}"

def exchange_code_for_tokens(cfg: Settings, code: str) -> Tuple[Optional[str], Optional[str]]:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": cfg.li_redirect_uri,
        "client_id": cfg.li_client_id,
        "client_secret": cfg.li_client_secret,
    }
    r = requests.post(TOKEN_URL, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=15)
    r.raise_for_status()
    js = r.json()
    return js.get("access_token"), js.get("id_token")

def fetch_userinfo(access_token: str) -> dict | None:
    r = requests.get(USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"}, timeout=15)
    r.raise_for_status()
    return r.json()

# ---- Signed state helpers ----
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def make_signed_state(secret: str, ttl_seconds: int = 900) -> str:
    payload = {"ts": int(time.time()), "nonce": base64.urlsafe_b64encode(hashlib.sha256(str(time.time()).encode()).digest())[:8].decode()}
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    sig = hmac.new(secret.encode(), raw, hashlib.sha256).digest()
    return f"{_b64url(raw)}.{_b64url(sig)}"

def verify_signed_state(secret: str, state: str, max_age_seconds: int = 900) -> bool:
    try:
        p_b64, s_b64 = state.split(".", 1)
        raw = _b64url_decode(p_b64)
        sig = _b64url_decode(s_b64)
        expected = hmac.new(secret.encode(), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return False
        payload = json.loads(raw.decode())
        ts = int(payload.get("ts", 0))
        return abs(int(time.time()) - ts) <= max_age_seconds
    except Exception:
        return False
