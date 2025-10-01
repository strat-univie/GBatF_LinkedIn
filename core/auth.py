import json
import time
import base64
import hmac
import hashlib
import requests
import urllib.parse as urlparse
from typing import Tuple, Optional

AUTH_URL = "https://www.linkedin.com/oauth/v2/authorization"
TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
USERINFO_URL = "https://api.linkedin.com/v2/userinfo"

# ---- Stateless CSRF helpers (no external deps, no circular imports) ----
def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("utf-8")

def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

def make_signed_state(secret: str, ttl_seconds: int = 900) -> str:
    payload = {
        "ts": int(time.time()),
        "rnd": _b64url_encode(hashlib.sha256(str(time.time()).encode("utf-8")).digest()[:16]),
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
    return f"{_b64url_encode(raw)}.{_b64url_encode(sig)}"

def verify_signed_state(secret: str, state: str, max_age_seconds: int = 900) -> bool:
    try:
        p_b64, s_b64 = state.split(".", 1)
        raw = _b64url_decode(p_b64)
        sig = _b64url_decode(s_b64)
        expected = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return False
        payload = json.loads(raw.decode("utf-8"))
        ts = int(payload.get("ts", 0))
        age = int(time.time()) - ts
        return 0 <= age <= max_age_seconds
    except Exception:
        return False

# ---- LinkedIn OAuth / OIDC ----
def build_linkedin_auth_url(client_id: str, redirect_uri: str, scope: str, state: str) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "scope": scope,
    }
    return f"{AUTH_URL}?{urlparse.urlencode(params)}"

def exchange_code_for_tokens(
    client_id: str, client_secret: str, redirect_uri: str, code: str
) -> Tuple[Optional[str], Optional[str]]:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    r = requests.post(TOKEN_URL, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=15)
    r.raise_for_status()
    js = r.json()
    return js.get("access_token"), js.get("id_token")

def fetch_userinfo(access_token: str) -> dict:
    r = requests.get(USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"}, timeout=15)
    r.raise_for_status()
    return r.json()
