# streamlit_app/core/utils.py
import json, re

def stringify_locale(loc) -> str:
    if isinstance(loc, dict):
        lang = (loc.get("language") or "").strip()
        country = (loc.get("country") or "").strip()
        return f"{lang}-{country}" if lang and country else (lang or country or "")
    return loc if isinstance(loc, str) else ""

def coerce_cell(v):
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, dict):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return ", ".join(map(str, v))
    return str(v)

# Chat helpers
def build_transcript(history):
    lines = []
    for m in history:
        if "plot" in m: lines.append("Assistant: [chart]")
        else:
            speaker = "User" if m["role"] == "user" else "Assistant"
            lines.append(f"{speaker}: {m['content']}")
    return "\n".join(lines)

def extract_python_code(text: str):
    pattern = r"```python\s(.*?)```"
    matches = re.findall(pattern, text, re.DOTALL)
    return matches[0] if matches else None

def remove_python_blocks(text: str):
    return re.sub(r"```python\s.*?```", "", text, flags=re.DOTALL).strip()
