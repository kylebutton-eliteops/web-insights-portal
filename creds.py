"""One place for Zscaler API credentials, used by every tool in the toolkit.

Order of precedence: values typed on the dashboard (held in this process's memory only), then the .env file next to
app.py, then environment variables. Accepts ZIA_* or ZSCALER_* names. Nothing here is ever written to disk.
"""
import os
import re
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
_mem = {}
_lock = threading.Lock()

FIELDS = {   # field -> accepted names (first is canonical)
    "vanity": ["ZIA_VANITY_DOMAIN", "ZSCALER_VANITY_DOMAIN", "VANITY", "VANITY_DOMAIN"],
    "client_id": ["ZIA_CLIENT_ID", "ZSCALER_CLIENT_ID", "CLIENT_ID"],
    "client_secret": ["ZIA_CLIENT_SECRET", "ZSCALER_CLIENT_SECRET", "CLIENT_SECRET"],
    "oneapi_cloud": ["ZSCALER_CLOUD", "ZIA_ONEAPI_CLOUD"],
    "username": ["ZIA_USERNAME"],
    "password": ["ZIA_PASSWORD"],
    "api_key": ["ZIA_API_KEY"],
    "legacy_cloud": ["ZIA_CLOUD"],
}


def _read_env_file(path):
    vals = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    vals[k.strip().upper()] = v.strip().strip('"').strip("'")
    return vals


def _clean_vanity(v):
    return re.sub(r"^https?://", "", (v or "").strip()).replace(".zslogin.net", "").strip("/")


def get():
    """All credential fields, resolved. Missing ones are empty strings."""
    file_vals = _read_env_file(os.path.join(HERE, ".env"))
    out = {}
    with _lock:
        mem = dict(_mem)
    for field, names in FIELDS.items():
        v = mem.get(field) or next((file_vals[n] for n in names if file_vals.get(n)), None) \
            or next((os.environ[n] for n in names if os.environ.get(n)), None)
        out[field] = (v or "").strip()
    out["vanity"] = _clean_vanity(out["vanity"])
    return out


def status():
    c = get()
    one = bool(c["vanity"] and c["client_id"] and c["client_secret"])
    leg = bool(c["username"] and c["password"] and c["api_key"] and c["legacy_cloud"])
    with _lock:
        typed = bool(_mem)
    file_vals = _read_env_file(os.path.join(HERE, ".env"))
    source = "typed on the dashboard (this session only)" if typed else (
        ".env file" if any(file_vals.get(n) for names in FIELDS.values() for n in names) else
        ("environment variables" if (one or leg) else ""))
    return {"oneapi": one, "legacy": leg, "ready": one or leg, "vanity": c["vanity"], "source": source,
            "client_id_tail": c["client_id"][-4:] if c["client_id"] else ""}


def set_memory(values):
    with _lock:
        for k, v in values.items():
            if k in FIELDS and (v or "").strip():
                _mem[k] = v.strip()


def clear_memory():
    with _lock:
        _mem.clear()


def as_impact():
    """The shape Category Impact's engine expects (it was written around environment variables)."""
    c = get()
    return {k: (c[k] or None) for k in ("client_id", "client_secret", "vanity", "username", "password", "api_key", "legacy_cloud")} \
        | {"oneapi_cloud": c["oneapi_cloud"]}
