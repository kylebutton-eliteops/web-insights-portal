"""Minimal ZIA OneAPI client: OAuth2 client-credentials token + urlLookup + category catalog."""
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

TOKEN_URL = "https://{vanity}.zslogin.net/oauth2/v1/token"
API_BASE = "https://api.zsapi.net/zia/api/v1"
AUDIENCE = "https://api.zscaler.com"
UA = "WebInsights-Portal/1.0"
HERE = os.path.dirname(os.path.abspath(__file__))

KEY_ALIASES = {
    "ZIA_VANITY_DOMAIN": ["ZIA_VANITY_DOMAIN", "VANITY", "VANITY_DOMAIN"],
    "ZIA_CLIENT_ID": ["ZIA_CLIENT_ID", "CLIENT_ID"],
    "ZIA_CLIENT_SECRET": ["ZIA_CLIENT_SECRET", "CLIENT_SECRET"],
}


def load_env(path):
    vals = {}
    if path and os.path.exists(path):
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    vals[k.strip().upper()] = v.strip().strip('"').strip("'")
    return vals


def get_creds(env_path=None, overrides=None):
    """Return (vanity, client_id, secret) from form overrides, .env file, then environment."""
    src = load_env(env_path or os.path.join(HERE, ".env"))
    out = {}
    for key, aliases in KEY_ALIASES.items():
        v = (overrides or {}).get(key) or next((src[a] for a in aliases if src.get(a)), None) or os.environ.get(key)
        out[key] = (v or "").strip()
    vanity = re.sub(r"^https?://", "", out["ZIA_VANITY_DOMAIN"]).replace(".zslogin.net", "").strip("/")
    return vanity, out["ZIA_CLIENT_ID"], out["ZIA_CLIENT_SECRET"]


def creds_configured(env_path=None):
    return all(get_creds(env_path))


def _http(method, url, token=None, body=None, form=None, timeout=60):
    headers = {"User-Agent": UA}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.headers, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode(errors="replace")
    except urllib.error.URLError as e:
        raise ConnectionError(f"Can't reach {url}: {e.reason}") from e


def get_token(vanity, client_id, secret):
    st, _, txt = _http("POST", TOKEN_URL.format(vanity=vanity),
                       form={"grant_type": "client_credentials", "client_id": client_id,
                             "client_secret": secret, "audience": AUDIENCE})
    if st != 200:
        raise ConnectionError(f"OneAPI sign-in failed (HTTP {st}): {txt[:200]}")
    return json.loads(txt)["access_token"]


def category_catalog(token):
    """id -> {'name', 'super'} for every URL category in the tenant (names from zia_category_names.json)."""
    labels = {}
    lf = os.path.join(HERE, "zia_category_names.json")
    if os.path.exists(lf):
        labels = json.load(open(lf))
    st, _, txt = _http("GET", f"{API_BASE}/urlCategories?customOnly=false", token)
    out = dict(labels)
    if st == 200:
        for c in json.loads(txt):
            cid = c["id"]
            name = c.get("configuredName") or labels.get(cid, {}).get("name") or cid.replace("_", " ").title()
            sup = labels.get(cid, {}).get("super") or (c.get("superCategory") or "").replace("_", " ").title()
            out[cid] = {"name": name, "super": sup}
    return out


def url_lookup(hosts, token, progress=None, pause=1.1):
    """Look up hosts 100 at a time. Returns {host: {'cats': [...], 'sec': [...], 'app': str, 'app_class': str, 'err': str}}."""
    results, total = {}, len(hosts)
    for i in range(0, total, 100):
        chunk = hosts[i:i + 100]
        st, txt = None, ""
        for attempt in range(6):
            st, hdrs, txt = _http("POST", f"{API_BASE}/urlLookup", token, body=chunk)
            if st == 429 or st >= 500:
                wait = int((hdrs or {}).get("Retry-After", 0) or 0) or min(60, 5 * 2 ** attempt)
                time.sleep(wait)
                continue
            break
        if st == 200:
            for item in json.loads(txt):
                results[item.get("url", "")] = {
                    "cats": item.get("urlClassifications") or [],
                    "sec": item.get("urlClassificationsWithSecurityAlert") or [],
                    "app": item.get("application") or "",
                    "app_class": item.get("applicationClass") or "",
                    "err": "",
                }
        for h in chunk:
            results.setdefault(h, {"cats": [], "sec": [], "app": "", "app_class": "",
                                   "err": "" if st == 200 else f"HTTP {st}: {txt[:120]}"})
        if progress:
            progress(min(i + 100, total), total)
        time.sleep(pause)
    return results
