#!/usr/bin/env python3
"""
Categorize a ZIA Web Insights export.

1. Reads one or more Web Insights CSV exports (auto-detects the header row and URL column).
2. Normalizes and de-duplicates the URLs, counting how many times each appears.
3. Looks up each unique URL with OneAPI /zia/api/v1/urlLookup (100 per call, rate-limited).
4. Writes an .xlsx (URLs, Category summary, All ZIA categories) plus a CSV of the URL sheet.

Credentials (OneAPI API client from ZIdentity), in order of precedence:
  --env-file PATH   a .env file with ZIA_VANITY_DOMAIN / ZIA_CLIENT_ID / ZIA_CLIENT_SECRET
  environment vars  ZIA_VANITY_DOMAIN / ZIA_CLIENT_ID / ZIA_CLIENT_SECRET
  interactive prompt (secret is not echoed)

Examples:
  python3 categorize_web_insights.py export.csv --dry-run          # dedupe + counts only, no API
  python3 categorize_web_insights.py export.csv --env-file client.env
  python3 categorize_web_insights.py a.csv b.csv --mode url -o results.xlsx
"""
import argparse, csv, getpass, json, os, re, sys, time, urllib.error, urllib.parse, urllib.request
from collections import Counter, defaultdict

TOKEN_URL = "https://{vanity}.zslogin.net/oauth2/v1/token"
API_BASE = "https://api.zsapi.net/zia/api/v1"
AUDIENCE = "https://api.zscaler.com"
UA = "WebInsights-Categorize/1.0"
URL_COL_CANDIDATES = ["url", "requested url", "request url", "host", "hostname", "server name", "domain", "destination"]

csv.field_size_limit(10**8)


# ---------------------------------------------------------------- input
def find_header(rows):
    """Return (header_index, url_col_index) – skips any report preamble rows."""
    for i, row in enumerate(rows[:50]):
        lowered = [c.strip().lower() for c in row]
        for cand in URL_COL_CANDIDATES:
            if cand in lowered:
                return i, lowered.index(cand)
    return None, None


def read_urls(paths, column=None):
    urls = []
    for p in paths:
        with open(p, newline="", encoding="utf-8-sig", errors="replace") as fh:
            rows = list(csv.reader(fh))
        if column:
            hdr = next((i for i, r in enumerate(rows[:50]) if column.lower() in [c.strip().lower() for c in r]), None)
            if hdr is None:
                sys.exit(f"{p}: column '{column}' not found in the first 50 rows")
            col = [c.strip().lower() for c in rows[hdr]].index(column.lower())
        else:
            hdr, col = find_header(rows)
            if hdr is None:
                sys.exit(f"{p}: couldn't find a URL column; pass --column \"<header name>\". "
                         f"First row was: {rows[0] if rows else '(empty)'}")
        print(f"{p}: header row {hdr + 1}, using column '{rows[hdr][col]}'", file=sys.stderr)
        low = [c.strip().lower() for c in rows[hdr]]
        wcol = low.index("hits") if "hits" in low else None   # pre-aggregated input
        for r in rows[hdr + 1:]:
            if len(r) > col and r[col].strip():
                w = int(r[wcol]) if wcol is not None and len(r) > wcol and r[wcol].strip().isdigit() else 1
                urls.append((r[col].strip(), w))
    return urls


def normalize(u, mode):
    u = u.strip().strip('"').strip()
    if not u or u.lower() in ("none", "n/a", "-"):
        return None
    u = re.sub(r"^[a-z][a-z0-9+.-]*://", "", u, flags=re.I)  # drop scheme
    if mode == "host":
        host = re.split(r"[/?#]", u, 1)[0]
        host = host.rsplit("@", 1)[-1]                      # drop userinfo
        if host.startswith("["):                            # IPv6 literal
            host = host.split("]")[0] + "]"
        else:
            host = host.split(":")[0]                       # drop port
        return host.lower().rstrip(".") or None
    return u[:1024]                                         # API max length


# ---------------------------------------------------------------- creds
def load_env_file(path):
    vals = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                vals[k.strip()] = v.strip().strip('"').strip("'")
    return vals


def token_info(token):
    """Decode (not verify) the JWT payload to show issuer / vanity / expiry."""
    import base64
    try:
        part = token.split(".")[1]; part += "=" * (-len(part) % 4)
        claims = json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return None
    iss = claims.get("iss", "")
    m = re.match(r"https://([^.]+)\.zslogin(beta)?\.net", iss)
    return {"issuer": iss, "vanity": m.group(1) if m else None, "exp": claims.get("exp")}


def read_token(path):
    t = open(path).read().strip()
    t = re.sub(r"^(Bearer\s+)", "", t, flags=re.I)
    if t.startswith("{"):
        t = json.loads(t).get("access_token", t)
    return t


def get_creds(env_file):
    src = load_env_file(env_file) if env_file else {}
    def pick(k, secret=False):
        v = src.get(k) or os.environ.get(k)
        if not v:
            v = (getpass.getpass if secret else input)(f"{k}: ").strip()
        return v
    vanity = pick("ZIA_VANITY_DOMAIN").replace(".zslogin.net", "").replace("https://", "").strip("/")
    return vanity, pick("ZIA_CLIENT_ID"), pick("ZIA_CLIENT_SECRET", secret=True)


# ---------------------------------------------------------------- API
def http(method, url, token=None, body=None, form=None, timeout=60):
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


def get_token(vanity, cid, secret):
    st, _, txt = http("POST", TOKEN_URL.format(vanity=vanity),
                      form={"grant_type": "client_credentials", "client_id": cid,
                            "client_secret": secret, "audience": AUDIENCE})
    if st != 200:
        sys.exit(f"Token request failed (HTTP {st}): {txt[:300]}")
    return json.loads(txt)["access_token"]


def category_catalog(token):
    """id -> friendly name, for every URL category (predefined + custom) in the tenant."""
    st, _, txt = http("GET", f"{API_BASE}/urlCategories/lite", token)
    if st != 200:
        print(f"warning: couldn't fetch category list (HTTP {st}); using raw IDs", file=sys.stderr)
        return {}
    labels = {}
    lf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zia_category_names.json")
    if os.path.exists(lf):  # console display names (the API only returns IDs)
        labels = {k: v["name"] for k, v in json.load(open(lf)).items()}
    out = {}
    for c in json.loads(txt):
        cid = c.get("id")
        out[cid] = c.get("configuredName") or labels.get(cid) or cid.replace("_", " ").title()
    return out


def lookup(urls, token, pause):
    results, total = {}, len(urls)
    for i in range(0, total, 100):
        chunk = urls[i:i + 100]
        for attempt in range(6):
            st, hdrs, txt = http("POST", f"{API_BASE}/urlLookup", token, body=chunk)
            if st == 429 or st >= 500:
                wait = int((hdrs or {}).get("Retry-After", 0) or 0) or min(60, 5 * 2 ** attempt)
                print(f"  HTTP {st}, retrying in {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            break
        if st == 200:
            for item in json.loads(txt):
                results[item.get("url", "")] = {
                    "cats": item.get("urlClassifications", []) or [],
                    "sec": item.get("urlClassificationsWithSecurityAlert", []) or [],
                    "app": item.get("application", "") or "",
                    "app_class": item.get("applicationClass", "") or "",
                    "err": "",
                }
        for u in chunk:  # anything the API didn't return (or a failed batch)
            results.setdefault(u, {"cats": [], "sec": [], "err": "" if st == 200 else f"HTTP {st}: {txt[:150]}"})
        print(f"  looked up {min(i + 100, total)}/{total}", file=sys.stderr)
        time.sleep(pause)
    return results


# ---------------------------------------------------------------- output
def write_outputs(out_path, counts, results, names, total_rows):
    from openpyxl import Workbook
    from openpyxl.styles import Font
    nm = lambda c: names.get(c, c.replace("_", " ").title())

    url_rows = []
    by_cat_hosts, by_cat_hits = Counter(), Counter()
    for u, n in counts.most_common():
        r = (results or {}).get(u, {"cats": [], "sec": [], "err": "not looked up (dry run)" if results is None else "no result"})
        cats = [nm(c) for c in r["cats"]] or (["(uncategorized)"] if results is not None and not r["err"] else [])
        sec = [nm(c) for c in r["sec"]]
        url_rows.append([u, n, "; ".join(cats), "; ".join(sec), r["err"], r.get("app", ""), r.get("app_class", "")])
        for c in cats + [f"[Security] {s}" for s in sec]:
            by_cat_hosts[c] += 1
            by_cat_hits[c] += n

    wb = Workbook()
    ws = wb.active; ws.title = "URLs"
    ws.append(["URL", "Times seen", "ZIA categories", "Security alert categories", "Lookup error", "API application", "API application class"])
    for row in url_rows: ws.append(row)

    ws2 = wb.create_sheet("Category summary")
    ws2.append(["Category", "Unique URLs", "Total hits"])
    for c, h in by_cat_hits.most_common(): ws2.append([c, by_cat_hosts[c], h])
    ws2.append([]); ws2.append(["Rows read", total_rows]); ws2.append(["Unique URLs", len(counts)])

    if names:
        ws3 = wb.create_sheet("All ZIA categories")
        ws3.append(["Category ID", "Name", "Hits in this export"])
        for cid, n in sorted(names.items(), key=lambda kv: kv[1].lower()):
            ws3.append([cid, n, by_cat_hits.get(n, 0)])

    for s in wb.worksheets:
        for cell in s[1]: cell.font = Font(bold=True)
        s.freeze_panes = "A2"
        for col in s.columns:
            s.column_dimensions[col[0].column_letter].width = min(70, max(12, max(len(str(c.value or "")) for c in col) + 2))
    wb.save(out_path)

    csv_path = os.path.splitext(out_path)[0] + "_urls.csv"
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "times_seen", "zia_categories", "security_alert_categories", "lookup_error", "api_application", "api_application_class"])
        w.writerows(url_rows)
    return csv_path


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exports", nargs="*", help="Web Insights CSV export(s)")
    ap.add_argument("--column", help="header name of the URL column (auto-detected if omitted)")
    ap.add_argument("--mode", choices=["host", "url"], default="host",
                    help="dedupe by hostname (default) or by full URL incl. path")
    ap.add_argument("--env-file", help=".env with ZIA_VANITY_DOMAIN / ZIA_CLIENT_ID / ZIA_CLIENT_SECRET")
    ap.add_argument("--token-file", help="file holding an existing OneAPI access token (raw, 'Bearer ...', or the token JSON)")
    ap.add_argument("--token-info", action="store_true", help="just print the vanity/issuer/expiry from --token-file and exit")
    ap.add_argument("--dry-run", action="store_true", help="dedupe and count only; no API calls")
    ap.add_argument("--pause", type=float, default=1.1, help="seconds between urlLookup calls (default 1.1)")
    ap.add_argument("-o", "--output", help="output .xlsx (default: <first export>_categorized.xlsx)")
    a = ap.parse_args()

    if a.token_info:
        info = token_info(read_token(a.token_file)) if a.token_file else None
        if not info: sys.exit("couldn't decode the token")
        exp = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(info["exp"])) if info["exp"] else "?"
        print(f"issuer : {info['issuer']}\nvanity : {info['vanity']}\nexpires: {exp}")
        return

    raw = read_urls(a.exports, a.column)
    counts = Counter()
    for u, w in raw:
        n = normalize(u, a.mode)
        if n: counts[n] += w
    print(f"{len(raw)} rows -> {len(counts)} unique {'hosts' if a.mode == 'host' else 'URLs'}", file=sys.stderr)

    results, names = None, {}
    if not a.dry_run:
        if a.token_file:
            token = read_token(a.token_file)
            info = token_info(token) or {}
            if info.get("exp") and info["exp"] < time.time() + 60:
                sys.exit("token in --token-file is expired; get a fresh one or use --env-file")
            print(f"using existing token (vanity: {info.get('vanity')})", file=sys.stderr)
        else:
            token = get_token(*get_creds(a.env_file))
        names = category_catalog(token)
        print(f"{len(names)} URL categories in tenant catalog", file=sys.stderr)
        results = lookup(list(counts), token, a.pause)

    out = a.output or os.path.splitext(a.exports[0])[0] + "_categorized.xlsx"
    csv_path = write_outputs(out, counts, results, names, sum(counts.values()))
    print(f"wrote {out}\nwrote {csv_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
