#!/usr/bin/env python3
"""
zia_category_impact.py - What breaks if we block these URL categories?

Takes ZIA web log exports (allowed traffic), dedupes them to FQDNs with hit
counts, looks up EVERY Zscaler classification for each FQDN via /urlLookup
(logs only show the one category that matched), and writes:

  results.json      -> load into the Category Impact viewer
  domains.csv       -> one row per FQDN, all categories, hits, users
  lookup_cache.json -> lookup results; reruns skip anything already looked up

Why: a URL can carry several categories (e.g. SharePoint = Corporate Marketing
+ File Host). While only Corporate Marketing is allowed it logs as Corporate
Marketing. Add an explicit Block rule for File Host above it and the same URL
now matches File Host and gets blocked. This finds those URLs before the change.

Stdlib only (Python 3.8+). No pip install needed.
For a point-and-click version run:  python zia_impact_gui.py

----------------------------------------------------------------------------
AUTH (pick one, credentials from env vars so they never land in shell history)

  OneAPI / ZIdentity (OAuth2 client credentials):
    ZSCALER_CLIENT_ID, ZSCALER_CLIENT_SECRET, ZSCALER_VANITY_DOMAIN
    optional ZSCALER_CLOUD (blank = production; e.g. "beta")

  Legacy ZIA API key:
    ZIA_USERNAME, ZIA_PASSWORD, ZIA_API_KEY, ZIA_CLOUD (e.g. zscalertwo.net)

EXAMPLES
  # Parse + dedupe only, no API calls (sanity-check the export first)
  python zia_category_impact.py logs/*.csv --no-lookup

  # Full run, OneAPI
  python zia_category_impact.py logs/*.csv --auth oneapi

  # Big tenant: look up the 20k busiest domains now, the rest on a later run
  python zia_category_impact.py logs/*.csv --auth legacy --max-lookups 20000
----------------------------------------------------------------------------
"""

import argparse
import csv
import glob
import gzip
import http.cookiejar
import io
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from types import SimpleNamespace

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

BATCH_SIZE = 100          # /urlLookup max URLs per request
MAX_URL_LEN = 1024        # /urlLookup max characters per URL
MIN_INTERVAL = 1.05       # /urlLookup is limited to 1 request/second
HOURLY_LIMIT = 400        # ...and 400 requests/hour

DEFAULT_OPTS = dict(
    auth="oneapi", no_lookup=False, max_lookups=0, min_hits=1, all_actions=False,
    allow_pattern=r"allow", url_column=None, action_column=None, category_column=None,
    user_column=None, out_dir="zia_impact_output", cache=None, base_url=None,
    token_url=None, tenant_label="",
)


class Stopped(Exception):
    """Raised when the user asks a run to stop."""


class ApiError(Exception):
    """An API call failed in a way retries won't fix."""

    def __init__(self, msg, status=None, detail=""):
        super().__init__(msg)
        self.status = status
        self.detail = detail


class AuthError(ApiError):
    """ZIA refused the credentials or token. Stop the run; nothing else will work."""


ONEAPI_401_HELP = (
    "Zscaler issued a OneAPI token, but ZIA refused it (HTTP {code}). The client ID and secret are fine; "
    "the API client doesn't have ZIA access. To fix: (1) ZIA Admin Portal > Administration > Role Management > "
    "Add API Role, with at least view access to URL categories, and save. (2) ZIdentity > Integration > "
    "API Resources > Sync Now, then check the role appears under Zscaler APIs > ZIA. (3) ZIdentity > Integration > "
    "API Clients > edit this client > Resources: tick the ZIA API role, save. Then click Run lookup again. "
    "If the client already has a ZIA role, check this tenant's ZIA is linked to the same ZIdentity "
    "(vanity domain) you entered."
)
LEGACY_401_HELP = (
    "ZIA refused the session (HTTP {code}). Check the admin username and password, that the API key is "
    "copied in full from Administration > Cloud Service API Security, that the cloud matches your admin "
    "portal address, and that this admin's role allows API access and can view URL categories."
)


def _short(detail):
    try:
        j = json.loads(detail)
        if isinstance(j, dict):
            return j.get("message") or j.get("detail") or j.get("code") or ""
    except ValueError:
        pass
    return re.sub(r"\s+", " ", detail or "").strip()[:200]


def jwt_claims(token):
    """Decode a JWT payload without verifying it, for diagnostics only (never logged in full)."""
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        import base64
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}


class Context:
    """Progress reporting + cooperative stop. The CLI prints; the GUI overrides."""

    def __init__(self):
        self.stop_event = threading.Event()

    def log(self, msg):
        print(msg, flush=True)

    def progress(self, phase, done=None, total=None, note=None):
        pass

    def check(self):
        if self.stop_event.is_set():
            raise Stopped()

    def sleep(self, seconds):
        if self.stop_event.wait(max(0, seconds)):
            raise Stopped()


# ----------------------------------------------------------------------------
# Log parsing
# ----------------------------------------------------------------------------

URL_COLS = ["url", "request url", "requested url", "eurl", "host", "hostname", "fqdn", "domain", "server name"]
ACTION_COLS = ["policy action", "action", "web action", "url filtering action", "status"]
CAT_COLS = ["url category", "urlcat", "urlcategory", "category"]
USER_COLS = ["user", "login", "user name", "username", "ologin"]
TIME_COLS = ["logged time", "time", "datetime", "timestamp", "date"]
USER_COUNT_COLS = ["users", "unique users", "user count", "unique_users"]  # exact match only
POLICY_SKIP = ("action", "reason", "type", "category", "department", "location", "user agent")
POLICY_NONE = {"", "-", "none", "na", "n/a", "null", "not applicable"}


def policy_kind(header):
    """What kind of policy a rule/policy column names: url, cloudapp, ssl, firewall, dlp, block, other."""
    n = norm(header)
    if "url filter" in n or n.startswith("url policy") or n.startswith("url rule"):
        return "url"
    if "cloud app" in n or "cloud application" in n or "web application" in n or "application control" in n:
        return "cloudapp"
    if "ssl" in n or "tls" in n:
        return "ssl"
    if "firewall" in n:
        return "firewall"
    if "dlp" in n:
        return "dlp"
    if "block" in n:
        return "block"
    return "other"


def policy_columns(headers, taken):
    """Columns naming the rule that allowed or blocked a transaction (URL filtering, cloud app, blocked policy...)."""
    out = []
    for i, h in enumerate(headers):
        n = norm(h)
        if i in taken or not re.search(r"\b(rule|policy)\b", n):
            continue
        if any(k in n for k in POLICY_SKIP):
            continue
        out.append(i)
    return out[:8]


HITS_COLS = ["hits", "count", "hit count", "requests", "transactions", "total transactions"]  # exact match only


def headerless_layout(lines):
    """A hand-made CSV with no header: column 1 = URL/domain, optional column 2 = hit count."""
    for i, line in enumerate(lines[:60]):
        try:
            row = next(csv.reader([line]))
        except Exception:
            continue
        if not row or not row[0].strip():
            continue
        host = to_fqdn(row[0])
        if not host or "." not in host:
            return None, None
        headers = ["url"] + [f"column {j + 1}" for j in range(1, len(row))]
        if len(row) > 1 and re.fullmatch(r"\s*[\d,]+(\.\d+)?\s*", row[1]):
            headers[1] = "hits"
        return i - 1, headers          # data starts at line i
    return None, None


def xlsx_to_csv_text(path):
    """Read every sheet of an .xlsx (stdlib only) and return CSV text per sheet."""
    import xml.etree.ElementTree as ET
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    rel_ns = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"
    out = []
    with zipfile.ZipFile(path) as zf:
        shared = []
        if "xl/sharedStrings.xml" in zf.namelist():
            for si in ET.fromstring(zf.read("xl/sharedStrings.xml")).findall("m:si", ns):
                shared.append("".join(t.text or "" for t in si.iter("{%s}t" % ns["m"])))
        rels = {}
        if "xl/_rels/workbook.xml.rels" in zf.namelist():
            for r in ET.fromstring(zf.read("xl/_rels/workbook.xml.rels")):
                rels[r.get("Id")] = r.get("Target").lstrip("/").replace("xl/", "", 1)
        wb = ET.fromstring(zf.read("xl/workbook.xml"))
        for sh in wb.findall("m:sheets/m:sheet", ns):
            target = "xl/" + rels.get(sh.get(rel_ns), "")
            if target not in zf.namelist():
                continue
            buf = io.StringIO()
            w = csv.writer(buf)
            with zf.open(target) as fh:
                for _, el in ET.iterparse(fh):
                    if el.tag != "{%s}row" % ns["m"]:
                        continue
                    cells = {}
                    for c in el.findall("m:c", ns):
                        ref = re.match(r"([A-Z]+)", c.get("r") or "")
                        idx = 0
                        for ch in (ref.group(1) if ref else ""):
                            idx = idx * 26 + ord(ch) - 64
                        idx = (idx or len(cells) + 1) - 1
                        t = c.get("t")
                        if t == "inlineStr":
                            val = "".join(x.text or "" for x in c.iter("{%s}t" % ns["m"]))
                        else:
                            v = c.find("m:v", ns)
                            val = v.text if v is not None and v.text is not None else ""
                            if t == "s" and val.isdigit() and int(val) < len(shared):
                                val = shared[int(val)]
                        cells[idx] = val
                    if cells:
                        w.writerow([cells.get(i, "") for i in range(max(cells) + 1)])
                    el.clear()
            out.append((sh.get("name") or "sheet", buf.getvalue()))
    return out


def open_text_streams(path):
    """Yield (name, text stream) for csv / csv.gz / zip of csvs / xlsx."""
    if path.lower().endswith((".xlsx", ".xlsm")):
        try:
            sheets = xlsx_to_csv_text(path)
        except (zipfile.BadZipFile, KeyError, ValueError) as e:
            raise ApiError(f"Couldn't read {os.path.basename(path)} as an Excel workbook: {e}")
        for sheet, text in sheets:
            yield f"{os.path.basename(path)}[{sheet}]", io.StringIO(text)
    elif path.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name.lower().endswith((".csv", ".txt", ".tsv")):
                    with zf.open(name) as fh:
                        yield f"{os.path.basename(path)}:{name}", io.TextIOWrapper(
                            fh, encoding="utf-8-sig", errors="replace", newline="")
    elif path.lower().endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8-sig", errors="replace", newline="") as fh:
            yield os.path.basename(path), fh
    else:
        with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            yield os.path.basename(path), fh


def norm(s):
    return re.sub(r"[\s_]+", " ", (s or "").strip().lower())


def pick_col(headers, candidates, override=None):
    """Return the index of the best-matching header, or None."""
    nh = [norm(h) for h in headers]
    if override:
        o = norm(override)
        if o in nh:
            return nh.index(o)
        raise ApiError(f"Column '{override}' not found. Headers are: {', '.join(headers)}")
    for c in candidates:            # exact match first
        if c in nh:
            return nh.index(c)
    for c in candidates:            # then 'contains'
        for i, h in enumerate(nh):
            if c in h and "super" not in h and "class" not in h:
                return i
    return None


def find_header(lines, url_override=None):
    """Web Insights exports can start with report-metadata lines. Find the real header row."""
    for i, line in enumerate(lines[:60]):
        try:
            row = next(csv.reader([line]))
        except Exception:
            continue
        if len(row) < 2:
            continue
        nh = [norm(h) for h in row]
        if url_override and norm(url_override) in nh:
            return i, row
        if any(c in nh for c in URL_COLS):
            return i, row
    return None, None


LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9_\-]*[a-z0-9])?$")


def lookup_ok(host):
    """Hostnames /urlLookup accepts: no wildcard or underscore-only labels, nothing over 1,024 chars."""
    if len(host) > MAX_URL_LEN or "*" in host or host.startswith("["):
        return False
    return all(LABEL_RE.match(lbl) for lbl in host.split("."))


HOST_RE = re.compile(r"^[a-z0-9_*]([a-z0-9_\-*]*[a-z0-9_*])?(\.[a-z0-9_]([a-z0-9_\-]*[a-z0-9_])?)*$")


def to_fqdn(raw):
    """Strip scheme, credentials, path, query, port and trailing dot. Returns lowercase host or None."""
    if not raw:
        return None
    s = raw.strip().strip('"').lower()
    if not s or s in ("-", "na", "n/a", "none"):
        return None
    s = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", s)
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if s.startswith("["):                       # IPv6 literal
        return s.split("]", 1)[0] + "]"
    if s.count(":") == 1:
        s = s.split(":", 1)[0]
    s = s.rstrip(".")
    if not s or len(s) > 253:
        return None
    if not HOST_RE.match(s):
        return None
    return s


def _chain_lines(*streams):
    for s in streams:
        for line in s:
            yield line


def parse_logs(paths, opts, ctx):
    stats = defaultdict(lambda: {"hits": 0, "users": set(), "logcats": defaultdict(int),
                                 "pol": defaultdict(lambda: defaultdict(int)),
                                 "first": None, "last": None})
    totals = {"files": 0, "rows": 0, "kept": 0, "skipped_action": 0, "skipped_url": 0,
              "actions": defaultdict(int), "columns": []}
    allow_re = re.compile(opts.allow_pattern, re.I)
    total_bytes = sum(os.path.getsize(p) for p in paths) or 1
    bytes_before = 0

    for path in paths:
        for name, fh in open_text_streams(path):
            text_lines = []
            for _ in range(60):
                ln = fh.readline()
                if not ln:
                    break
                text_lines.append(ln)
            hi, headers = find_header(text_lines, opts.url_column)
            if headers is None:
                hi, headers = headerless_layout(text_lines)
                if headers is None:
                    ctx.log(f"  ! {name}: no URL/host column found in the first 60 lines, skipped")
                    continue
                ctx.log(f"  - {name}: no header row, reading column 1 as URLs"
                        + (" and column 2 as hit counts" if "hits" in headers else ""))
            totals["files"] += 1
            ui = pick_col(headers, URL_COLS, opts.url_column)
            ai = pick_col(headers, ACTION_COLS, opts.action_column)
            ci = pick_col(headers, CAT_COLS, opts.category_column)
            si = pick_col(headers, USER_COLS, opts.user_column)
            ti = pick_col(headers, TIME_COLS, None)
            ni = next((headers.index(h) for h in headers if norm(h) in HITS_COLS), None)
            pcols = policy_columns(headers, {x for x in (ui, ai, ci, si, ti, ni) if x is not None})
            uci = next((headers.index(h) for h in headers if norm(h) in [norm(x) for x in USER_COUNT_COLS]), None)
            if si is not None and si == uci and not opts.user_column:
                si = None
            col = lambda i: headers[i] if i is not None else None
            totals["columns"].append({"file": name, "url": col(ui), "action": col(ai),
                                      "category": col(ci), "user": col(si), "time": col(ti),
                                      "hits": col(ni), "policy": [headers[i] for i in pcols],
                                      "headers": headers})
            ctx.log(f"  - {name}: url='{col(ui)}' action='{col(ai) or '-'}' "
                    f"category='{col(ci) or '-'}' user='{col(si) or '-'}'"
                    + (f" hits='{col(ni)}'" if ni is not None else "")
                    + (f" policy={[headers[i] for i in pcols]}" if pcols else ""))
            if ai is None and not opts.all_actions:
                ctx.log("    (no action column: treating every row as allowed)")

            remainder = "".join(text_lines[hi + 1:])
            stream = _chain_lines(io.StringIO(remainder), fh)
            raw = getattr(fh, "buffer", None)
            for row in csv.reader(stream):
                if not row or len(row) <= ui:
                    continue
                totals["rows"] += 1
                if totals["rows"] % 50000 == 0:
                    ctx.check()
                    pos = bytes_before
                    try:
                        if raw is not None and not path.lower().endswith((".gz", ".zip")):
                            pos = bytes_before + raw.tell()
                    except Exception:
                        pass
                    ctx.progress("parsing", min(pos, total_bytes), total_bytes,
                                 f"{totals['rows']:,} rows, {len(stats):,} domains")
                if ai is not None and ai < len(row):
                    act = row[ai].strip()
                    totals["actions"][act or "(blank)"] += 1
                    if not opts.all_actions and not allow_re.search(act):
                        totals["skipped_action"] += 1
                        continue
                host = to_fqdn(row[ui])
                if not host:
                    totals["skipped_url"] += 1
                    continue
                totals["kept"] += 1
                st = stats[host]
                weight = 1
                if ni is not None and ni < len(row):
                    try:
                        weight = max(1, int(float(row[ni].replace(",", "").strip())))
                    except ValueError:
                        pass
                st["hits"] += weight
                if uci is not None and uci < len(row):
                    try:
                        st["ucount"] = max(st.get("ucount", 0), int(float(row[uci].replace(",", "").strip())))
                    except ValueError:
                        pass
                if si is not None and si < len(row) and row[si].strip():
                    if len(st["users"]) < 100000:
                        st["users"].add(row[si].strip().lower())
                for pi in pcols:
                    if pi < len(row) and row[pi].strip().lower() not in POLICY_NONE:
                        st["pol"][headers[pi]][row[pi].strip()] += weight
                if ci is not None and ci < len(row) and row[ci].strip():
                    st["logcats"][row[ci].strip()] += 1
                if ti is not None and ti < len(row) and row[ti].strip():
                    t = row[ti].strip()
                    if st["first"] is None or t < st["first"]:
                        st["first"] = t
                    if st["last"] is None or t > st["last"]:
                        st["last"] = t
        bytes_before += os.path.getsize(path)
        ctx.progress("parsing", bytes_before, total_bytes, f"{totals['rows']:,} rows, {len(stats):,} domains")
    return stats, totals


# ----------------------------------------------------------------------------
# Zscaler API clients
# ----------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, ctx, per_hour=HOURLY_LIMIT, min_interval=MIN_INTERVAL):
        self.ctx = ctx
        self.per_hour = per_hour
        self.min_interval = min_interval
        self.calls = []
        self.last = 0.0

    def wait(self):
        now = time.time()
        self.calls = [t for t in self.calls if now - t < 3600]
        if len(self.calls) >= self.per_hour:
            sleep_for = 3600 - (now - self.calls[0]) + 1
            resume = datetime.fromtimestamp(time.time() + sleep_for).strftime("%H:%M")
            self.ctx.log(f"    hourly limit reached ({self.per_hour}/hr), resuming at {resume}")
            self.ctx.progress("waiting", note=f"Zscaler hourly limit reached. Resuming at {resume}.")
            self.ctx.sleep(sleep_for)
        gap = time.time() - self.last
        if gap < self.min_interval:
            self.ctx.sleep(self.min_interval - gap)
        self.last = time.time()
        self.calls.append(self.last)


class ZiaClient:
    def __init__(self, ctx, base_url, headers=None, opener=None):
        self.ctx = ctx
        self.base = base_url.rstrip("/")
        self.headers = {"Content-Type": "application/json", "Accept": "application/json",
                        "User-Agent": "zia-category-impact/1.1"}
        self.headers.update(headers or {})
        self.opener = opener or urllib.request.build_opener()
        self.limiter = RateLimiter(ctx)
        self.auth_kind = "legacy"

    def call(self, method, path, body=None, limited=False, retries=6):
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        for attempt in range(retries):
            self.ctx.check()
            if limited:
                self.limiter.wait()
            req = urllib.request.Request(url, data=data, method=method, headers=self.headers)
            try:
                with self.opener.open(req, timeout=120) as r:
                    raw = r.read()
                    return json.loads(raw) if raw else None
            except urllib.error.HTTPError as e:
                detail = e.read().decode(errors="replace")[:500]
                if e.code == 429:
                    wait = _retry_after(e, detail)
                    self.ctx.log(f"    429 rate limited, waiting {wait}s")
                    self.ctx.sleep(wait)
                    continue
                if e.code in (500, 502, 503, 504) and attempt < retries - 1:
                    self.ctx.sleep(2 ** attempt)
                    continue
                if e.code in (401, 403):
                    helptext = ONEAPI_401_HELP if self.auth_kind == "oneapi" else LEGACY_401_HELP
                    extra = _short(detail)
                    raise AuthError(helptext.format(code=e.code) + (f" (Zscaler said: {extra}; {method} {path})" if extra else ""))
                raise ApiError(f"HTTP {e.code} on {method} {path}: {_short(detail)}", e.code, detail)
            except urllib.error.URLError as e:
                if attempt < retries - 1:
                    self.ctx.sleep(2 ** attempt)
                    continue
                raise ApiError(f"Can't reach {self.base}: {e.reason}")
        raise ApiError(f"Gave up on {method} {path} after {retries} attempts")

    def close(self):
        pass


def _retry_after(err, body):
    h = err.headers.get("Retry-After") if err.headers else None
    m = re.search(r"(\d+)", h or "") or re.search(r'"Retry-After"\s*:\s*"?(\d+)', body or "")
    return max(int(m.group(1)) if m else 2, 1) + 1


def env_creds():
    e = os.environ.get
    return {
        "client_id": e("ZSCALER_CLIENT_ID"), "client_secret": e("ZSCALER_CLIENT_SECRET"),
        "vanity": e("ZSCALER_VANITY_DOMAIN"), "oneapi_cloud": e("ZSCALER_CLOUD", ""),
        "username": e("ZIA_USERNAME"), "password": e("ZIA_PASSWORD"),
        "api_key": e("ZIA_API_KEY"), "legacy_cloud": e("ZIA_CLOUD"),
    }


def oneapi_client(opts, creds, ctx):
    cid, secret, vanity = creds.get("client_id"), creds.get("client_secret"), creds.get("vanity")
    cloud = (creds.get("oneapi_cloud") or "").strip()
    if not (cid and secret and vanity):
        raise ApiError("OneAPI needs a client ID, client secret and vanity domain")
    prod = not cloud or cloud == "production"
    token_host = f"{vanity}.zslogin.net" if prod else f"{vanity}.zslogin{cloud}.net"
    api_host = "api.zsapi.net" if prod else f"api.{cloud}.zsapi.net"
    token_url = opts.token_url or f"https://{token_host}/oauth2/v1/token"
    base = opts.base_url or f"https://{api_host}/zia/api/v1"
    form = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": cid,
                                   "client_secret": secret, "audience": "https://api.zscaler.com"}).encode()
    req = urllib.request.Request(token_url, data=form, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            tok = json.loads(r.read())["access_token"]
    except urllib.error.HTTPError as e:
        raise ApiError(f"Token request failed (HTTP {e.code}): {e.read().decode(errors='replace')[:300]}")
    except urllib.error.URLError as e:
        raise ApiError(f"Can't reach {token_url}: {e.reason}")
    ctx.log(f"Signed in to ZIdentity; token issued ({base})")
    claims = jwt_claims(tok)
    if claims:
        aud = claims.get("aud")
        scope = claims.get("scope") or claims.get("scp") or ""
        if isinstance(scope, list):
            scope = " ".join(scope)
        ctx.log(f"  token audience: {aud if aud else '-'}")
        if scope:
            zia = [x for x in str(scope).split() if "zia" in x.lower() or "zscaler" in x.lower()]
            ctx.log(f"  token scopes: {len(str(scope).split())} granted" + (f" (ZIA-related: {', '.join(zia[:5])})" if zia else " (none mention ZIA)"))
    client = ZiaClient(ctx, base, {"Authorization": f"Bearer {tok}"})
    client.auth_kind = "oneapi"
    return client


def obfuscate_api_key(api_key, ts_ms):
    """ZIA legacy API key obfuscation (as documented by Zscaler)."""
    n = str(ts_ms)[-6:]
    r = str(int(n) >> 1).zfill(6)
    key = "".join(api_key[int(c)] for c in n)
    key += "".join(api_key[int(c) + 2] for c in r)
    return key


def legacy_client(opts, creds, ctx):
    user, pw, key = creds.get("username"), creds.get("password"), creds.get("api_key")
    cloud = (creds.get("legacy_cloud") or "").strip()
    if not (user and pw and key and (cloud or opts.base_url)):
        raise ApiError("Legacy auth needs a username, password, API key and cloud (e.g. zscalertwo.net)")
    if len(key) < 12:
        raise ApiError("That API key looks too short; copy the full key from Cloud Service API Security")
    base = opts.base_url or f"https://zsapi.{cloud}/api/v1"
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    client = ZiaClient(ctx, base, opener=opener)
    ts = int(time.time() * 1000)
    client.call("POST", "/authenticatedSession",
                {"apiKey": obfuscate_api_key(key, ts), "username": user, "password": pw, "timestamp": ts})
    ctx.log(f"Authenticated via legacy API key ({base})")

    def close():
        try:
            client.call("DELETE", "/authenticatedSession", retries=1)
        except Exception:
            pass
    client.close = close
    return client


# ----------------------------------------------------------------------------
# Lookups
# ----------------------------------------------------------------------------

def load_cache(path):
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except ValueError:
            return {}
    return {}


def save_cache(path, cache):
    if not path:
        return
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cache, f)
    os.replace(tmp, path)


def _lookup_batch(client, batch, cache, ctx, skipped):
    """Look up one batch. If Zscaler rejects an entry (HTTP 400), drop it and retry the rest."""
    pending = list(batch)
    while pending:
        try:
            res = client.call("POST", "/urlLookup", pending, limited=True) or []
        except AuthError:
            raise
        except ApiError as e:
            if e.status != 400:
                raise
            text = f"{e} {e.detail}"
            bad = [d for d in pending if f"[{d}]" in text or f"'{d}'" in text or f'"{d}"' in text]
            if not bad:
                m = re.search(r"\[([^\]]+)\]", text)
                bad = [d for d in pending if m and m.group(1).strip().lower() == d]
            if not bad and len(pending) > 1:          # can't tell which one: split and try each half
                mid = len(pending) // 2
                _lookup_batch(client, pending[:mid], cache, ctx, skipped)
                _lookup_batch(client, pending[mid:], cache, ctx, skipped)
                return
            bad = bad or pending
            for d in bad:
                cache[d] = {"c": [], "s": [], "invalid": True}
                skipped.append(d)
                ctx.log(f"    skipped {d}: Zscaler can't look up this hostname format")
            pending = [d for d in pending if d not in bad]
            continue
        for item in res:
            u = (item.get("url") or "").lower().rstrip(".")
            cache[u] = {"c": item.get("urlClassifications") or [],
                        "s": item.get("urlClassificationsWithSecurityAlert") or [],
                        "app": item.get("application") or "",
                        "appc": item.get("applicationClass") or ""}   # extra keys so the Insights portal can reuse the cache
        for d in pending:                        # anything the API didn't echo back
            cache.setdefault(d, {"c": [], "s": [], "missing": True})
        return


def lookup_all(client, domains, cache, cache_path, max_lookups, ctx):
    skipped = []
    for d in domains:
        if d not in cache and not lookup_ok(d):
            cache[d] = {"c": [], "s": [], "invalid": True}
            skipped.append(d)
    if skipped:
        ctx.log(f"  {len(skipped):,} hostname(s) can't be looked up (wildcard or malformed, e.g. {skipped[0]}); "
                "they stay in the results without categories")
    todo = [d for d in domains if d not in cache]
    if max_lookups:
        todo = todo[:max_lookups]
    batches = [todo[i:i + BATCH_SIZE] for i in range(0, len(todo), BATCH_SIZE)]
    if not batches:
        ctx.log("All domains already in the cache; no lookups needed.")
        return 0
    hours = (len(batches) - 1) // HOURLY_LIMIT
    eta_min = hours * 60 + min(len(batches), HOURLY_LIMIT) * MIN_INTERVAL / 60
    ctx.log(f"Looking up {len(todo):,} domains in {len(batches):,} requests "
            f"(about {eta_min:.0f} min at 1 req/s, {HOURLY_LIMIT}/hr). Stopping is safe; reruns resume.")
    done = 0
    ctx.progress("lookup", 0, len(todo))
    try:
        for i, batch in enumerate(batches, 1):
            _lookup_batch(client, batch, cache, ctx, skipped)
            done += len(batch)
            ctx.progress("lookup", done, len(todo))
            if i % 10 == 0 or i == len(batches):
                save_cache(cache_path, cache)
                ctx.log(f"    {done:,}/{len(todo):,} looked up")
    finally:
        save_cache(cache_path, cache)
    return done


RULE_CONDITIONS = {
    "users": "users", "groups": "groups", "departments": "departments", "locations": "locations",
    "locationGroups": "location groups", "timeWindows": "time windows", "deviceGroups": "device groups",
    "devices": "devices", "deviceTrustLevels": "device trust", "userAgentTypes": "user agents",
    "sourceIpGroups": "source IPs", "workloadGroups": "workloads", "userRiskScoreLevels": "user risk",
    "overrideUsers": None, "overrideGroups": None,
}


def fetch_url_rules(client, ctx):
    """URL filtering rules in evaluation order, reduced to what the simulation needs."""
    try:
        raw = client.call("GET", "/urlFilteringRules") or []
    except ApiError as e:   # includes AuthError: the role may read categories but not URL policy
        ctx.log("  ! couldn't read URL filtering rules (" + str(e)[:160] + "). 'Enforced by' will only use "
                "rule columns from the logs. Give the API role view access to URL Filtering policy to fix.")
        return []
    rules = []
    for r in raw:
        if str(r.get("state", "ENABLED")).upper() != "ENABLED":
            continue
        cats = [c for c in (r.get("urlCategories") or []) if c]
        cond = sorted({lbl for k, lbl in RULE_CONDITIONS.items() if lbl and r.get(k)})
        rules.append({"n": r.get("name") or f"Rule {r.get('order')}", "o": r.get("order") or 0,
                      "a": str(r.get("action") or "").upper(), "cats": cats, "cond": cond})
    rules.sort(key=lambda x: x["o"])
    ctx.log(f"  read {len(rules)} enabled URL filtering rule(s) for the 'Enforced by' simulation")
    return rules


def simulate_url_rule(cat_ids, rules):
    """First URL filtering rule, top-down, whose categories match. Conditional rules hit first are reported too."""
    if not rules or not cat_ids:
        return None
    pre = []
    for r in rules:
        if r["cats"] and "ANY" not in r["cats"] and not (set(r["cats"]) & cat_ids):
            continue
        if r["cond"]:
            if len(pre) < 3:
                pre.append({"n": r["n"], "a": r["a"], "o": r["o"], "w": r["cond"]})
            continue
        return {"n": r["n"], "a": r["a"], "o": r["o"], **({"pre": pre} if pre else {})}
    return {"n": None, **({"pre": pre} if pre else {})}


def fetch_category_catalog(client, ctx):
    """Display names for predefined categories + URL lists for custom categories."""
    names, custom, supers = {}, [], {}
    try:
        for c in client.call("GET", "/urlCategories/lite") or []:
            names[c.get("id")] = c.get("configuredName") or c.get("id")
            if c.get("superCategory"):
                supers[c.get("id")] = c.get("superCategory")
    except AuthError:
        raise
    except ApiError as e:
        ctx.log(f"  ! couldn't read category names ({e}); using raw category IDs")
    try:
        for c in client.call("GET", "/urlCategories?customOnly=true") or []:
            entries = [u.strip().lower() for u in (c.get("urls") or []) + (c.get("dbCategorizedUrls") or []) if u]
            custom.append({"id": c.get("id"), "name": c.get("configuredName") or c.get("id"), "entries": entries})
            names[c.get("id")] = c.get("configuredName") or c.get("id")
            if c.get("superCategory"):
                supers[c.get("id")] = c.get("superCategory")
    except AuthError:
        raise
    except ApiError as e:
        ctx.log(f"  ! couldn't read custom categories ({e}); skipping custom-category matching")
    return names, custom, supers


def custom_matches(host, custom):
    """ZIA semantics: 'example.com' matches that host; '.example.com' matches it and all subdomains."""
    hits = []
    for c in custom:
        for e in c["entries"]:
            e_host = to_fqdn(e.lstrip(".")) or ""
            if not e_host:
                continue
            if e.startswith("."):
                if host == e_host or host.endswith("." + e_host):
                    hits.append(c["id"]); break
            elif host == e_host:
                hits.append(c["id"]); break
    return hits


def enforcers(o_, kinds):
    """(url rule, source, cloud app rule, other policy columns) for one domain."""
    by = {}
    for col, vals in o_.get("p", {}).items():
        by.setdefault(kinds.get(col, "other"), []).extend(v for v, _ in vals)
    url, src = "; ".join(dict.fromkeys(by.get("url", []))), "log" if by.get("url") else ""
    if not url and o_.get("ur"):
        ur = o_["ur"]
        url = (f"{ur['n']} (#{ur['o']}, {ur['a'].lower()})" if ur.get("n") else "no matching rule (default)")
        if ur.get("pre"):
            url += "; earlier conditional: " + ", ".join(f"{p['n']} ({'/'.join(p['w'])})" for p in ur["pre"])
        src = "simulated"
    cloud = "; ".join(dict.fromkeys(by.get("cloudapp", [])))
    other = "; ".join(f"{c}: {v}" for c, vals in o_.get("p", {}).items()
                      if kinds.get(c, "other") not in ("url", "cloudapp") for v, _ in vals)
    return url, src, cloud, other


def pretty(cid):
    return cid.replace("_", " ").title() if cid else cid


# ----------------------------------------------------------------------------
# Engine
# ----------------------------------------------------------------------------

def run(paths, opts=None, creds=None, ctx=None):
    """Parse logs, look up categories, write outputs. Returns a summary dict."""
    o = dict(DEFAULT_OPTS)
    src = vars(opts) if isinstance(opts, SimpleNamespace) else (opts or {})
    o.update({k: v for k, v in src.items() if v is not None})
    opts = SimpleNamespace(**o)
    ctx = ctx or Context()
    creds = creds or env_creds()

    if not paths:
        raise ApiError("No log files given")
    os.makedirs(opts.out_dir, exist_ok=True)
    cache_path = opts.cache or os.path.join(opts.out_dir, "lookup_cache.json")

    ctx.log(f"Parsing {len(paths)} file(s) ...")
    ctx.progress("parsing", 0, 1)
    stats, totals = parse_logs(paths, opts, ctx)
    ctx.log(f"Rows {totals['rows']:,} | kept {totals['kept']:,} | not allowed {totals['skipped_action']:,} "
            f"| unparseable URL {totals['skipped_url']:,} | unique FQDNs {len(stats):,}")
    top_actions = sorted(totals["actions"].items(), key=lambda x: -x[1])[:8]
    if top_actions:
        ctx.log("Action values seen: " + ", ".join(f"{k} ({v:,})" for k, v in top_actions))
    if not stats:
        raise ApiError("No rows kept. Check the allowed-action pattern and URL column against the values in the log.")

    domains = sorted((d for d, s in stats.items() if s["hits"] >= opts.min_hits), key=lambda d: -stats[d]["hits"])
    cache = load_cache(cache_path)
    url_rules = []
    names, custom, supers = {}, [], {}
    looked_now = 0

    if not opts.no_lookup:
        ctx.progress("auth", note="Signing in to Zscaler")
        client = oneapi_client(opts, creds, ctx) if opts.auth == "oneapi" else legacy_client(opts, creds, ctx)
        try:
            ctx.progress("catalog", note="Reading category names and custom categories")
            names, custom, supers = fetch_category_catalog(client, ctx)
            url_rules = fetch_url_rules(client, ctx)
            looked_now = lookup_all(client, domains, cache, cache_path, opts.max_lookups, ctx)
        finally:
            client.close()

    ctx.progress("writing", note="Writing results")
    out_domains, cat_ids, looked_up = [], set(), 0
    for d in domains:
        s = stats[d]
        hit = cache.get(d)
        cats = list(dict.fromkeys(hit["c"])) if hit else []
        sec = list(dict.fromkeys(hit["s"])) if hit else []
        cust = custom_matches(d, custom) if custom else []
        if hit:
            looked_up += 1
        cat_ids.update(cats, sec, cust)
        out_domains.append({
            "d": d, "h": s["hits"], "u": max(len(s["users"]), s.get("ucount", 0)),
            "c": cats, "s": sec, "x": cust,
            "l": sorted(s["logcats"], key=lambda k: -s["logcats"][k]),
            "p": {col: sorted(v.items(), key=lambda kv: -kv[1])[:5] for col, v in s["pol"].items()},
            "f": s["first"], "t": s["last"], "k": bool(hit),
            **({"z": True} if hit and hit.get("invalid") else {}),
            **({"ur": simulate_url_rule(set(cats) | set(sec) | set(cust), url_rules)} if url_rules and hit else {}),
        })
    for cid in cat_ids:
        names.setdefault(cid, pretty(cid))

    result = {
        "meta": {
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tenant": opts.tenant_label,
            "files": [os.path.basename(p) for p in paths],
            "rows": totals["rows"], "kept": totals["kept"],
            "unique": len(stats), "included": len(out_domains), "looked_up": looked_up,
            "min_hits": opts.min_hits, "allowed_only": not opts.all_actions,
        },
        "names": names,
        "supers": supers,
        "pkinds": {h: policy_kind(h) for c in totals["columns"] for h in c.get("policy", [])},
        "urlRules": [{"n": r["n"], "o": r["o"], "a": r["a"], "cond": r["cond"]} for r in url_rules],
        "custom": [{"id": c["id"], "name": c["name"], "n": len(c["entries"])} for c in custom],
        "domains": out_domains,
    }
    jpath = os.path.join(opts.out_dir, "results.json")
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(result, f, separators=(",", ":"))

    cpath = os.path.join(opts.out_dir, "domains.csv")
    with open(cpath, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["fqdn", "hits", "unique_users", "zscaler_categories", "security_alert_categories",
                    "custom_categories", "logged_categories", "url_filtering_rule", "url_rule_source",
                    "cloud_app_rule", "other_policy_columns", "first_seen", "last_seen", "looked_up"])
        kinds = {h: policy_kind(h) for c in totals["columns"] for h in c.get("policy", [])}
        for o_ in out_domains:
            w.writerow([o_["d"], o_["h"], o_["u"], "; ".join(names.get(c, c) for c in o_["c"]),
                        "; ".join(names.get(c, c) for c in o_["s"]), "; ".join(names.get(c, c) for c in o_["x"]),
                        "; ".join(o_["l"]), *enforcers(o_, kinds), o_["f"] or "", o_["t"] or "", "yes" if o_["k"] else "no"])

    pending = len(out_domains) - looked_up
    ctx.log(f"Wrote {jpath}\nWrote {cpath}")
    invalid = sum(1 for o_ in out_domains if o_.get("z"))
    if invalid:
        ctx.log(f"{invalid:,} hostname(s) couldn't be looked up (format Zscaler doesn't accept); listed without categories")
    ctx.log(f"{looked_up - invalid:,} of {len(out_domains):,} domains have categories"
            + (f"; {pending:,} still pending (run again to continue)" if pending and not opts.no_lookup else ""))
    return {
        "rows": totals["rows"], "kept": totals["kept"], "unique": len(stats),
        "included": len(out_domains), "looked_up": looked_up, "looked_now": looked_now,
        "pending": pending, "actions": dict(top_actions), "columns": totals["columns"],
        "results_path": jpath, "csv_path": cpath,
    }


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="+", help="ZIA log exports: .csv, .csv.gz or .zip (globs ok)")
    ap.add_argument("--auth", choices=["oneapi", "legacy"], default="oneapi")
    ap.add_argument("--no-lookup", action="store_true", help="parse + dedupe only, skip API calls")
    ap.add_argument("--max-lookups", type=int, default=0, help="cap new lookups this run (busiest domains first)")
    ap.add_argument("--min-hits", type=int, default=1, help="ignore domains seen fewer than N times")
    ap.add_argument("--all-actions", action="store_true", help="keep blocked rows too (default: allowed only)")
    ap.add_argument("--allow-pattern", default=r"allow", help="regex for 'allowed' action values (default: allow)")
    ap.add_argument("--url-column"); ap.add_argument("--action-column")
    ap.add_argument("--category-column"); ap.add_argument("--user-column")
    ap.add_argument("--out-dir", default="zia_impact_output")
    ap.add_argument("--cache", default=None, help="lookup cache file (default: <out-dir>/lookup_cache.json)")
    ap.add_argument("--base-url", help="override API base, e.g. https://zsapi.zscalertwo.net/api/v1")
    ap.add_argument("--token-url", help="override OneAPI token URL")
    ap.add_argument("--tenant-label", default="", help="label shown in the viewer, e.g. your company name")
    args = ap.parse_args()

    paths = []
    for p in args.logs:
        paths.extend(sorted(glob.glob(p)) or [p])
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        raise SystemExit(f"Not found: {', '.join(missing)}")
    opts = {k: v for k, v in vars(args).items() if k != "logs"}
    try:
        run(paths, opts)
    except Stopped:
        raise SystemExit("Stopped.")
    except KeyboardInterrupt:
        raise SystemExit("\nInterrupted. Progress is saved; run the same command to resume.")
    except ApiError as e:
        raise SystemExit(f"Error: {e}")


if __name__ == "__main__":
    main()
