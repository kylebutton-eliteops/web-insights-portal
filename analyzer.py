"""Turn a ZIA Web Insights CSV export into a per-host summary (and optional OneAPI category lookup)."""
import csv
import io
import re
import zipfile
from collections import Counter

import pandas as pd

import engine

csv.field_size_limit(10**8)

# Columns we use when the export has them (any can be missing).
WANTED = ["Event Time", "User", "URL", "Policy Action", "Cloud Application Class", "Cloud Application",
          "URL Class", "URL Super Category", "URL Category", "Department", "Location", "Forwarding Rule",
          "Certificate Chain Validity", "ALPN Protocol", "Threat Category"]
RULE_COL = re.compile(r"rule", re.I)
SKIP_RULE_COLS = {"Forwarding Rule"}

SSL_RULES = [
    ("Expected - Microsoft 365 / Teams endpoint",
     r"(teams\.(microsoft|cloud\.microsoft)|trouter|skype|officeapps\.live\.com|office365?\.com|outlook\.office|sharepoint\.com"
     r"|msedge\.net|\.svc\.ms$|events\.data\.micro|pipe\.aria|office\.net|cdn\.office|onecdn|protection\.outlook|substrate"
     r"|delve|microsoftonline|msocdn|^52\.(11[2-5]|122)\.)"),
    ("Expected - OS / software update",
     r"(windowsupdate|delivery\.mp\.microsoft|update\.microsoft|swcdn|swdist|swscan|mesu\.apple|gdmf|updates\.cdn-apple"
     r"|gvt1\.com|dl\.google\.com|officecdn|c2r\.ts\.cdn)"),
    ("Expected - certificate revocation (OCSP/CRL)", r"(ocsp|crl|lencr\.org|pki\.goog|digicert|entrust|godaddy|cacert)"),
    ("Expected - Apple service (cert pinning)", r"(apple\.com|cdn-apple|mzstatic|icloud|itunes|safebrowsing\.apple|apple-cloudkit)"),
    ("Expected - Google / Android device service (cert pinning)",
     r"(googleapis\.com|gstatic\.com|google\.fastly|googleusercontent|app-measurement|clients[0-9]\.google|android)"),
    ("Expected - connectivity / captive-portal check", r"(captive|connectivitycheck|msftconnecttest|msftncsi)"),
    ("Expected - remote access tool (cert pinning)", r"(teamviewer|anydesk|bomgar|beyondtrust)"),
    ("Expected - Zscaler / Microsoft device management",
     r"(zscaler|zsapi|zscloud|manage\.microsoft|dm\.microsoft|wns\.windows)"),
    ("Review - financial site (confirm privacy bypass is intentional)",
     r"(fidelity|capitalone|schwab|paypal|stripe|affirm|chase|mastercard|financialengines|finviz|stocktwits|bank|invest)"),
    ("Review - health site (confirm privacy bypass is intentional)", r"(health|webmd|mychart|epic)"),
]


# ------------------------------------------------------------------ helpers
def find_header(path):
    """Web Insights exports start with a few report lines; find the real header row."""
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        for i, row in enumerate(csv.reader(fh)):
            low = [c.strip().lower() for c in row]
            if "url" in low or "hostname" in low or "host" in low:
                return i, [c.strip() for c in row]
            if i > 50:
                break
    raise ValueError("Couldn't find a header row with a URL column in the first 50 lines. "
                     "Is this a Web Insights CSV export?")


def to_host(u):
    u = re.sub(r"^[a-z][a-z0-9+.-]*://", "", str(u).strip(), flags=re.I)
    h = re.split(r"[/?#]", u, maxsplit=1)[0].rsplit("@", 1)[-1]
    h = h.split("]")[0] + "]" if h.startswith("[") else h.split(":")[0]
    return h.lower().rstrip(".")


def reg_domain(h):
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", h):
        return h
    p = h.split(".")
    if len(p) > 2 and p[-2] in ("co", "com", "org", "net", "gov", "ac") and len(p[-1]) == 2:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def top_per_host(df, col, fill="None"):
    """Most common value of `col` per host."""
    s = df.groupby(["Host", df[col].fillna(fill)]).size().rename("n").reset_index()
    s = s.sort_values(["Host", "n"], ascending=[True, False]).drop_duplicates("Host")
    return s.set_index("Host")[col]


def mix_per_host(df, col, fill="None", pct=True, limit=6):
    """'A (90%); B (10%)' per host (just 'A' when there is only one value)."""
    s = df.groupby(["Host", df[col].fillna(fill)]).size().rename("n").reset_index()
    s = s.sort_values(["Host", "n"], ascending=[True, False])
    tot = s.groupby("Host").n.transform("sum")
    s["lab"] = s[col] + (" (" + (s.n / tot * 100).round().astype(int).astype(str) + "%)" if pct
                         else " (" + s.n.map("{:,}".format) + ")")
    one = s.groupby("Host")[col].transform("size") == 1
    s.loc[one, "lab"] = s.loc[one, col]
    return s.groupby("Host").lab.agg(lambda x: "; ".join(list(x)[:limit]) + ("; ..." if len(x) > limit else ""))


def ssl_review(host, pct, api_cats=""):
    if pct >= 1:
        return "Inspected", ""
    status = "Not inspected" if pct <= 0 else f"Partly inspected ({pct:.0%})"
    for label, rx in SSL_RULES:
        if re.search(rx, host):
            return label, status
    if "Advertising" in api_cats:
        return "Review - advertising / tracking not inspected", status
    if pct > 0:
        return "Review - inspected only some of the time (rule matches some paths/users?)", status
    return "Review - not inspected, no obvious reason", status


def pct_label(p):
    return "<1%" if p < 0.01 else (">99%" if 0.99 < p < 1 else f"{p:.0%}")


# ------------------------------------------------------------------ main
def analyze(path, use_api=False, progress=lambda pct, msg: None):
    progress(2, "Reading the export header")
    hdr_row, header = find_header(path)
    cols = [c for c in header if c in WANTED or (RULE_COL.search(c) and c not in SKIP_RULE_COLS)]
    url_col = "URL" if "URL" in header else next(c for c in header if c.lower() in ("url", "hostname", "host"))
    if url_col not in cols:
        cols.append(url_col)
    rule_cols = [c for c in cols if RULE_COL.search(c) and c not in SKIP_RULE_COLS]

    progress(5, "Loading rows (a 1M-row export takes about 20 seconds)")
    df = pd.read_csv(path, skiprows=hdr_row, usecols=cols, dtype=str, encoding="utf-8-sig",
                     on_bad_lines="skip", engine="c")
    df = df[df[url_col].notna()]
    if url_col != "URL":
        df = df.rename(columns={url_col: "URL"})
    total = len(df)
    if total == 0:
        raise ValueError("The export has a header but no rows.")

    progress(25, f"De-duplicating {total:,} rows to hostnames")
    df["Host"] = df["URL"].map(to_host)
    df = df[df.Host != ""]
    g = df.groupby("Host")
    H = pd.DataFrame({"Hits": g.size()})
    H["% of hits"] = (H.Hits / total).round(4)
    H["Unique full URLs"] = g.URL.nunique()
    has = lambda c: c in df.columns

    if has("User"):
        H["Unique users"] = g.User.nunique()
    if has("Department"):
        H["Departments"] = g.Department.nunique()
        H["Top departments (hits)"] = mix_per_host(df, "Department", pct=False, limit=3)

    progress(40, "Summarizing categories, apps and rules")
    custom = set()
    if has("URL Category"):
        H["Logged URL category"] = top_per_host(df, "URL Category")
        H["All logged categories (hits)"] = mix_per_host(df, "URL Category", pct=False)
        if has("URL Super Category"):
            H["Logged super category"] = top_per_host(df, "URL Super Category")
            custom = set(df.loc[df["URL Super Category"] == "User-Defined", "URL Category"].dropna())
    if has("URL Class"):
        H["URL class"] = top_per_host(df, "URL Class")
    if has("Cloud Application"):
        H["Cloud application"] = top_per_host(df, "Cloud Application")
    if has("Cloud Application Class"):
        H["Cloud app class"] = top_per_host(df, "Cloud Application Class")
    if has("Policy Action"):
        H["Policy action"] = mix_per_host(df, "Policy Action", pct=False)
    if has("Forwarding Rule"):
        fr = df["Forwarding Rule"].fillna("None (default)")
        df["_fr"] = fr
        n_fr = df.groupby("Host")._fr.nunique()
        H["Forwarding rule"] = top_per_host(df, "_fr").where(n_fr == 1, "Mixed")
        H["Forwarding rule detail (hits)"] = mix_per_host(df, "_fr", pct=False)
    for rc in rule_cols:   # e.g. URL Filtering Rule Name, SSL Inspection Rule Name if the export has them
        H[rc] = mix_per_host(df, rc, fill="(none)", pct=False)
    if has("Certificate Chain Validity"):
        df["_ssl"] = df["Certificate Chain Validity"].notna()
        H["SSL inspected %"] = df.groupby("Host")._ssl.mean().round(4)
    if has("ALPN Protocol"):
        H["Protocol (main)"] = top_per_host(df, "ALPN Protocol", fill="(none logged)")
        H["Protocol mix"] = mix_per_host(df, "ALPN Protocol", fill="(none logged)")
    if has("Event Time"):
        progress(55, "Working out first and last seen")
        t = pd.to_datetime(df["Event Time"].str.replace(r"\s+[A-Z]{2,4}$", "", regex=True),
                           format="%B %d, %Y %I:%M:%S %p", errors="coerce")
        df["_t"] = t
        tz = df["Event Time"].dropna().str.extract(r"\s([A-Z]{2,4})$")[0].mode()
        tz = tz.iloc[0] if len(tz) else ""
        H[f"First seen ({tz})".replace(" ()", "")] = df.groupby("Host")._t.min().dt.strftime("%Y-%m-%d %H:%M")
        H[f"Last seen ({tz})".replace(" ()", "")] = df.groupby("Host")._t.max().dt.strftime("%Y-%m-%d %H:%M")

    # Custom-category gaps
    if custom:
        progress(60, "Checking custom-category gaps")
        hc = df.groupby(["Host", "URL Category"]).size().rename("n").reset_index()
        hc["custom"] = hc["URL Category"].isin(custom)
        hc["dom"] = hc.Host.map(reg_domain)
        dom_size = hc.groupby("dom").Host.nunique()
        dom_custom = hc[hc.custom].groupby("dom")["URL Category"].agg(lambda s: ", ".join(sorted(set(s))))
        gaps = {}
        for host, d in hc.groupby("Host"):
            cu, other = d[d.custom], d[~d.custom]
            if len(cu) and len(other):
                gaps[host] = (f"Partial - {pct_label(cu.n.sum() / d.n.sum())} of hits in {', '.join(cu['URL Category'])}; "
                              f"rest fell to {', '.join(other['URL Category'])}")
            elif not len(cu):
                dom = d.dom.iloc[0]
                if dom in dom_custom.index and dom_size[dom] <= 25:
                    gaps[host] = f"Sibling - other {dom} hosts are in {dom_custom[dom]}; this host isn't"
        H["Tenant custom category"] = hc[hc.custom].groupby("Host")["URL Category"].agg(lambda s: ", ".join(s))
        H["Custom category gap"] = pd.Series(gaps)

    # Optional OneAPI lookup
    api_note = ""
    if use_api:
        progress(65, "Signing in to OneAPI")
        ectx = engine.Ctx(lambda d, n: progress(65 + int(25 * d / max(n, 1)), f"Looking up categories in Zscaler: {d:,} of {n:,} hosts"))
        client = engine.open_client(ectx)
        try:
            catalog = engine.catalog(client, ectx)
            hosts = list(H.sort_values("Hits", ascending=False).index)
            res, cache_hits = engine.lookup(hosts, client, ectx)
        finally:
            client.close()
        name = lambda c: catalog.get(c, {}).get("name") or c.replace("_", " ").title()
        sup = lambda c: catalog.get(c, {}).get("super", "")
        # learn friendly app names from the logs where we can
        app_map, cls_map = {}, {}
        if has("Cloud Application"):
            for h, r in res.items():
                if r["app"] and h in H.index and H.at[h, "Cloud application"] not in ("None", None):
                    app_map.setdefault(r["app"], Counter())[H.at[h, "Cloud application"]] += 1
                if r["app_class"] and has("Cloud Application Class") and h in H.index:
                    cls_map.setdefault(r["app_class"], Counter())[H.at[h, "Cloud app class"]] += 1
        pretty = lambda x, m: "" if not x else (m[x].most_common(1)[0][0] if x in m else x.replace("_", " ").title())
        H["API categories"] = pd.Series({h: "; ".join(name(c) for c in r["cats"]) or "(uncategorized)" for h, r in res.items()})
        H["# API categories"] = pd.Series({h: len(r["cats"]) for h, r in res.items()})
        H["API super categories"] = pd.Series({h: "; ".join(dict.fromkeys(sup(c) for c in r["cats"] if sup(c))) for h, r in res.items()})
        H["API security alerts"] = pd.Series({h: "; ".join(name(c) for c in r["sec"]) for h, r in res.items()})
        H["API application"] = pd.Series({h: pretty(r["app"], app_map) for h, r in res.items()})
        H["API application class"] = pd.Series({h: pretty(r["app_class"], cls_map) for h, r in res.items()})
        H["API category IDs"] = pd.Series({h: "; ".join(r["cats"]) for h, r in res.items()})
        H["API lookup error"] = pd.Series({h: r["err"] for h, r in res.items()})
        if "Logged URL category" in H:
            H["Logged category in API list?"] = [
                "" if (lc in custom or not lc) else ("Yes" if lc in (ac or "").split("; ") else "No")
                for lc, ac in zip(H["Logged URL category"], H["API categories"])]
        api_note = (f"OneAPI lookup: {sum(1 for r in res.values() if r['err'])} errors; "
                    f"{cache_hits:,} of {len(res):,} hosts came from the shared lookup cache")

    if "SSL inspected %" in H:
        progress(92, "Classifying SSL inspection")
        api_c = H["API categories"] if "API categories" in H else pd.Series("", index=H.index)
        rv = [ssl_review(h, p, api_c.get(h, "") or "") for h, p in H["SSL inspected %"].items()]
        H["SSL status"] = [s for _, s in rv]
        H["SSL bypass review"] = [r for r, _ in rv]

    H = H.sort_values("Hits", ascending=False).reset_index().rename(columns={"index": "Host"})

    # Category summaries
    progress(95, "Building summaries")
    summaries = {}
    if has("URL Category"):
        c = df.groupby(["URL Category", "URL Super Category"] if has("URL Super Category") else ["URL Category"]) \
              .agg(Hits=("Host", "size"), **{"Unique hosts": ("Host", "nunique")}).reset_index()
        c["% of hits"] = (c.Hits / total).round(4)
        summaries["logged_categories"] = c.sort_values("Hits", ascending=False)
    if "API category IDs" in H:
        rows = [(cid, h, n) for h, ids, n in zip(H.Host, H["API category IDs"], H.Hits) for cid in (ids or "").split("; ") if cid]
        a = pd.DataFrame(rows, columns=["id", "Host", "Hits"])
        if len(a):
            a = a.groupby("id").agg(**{"Unique hosts": ("Host", "nunique"), "Hits (host counted in every category)": ("Hits", "sum")}).reset_index()
            a.insert(0, "Category", a.id.map(lambda x: catalog.get(x, {}).get("name") or x))
            a.insert(1, "Super category", a.id.map(lambda x: catalog.get(x, {}).get("super", "")))
            summaries["api_categories"] = a.rename(columns={"id": "Category ID"}).sort_values("Unique hosts", ascending=False)
    if "SSL bypass review" in H:
        s = H.groupby("SSL bypass review").agg(**{"Unique hosts": ("Host", "size"), "Hits": ("Hits", "sum")}).reset_index()
        summaries["ssl_review"] = s.sort_values("Unique hosts", ascending=False)
    if "Forwarding rule detail (hits)" in H:
        f = df.groupby("_fr").agg(Hits=("Host", "size"), **{"Unique hosts": ("Host", "nunique")}).reset_index()
        summaries["forwarding_rules"] = f.rename(columns={"_fr": "Forwarding rule"}).sort_values("Hits", ascending=False)
    for rc in rule_cols:
        r = df.groupby(df[rc].fillna("(none)")).agg(Hits=("Host", "size"), **{"Unique hosts": ("Host", "nunique")}).reset_index()
        summaries["rule_" + re.sub(r"\W+", "_", rc.lower()).strip("_")] = r.sort_values("Hits", ascending=False)

    info = {
        "rows": total, "hosts": len(H), "urls": int(df.URL.nunique()),
        "users": int(df.User.nunique()) if has("User") else None,
        "time_range": (f"{df._t.min():%Y-%m-%d %H:%M} to {df._t.max():%Y-%m-%d %H:%M}" if has("Event Time") and df._t.notna().any() else ""),
        "policy_actions": df["Policy Action"].value_counts().to_dict() if has("Policy Action") else {},
        "rule_columns": rule_cols, "api": use_api, "api_note": api_note,
        "missing_columns": [c for c in ["URL Category", "Certificate Chain Validity", "Forwarding Rule", "ALPN Protocol", "Event Time"] if c not in header],
        "row_cap_warning": total >= 1_000_000,
    }
    progress(99, "Writing files")
    return H, summaries, info


def to_zip(H, summaries, info):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("hosts.csv", H.to_csv(index=False))
        for k, v in summaries.items():
            z.writestr(f"{k}.csv", v.to_csv(index=False))
    return buf.getvalue()


def to_xlsx(path, H, summaries, info):
    with pd.ExcelWriter(path, engine="openpyxl") as w:
        about = pd.DataFrame({"Item": ["Rows analyzed", "Unique hosts", "Unique full URLs", "Users", "Time range",
                                       "OneAPI lookup", "Rule-name columns found"],
                              "Value": [info["rows"], info["hosts"], info["urls"], info["users"] or "", info["time_range"],
                                        "Yes" if info["api"] else "No", ", ".join(info["rule_columns"]) or "None"]})
        about.to_excel(w, sheet_name="About", index=False)
        H.to_excel(w, sheet_name="Hosts", index=False)
        for k, v in summaries.items():
            v.to_excel(w, sheet_name=k.replace("_", " ").title()[:31], index=False)
        for ws in w.book.worksheets:
            ws.freeze_panes = "A2"
            for col in ws.columns:
                ws.column_dimensions[col[0].column_letter].width = min(60, max(10, max(len(str(c.value or "")) for c in col[:200]) + 2))
