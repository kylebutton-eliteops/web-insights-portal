# Web Insights Portal

A small local web app that turns a **ZIA Web Insights CSV export** into a de-duplicated, categorized list of hosts,
and gives you a CSV (plus a zip of summaries and an Excel workbook) back.

For each host it reports: hits and % of traffic, unique URLs, users and departments, the categories ZIA logged
(including tenant custom categories), custom-category gaps, URL class, cloud application and class, policy action,
forwarding rule, any rule-name columns in the export, SSL inspection (with an "expected vs review" bypass label),
protocol mix, and first/last seen. Optionally it also asks Zscaler's OneAPI for each host's **current** categories and app.

## Quick start

```bash
cd web_insights_portal
./run.sh            # Windows PowerShell: .\run.ps1
```

Open http://127.0.0.1:5055, upload the export, download the results. The full how-to (exporting from ZIA, OneAPI
setup, what every output column means, troubleshooting) is on the **How to use** page inside the app.

**Help document:** open `HELP.html` in any browser for the full instructions without starting the app.

Needs Python 3.9+. The first run creates `.venv/` and installs Flask, pandas and openpyxl.

## 1. Export from Web Insights

1. ZIA admin console → **Analytics → Web Insights → Logs** (names may differ slightly in the new Experience Center).
2. Pick a time range. Exports cap at **1,000,000 rows**, so keep busy tenants to a few hours or a day per export.
3. Column picker: **URL** is required. Recommended: Event Time, User, Policy Action, URL Category, URL Super Category,
   URL Class, Cloud Application, Cloud Application Class, Department, Forwarding Rule, Certificate Chain Validity,
   ALPN Protocol. Add any **rule-name** columns (URL Filtering / Cloud App Control / SSL Inspection) to get
   "which rule did it hit"; every column with "Rule" in its name is picked up automatically.
4. **Export → CSV**, and upload the file as downloaded (don't re-save it in Excel).

## 2. Optional: OneAPI category lookup

1. ZIA: create a **read-only** admin role (View Only, with URL Categories / URL Filtering view access).
2. ZIdentity: **Integration → API Clients → Add**, Client Secret auth, assign the ZIA role.
3. `cp .env.example .env` and fill in `ZIA_VANITY_DOMAIN` (just the prefix, e.g. `acme`), `ZIA_CLIENT_ID`,
   `ZIA_CLIENT_SECRET`. Or type them into the upload form each time (not saved).

The lookup does 100 hosts per call at about one call a second, so about a minute per 4,500 hosts. It returns
Zscaler's built-in categories only; tenant custom categories come from the logs.

## Outputs

| File | Contents |
|---|---|
| `*_hosts.csv` | One row per host with every column above |
| `*_all_csv.zip` | hosts.csv plus logged-category, OneAPI-category, SSL review, forwarding rule and rule-name summaries |
| `*.xlsx` | Everything as workbook tabs (import into Google Sheets with File → Import) |

## Privacy and data

- Listens on `127.0.0.1` only; nothing is reachable from the network.
- The uploaded export (which contains user names) is **deleted after processing** unless you tick "Keep".
  Outputs contain no user names, only counts. They stay in `data/outputs/` until you delete them.
- Credentials typed into the form are used for that run only. Keep `.env` out of git (already in `.gitignore`).

## Files

- `app.py`: Flask app (upload, progress, downloads, how-to page)
- `analyzer.py`: the processing (header detection, de-dupe, summaries, SSL and custom-category checks)
- `categorize_web_insights.py`: command-line version (`python3 categorize_web_insights.py export.csv --env-file .env`; `--dry-run` skips the API)
- `zia_api.py`: OneAPI token, `urlLookup`, category catalog
- `HELP.html`: standalone copy of the How to use page (opens without the app running)
- `zia_category_names.json`: category ID → console display name (the API only returns IDs)
