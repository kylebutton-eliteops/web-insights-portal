# ZIA Toolkit

One local dashboard for Zscaler **ZIA Web Insights** exports, on one port (http://127.0.0.1:5055). Connect Zscaler once,
add your exports once, then open any tool. Every tool shares the same credentials, the same exports and the same lookup cache.

| Tool | What it does |
|---|---|
| **Web Insights** | Turns an export into a de-duplicated, categorized host list: hits, users and departments, logged and current Zscaler categories (including custom-category gaps), cloud apps, forwarding and rule hits, SSL inspection with an "expected vs review" label, protocols, first and last seen. CSV, zip of summaries, and Excel workbook out. |
| **Block impact** | Answers "if we block these URL categories, what allowed traffic breaks?" Looks up every category of each domain (logs only record the one that matched), shows what a planned block would catch including hidden multi-category matches, and which rule enforces each domain. |

## Quick start

```bash
./run.sh            # Windows PowerShell: .\run.ps1
```

Needs Python 3.9+. The first run creates `.venv/` and installs Flask, pandas and openpyxl, then opens your browser.
The dashboard walks you through three steps:

1. **Connect Zscaler once** (optional for Web Insights, needed for current categories and Block impact). Type a OneAPI
   client into the dashboard (kept in memory only) or put it in `.env`:
   `cp .env.example .env` and fill in `ZIA_VANITY_DOMAIN` (just the prefix, e.g. `acme`), `ZIA_CLIENT_ID`, `ZIA_CLIENT_SECRET`.
2. **Add your exports once** to the library on the dashboard.
3. **Pick a tool.**

The full how-to (exporting from ZIA, OneAPI setup, every output column, troubleshooting) is on the **How to use** tab.
`HELP.html` is a standalone copy you can open without starting anything.

## Export from Web Insights

1. ZIA admin console → **Analytics → Web Insights → Logs** (names may differ slightly in the new Experience Center).
2. Pick a time range. Exports cap at **1,000,000 rows**, so keep busy tenants to a few hours or a day per export
   (Block impact accepts up to 14 days of allowed traffic, several files at once).
3. Column picker: **URL** is required. Recommended: Event Time, User, Policy Action, URL Category, URL Super Category,
   URL Class, Cloud Application, Cloud Application Class, Department, Forwarding Rule, Certificate Chain Validity,
   ALPN Protocol, plus any **rule-name** columns (URL Filtering / Cloud App Control / SSL Inspection). For Block impact,
   filter to **Policy Action = Allowed**.
4. **Export → CSV** and add the file as downloaded (don't re-save it in Excel).

## OneAPI setup

1. ZIA: create a **read-only** API role (view access to URL categories and URL Filtering policy).
2. ZIdentity: **Integration → API Resources → Sync Now**, then **API Clients → Add**, Client Secret auth, and tick the ZIA role under Resources.
3. Enter the client once (dashboard or `.env`). A legacy ZIA API key also works via `.env` (see `.env.example`).

Lookups run 100 hosts per call at about one call a second. They return Zscaler's built-in categories; tenant custom
categories come from the logs. Results go into one shared cache, so a host looked up by either tool is never looked up again by the other.

## Privacy and data

- Listens on `127.0.0.1` only. The only data sent anywhere is hostnames to Zscaler's own URL lookup API.
- Exports contain user names. Everything is saved directly in the folder you run the toolkit from: exports in `logs/`, results in `output/` (Web Insights results in `output/web_insights/`) and the lookup cache in `lookup_cache.json`. All of it is git-ignored. Exports stay in `logs/` until you remove them on the dashboard; Web Insights outputs contain counts only. Set `ZIA_TOOLKIT_WORKSPACE` to keep them somewhere else.
- Credentials typed on the dashboard live in memory until you stop the toolkit and are never written to disk. Keep `.env` out of git (already in `.gitignore`).

## Files

- `app.py`: the Flask dashboard and Web Insights routes
- `analyzer.py`: Web Insights processing (header detection, de-dupe, summaries, SSL and custom-category checks)
- `creds.py`, `engine.py`, `shared.py`: shared credentials, the single Zscaler client / lookup engine, and the shared cache and workspace
- `impact_bp.py` and `category_impact/`: Block impact (the engine, its page, and its own README)
- `static/toolkit.css`, `templates/`: the shared look
- `categorize_web_insights.py`: standalone command-line version of Web Insights (`python3 categorize_web_insights.py export.csv --env-file .env`; `--dry-run` skips the API)
- `HELP.html`: standalone copy of the How to use page
- `zia_category_names.json`: category ID → console display name (the API only returns IDs)

## Claude skill

`skill/zia-web-insights-categorize.zip` is a Claude skill that teaches Claude this workflow, so you can hand it a
Web Insights export and ask for the breakdown in plain words.

1. Download [zia-web-insights-categorize.zip](skill/zia-web-insights-categorize.zip) (use the download button on that page).
2. In Claude, go to **Customize > Skills**, click **+**, then **Create skill**, then **Upload a skill**, and pick the zip.
3. Turn the skill on with the switch next to it.

Skills need code execution ("Create and edit files" under Settings > Capabilities, or your organization's equivalent).
The source is in `skill/zia-web-insights-categorize/SKILL.md`.
