---
name: "zia-web-insights-categorize"
description: "Analyze a ZIA Web Insights CSV export: dedupe URLs by host, count hits, add Zscaler categories (logs + OneAPI urlLookup), cloud apps, rules, SSL bypass review and custom-category gaps."
---

# ZIA Web Insights categorization

Use this skill when someone shares a ZIA **Web Insights log export** (CSV) or asks to: de-duplicate a URL list, look up Zscaler URL categories, count how often each URL/host appears, see which rule traffic hit, review SSL inspection bypasses, find custom-category gaps, or run/extend the **Web Insights Portal**. Not for Zscaler Client Connector log bundles or pcaps.

## Get the tools
The tools are in the public repo **kylebutton-eliteops/web-insights-portal** (MIT license).
1. In a session with a shell: `git clone --depth 1 https://github.com/kylebutton-eliteops/web-insights-portal` (reuse the clone if it is already there), then `pip install -r web-insights-portal/requirements.txt` (add `--break-system-packages` if pip asks for it). If the shell can't reach GitHub, ask the person to attach the repo zip (https://github.com/kylebutton-eliteops/web-insights-portal/archive/refs/heads/main.zip).
2. When the person wants to run the portal on their own computer, point them at the repo's `README.md` and `HELP.html`: download, `./run.sh` (Windows: `.\run.ps1`), open http://127.0.0.1:5055.

What's there:
- `app.py` - local Flask portal. Upload the CSV, optional OneAPI lookup, download hosts CSV / zip of summary CSVs / Excel workbook. `HELP.html` and the in-app How to use page are the user instructions.
- `analyzer.py` - the processing. For a one-off analysis in a session, import it directly: `analyzer.analyze(path, use_api=False)` returns the per-host table, summaries and info.
- `zia_api.py` - OneAPI token, `urlLookup`, category catalog.
- `categorize_web_insights.py` - small CLI: `python3 categorize_web_insights.py export.csv --env-file client.env` (`--dry-run` = dedupe and count only, `--mode url` = dedupe by full URL, `--token-file` = reuse an existing bearer token, `--token-info` = print the vanity domain and expiry from a token).
- `zia_category_names.json` - category ID -> console display name.

## Workflow
1. **Look at the export first.** Web Insights exports start with a few report lines (Administrator, Report Created, filters) before the real header; find the header row with the URL column. List which columns are present before promising anything.
2. **The export usually already has categories.** URL Category, URL Super Category, URL Class, Cloud Application and Cloud Application Class are logged per row, including the tenant's custom categories (super category `User-Defined`). Build the category breakdown from the file before reaching for the API.
3. **Check for the row cap.** Exactly 1,000,000 rows means the export hit Web Insights' limit and covers less time than requested; say so, with the actual time range. Also state any filter baked into the export (e.g. Policy Action = Allow).
4. **Dedupe by hostname** by default (strip scheme, path, port); keep hit counts and the number of distinct full URLs per host. Offer full-URL dedupe only if asked.
5. **Hosts can have several categories.** In the logs, one host can be logged under different categories (a custom category matching only some paths, or a category change). Count hits per logged category on the category summary; on the per-host view show the main one plus the others with hit counts.
6. **OneAPI lookup (optional)** gives Zscaler's *current* built-in categories: `POST https://api.zsapi.net/zia/api/v1/urlLookup`, 100 hosts per call, about one call a second, back off on 429. It returns category **IDs** only (e.g. `OSS_UPDATES`, `WEB_BANNERS`), often 2-4 per host, plus `application` / `applicationClass`. Convert IDs to console names with `zia_category_names.json`; for IDs not in it, match against the names logged in the export for the same hosts, and say which names you had to guess. Custom categories of another tenant never come back from the API.
7. **Rules.** The default export only has Forwarding Rule. Any column with "Rule" in its name (URL Filtering / Cloud App Control / SSL Inspection rule names) is picked up automatically; if none are present, say the export needs those columns turned on rather than inferring a rule.
8. **SSL inspection** is inferred from Certificate Chain Validity (a value = inspected, blank = not inspected). The Expected / Review labels are pattern-based guesses to sort hosts (M365/Teams, OS updates, OCSP/CRL, Apple/Google device services, pinned apps = expected; finance, health, ad-tech, partly inspected = review). Present them as such, never as confirmed policy.
9. **Custom-category gaps.** Partial = some hits in a custom category and the rest fell to Zscaler's default (usually a missing path or subdomain). Sibling = other hosts on the same domain are in a custom category and this one isn't; very large domains are skipped or it flags hundreds of hosts.
10. **Verify totals** (hits sum back to the row count; host counts match across tabs) before reporting. Lead with the answer: rows, unique hosts, top categories, then caveats.

## Credentials
- OneAPI uses a ZIdentity API client (client ID + secret, Client Secret auth) with a **read-only** ZIA role; the tools fetch a short-lived token themselves. The **vanity domain** is the prefix of the ZIdentity sign-in address (`<vanity>.zslogin.net`); it is also in a token's `iss` claim. A value like `zscalertwo.net-<number>` is the ZIA cloud + org ID from the legacy API, not the vanity domain.
- Never ask for or echo the secret in chat. Have the person put the three values in a file on their machine (`ZIA_VANITY_DOMAIN`, `ZIA_CLIENT_ID`, `ZIA_CLIENT_SECRET`; the tools also accept `vanity` / `client_id` / `client_secret`), read only key names and lengths when checking it, and remind them to delete it afterwards.
- Only use credentials for a tenant the person is authorized on today (their own or the client's). The client's own tenant is the only way to get its custom categories from the API. Never commit a `.env`.

## Getting results into Google Sheets
The Sheets connector can't take a few thousand wide rows in one write (about 40 KB per call is the practical limit). For big tables: produce a CSV/xlsx, have the person import it as a new tab (File -> Import -> Insert new sheet), then add columns elsewhere as lookup formulas (`VLOOKUP` / `INDEX-MATCH` on Host) and summary tabs as `COUNTIF` / `SUMIFS` over the host tab. Small lookup tables (under about 1,000 short rows) can be written directly in two or three calls. Change the person's existing sheet in place; keep the same link.

## Customer data
The raw export contains user names/emails, departments and internal hostnames. Keep it in the scratchpad, never in the repo or in memory. Outputs carry counts only (unique users, departments), no user names. The portal deletes the upload after processing unless "Keep" is ticked.

## Problems with the tool
If the portal or script misbehaves, help the person open an issue at https://github.com/kylebutton-eliteops/web-insights-portal/issues. Issues are public: no exports, output files, credentials, tenant names or internal hostnames in them.
