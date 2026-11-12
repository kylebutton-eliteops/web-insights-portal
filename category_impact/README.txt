NOTE: inside the ZIA Toolkit this tool runs at /impact on the toolkit's port. Credentials, the exports library and the
lookup cache are shared with the other tools, so skip the Python/launcher steps and the "Zscaler API" credentials box below:
connect Zscaler once on the dashboard (or in .env), add exports there, then open Block impact.

ZIA Category Impact - Quick start
================================

WHAT IT DOES
  Answers one question before you change policy: "If we block these URL
  categories, which allowed traffic breaks?"

  ZIA logs record only the one category a URL matched, but most URLs carry
  several. Example: SharePoint is Corporate Marketing AND File Host, so an
  explicit File Host block also blocks SharePoint. This tool takes your
  allowed web logs, asks Zscaler for EVERY category of each domain, and shows
  what a planned block would catch, with hit counts, user counts, the rule
  that currently allows the traffic, and the "hidden" matches nobody expects.

  Everything runs on your own computer. The only thing sent anywhere is the
  list of domain names, to Zscaler's own URL lookup API. Credentials are held
  in memory for the run and never saved.


WHAT YOU NEED
  1. Python 3.8 or newer.
       Mac: usually already installed. Check in Terminal: python3 --version
            If missing, Terminal offers to install it, or use python.org.
       Windows: install from https://www.python.org/downloads/
            and tick "Add python.exe to PATH" during setup.
     No other software or packages are needed.

  2. A ZIA web log export (CSV). See STEP 1.

  3. Zscaler API access with read access to URL categories, either:
       - OneAPI (ZIdentity): Client ID, Client secret, vanity domain
         (ZIdentity > Integration > API Clients). The client MUST have a
         ZIA API role, or every lookup fails with HTTP 401:
           1. ZIA Admin Portal > Administration > Role Management >
              Add API Role with view access to URL categories and
              URL Filtering policy.
           2. ZIdentity > Integration > API Resources > Sync Now.
           3. ZIdentity > Integration > API Clients > edit the client >
              Resources > tick that ZIA role > Save.
         or
       - Legacy ZIA API key: admin username, password, API key and cloud
         (ZIA Admin Portal > Administration > Cloud Service API Security).


STEP 1 - EXPORT THE LOGS FROM ZIA
  ZIA Admin Portal > Analytics > Web Insights > switch to the Logs view.
    - Time range: up to the last 14 days.
    - Filter: Policy Action = Allowed.
    - Columns to turn on before exporting (the tool works without some of
      these, but you lose detail):
        URL                          required
        Policy Action                which rows were allowed
        URL Category                 needed for "Logged as" and Hidden matches
        User                         user counts
        URL Filtering Rule Name      shows which rule allowed the traffic
        Cloud App / Cloud Application Policy rule name
        Blocked Policy rule name
    - Export to CSV. Several files are fine.
  A CSV from a SIEM / ADX, or a hand-made list of domains, also works.


STEP 2 - START THE TOOL
  Unzip this folder somewhere convenient (Documents is fine).

  Mac (Terminal - most reliable):
    1. Open Terminal.
    2. Type  cd  and a space, drag this folder into the Terminal window,
       press Return.
    3. Type  python3 zia_impact_gui.py  and press Return.
    Or double-click "Start ZIA Impact (Mac).command". If macOS says it
    "could not verify" the file, click Done, then System Settings >
    Privacy & Security > scroll down > "Open Anyway".

  Windows:
    Double-click "Start ZIA Impact (Windows).bat".
    Or open a Command Prompt in this folder and run:  python zia_impact_gui.py

  A browser tab opens automatically at http://127.0.0.1:8765 (the same
  address every time, so saved lists and settings are remembered). Keep the Terminal / Command Prompt
  window open while you use the tool; closing it stops the tool.

  Check the top-right of the page shows a green "Connected" badge.
  Do NOT open zia_impact_gui.html directly - it only works through the tool.


STEP 3 - DRY RUN, THEN LOOKUP  (tab 1: Run lookup)
  1. Drop your CSV(s) into box A (or click "Upload CSV...").
  2. Click "Dry run". It reads the files in seconds without contacting
     Zscaler and lists the columns it found. Read any yellow warnings:
     they tell you if a column is missing from the export.
  3. Fill in box B with your API details (OneAPI or Legacy API key).
  4. Click "Run lookup". Zscaler allows 400 requests an hour at 100 domains
     each (40,000 domains an hour). A typical 14-day export finishes in
     minutes. If you stop, or hit the hourly limit, running again resumes
     where it left off.


STEP 4 - REVIEW THE IMPACT  (tab 2: Review impact)
  1. In "What would a block catch?", pick a saved list (the "High-risk
     categories (example)" list is preloaded) or paste your own
     categories, one per line, and click "Evaluate list". You can also
     tick categories in the "Categories" menu above the table.
     Names as shown in ZIA, API names (FILE_HOST) and super categories all
     work.
  2. Read the four numbers: domains affected, hits affected (and % of all
     allowed traffic), hidden matches, and the most users on one domain.
     Below them, "Impact by blocking category" splits that impact by the
     category each domain would be blocked under, so you can see which
     category on your list does the damage. Click a row to filter to it.
  3. Work through the table, starting with "Hidden only". Each row shows
     the category it "Would be blocked as" (the first planned category in
     Zscaler's order, which is what ZIA has been seen to log), every Zscaler
     category (outlined = primary, red = planned block), what the logs
     recorded, and "Enforced by": the URL filtering rule that decides the
     traffic and any cloud app rule. The URL rule comes from the log's
     URL Filtering Rule column when the export has it; otherwise the tool
     reads your URL filtering rules and simulates them top-down by order
     against the domain's categories (marked "sim"). "Conditional" means an
     earlier rule limited to certain users, groups, locations or times also
     matches, so those people get that rule instead.
     Filter with "Enforced by" (one rule) and "Action" (Block, Caution,
     Allow, Default rule, Conditional), or click a rule in the column.
  4. Tick "Exc" on domains that must keep working, then "Copy as URL list"
     to paste into a custom URL category or an allow rule placed ABOVE the
     new block.
  5. "Download domains.csv" gives the full table for Excel;
     "Download results.json" can be sent to a colleague, who opens it with
     "Open other results..." without running a lookup.

  Hover over any "?" or button in the tool for an explanation.


FILES
  zia_impact_gui.py        the tool (start this)
  zia_impact_gui.html      its page (opened by the tool)
  zia_category_impact.py   the engine; can also run on its own from a
                           command line (python3 zia_category_impact.py -h)
  ~/ZIA Category Impact/   in your home folder, created on first run: your
                           uploaded logs, the lookup cache and results. Kept
                           between runs and new versions of the tool. Delete it
                           to start fresh. (Set ZIA_IMPACT_WORKSPACE to use a
                           different folder.)


TROUBLESHOOTING
  "Not connected" or uploads fail
      The tool isn't running, or the page was opened directly. Start the
      tool (STEP 2) and use the tab it opens.
  "This tab is from an earlier session"
      The tool was restarted. Reload the page.
  "Categories missing" on Review impact
      Only a dry run has been done. Enter API details and click Run lookup.
  Logged as is empty / Hidden matches always 0
      The export has no URL Category column. Re-export with it turned on.
  Allowed by only shows an SSL inspection rule
      Add the URL Filtering Rule Name and cloud app policy columns to the
      export.
  HTTP 401 / 403 during lookup (OneAPI)
      The token was issued but ZIA refused it: the API client has no ZIA
      API role. Follow the three steps under "What you need" above.
  HTTP 401 / 403 during lookup (legacy key)
      Check username, password, the full API key and the cloud name, and
      that the admin's role allows API access.
