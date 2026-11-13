"""ZIA Toolkit: one local dashboard for ZIA Web Insights tools.

Run:  python3 app.py        then open http://127.0.0.1:5055

One set of Zscaler credentials (creds.py), one lookup engine and cache (engine.py, shared.py), and one library of
uploaded exports (shared by Web Insights and Block impact).
"""
import datetime
import os
import threading
import traceback
import uuid

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, url_for

import analyzer
import creds
import engine
import impact_bp
import shared

HERE = os.path.dirname(os.path.abspath(__file__))
gui = impact_bp.gui           # Category Impact's helpers; its UPLOADS folder is the shared exports library
LIBRARY = gui.UPLOADS
OUTPUTS = os.path.join(gui.OUTPUT, "web_insights")   # Web Insights results, next to Block impact's
os.makedirs(OUTPUTS, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 ** 3   # 2 GB uploads
app.register_blueprint(impact_bp.bp)
JOBS = {}   # job_id -> dict(status, pct, msg, info, error, files, preview, summaries)


@app.context_processor
def inject_globals():
    return {"impact_url": "/impact/", "conn": creds.status()}


def library():
    return gui.list_files()


def fmt_size(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


app.jinja_env.filters["size"] = fmt_size


def run_job(job_id, path, use_api):
    job = JOBS[job_id]

    def progress(pct, msg):
        job["pct"], job["msg"] = pct, msg

    try:
        H, summaries, info = analyzer.analyze(path, use_api=use_api, progress=progress)
        base = os.path.join(OUTPUTS, job_id)
        stem = job["stem"]
        files = {
            "hosts": (f"{stem}_hosts.csv", base + "_hosts.csv"),
            "zip": (f"{stem}_all_csv.zip", base + "_all.zip"),
            "xlsx": (f"{stem}.xlsx", base + ".xlsx"),
        }
        H.to_csv(files["hosts"][1], index=False)
        with open(files["zip"][1], "wb") as fh:
            fh.write(analyzer.to_zip(H, summaries, info))
        analyzer.to_xlsx(files["xlsx"][1], H, summaries, info)
        preview_cols = [c for c in ["Host", "Hits", "Logged URL category", "API categories", "Cloud application",
                                    "Forwarding rule", "SSL bypass review", "Custom category gap"] if c in H.columns]
        job.update(status="done", pct=100, msg="Done", info=info, files=files,
                   preview=H[preview_cols].head(25).fillna("").to_dict("records"), preview_cols=preview_cols,
                   summaries={k: v.head(15).fillna("").to_dict("records") for k, v in summaries.items()})
    except Exception as e:
        traceback.print_exc()
        job.update(status="error", error=str(e))


# ---------------------------------------------------------------- dashboard
@app.route("/")
def dashboard():
    return render_template("dashboard.html", cache_count=shared.count(), workspace=shared.WORKSPACE, files=library(),
                           jobs=sorted(JOBS.items(), key=lambda kv: kv[1]["started"], reverse=True)[:5],
                           msg=request.args.get("msg", ""), err=request.args.get("err", ""))


@app.route("/connect", methods=["POST"])
def connect():
    if request.form.get("action") == "disconnect":
        creds.clear_memory()
        return redirect(url_for("dashboard", msg="Cleared the credentials typed this session."))
    creds.set_memory({k: request.form.get(k, "") for k in ("vanity", "client_id", "client_secret")})
    if not creds.status()["oneapi"]:
        return redirect(url_for("dashboard", err="Vanity domain, client ID and client secret are all needed."))
    ctx = engine.Ctx()
    try:
        engine.open_client(ctx)   # test sign-in
    except Exception as e:
        creds.clear_memory()
        return redirect(url_for("dashboard", err=f"Sign-in failed: {e}"))
    return redirect(url_for("dashboard", msg="Connected. Both tools will use these credentials until you stop the toolkit."))


@app.route("/exports/upload", methods=["POST"])
def exports_upload():
    saved, errors = 0, []
    os.makedirs(LIBRARY, exist_ok=True)
    for f in request.files.getlist("export"):
        if not f.filename:
            continue
        try:
            name = gui.safe_name(f.filename)
        except ValueError as e:
            errors.append(str(e))
            continue
        f.save(os.path.join(LIBRARY, name))
        saved += 1
    if errors and not saved:
        return redirect(url_for("dashboard", err=errors[0]))
    return redirect(url_for("dashboard", msg=f"Added {saved} export(s) to the library."))


@app.route("/exports/delete", methods=["POST"])
def exports_delete():
    name = request.form.get("name", "")
    try:
        if name == "__all__":
            for f in library():
                os.remove(os.path.join(LIBRARY, f["name"]))
        else:
            p = os.path.join(LIBRARY, gui.safe_name(name))
            if os.path.exists(p):
                os.remove(p)
    except ValueError as e:
        return redirect(url_for("dashboard", err=str(e)))
    return redirect(url_for("dashboard", msg="Removed."))


@app.route("/cache/clear", methods=["POST"])
def clear_cache():
    shared.clear()
    return redirect(url_for("dashboard", msg="Lookup cache cleared."))


# ---------------------------------------------------------------- Web Insights
@app.route("/insights")
def index():
    csvs = [f for f in library() if f["name"].lower().endswith(".csv")]
    return render_template("index.html", files=csvs, other=len(library()) - len(csvs),
                           jobs=sorted(JOBS.items(), key=lambda kv: kv[1]["started"], reverse=True)[:10],
                           selected=request.args.get("file", ""), error=request.args.get("err", ""))


@app.route("/help")
def help_page():
    return render_template("help.html", workspace=shared.WORKSPACE)


@app.route("/insights/run", methods=["POST"])
def upload():
    name = request.form.get("file", "")
    try:
        path = os.path.join(LIBRARY, gui.safe_name(name))
    except ValueError:
        path = ""
    if not path or not os.path.exists(path) or not name.lower().endswith(".csv"):
        return redirect(url_for("index", err="Choose an export from the library first (add one on the dashboard)."))
    use_api = request.form.get("use_api") == "on"
    if use_api and not creds.status()["ready"]:
        return redirect(url_for("index", err="Connect Zscaler on the dashboard first, or untick the lookup."))
    job_id = uuid.uuid4().hex[:12]
    stem = os.path.splitext(name)[0][:60] + "_categorized"
    JOBS[job_id] = dict(status="running", pct=0, msg="Starting", filename=name, stem=stem,
                        started=datetime.datetime.now(), use_api=use_api)
    threading.Thread(target=run_job, args=(job_id, path, use_api), daemon=True).start()
    return redirect(url_for("job_page", job_id=job_id))


@app.route("/job/<job_id>")
def job_page(job_id):
    job = JOBS.get(job_id) or abort(404)
    return render_template("job.html", job_id=job_id, job=job)


@app.route("/job/<job_id>/status")
def job_status(job_id):
    job = JOBS.get(job_id) or abort(404)
    return jsonify({k: job.get(k) for k in ("status", "pct", "msg", "error")})


@app.route("/job/<job_id>/download/<kind>")
def download(job_id, kind):
    job = JOBS.get(job_id) or abort(404)
    if job.get("status") != "done" or kind not in job["files"]:
        abort(404)
    name, path = job["files"][kind]
    return send_file(path, as_attachment=True, download_name=name)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5055))
    print(f"""
  ZIA Toolkit running at http://127.0.0.1:{port}   (opening your browser)

  Quick start
    1. Connect Zscaler once: type your OneAPI client on the dashboard, or put it in .env and restart.
    2. Add your Web Insights CSV export(s) to the library on the dashboard.
    3. Open Web Insights (categorize hosts) or Block impact (what breaks if we block these categories?).
    Full instructions: the "How to use" tab.

  Exports library, lookup cache and results: {shared.WORKSPACE}
  Press Ctrl+C to stop.
""")
    if not os.environ.get("NO_BROWSER"):
        import webbrowser
        threading.Timer(1.0, lambda: webbrowser.open(f"http://127.0.0.1:{port}/")).start()
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
