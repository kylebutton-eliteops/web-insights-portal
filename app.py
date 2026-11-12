"""Web Insights Portal: upload a ZIA Web Insights CSV export, get a de-duplicated, categorized CSV back.

Run:  python3 app.py        then open http://127.0.0.1:5055
"""
import datetime
import os
import threading
import traceback
import uuid

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, url_for

import analyzer
import zia_api

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
UPLOADS, OUTPUTS = os.path.join(DATA, "uploads"), os.path.join(DATA, "outputs")
os.makedirs(UPLOADS, exist_ok=True)
os.makedirs(OUTPUTS, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 ** 3   # 2 GB uploads
JOBS = {}   # job_id -> dict(status, pct, msg, info, error, files, preview, summaries)


def run_job(job_id, path, use_api, creds, keep_upload):
    job = JOBS[job_id]

    def progress(pct, msg):
        job["pct"], job["msg"] = pct, msg

    try:
        H, summaries, info = analyzer.analyze(path, use_api=use_api, creds=creds, progress=progress)
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
    finally:
        if not keep_upload and os.path.exists(path):
            os.remove(path)   # the raw export holds user names / emails; don't keep it around


@app.route("/")
def index():
    return render_template("index.html", api_ready=zia_api.creds_configured(),
                           jobs=sorted(JOBS.items(), key=lambda kv: kv[1]["started"], reverse=True)[:10])


@app.route("/help")
def help_page():
    return render_template("help.html")


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("export")
    if not f or not f.filename:
        return render_template("index.html", api_ready=zia_api.creds_configured(), jobs=[],
                               error="Choose a Web Insights CSV export first."), 400
    if not f.filename.lower().endswith(".csv"):
        return render_template("index.html", api_ready=zia_api.creds_configured(), jobs=[],
                               error="That isn't a .csv file. In Web Insights, use Export to CSV."), 400
    job_id = uuid.uuid4().hex[:12]
    path = os.path.join(UPLOADS, job_id + ".csv")
    f.save(path)

    use_api = request.form.get("use_api") == "on"
    creds = None
    if use_api:
        overrides = {k: request.form.get(k, "").strip() for k in ("ZIA_VANITY_DOMAIN", "ZIA_CLIENT_ID", "ZIA_CLIENT_SECRET")}
        creds = zia_api.get_creds(overrides={k: v for k, v in overrides.items() if v})
        if not all(creds):
            os.remove(path)
            return render_template("index.html", api_ready=False, jobs=[],
                                   error="The Zscaler lookup needs a vanity domain, client ID and client secret "
                                         "(in the .env file or the fields below)."), 400

    stem = os.path.splitext(os.path.basename(f.filename))[0][:60] + "_categorized"
    JOBS[job_id] = dict(status="running", pct=0, msg="Starting", filename=f.filename, stem=stem,
                        started=datetime.datetime.now(), use_api=use_api)
    threading.Thread(target=run_job, args=(job_id, path, use_api, creds, request.form.get("keep") == "on"),
                     daemon=True).start()
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
    print(f"\n  Web Insights Portal running at http://127.0.0.1:{port}\n  Press Ctrl+C to stop.\n")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
