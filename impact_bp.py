"""Category Impact, mounted inside the toolkit at /impact.

The engine and page are the standalone tool's (category_impact/); this blueprint replaces its small HTTP server so
everything runs on one port. Same checks as before: localhost Host header and a per-process token on every call.
"""
import os
import secrets
import shutil
import sys
import urllib.parse

from flask import Blueprint, Response, abort, jsonify, request, send_file

import shared  # sets ZIA_IMPACT_WORKSPACE before the tool is imported
import engine  # noqa: F401  (points Category Impact at the toolkit's credentials)

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "category_impact"))
core = engine.core
import zia_impact_gui as gui  # noqa: E402

bp = Blueprint("impact", __name__, url_prefix="/impact")
gui.TOKEN = secrets.token_urlsafe(24)


def _guard(download=False):
    host = (request.host or "").split(":")[0]
    if host not in ("127.0.0.1", "localhost"):
        abort(403)
    sent = request.args.get("t", "") if download else request.headers.get("X-Token", "")
    if not secrets.compare_digest(sent, gui.TOKEN):
        return jsonify(error="This tab is from an earlier session of the tool. Reload the page."), 403
    return None


@bp.route("/")
def page():
    host = (request.host or "").split(":")[0]
    if host not in ("127.0.0.1", "localhost"):
        abort(403)
    with open(os.path.join(HERE, "category_impact", "zia_impact_gui.html"), encoding="utf-8") as f:
        html = f.read().replace("__TOKEN__", gui.TOKEN)
    return Response(html, mimetype="text/html", headers={"Cache-Control": "no-store"})


@bp.route("/download")
def download():
    bad = _guard(download=True)
    if bad:
        return bad
    name = request.args.get("f", "")
    if name not in ("results.json", "domains.csv"):
        abort(404)
    path = os.path.join(gui.OUTPUT, name)
    if not os.path.exists(path):
        return jsonify(error="Not found yet. Run a lookup first."), 404
    return send_file(path, as_attachment=True, download_name=name, mimetype="application/json" if name.endswith("json") else "text/csv")


@bp.route("/api/state")
def state():
    bad = _guard()
    if bad:
        return bad
    env = core.env_creds()
    job = gui.STATE["job"]
    return jsonify(
        files=gui.list_files(),
        env={"oneapi": bool(env["client_id"] and env["client_secret"] and env["vanity"]),
             "legacy": bool(env["username"] and env["password"] and env["api_key"] and env["legacy_cloud"]),
             "vanity": env["vanity"] or "", "legacy_cloud": env["legacy_cloud"] or "", "username": env["username"] or ""},
        job=job.snapshot() if job else None,
        has_results=os.path.exists(os.path.join(gui.OUTPUT, "results.json")),
        cache=shared.count(), workspace=shared.WORKSPACE)


@bp.route("/api/results")
def results():
    bad = _guard()
    if bad:
        return bad
    path = os.path.join(gui.OUTPUT, "results.json")
    if not os.path.exists(path):
        return jsonify(error="Not found yet. Run a lookup first."), 404
    return send_file(path, mimetype="application/json", max_age=0)


def _busy():
    job = gui.STATE["job"]
    return bool(job and job.finished is None)


@bp.route("/api/upload", methods=["POST"])
def upload():
    bad = _guard()
    if bad:
        return bad
    try:
        name = gui.safe_name(request.args.get("name", ""))
    except ValueError as e:
        return jsonify(error=str(e)), 400
    os.makedirs(gui.UPLOADS, exist_ok=True)
    dest = os.path.join(gui.UPLOADS, name)
    tmp = dest + ".part"
    want = request.content_length or 0
    got = 0
    try:
        with open(tmp, "wb") as f:
            while True:
                chunk = request.stream.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
                got += len(chunk)
    except OSError as e:
        if os.path.exists(tmp):
            os.remove(tmp)
        return jsonify(error=f"Couldn't save {name} in {gui.UPLOADS}: {e.strerror or e}"), 500
    if want and got != want:
        os.remove(tmp)
        return jsonify(error="Upload was cut off"), 400
    os.replace(tmp, dest)
    return jsonify(files=gui.list_files())


@bp.route("/api/delete", methods=["POST"])
def delete():
    bad = _guard()
    if bad:
        return bad
    if _busy():
        return jsonify(error="Wait for the current run to finish"), 400
    body = request.get_json(silent=True) or {}
    try:
        if body.get("all"):
            for f in gui.list_files():
                os.remove(os.path.join(gui.UPLOADS, f["name"]))
        else:
            p = os.path.join(gui.UPLOADS, gui.safe_name(body.get("name", "")))
            if os.path.exists(p):
                os.remove(p)
    except ValueError as e:
        return jsonify(error=str(e)), 400
    return jsonify(files=gui.list_files())


@bp.route("/api/clear-cache", methods=["POST"])
def clear_cache():
    bad = _guard()
    if bad:
        return bad
    if _busy():
        return jsonify(error="Wait for the current run to finish"), 400
    shared.clear()
    return jsonify(cache=0)


@bp.route("/api/clientlog", methods=["POST"])
def clientlog():
    bad = _guard()
    if bad:
        return bad
    print(f"[browser] {str((request.get_json(silent=True) or {}).get('msg', ''))[:500]}", flush=True)
    return jsonify(ok=True)


@bp.route("/api/run", methods=["POST"])
def run():
    bad = _guard()
    if bad:
        return bad
    try:
        return jsonify(gui.start_job(request.get_json(silent=True) or {}))
    except ValueError as e:
        return jsonify(error=str(e)), 400


@bp.route("/api/stop", methods=["POST"])
def stop():
    bad = _guard()
    if bad:
        return bad
    job = gui.STATE["job"]
    if job and job.finished is None:
        job.stop_event.set()
        job.log("Stopping after the current request ...")
    return jsonify(ok=True)
