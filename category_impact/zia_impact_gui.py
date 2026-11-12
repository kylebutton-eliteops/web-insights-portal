#!/usr/bin/env python3
"""
zia_impact_gui.py - point-and-click front end for zia_category_impact.py

    python zia_impact_gui.py            (opens your browser)
    python zia_impact_gui.py --port 8800 --no-browser

Runs a small web server on 127.0.0.1 only. Your browser talks to it; it talks
to the Zscaler API. Log files you add are copied into ~/ZIA Category Impact/ (kept between runs),
credentials are held in memory for the run and never written to disk.

Keep these three files together in one folder:
    zia_category_impact.py   zia_impact_gui.py   zia_impact_gui.html
Stdlib only (Python 3.8+).
"""

import argparse
import json
import os
import re
import secrets
import shutil
import sys
import threading
import time
import traceback
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import zia_category_impact as core  # noqa: E402

# One fixed workspace per user, so uploads, the lookup cache and results survive restarts,
# re-downloads and starting the tool from a different folder. Override with ZIA_IMPACT_WORKSPACE.
WORKSPACE = os.environ.get("ZIA_IMPACT_WORKSPACE") or os.path.join(os.path.expanduser("~"), "ZIA Category Impact")
DEFAULT_PORT = 8765   # fixed, so the browser keeps saved lists and settings between runs
UPLOADS = os.path.join(WORKSPACE, "logs")
OUTPUT = os.path.join(WORKSPACE, "output")
CACHE = os.path.join(WORKSPACE, "lookup_cache.json")
ALLOWED_EXT = (".csv", ".csv.gz", ".gz", ".zip", ".txt", ".tsv", ".xlsx", ".xlsm")
TOKEN = secrets.token_urlsafe(24)


class Job(core.Context):
    def __init__(self, mode):
        super().__init__()
        self.mode = mode
        self.phase = "starting"
        self.done = 0
        self.total = 0
        self.note = ""
        self.lines = []
        self.started = time.time()
        self.finished = None
        self.error = None
        self.summary = None
        self.lookup_started = None
        self.lock = threading.Lock()

    def log(self, msg):
        with self.lock:
            for line in str(msg).splitlines():
                self.lines.append(f"{time.strftime('%H:%M:%S')}  {line}")
            self.lines = self.lines[-400:]

    def progress(self, phase, done=None, total=None, note=None):
        with self.lock:
            if phase == "lookup" and self.lookup_started is None:
                self.lookup_started = time.time()
            self.phase = phase
            if done is not None:
                self.done = done
            if total is not None:
                self.total = total
            self.note = note or ("" if phase not in ("waiting",) else self.note)

    def snapshot(self):
        with self.lock:
            eta = None
            if self.phase in ("lookup", "waiting") and self.lookup_started and self.done and self.total:
                remaining = self.total - self.done
                reqs = -(-remaining // core.BATCH_SIZE)
                eta = int(reqs * core.MIN_INTERVAL + (reqs // core.HOURLY_LIMIT) * 3600)
            return {
                "mode": self.mode, "phase": self.phase, "done": self.done, "total": self.total,
                "note": self.note, "log": self.lines[-200:], "started": self.started,
                "finished": self.finished, "error": self.error, "summary": self.summary,
                "eta": eta, "running": self.finished is None,
            }


STATE = {"job": None}


def list_files():
    os.makedirs(UPLOADS, exist_ok=True)
    out = []
    for n in sorted(os.listdir(UPLOADS)):
        p = os.path.join(UPLOADS, n)
        if os.path.isfile(p) and not n.endswith(".part"):
            out.append({"name": n, "size": os.path.getsize(p)})
    return out


def safe_name(name):
    name = os.path.basename(urllib.parse.unquote(name or "")).strip()
    name = re.sub(r"[^A-Za-z0-9._ ()\-]", "_", name)[:180]
    if not name or name.startswith("."):
        raise ValueError("Bad file name")
    if not name.lower().endswith(ALLOWED_EXT):
        raise ValueError("Only .csv, .csv.gz, .zip, .xlsx, .txt or .tsv log exports are accepted. Save other formats as CSV first.")
    return name


def cache_count():
    try:
        with open(CACHE, encoding="utf-8") as f:
            return len(json.load(f))
    except Exception:
        return 0


def start_job(body):
    job = STATE["job"]
    if job and job.finished is None:
        raise ValueError("A run is already in progress")
    files = [os.path.join(UPLOADS, f["name"]) for f in list_files()]
    selected = body.get("files")
    if selected:
        files = [p for p in files if os.path.basename(p) in set(selected)]
    if not files:
        raise ValueError("Add at least one log export first")

    mode = "dry" if body.get("mode") == "dry" else "full"
    o = body.get("options") or {}

    def num(v, d):
        try:
            return max(0, int(v))
        except (TypeError, ValueError):
            return d

    opts = {
        "auth": "legacy" if body.get("auth") == "legacy" else "oneapi",
        "no_lookup": mode == "dry",
        "min_hits": max(1, num(o.get("min_hits"), 1)),
        "max_lookups": num(o.get("max_lookups"), 0),
        "all_actions": bool(o.get("all_actions")),
        "allow_pattern": o.get("allow_pattern") or "allow",
        "url_column": o.get("url_column") or None,
        "action_column": o.get("action_column") or None,
        "category_column": o.get("category_column") or None,
        "user_column": o.get("user_column") or None,
        "tenant_label": (o.get("tenant_label") or "").strip(),
        "base_url": o.get("base_url") or None,
        "out_dir": OUTPUT, "cache": CACHE,
    }
    try:
        re.compile(opts["allow_pattern"])
    except re.error:
        raise ValueError("The allowed-action pattern isn't a valid regular expression")

    env = core.env_creds()
    given = {k: (v or "").strip() for k, v in (body.get("creds") or {}).items()}
    creds = {k: given.get(k) or env.get(k) for k in env}   # form wins, env fills gaps

    job = Job(mode)
    STATE["job"] = job

    def work():
        try:
            job.summary = core.run(files, opts, creds, job)
            job.progress("done", note="Finished")
        except core.Stopped:
            job.log("Stopped. Lookups so far are saved; run again to continue.")
            job.progress("stopped", note="Stopped")
        except core.ApiError as e:
            job.error = str(e)
            job.log(f"Error: {e}")
            job.progress("error", note=str(e))
        except Exception as e:  # pragma: no cover
            job.error = f"{type(e).__name__}: {e}"
            job.log(traceback.format_exc())
            job.progress("error", note=job.error)
        finally:
            job.finished = time.time()
            creds.clear()

    threading.Thread(target=work, daemon=True).start()
    return job.snapshot()


class Handler(BaseHTTPRequestHandler):
    server_version = "ZIAImpact/1.1"

    def log_message(self, fmt, *args):
        pass

    # --- helpers ---
    def _host_ok(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost")

    def _auth_ok(self):
        return self._host_ok() and secrets.compare_digest(self.headers.get("X-Token", ""), TOKEN)

    def _json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _err(self, msg, code=400):
        self._json({"error": msg}, code)

    def _drain(self):
        left = int(self.headers.get("Content-Length") or 0) - getattr(self, "_consumed", 0)
        while left > 0:
            chunk = self.rfile.read(min(1 << 20, left))
            if not chunk:
                break
            left -= len(chunk)
        self._consumed = int(self.headers.get("Content-Length") or 0)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 1_000_000:
            raise ValueError("Request too large")
        return json.loads(self.rfile.read(n) or b"{}")

    def _file(self, path, ctype, download_name=None):
        if not os.path.exists(path):
            return self._err("Not found yet. Run a lookup first.", 404)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(os.path.getsize(path)))
        self.send_header("Cache-Control", "no-store")
        if download_name:
            self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
        self.end_headers()
        with open(path, "rb") as f:
            shutil.copyfileobj(f, self.wfile)

    # --- routes ---
    def do_GET(self):
        if not self._host_ok():
            return self._err("Forbidden", 403)
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "zia_impact_gui.html"), encoding="utf-8") as f:
                html = f.read().replace("__TOKEN__", TOKEN)
            b = html.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            return self.wfile.write(b)
        if u.path == "/download":
            # plain links can't send headers, so downloads carry the token in the query
            if not secrets.compare_digest((q.get("t") or [""])[0], TOKEN):
                return self._err("Forbidden", 403)
            f = (q.get("f") or [""])[0]
            if f == "results.json":
                return self._file(os.path.join(OUTPUT, "results.json"), "application/json", "results.json")
            if f == "domains.csv":
                return self._file(os.path.join(OUTPUT, "domains.csv"), "text/csv", "domains.csv")
            return self._err("Unknown file", 404)
        if not self._auth_ok():
            return self._err("This tab is from an earlier session of the tool. Reload the page.", 403)
        if u.path == "/api/state":
            env = core.env_creds()
            job = STATE["job"]
            return self._json({
                "files": list_files(),
                "env": {"oneapi": bool(env["client_id"] and env["client_secret"] and env["vanity"]),
                        "legacy": bool(env["username"] and env["password"] and env["api_key"] and env["legacy_cloud"]),
                        "vanity": env["vanity"] or "", "legacy_cloud": env["legacy_cloud"] or "",
                        "username": env["username"] or ""},
                "job": job.snapshot() if job else None,
                "has_results": os.path.exists(os.path.join(OUTPUT, "results.json")),
                "cache": cache_count(),
                "workspace": WORKSPACE,
            })
        if u.path == "/api/results":
            return self._file(os.path.join(OUTPUT, "results.json"), "application/json")
        return self._err("Not found", 404)

    def do_POST(self):
        self._consumed = 0
        if not self._auth_ok():
            self._drain()
            print(f"Refused {self.path.split('?')[0]}: " + ("wrong host " + str(self.headers.get('Host')) if not self._host_ok()
                  else "page from an earlier session (reload the browser tab)"), flush=True)
            return self._err("This tab is from an earlier session of the tool. Reload the page.", 403)
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        try:
            if u.path == "/api/upload":
                try:
                    name = safe_name((q.get("name") or [""])[0])
                except ValueError as e:
                    self._drain()
                    print(f"Refused upload {(q.get('name') or [''])[0]!r}: {e}", flush=True)
                    raise
                n = int(self.headers.get("Content-Length") or 0)
                os.makedirs(UPLOADS, exist_ok=True)
                dest = os.path.join(UPLOADS, name)
                tmp = dest + ".part"
                left = n
                try:
                    with open(tmp, "wb") as f:
                        while left > 0:
                            chunk = self.rfile.read(min(1 << 20, left))
                            if not chunk:
                                break
                            f.write(chunk)
                            left -= len(chunk)
                            self._consumed = n - left
                except OSError as e:
                    self._drain()
                    if os.path.exists(tmp):
                        os.remove(tmp)
                    print(f"Upload of {name} failed: {e}", flush=True)
                    return self._err(f"Couldn't save {name} in {UPLOADS}: {e.strerror or e}", 500)
                if left:
                    print(f"Upload of {name} was cut off ({n - left:,} of {n:,} bytes)", flush=True)
                    os.remove(tmp)
                    return self._err("Upload was cut off")
                os.replace(tmp, dest)
                print(f"Added {name} ({n:,} bytes)", flush=True)
                return self._json({"files": list_files()})
            if u.path == "/api/delete":
                body = self._body()
                job = STATE["job"]
                if job and job.finished is None:
                    return self._err("Wait for the current run to finish")
                if body.get("all"):
                    for f in list_files():
                        os.remove(os.path.join(UPLOADS, f["name"]))
                else:
                    p = os.path.join(UPLOADS, safe_name(body.get("name", "")))
                    if os.path.exists(p):
                        os.remove(p)
                return self._json({"files": list_files()})
            if u.path == "/api/clear-cache":
                job = STATE["job"]
                if job and job.finished is None:
                    return self._err("Wait for the current run to finish")
                if os.path.exists(CACHE):
                    os.remove(CACHE)
                return self._json({"cache": 0})
            if u.path == "/api/clientlog":
                print(f"[browser] {str(self._body().get('msg',''))[:500]}", flush=True)
                return self._json({"ok": True})
            if u.path == "/api/run":
                return self._json(start_job(self._body()))
            if u.path == "/api/stop":
                job = STATE["job"]
                if job and job.finished is None:
                    job.stop_event.set()
                    job.log("Stopping after the current request ...")
                return self._json({"ok": True})
        except ValueError as e:
            self._drain()
            return self._err(str(e))
        except Exception as e:
            self._drain()
            print(f"Error handling {u.path}: {e}", flush=True)
            return self._err(f"The tool hit an error: {e}", 500)
        self._drain()
        return self._err("Not found", 404)


def find_old_workspaces():
    """Workspaces left by earlier versions, which created one in whatever folder the tool was started from."""
    seen, out = set(), []
    roots = [os.getcwd(), HERE, os.path.dirname(HERE), os.path.expanduser("~"),
             os.path.join(os.path.expanduser("~"), "Downloads"), os.path.join(os.path.expanduser("~"), "Desktop"),
             os.path.join(os.path.expanduser("~"), "Documents")]
    for root in roots:
        if not os.path.isdir(root):
            continue
        base_depth = root.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, _ in os.walk(root):
            depth = dirpath.count(os.sep) - base_depth
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in ("node_modules", "Library", "AppData")]
            if depth >= 3:
                dirnames[:] = []
            if os.path.basename(dirpath) == "zia_impact_workspace":
                real = os.path.realpath(dirpath)
                if real not in seen and real != os.path.realpath(WORKSPACE):
                    seen.add(real)
                    out.append(dirpath)
                dirnames[:] = []
    return out


def import_old_workspaces():
    """Copy logs, cached lookups and the latest results from older workspaces into the fixed one."""
    marker = os.path.join(WORKSPACE, ".imported.json")
    try:
        with open(marker, encoding="utf-8") as f:
            done = set(json.load(f))
    except Exception:
        done = set()
    olds = [o for o in find_old_workspaces() if os.path.realpath(o) not in done]
    if not olds:
        return
    cache = {}
    try:
        with open(CACHE, encoding="utf-8") as f:
            cache = json.load(f)
    except Exception:
        pass
    before = len(cache)
    logs = 0
    newest_out = None
    for old in olds:
        try:
            with open(os.path.join(old, "lookup_cache.json"), encoding="utf-8") as f:
                for k, v in json.load(f).items():
                    if k not in cache or (cache[k].get("missing") and not v.get("missing")):
                        cache[k] = v
        except Exception:
            pass
        od = os.path.join(old, "logs")
        if os.path.isdir(od):
            for n in os.listdir(od):
                src, dst = os.path.join(od, n), os.path.join(UPLOADS, n)
                if os.path.isfile(src) and not n.endswith(".part") and not os.path.exists(dst):
                    shutil.copy2(src, dst)
                    logs += 1
        res = os.path.join(old, "output", "results.json")
        if os.path.exists(res) and (newest_out is None or os.path.getmtime(res) > os.path.getmtime(newest_out[0])):
            newest_out = (res, os.path.join(old, "output"))
    if len(cache) > before:
        tmp = CACHE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cache, f)
        os.replace(tmp, CACHE)
    copied_results = False
    if newest_out and not os.path.exists(os.path.join(OUTPUT, "results.json")):
        for n in ("results.json", "domains.csv"):
            if os.path.exists(os.path.join(newest_out[1], n)):
                shutil.copy2(os.path.join(newest_out[1], n), os.path.join(OUTPUT, n))
        copied_results = True
    with open(marker, "w", encoding="utf-8") as f:
        json.dump(sorted(done | {os.path.realpath(o) for o in olds}), f)
    if logs or len(cache) > before or copied_results:
        print(f"Brought over earlier work from {len(olds)} older workspace folder(s): "
              f"{logs} log file(s), {len(cache) - before:,} cached lookups"
              + (", latest results" if copied_results else "") + ". The old folders were left as they were.")


def main():
    ap = argparse.ArgumentParser(description="Local GUI for the ZIA category impact tool")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port to listen on (default {DEFAULT_PORT}; the next free one if busy)")
    ap.add_argument("--no-browser", action="store_true", help="don't open a browser tab")
    args = ap.parse_args()
    if not os.path.exists(os.path.join(HERE, "zia_impact_gui.html")):
        raise SystemExit("zia_impact_gui.html must sit next to this script")
    os.makedirs(UPLOADS, exist_ok=True)
    os.makedirs(OUTPUT, exist_ok=True)
    try:
        import_old_workspaces()
    except Exception as e:
        print(f"(Couldn't check for older workspaces: {e})")
    srv = None
    for port in ([args.port] + list(range(args.port + 1, args.port + 20)) if args.port else [0]):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            break
        except OSError:
            continue
    if srv is None:
        raise SystemExit(f"Ports {args.port}-{args.port + 19} are all in use. Is the tool already running in another window?")
    if args.port and srv.server_address[1] != args.port:
        print(f"Port {args.port} is busy (another copy of the tool may be running); using {srv.server_address[1]}. "
              "Saved lists and settings belong to the usual address, so close the other copy to see them.")
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    print(f"ZIA Category Impact is running at {url}")
    print(f"Your logs, lookup cache and results are kept in: {WORKSPACE}")
    nfiles = len(list_files())
    if nfiles or cache_count():
        print(f"  {nfiles} log file(s) and {cache_count():,} cached lookups ready")
    print("Press Ctrl+C here to quit.")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        job = STATE["job"]
        if job and job.finished is None:
            job.stop_event.set()
            time.sleep(1.5)
        print("\nBye.")


if __name__ == "__main__":
    main()
