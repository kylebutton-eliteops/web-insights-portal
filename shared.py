"""Paths and the lookup cache shared by every tool in the toolkit.

One cache file (host -> Zscaler categories + application) so a host looked up in one tool is never looked up again
by the other. The format is Category Impact's own cache, plus 'app'/'appc' keys that the Insights portal reads.
"""
import json
import os
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
# Everything is kept directly in the folder the toolkit runs from: logs/ (exports library), output/ (results) and
# lookup_cache.json. Set ZIA_TOOLKIT_WORKSPACE to keep them somewhere else.
WORKSPACE = os.environ.get("ZIA_TOOLKIT_WORKSPACE") or os.environ.get("ZIA_IMPACT_WORKSPACE") or HERE
os.environ["ZIA_IMPACT_WORKSPACE"] = WORKSPACE        # Category Impact reads this when imported
CACHE = os.path.join(WORKSPACE, "lookup_cache.json")
LOCK = threading.Lock()


def load():
    try:
        with open(CACHE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save(cache):
    os.makedirs(WORKSPACE, exist_ok=True)
    with LOCK:
        tmp = CACHE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cache, f)
        os.replace(tmp, CACHE)


def count():
    return len(load())


def clear():
    if os.path.exists(CACHE):
        os.remove(CACHE)
