"""The toolkit's single Zscaler lookup engine (Category Impact's client, rate limiter and cache), used by every tool."""
import json
import os
import sys
from types import SimpleNamespace

import creds
import shared

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "category_impact"))
import zia_category_impact as core  # noqa: E402

core.env_creds = creds.as_impact   # Category Impact now reads the toolkit's credentials, not its own environment variables


def _with_overrides(fn):
    """ZIA_TOKEN_URL / ZIA_API_BASE (testing, non-standard clouds) apply to every tool, including Category Impact."""
    def wrapped(opts, creds_, ctx):
        if os.environ.get("ZIA_TOKEN_URL") and not getattr(opts, "token_url", None):
            opts.token_url = os.environ["ZIA_TOKEN_URL"]
        if os.environ.get("ZIA_API_BASE") and not getattr(opts, "base_url", None):
            opts.base_url = os.environ["ZIA_API_BASE"]
        return fn(opts, creds_, ctx)
    return wrapped


core.oneapi_client = _with_overrides(core.oneapi_client)
core.legacy_client = _with_overrides(core.legacy_client)


class Ctx(core.Context):
    def __init__(self, progress=None):
        super().__init__()
        self._cb = progress
        self.messages = []

    def log(self, msg):
        self.messages.append(str(msg))

    def progress(self, phase, done=None, total=None, note=None):
        if self._cb and phase == "lookup" and total:
            self._cb(done or 0, total)


def open_client(ctx):
    c = creds.status()
    opts = SimpleNamespace(token_url=None, base_url=None)
    if c["oneapi"]:
        return core.oneapi_client(opts, creds.as_impact(), ctx)
    if c["legacy"]:
        return core.legacy_client(opts, creds.as_impact(), ctx)
    raise core.ApiError("No Zscaler API credentials. Add them on the dashboard or in the .env file.")


def catalog(client, ctx):
    """id -> {'name', 'super'} for every category, with friendly names from zia_category_names.json."""
    labels = {}
    lf = os.path.join(HERE, "zia_category_names.json")
    if os.path.exists(lf):
        labels = json.load(open(lf))
    names, _custom, supers = core.fetch_category_catalog(client, ctx)
    out = dict(labels)
    for cid, nm in names.items():
        lab = labels.get(cid, {})
        name = nm if nm and nm != cid else (lab.get("name") or str(cid).replace("_", " ").title())
        sup = lab.get("super") or (supers.get(cid) or "").replace("_", " ").title()
        out[cid] = {"name": name, "super": sup}
    return out


def lookup(hosts, client, ctx):
    """Look up hosts through the shared cache. Returns ({host: {cats, sec, app, app_class, err}}, cache_hits)."""
    cache = core.load_cache(shared.CACHE)
    # entries written by older Category Impact runs have no application data; refresh those once
    for h in list(cache):
        e = cache[h]
        if "app" not in e and not e.get("invalid") and not e.get("missing"):
            del cache[h]
    wanted = [h.lower().rstrip(".") for h in hosts]
    hits = sum(1 for h in wanted if h in cache)
    os.makedirs(shared.WORKSPACE, exist_ok=True)
    core.lookup_all(client, wanted, cache, shared.CACHE, 0, ctx)
    out = {}
    for orig, h in zip(hosts, wanted):
        e = cache.get(h) or {}
        err = "can't be looked up" if e.get("invalid") else ("not returned by Zscaler" if e.get("missing") or not e else "")
        out[orig] = {"cats": e.get("c", []), "sec": e.get("s", []), "app": e.get("app", ""),
                     "app_class": e.get("appc", ""), "err": err}
    return out, hits
