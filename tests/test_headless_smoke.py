"""Headless-Chromium runtime smoke — catches the class of JS bug the static gate CANNOT.

The static/`node` JS tests parse and behaviourally exercise individual helpers, but they
run against a *stub* Chart and can't see a real browser executing the whole page: the
1.8.10 "every dashboard hung at 'connecting…'" incident was `wireLegendFullName()` recursing
infinitely on Chart.js v4.4's reactive-options proxy — a RUNTIME error no static check saw.

These tests load each real dashboard page in headless Chromium against a live in-process
server (real bundled assets, a seeded /api/data snapshot), and assert the page's JS ran to
completion without a fatal console error (`RangeError: Maximum call stack size exceeded`,
any `Uncaught`) and that charts actually mounted. Skipped when chromium is absent (local
runs without it, and the emulated RUN_TESTS=0 cross-arch build) — the in-image gate installs
chromium so a native `docker build` runs them for real.
"""
import asyncio
import re
import shutil
import subprocess
import tempfile
import time
import urllib.parse

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

import app as appmod
import auth
import config
import db


@web.middleware
async def _no_sse(request, handler):
    """Short-circuit the long-lived SSE so headless Chromium's page-load (and `--dump-dom`)
    can complete — the persistent /api/stream response otherwise holds the load open forever.
    Chart creation (where the legend-hang bug fires) runs on the first /api/data tick, which is
    unaffected; the frontend falls back to polling when the stream isn't a live event source."""
    if request.path == "/api/stream":
        return web.Response(status=204)
    return await handler(request)

CHROME = (shutil.which("chromium") or shutil.which("chromium-browser")
          or shutil.which("google-chrome"))

pytestmark = pytest.mark.skipif(not CHROME, reason="chromium not available for headless smoke")

# Dashboards that build Chart.js charts and render without external backend config. The
# legend-hang class lives in the SHARED aimon-core.js every dashboard loads, so these cover it;
# /spend is omitted because it hard-404s until LiteLLM is configured (not a JS concern).
PAGES = ["/", "/litellm", "/vllm", "/alerts"]

# A console line that means the page's JS aborted mid-run — the exact failure signature of the
# legend-hang class (infinite recursion → stack overflow) plus any other uncaught exception.
# Match GENUINE page JS-error phrases. The bare word "Unhandled" must NOT be here: some Chromium
# builds dump internal telemetry (Histogram: lines whose metric names contain "Unhandled") to
# stderr under --v=1, and a bare-word match false-positived on that noise (CI flake). The real JS
# signature is "Unhandled (promise) rejection". "Uncaught" stays broad — it's JS-specific and has
# never collided with telemetry, and narrowing it would miss "Uncaught (in promise) …" forms.
_FATAL_JS = re.compile(
    r"Maximum call stack size exceeded|\bUncaught\b|Unhandled(?: promise)? rejection|"
    r"is not a function|is not defined|SyntaxError",
    re.IGNORECASE)


def _seed_latest():
    """A snapshot rich enough that /api/data drives real chart creation on every page under
    test — the legend wiring only runs once a chart is built, so empty data wouldn't exercise it."""
    appmod._latest = {"ts": 1.0, "collectors": {
        "host": {"available": True, "ncpu": 8, "cpu_pct": 12.0, "mem_pct": 40.0,
                 "cpu_per_core": [10.0] * 8},
        "litellm": {"available": True, "spend_mode": "full", "requests": 42, "tokens": 1000,
                    "per_model": [{"model": "azure/gpt-x", "requests": 30, "tokens": 800},
                                  {"model": "vllm/local", "requests": 12, "tokens": 200}],
                    "top_keys": [{"key": "hA", "alias": "alice", "reqs": 20},
                                 {"key": "hB", "alias": "bob", "reqs": 22}]},
        "vllm": {"available": True, "model": "local", "running": 2, "waiting": 1,
                 "multi_model": False},
    }}


def _render(url: str) -> tuple[str, str]:
    """Load `url` in headless Chromium, dumping the post-run DOM to stdout and console/JS
    errors to stderr. Bounded by a virtual-time budget (so a genuine infinite hang can't wedge
    the build) and a hard subprocess timeout."""
    assert CHROME                                 # guaranteed by the module-level skipif
    # Isolated per-render profile: without --user-data-dir, concurrent/back-to-back Chromium
    # invocations contend on (and lock) the shared DEFAULT profile dir → the subprocess hangs to
    # its 90s timeout under load. A throwaway dir per render removes that contention entirely.
    with tempfile.TemporaryDirectory(prefix="aimon-smoke-") as _profile:
        p = subprocess.run(
            [CHROME, "--headless=new", "--no-sandbox", "--disable-gpu",
             "--disable-dev-shm-usage", f"--user-data-dir={_profile}",
             "--enable-logging=stderr", "--v=1",
             "--no-first-run", "--disable-background-networking", "--disable-component-update",
             "--disable-sync", "--disable-default-apps",
             "--virtual-time-budget=8000", "--run-all-compositor-stages-before-draw",
             "--dump-dom", url],
            capture_output=True, text=True, timeout=90)
    return p.stdout, p.stderr


async def test_dashboards_render_without_fatal_js(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "smoke.db"))
    # Auth ENABLED (not open mode): /alerts is denied outright in open mode, so we
    # instead authenticate every page load with a scoped admin PAT via ?token= —
    # the sensitive-surface gate allows a scoped PAT on /alerts (only the shared
    # master token is withheld there). The pages forward it as a Bearer on API calls.
    monkeypatch.setattr(config, "ALLOW_OPEN", False)
    db.init()
    _seed_latest()
    db.user_create("smoke", "smoke@example.com",
                   auth.hash_password("smokepw123"), "admin", time.time())
    _raw, _tid, _prefix = appmod._new_pat()
    db.api_token_create(_tid, "smoke", "admin", "smoke",
                        appmod._hash_token(_raw), _prefix, time.time())
    _tokq = "?token=" + urllib.parse.quote(_raw)
    smoke_app = appmod.build_app()
    smoke_app.middlewares.append(_no_sse)     # let the headless page-load actually finish
    server = TestServer(smoke_app)
    await server.start_server()
    # Kill the background sampler so it can't rebind _latest out from under the seeded snapshot.
    app = server.app
    for _t in app.get(appmod._BACKENDS, []) or []:
        _t.cancel()
    for _key in (appmod._SAMPLER, appmod._MU_BACKFILL):
        _t = app.get(_key)
        if _t is not None:
            _t.cancel()
    try:
        for page in PAGES:
            url = str(server.make_url(page)) + _tokq
            # to_thread: chromium blocks, but the server shares THIS event loop and must stay
            # free to answer chromium's own HTTP requests — a blocking subprocess.run would deadlock.
            dom, err = await asyncio.to_thread(_render, url)
            hit = _FATAL_JS.search(err)
            assert not hit, f"{page}: fatal JS console error: {hit.group(0)!r}\n{err[-800:]}"
            # The page actually rendered (charts mounted) — not a blank/error shell.
            assert "<canvas" in dom.lower(), f"{page}: no chart canvas in rendered DOM"
    finally:
        await server.close()
