# Dynamic QA — runs the real aiohttp app + real collectors against a stub
# backend server. Proves: endpoints serve, auth gate works, host metrics are
# live, unconfigured backends degrade gracefully, and each collector parses
# real JSON responses correctly.
import asyncio
import pathlib

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
import re
import time

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import app as appmod
import config
import db
import auth
import alerts
import anomaly
from collectors import host, litellm, ollama, llamacpp, gpu, procs, vllm, network


# ------------------------------------------------------------- app endpoints --
async def _client():
    db.init()
    c = TestClient(TestServer(appmod.build_app()))
    await c.start_server()
    # Kill the background sampler tasks immediately: they rebind the module-global
    # appmod._latest on their own cadence, which races (and cross-test pollutes) the
    # many nav/config tests that monkeypatch _latest for deterministic assertions
    # (e.g. a stale gpu/litellm "unconfigured" note stripping a link that should
    # show). Tests that exercise the loops call them directly, not via _client().
    app = c.app
    for _t in app.get(appmod._BACKENDS, []) or []:
        _t.cancel()
    for _key in (appmod._SAMPLER, appmod._MU_BACKFILL):    # sampler + one-time backfill task
        _t = app.get(_key)
        if _t is not None:
            _t.cancel()
    return c


async def test_healthz_open_and_ok():
    """/healthz stays OPEN and 200 (the container HEALTHCHECK depends on it), but an
    ANONYMOUS caller gets liveness only — no build version (see
    test_healthz_hides_version_from_anonymous)."""
    c = await _client()
    try:
        r = await c.get("/healthz")
        assert r.status == 200
        body = await r.json()
        assert "version" not in body        # no CVE-matching hint for anonymous callers
        assert body["status"] in ("ok", "starting")
    finally:
        await c.close()


async def test_healthz_hides_version_from_anonymous(monkeypatch):
    """/healthz must stay an OPEN 200 liveness probe, but the build version + sample count
    are AUTHENTICATED-only. An open endpoint naming the exact version lets an attacker
    match known CVEs for free — the `Server` header omits it for the same reason. A valid
    token still sees both (operators need them)."""
    tok = "healthz-probe-token-123456"
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", tok)
    c = await _client()
    try:
        r = await c.get("/healthz")                       # anonymous
        assert r.status == 200                            # probe must never be gated
        anon = await r.json()
        assert anon["status"] in ("ok", "starting")
        assert "version" not in anon and "samples" not in anon
        authed = await (await c.get(
            "/healthz", headers={"Authorization": f"Bearer {tok}"})).json()
        assert authed["version"] == config.VERSION
        assert "samples" in authed
    finally:
        await c.close()


async def test_data_endpoint_shape():
    c = await _client()
    try:
        r = await c.get("/api/data?history=1")
        assert r.status == 200
        d = await r.json()
        assert d["version"] == config.VERSION
        assert "latest" in d and "history" in d
        assert "collectors" in d["latest"]
    finally:
        await c.close()


async def test_index_and_assets_served():
    c = await _client()
    try:
        r = await c.get("/")
        assert r.status == 200
        html = await r.text()
        assert "AI-Monitoring" in html and "card-host" in html
        a = await c.get("/assets/chart.umd.min.js")
        assert a.status == 200
    finally:
        await c.close()


def test_serve_page_accepts_user_and_role_kwargs():
    # Regression (1.4.0): every page handler calls _serve_page(path, prefix,
    # user=, role=); a wrapper/caller that drops those kwargs returns 500 on
    # every page (this is exactly what broke scripts/demo_seed.py). Guard the
    # signature + that the user/role path renders (admin sidebar injected).
    resp = appmod._serve_page(appmod._WEB / "index.html", "",
                              user="alice", role="admin")
    assert isinstance(resp, web.Response) and resp.status == 200
    body = resp.text or ""
    assert "card-llm-summary" in body          # the new overview strip
    assert "Users" in body                     # admin-only sidebar link injected
    # anonymous (no user/role) must also render, not error
    anon = appmod._serve_page(appmod._WEB / "index.html", "")
    assert anon.status == 200 and "Users" not in (anon.text or "")


def test_serve_page_injects_currency(monkeypatch):
    """MONITOR_CURRENCY (default $) is injected as a nonce'd `window.CUR` global into every
    dashboard page so the JS money helpers render the operator's currency (e.g. €)."""
    monkeypatch.setattr(config, "CURRENCY", "€")
    body = appmod._serve_page(appmod._WEB / "spend.html", "", user="a", role="admin").text or ""
    assert 'window.CUR="\\u20ac"' in body                       # € injected (json-escaped)
    assert re.search(r'<script nonce="[^"]+">window\.CUR=', body)   # nonce'd → CSP allows it
    monkeypatch.setattr(config, "CURRENCY", "$")
    body2 = appmod._serve_page(appmod._WEB / "spend.html", "", user="a", role="admin").text or ""
    assert 'window.CUR="$"' in body2                            # default is $


def test_overview_summary_hidden_when_litellm_unconfigured():
    # The LLM cost/usage strip must not leave an empty panel on a pure-infra
    # deployment: it is display:none by default and only shown by JS when the
    # LiteLLM backend is configured (showCard(..., isConfigured(l))).
    html = (appmod._WEB / "index.html").read_text(encoding="utf-8")
    i = html.find('id="card-llm-summary"')
    assert i > 0
    # the element ships hidden (JS reveals it only when configured)
    tag = html[i:html.find(">", i)]
    assert "display:none" in tag
    assert 'showCard("card-llm-summary", isConfigured(l))' in html


async def test_litellm_page_served_and_gated(monkeypatch):
    c = await _client()
    try:
        r = await c.get("/litellm")
        assert r.status == 200
        html = await r.text()
        assert "LiteLLM" in html and "chart-grid" in html
    finally:
        await c.close()
    # with a token set, /litellm is auth-gated like /
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "tok-litellm-1")
    c2 = await _client()
    try:
        r2 = await c2.get("/litellm", allow_redirects=False)
        assert r2.status == 302 and "/login" in r2.headers.get("Location", "")
        r = await c2.get("/litellm?token=tok-litellm-1", allow_redirects=False)
        assert r.status == 302  # token -> cookie redirect
        assert "aimon_session=" in r.headers.get("Set-Cookie", "")
    finally:
        await c2.close()


async def test_ollama_page_served_and_gated(monkeypatch):
    c = await _client()
    try:
        r = await c.get("/ollama")
        assert r.status == 200
        html = await r.text()
        assert "Ollama" in html and "chart-grid" in html
    finally:
        await c.close()
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "tok-ol-1")
    c2 = await _client()
    try:
        r2 = await c2.get("/ollama", allow_redirects=False)
        assert r2.status == 302 and "/login" in r2.headers.get("Location", "")
        r = await c2.get("/ollama?token=tok-ol-1", allow_redirects=False)
        assert r.status == 302
    finally:
        await c2.close()


async def test_llamacpp_page_served_and_gated(monkeypatch):
    monkeypatch.setattr(config, "LLAMACPP_BASE_URL", "http://lc:8080")  # so its nav link stays
    monkeypatch.setattr(appmod, "_latest", {"ts": 0, "collectors": {}})
    c = await _client()
    try:
        r = await c.get("/llamacpp")
        assert r.status == 200
        html = await r.text()
        assert "llama.cpp" in html and "chart-grid" in html
        # the KPI + model cards the page renders into
        assert 'id="l-kpis"' in html and 'id="l-model"' in html
        # nav link back-references present on the dedicated page
        assert 'href="/llamacpp"' in html
    finally:
        await c.close()
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "tok-lc-1")
    c2 = await _client()
    try:
        r2 = await c2.get("/llamacpp", allow_redirects=False)
        assert r2.status == 302 and "/login" in r2.headers.get("Location", "")
        r = await c2.get("/llamacpp?token=tok-lc-1", allow_redirects=False)
        assert r.status == 302
    finally:
        await c2.close()


async def test_nav_includes_llamacpp(monkeypatch):
    # unconfigured → hidden; env URL set → shown (mirrors ollama/litellm)
    monkeypatch.setattr(appmod, "_latest", {"ts": 0, "collectors": {}})
    assert appmod._configured("llamacpp", False) is False
    assert appmod._configured("llamacpp", True) is True
    # configured-but-DOWN keeps the link (real error != unconfigured)
    monkeypatch.setattr(appmod, "_latest", {"ts": 1, "collectors": {
        "llamacpp": {"available": False, "error": "conn: ClientError"}}})
    assert appmod._configured("llamacpp", False) is True


def test_llamacpp_series_keys_present():
    # the charts on /llamacpp read these series keys — guard the contract
    # deterministically against the row builder (no dependency on stored samples).
    import app as a
    snap = {"ts": 0, "collectors": {
        "host": {"available": True, "cpu_pct": 1, "mem_pct": 1,
                 "disk": {"pct": 1}, "load": [0, 0, 0]},
        "gpu": {"available": False}, "ollama": {"available": False},
        "litellm": {"available": False},
        "llamacpp": {"available": True, "slots_active": 1,
                     "predicted_per_second": 55, "kv_cache_pct": 40}}}
    row = a._metrics_row(snap)
    for k in ("tok", "slots", "kvcache"):
        assert k in row, f"series point missing llama.cpp key {k!r}"
    assert row["tok"] == 55 and row["slots"] == 1 and row["kvcache"] == 40


async def test_auth_rate_limit_locks_out(monkeypatch):
    import app as a
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "supersecrettoken1234")
    monkeypatch.setattr(config, "AUTH_MAX_FAILS", 3)
    monkeypatch.setattr(config, "AUTH_LOCKOUT_S", 900.0)
    a._auth_fails.clear(); a._auth_locked_until.clear()
    c = await _client()
    try:
        for _ in range(3):
            assert (await c.get("/api/data?token=wrong")).status == 401
        r = await c.get("/api/data?token=wrong")          # 4th → locked
        assert r.status == 429 and r.headers.get("Retry-After")
        # a WRONG token stays refused while the IP is locked
        assert (await c.get("/api/data?token=wrong")).status == 429
        # F-1 fix: a CORRECT token is HONOURED even from a locked IP — the lockout gates
        # FAILED auth only. (Was 429: a shared proxy/tunnel IP let one attacker DoS everyone.)
        assert (await c.get("/api/data?token=supersecrettoken1234")).status == 200
    finally:
        a._auth_fails.clear(); a._auth_locked_until.clear()
        await c.close()


async def test_lockout_never_denies_a_valid_credential_pentest_f1(monkeypatch):
    """PENTEST F-1 (shared-IP lockout DoS): behind a reverse proxy / tunnel with
    AUTH_TRUSTED_PROXY=0, every client shares one source IP, so an attacker spamming bad
    tokens could lock out ALL legitimate users. The brute-force lockout must gate FAILED auth
    only — a request that presents a VALID token/session is always served, so the attacker
    can no longer deny service to the clients sharing that IP. Direct-exposure lockout of
    WRONG attempts is unchanged."""
    import app as a
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "supersecrettoken1234")
    monkeypatch.setattr(config, "AUTH_MAX_FAILS", 5)
    a._auth_fails.clear(); a._auth_locked_until.clear()
    c = await _client()
    try:
        # attacker locks the shared IP
        for _ in range(6):
            await c.get("/api/data?token=attacker-guess")
        assert (await c.get("/api/data?token=attacker-guess")).status == 429, "IP must be locked"
        # legitimate client on the SAME IP, holding the real token, is still served
        assert (await c.get("/api/data?token=supersecrettoken1234")).status == 200, \
            "F-1: a valid credential must never be denied by the lockout"
    finally:
        a._auth_fails.clear(); a._auth_locked_until.clear()
        await c.close()


async def test_auth_success_clears_fail_counter(monkeypatch):
    import app as a
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "supersecrettoken1234")
    monkeypatch.setattr(config, "AUTH_MAX_FAILS", 3)
    a._auth_fails.clear(); a._auth_locked_until.clear()
    c = await _client()
    try:
        assert (await c.get("/api/data?token=wrong")).status == 401
        assert (await c.get("/api/data?token=wrong")).status == 401
        # a good token clears the counter, so no lockout builds up
        assert (await c.get("/api/data?token=supersecrettoken1234")).status == 200
        assert (await c.get("/api/data?token=wrong")).status == 401   # not 429
    finally:
        a._auth_fails.clear(); a._auth_locked_until.clear()
        await c.close()


def test_weak_token_flagged_by_selfcheck(monkeypatch):
    import app as a
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "short")
    assert any("weak dashboard token" in p for p in a.startup_selfcheck())
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "a" * 20)
    assert not any("weak dashboard token" in p for p in a.startup_selfcheck())


async def test_stream_sse_pushes_snapshot():
    import json as _json
    c = await _client()
    try:
        resp = await c.get("/api/stream")
        assert resp.status == 200
        assert resp.headers["Content-Type"].startswith("text/event-stream")
        chunk = await asyncio.wait_for(resp.content.read(8192), 8)
        assert chunk.startswith(b"data: ")
        payload = _json.loads(chunk.split(b"data: ", 1)[1].split(b"\n\n", 1)[0])
        assert "collectors" in payload and "ts" in payload
        resp.close()
    finally:
        await c.close()


async def test_gpu_page_served_and_gated(monkeypatch):
    c = await _client()
    try:
        r = await c.get("/gpu")
        assert r.status == 200
        html = await r.text()
        assert "GPU" in html and "chart-grid" in html
    finally:
        await c.close()
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "tok-gpu-1")
    c2 = await _client()
    try:
        r2 = await c2.get("/gpu", allow_redirects=False)
        assert r2.status == 302 and "/login" in r2.headers.get("Location", "")
        r = await c2.get("/gpu?token=tok-gpu-1", allow_redirects=False)
        assert r.status == 302
        assert "aimon_session=" in r.headers.get("Set-Cookie", "")
    finally:
        await c2.close()


async def test_auth_gate(monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "secrettoken")
    c = await _client()
    try:
        # data endpoint blocked without token
        assert (await c.get("/api/data")).status == 401
        # allowed with bearer
        r = await c.get("/api/data",
                        headers={"Authorization": "Bearer secrettoken"})
        assert r.status == 200
        # allowed with ?token=
        assert (await c.get("/api/data?token=secrettoken")).status == 200
        # healthz always open (container probe)
        assert (await c.get("/healthz")).status == 200
        # static assets MUST stay open even with a token set, else the browser
        # (which loads assets without ?token) 401s and the page renders blank.
        assert (await c.get("/assets/chart.umd.min.js")).status == 200
    finally:
        await c.close()


# --------------------------------------------------- reverse-proxy sub-path ----
async def test_subpath_prefix_rewrites_links():
    """With X-Forwarded-Prefix, served HTML links/fetches are prefixed; without
    it, HTML is unchanged (root mount). Proves Apache `ProxyPass /ai_monitoring/`
    works without breaking the default root deployment."""
    c = await _client()
    try:
        P = "/ai_monitoring"
        r = await c.get("/", headers={"X-Forwarded-Prefix": P})
        assert r.status == 200
        h = await r.text()
        # nav links, assets, and JS fetches all carry the prefix
        assert f'href="{P}/litellm"' in h
        assert f'src="{P}/assets/' in h
        assert f'fetch("{P}/api/' in h
        assert f'api("{P}/api/' in h
        # nav-hide / alert-dot selectors match the rewritten hrefs
        assert f'a[href="{P}/' in h
        # no un-prefixed absolute API path leaks through
        assert 'fetch("/api/' not in h and 'api("/api/' not in h
        # root mount (no header) is byte-for-byte the original
        r2 = await c.get("/")
        h2 = await r2.text()
        assert 'href="/litellm"' in h2 and f'href="{P}/litellm"' not in h2
        # login form POST target must carry the prefix, else the login submit
        # escapes the sub-path and hits the proxy root ("/login" → 404).
        rl = await c.get("/login", headers={"X-Forwarded-Prefix": P})
        hl = await rl.text()
        assert f'action="{P}/login"' in hl, "login form action not prefixed"
        assert 'action="/login"' not in hl
        # unprefixed login page keeps the bare action (root mount unchanged)
        rl2 = await c.get("/login")
        assert 'action="/login"' in (await rl2.text())
    finally:
        await c.close()


async def test_subpath_prefix_validation_and_redirect(monkeypatch):
    """Malformed X-Forwarded-Prefix is ignored (injection guard); a valid one is
    honored in the cookie-redirect Location so auth lands on the right URL."""
    # injection attempt must NOT appear in output → treated as root mount
    c = await _client()
    try:
        r = await c.get("/", headers={"X-Forwarded-Prefix": '/x"><script>'})
        h = await r.text()
        assert "<script>x" not in h and '/x"' not in h
    finally:
        await c.close()
    # valid prefix → redirect Location keeps it
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "tok-pfx-1")
    c2 = await _client()
    try:
        r = await c2.get("/litellm?token=tok-pfx-1", allow_redirects=False,
                         headers={"X-Forwarded-Prefix": "/ai_monitoring"})
        assert r.status == 302
        assert r.headers["Location"] == "/ai_monitoring/litellm"
    finally:
        await c2.close()


async def test_litellm_heavy_calls_are_throttled(monkeypatch):
    """The heavy /spend/logs call must NOT be re-hit every sample — it polls on
    LITELLM_HEAVY_INTERVAL and reuses the cached result in between, so a busy
    proxy isn't hammered. Backlog (cheap) still refreshes every tick."""
    hits = {"spend": 0, "backlog": 0}

    async def _s(_r): hits["spend"] += 1; return web.json_response([])

    async def _b(_r): hits["backlog"] += 1; return web.json_response(
        {"in_flight_requests": 3})

    async def _live(_r): return web.json_response({"status": "healthy"})
    async def _models(_r): return web.json_response({"data": []})

    app = web.Application()
    app.router.add_get("/health/liveliness", _live)
    app.router.add_get("/v1/models", _models)
    app.router.add_get("/health/backlog", _b)
    app.router.add_get("/spend/logs", _s)
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LITELLM_BASE_URL",
                            str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LITELLM_BACKLOG_PROBE_SELFCOUNT", False)
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 9999)  # never re-fetch
        async with aiohttp.ClientSession() as s:
            await litellm.sample(s)          # tick 1: heavy runs once
            await litellm.sample(s)          # tick 2: heavy cached
            r3 = await litellm.sample(s)      # tick 3: heavy cached
        # /spend hit once across 3 samples; backlog (cheap) every time
        assert hits["spend"] == 1, hits
        assert hits["backlog"] == 3, hits
        assert r3["backlog"] == 3            # cached heavy fields still surface
    finally:
        await srv.close()


async def test_litellm_heavy_sample_surfaces_known_keys(monkeypatch):
    """_heavy_sample() piggy-backs collectors.litellm.key_budgets() (/key/list) onto the
    same HEAVY cadence as /spend/logs and surfaces the confirmed aliases as
    `known_keys` — the write side that lets the by-key charts fold a real-but-INVALID
    auth attempt into 'Other' (db.known_keys_upsert/known_keys_set, config.key_known).
    A /key/list failure must NOT crash the sample or drop the rest of the heavy fields."""
    async def _live(_r): return web.json_response({"status": "healthy"})
    async def _models(_r): return web.json_response({"data": []})
    async def _backlog(_r): return web.json_response({"in_flight_requests": 1})
    async def _spend(_r): return web.json_response([])

    async def _keylist(r):
        if int(r.query.get("page", "1")) > 1:
            return web.json_response({"keys": []})
        return web.json_response({"keys": [
            {"key_alias": "alex-batista", "max_budget": 10.0, "spend": 1.0},
            {"key_alias": "claude-code", "max_budget": 0, "spend": 0.5},
        ], "total_pages": 1})

    app = web.Application()
    app.router.add_get("/health/liveliness", _live)
    app.router.add_get("/v1/models", _models)
    app.router.add_get("/health/backlog", _backlog)
    app.router.add_get("/spend/logs", _spend)
    app.router.add_get("/key/list", _keylist)
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LITELLM_BASE_URL", str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LITELLM_BACKLOG_PROBE_SELFCOUNT", False)
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 9999)
        litellm._KEY_BUDGETS_CACHE = None                # isolate from other tests
        async with aiohttp.ClientSession() as s:
            out = await litellm.sample(s)
        assert set(out.get("known_keys") or []) == {"alex-batista", "claude-code"}
    finally:
        await srv.close()


async def test_heavy_sample_skips_key_list_walk_under_freeze_gates(monkeypatch):
    """Review-fix: the /key/list (+/team/list +/user/list) management walk in key_budgets is a
    HEAVY pull (~100 sequential requests) — no cheaper than /spend/logs — so it must honour the
    SAME freeze gates: skipped when the circuit breaker is open, under load-shed, or in 'off'
    mode. Guards against the ungated-walk regression that hammered a proxy the operator had
    explicitly configured (off/load-shed) to protect."""
    hits = {"keylist": 0}
    async def _live(_r): return web.json_response({"status": "healthy"})
    async def _models(_r): return web.json_response({"data": []})
    async def _backlog(_r): return web.json_response({"in_flight_requests": 0})
    async def _spend(_r): return web.json_response([])
    async def _keylist(r):
        hits["keylist"] += 1
        return web.json_response({"keys": [{"key_alias": "k", "spend": 0}], "total_pages": 1})
    app = web.Application()
    for _p, _h in (("/health/liveliness", _live), ("/v1/models", _models),
                   ("/health/backlog", _backlog), ("/spend/logs", _spend), ("/key/list", _keylist)):
        app.router.add_get(_p, _h)
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LITELLM_BASE_URL", str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 9999)
        monkeypatch.setattr(config, "LITELLM_BACKLOG_PROBE_SELFCOUNT", False)
        litellm._KEY_BUDGETS_CACHE = None
        litellm._CB.pop("key_list", None)
        litellm._CB["spend"] = {"fails": 99, "until": 9e18}   # breaker OPEN
        async with aiohttp.ClientSession() as s:
            out = await litellm.sample(s)
        assert hits["keylist"] == 0, "key_budgets walk ran despite an OPEN circuit breaker"
        assert not out.get("known_keys")
    finally:
        litellm._CB.pop("spend", None)
        await srv.close()


async def test_litellm_heavy_sample_key_list_failure_is_non_fatal(monkeypatch):
    """A /key/list failure (e.g. scope-limited master key) must not crash the sample or
    drop already-derived heavy fields — key_budgets() degrades to its own cache/None and
    `known_keys` is simply absent that tick."""
    async def _live(_r): return web.json_response({"status": "healthy"})
    async def _models(_r): return web.json_response({"data": []})
    async def _backlog(_r): return web.json_response({"in_flight_requests": 2})
    async def _spend(_r): return web.json_response([])
    async def _keylist(_r): return web.json_response({"error": "forbidden"}, status=403)

    app = web.Application()
    app.router.add_get("/health/liveliness", _live)
    app.router.add_get("/v1/models", _models)
    app.router.add_get("/health/backlog", _backlog)
    app.router.add_get("/spend/logs", _spend)
    app.router.add_get("/key/list", _keylist)
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LITELLM_BASE_URL", str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LITELLM_BACKLOG_PROBE_SELFCOUNT", False)
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 9999)
        litellm._KEY_BUDGETS_CACHE = None
        async with aiohttp.ClientSession() as s:
            out = await litellm.sample(s)
        assert out["available"] is True
        assert out["backlog"] == 2               # rest of the sample is unaffected
        assert not out.get("known_keys")          # no confirmed keys this tick
    finally:
        await srv.close()


async def test_known_keys_baseline_survives_a_failed_key_list_poll(tmp_path, monkeypatch):
    """Not just the cold-start-empty case: a /key/list poll can also fail on a LATER heavy
    cycle, AFTER known_keys already has a real baseline from earlier successful polls (a
    scope change on the master key, a transient 403/500, ...). The sampler only calls
    db.known_keys_upsert() when the tick's `known_keys` field is present (see app.py's
    `if _ll.get("known_keys"): db.known_keys_upsert(...)` — mirrored here); a failed tick
    carries no `known_keys` field at all, so that call is simply skipped and the
    already-persisted baseline must be read back unchanged, not wiped or replaced."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "kk_stale_baseline.db"))
    db.init()
    db.known_keys_upsert(["pedro", "alex-batista"], 1000.0)   # baseline from earlier polls
    assert db.known_keys_set() == {"pedro", "alex-batista"}

    async def _live(_r): return web.json_response({"status": "healthy"})
    async def _models(_r): return web.json_response({"data": []})
    async def _backlog(_r): return web.json_response({"in_flight_requests": 1})
    async def _spend(_r): return web.json_response([])
    async def _keylist(_r): return web.json_response({"error": "internal"}, status=500)

    app = web.Application()
    app.router.add_get("/health/liveliness", _live)
    app.router.add_get("/v1/models", _models)
    app.router.add_get("/health/backlog", _backlog)
    app.router.add_get("/spend/logs", _spend)
    app.router.add_get("/key/list", _keylist)
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LITELLM_BASE_URL", str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LITELLM_BACKLOG_PROBE_SELFCOUNT", False)
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 9999)
        litellm._KEY_BUDGETS_CACHE = None
        async with aiohttp.ClientSession() as s:
            out = await litellm.sample(s)
        assert not out.get("known_keys")            # this tick confirmed nothing
        # app.py's write-side guard, mirrored exactly:
        if out.get("known_keys"):
            db.known_keys_upsert(out["known_keys"], 2000.0)
        assert db.known_keys_set() == {"pedro", "alex-batista"}   # stale baseline intact
    finally:
        await srv.close()


async def test_sample_once_not_stalled_by_slow_backend():
    """Host/GPU/procs sampling must NOT wait on the HTTP backends — a slow LiteLLM
    can't make host CPU/RAM go stale. _sample_once reads the decoupled backends'
    last value and returns fast even if a backend would block for a long time."""
    import app as appmod
    import time as _time
    # a decoupled loop has stored litellm's latest; _sample_once must just read it
    appmod._backend_latest["litellm"] = {"available": True, "_marker": 42}
    async with aiohttp.ClientSession() as s:
        t0 = _time.perf_counter()
        snap = await appmod._sample_once(s)
        dt = _time.perf_counter() - t0
    assert dt < 1.0, f"_sample_once should be fast (local only), took {dt:.2f}s"
    # host sampled fresh, litellm came from the decoupled cache (not re-sampled)
    assert snap["collectors"]["host"]["available"] is True
    assert snap["collectors"]["litellm"] == {"available": True, "_marker": 42}


async def test_backend_loop_bounds_a_hung_backend():
    """A backend whose sample never returns (wedged nvidia-smi / dead proxy) must be timed out by
    the loop's wait_for bound — the loop SURVIVES and keeps ticking instead of freezing forever
    (the wedged-loop bug; that anti-wedge guarantee is this test's subject).

    The timeout is now recorded as a real FAILURE. This test used to assert the prior value was
    preserved, which meant a hung backend kept presenting `available: True` indefinitely: the
    panel showed it healthy, the recovery hysteresis could emit 'back UP' for something wedged,
    and no down: alert could ever arm. A timeout IS the signal."""
    import app as appmod
    appmod._backend_latest["ollama"] = {"available": True, "_pre": 1}

    async def _hang(_s):
        await asyncio.sleep(100)      # simulate a wedged backend

    task = asyncio.create_task(appmod._backend_loop("ollama", _hang, None, 0.3))
    await asyncio.sleep(0.8)          # > bound, so at least one tick timed out
    alive_mid_run = not task.done()   # the anti-wedge guarantee: still looping, not crashed
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert alive_mid_run, "the loop must survive a wedged backend, not die on the timeout"
    got = appmod._backend_latest["ollama"]
    assert got.get("available") is False, f"a timeout must be recorded as down, got {got}"
    assert "timeout" in str(got.get("error", "")), got
    assert got.get("_pre") is None, "the stale good sample must not survive a timeout"


async def test_containers_collector_reads_docker_socket(tmp_path, monkeypatch):
    """The containers collector queries the Docker API over a unix socket and
    reports per-container running state + alive-time. Stub the Docker API on a
    real unix socket and verify parsing (running uptime, 404=not found)."""
    from collectors import containers as C
    from datetime import datetime, timezone, timedelta
    started = (datetime.now(timezone.utc) - timedelta(seconds=3661)) \
        .strftime("%Y-%m-%dT%H:%M:%S.%f000Z")   # ~1h1m ago, nanosecond format

    async def handler(req):
        if req.match_info["name"] == "gone":
            return web.json_response({"message": "no such container"}, status=404)
        return web.json_response(
            {"State": {"Running": True, "Status": "running", "StartedAt": started}})

    app = web.Application()
    app.router.add_get("/containers/{name}/json", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = str(tmp_path / "docker.sock")
    await web.UnixSite(runner, sock).start()
    try:
        monkeypatch.setattr(config, "DOCKER_SOCKET", sock)
        monkeypatch.setattr(config, "MONITOR_CONTAINERS", ["new_litellm", "gone"])
        C._session = None                       # force a fresh unix-socket session
        out = await C.sample()
        assert out["available"] is True
        by = {c["name"]: c for c in out["containers"]}
        assert by["new_litellm"]["running"] is True
        assert 3600 <= by["new_litellm"]["uptime_s"] <= 3720   # ~3661s
        assert by["gone"]["running"] is False
        assert by["gone"]["status"] == "not found"
    finally:
        if C._session:
            await C._session.close()
        C._session = None
        await runner.cleanup()


async def test_containers_auto_discovers_all_host_containers(tmp_path, monkeypatch):
    """With MONITOR_CONTAINERS empty, the collector lists ALL host containers via
    /containers/json and reports each — running first. Stub both the list and the
    per-container inspect on a unix socket."""
    from collectors import containers as C
    from datetime import datetime, timezone, timedelta
    started = (datetime.now(timezone.utc) - timedelta(seconds=120)) \
        .strftime("%Y-%m-%dT%H:%M:%S.%f000Z")

    async def list_h(_req):
        return web.json_response([
            {"Names": ["/new_litellm"], "State": "running"},
            {"Names": ["/new_caddy"], "State": "exited"},
        ])

    async def inspect_h(req):
        name = req.match_info["name"]
        running = name == "new_litellm"
        return web.json_response({"State": {
            "Running": running,
            "Status": "running" if running else "exited",
            "StartedAt": started if running else "0001-01-01T00:00:00Z"}})

    app = web.Application()
    app.router.add_get("/containers/json", list_h)
    app.router.add_get("/containers/{name}/json", inspect_h)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = str(tmp_path / "docker.sock")
    await web.UnixSite(runner, sock).start()
    try:
        monkeypatch.setattr(config, "DOCKER_SOCKET", sock)
        monkeypatch.setattr(config, "MONITOR_CONTAINERS", [])      # empty -> discover all
        C._session = None
        out = await C.sample()
        assert out["available"] is True
        names = [c["name"] for c in out["containers"]]
        assert set(names) == {"new_litellm", "new_caddy"}
        assert names[0] == "new_litellm"                          # running sorts first
        run = next(c for c in out["containers"] if c["name"] == "new_litellm")
        assert run["running"] and 110 <= run["uptime_s"] <= 140
    finally:
        if C._session:
            await C._session.close()
        C._session = None
        await runner.cleanup()


def test_collector_status_logging(caplog):
    """At DEBUG level (MONITOR_DEBUG=1 / LOG_LEVEL=debug) the collector logger emits each
    collector's availability + error on change, incl. a GPU hint — visible in docker logs."""
    import app as appmod
    import logging
    appmod._status_prev.clear()
    snap = {"collectors": {
        "host": {"available": True},
        "gpu": {"available": False, "error": "unconfigured"},
        "litellm": {"available": False, "error": "conn: ClientConnectorError"},
    }}
    with caplog.at_level(logging.DEBUG, logger="aimon.collector"):
        appmod._log_collector_status(snap)
    msgs = [r.getMessage() for r in caplog.records if r.name == "aimon.collector"]
    assert any("host: OK" in m for m in msgs)
    assert any("gpu: unavailable — unconfigured" in m and "GPU_SSH" in m for m in msgs)
    assert any("litellm: unavailable — conn: ClientConnectorError" in m for m in msgs)
    # unchanged status is NOT re-logged (only on change)
    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger="aimon.collector"):
        appmod._log_collector_status(snap)
    assert [r for r in caplog.records if r.name == "aimon.collector"] == []
    # below DEBUG => silent (the function early-returns on !isEnabledFor(DEBUG))
    caplog.clear()
    appmod._status_prev.clear()
    with caplog.at_level(logging.WARNING, logger="aimon.collector"):
        appmod._log_collector_status(snap)
    assert [r for r in caplog.records if r.name == "aimon.collector"] == []


def test_gpu_file_mode(tmp_path, monkeypatch):
    """GPU file mode: read nvidia-smi CSV the host writes to a mounted file (the
    secure, SSH-free local-GPU path). Fresh file parses; a stale file degrades to
    unavailable so the panel never shows frozen numbers."""
    from collectors import gpu
    import os as _os, time as _time
    f = tmp_path / "gpu.csv"
    f.write_text("NVIDIA RTX 4090, 73, 8192, 24564, 65, 210.5, 450, Not Active\n")
    monkeypatch.setattr(config, "GPU_METRICS_FILE", str(f))
    monkeypatch.setattr(config, "GPU_FILE_MAX_AGE", 60.0)
    out = gpu.sample()
    assert out["available"] is True and out["mode"] == "file"
    assert out["util"] == 73.0 and out["vram_used"] == 8192 * 1024 * 1024
    assert out["count"] == 1
    # stale file -> unavailable (host stopped writing)
    old = _time.time() - 120
    _os.utime(f, (old, old))
    stale = gpu.sample()
    assert stale["available"] is False and "stale" in stale["error"]


def test_gpu_na_fields_unified_memory(tmp_path, monkeypatch):
    """A GPU that reports '[N/A]' for columns it lacks (e.g. the GB10 superchip:
    unified memory → no separate VRAM) must still be reported with util/temp/power,
    not dropped. Regression for the ValueError-drops-whole-GPU bug."""
    from collectors import gpu
    f = tmp_path / "gpu.csv"
    f.write_text("NVIDIA GB10, 0, [N/A], [N/A], 44, 10.07, [N/A], Not Active\n")
    monkeypatch.setattr(config, "GPU_METRICS_FILE", str(f))
    monkeypatch.setattr(config, "GPU_FILE_MAX_AGE", 600.0)
    out = gpu.sample()
    assert out["available"] is True and out["count"] == 1
    assert out["temp_max"] == 44.0 and out["power"] == 10.1
    # VRAM is None (not 0) so the dashboard hides the VRAM tiles for unified memory
    assert out["vram_used"] is None and out["vram_total"] is None


def test_db_connect_commits_and_closes(tmp_path, monkeypatch):
    """_connect() is a context manager that commits on success AND closes the
    connection (sqlite's own `with conn:` commits but leaks the connection)."""
    import sqlite3
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "t.db"))
    held = {}
    with db._connect() as conn:
        conn.execute("CREATE TABLE t(x)")
        conn.execute("INSERT INTO t VALUES (1)")
        held["c"] = conn
    # closed after the block
    with pytest.raises(sqlite3.ProgrammingError):
        held["c"].execute("SELECT 1")
    # committed -> visible from a fresh connection
    with db._connect() as c2:
        assert c2.execute("SELECT x FROM t").fetchone()[0] == 1


def test_db_connect_rolls_back_on_error(tmp_path, monkeypatch):
    """On an exception inside the block, the transaction rolls back (and the
    connection still closes) — no half-written state."""
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "t.db"))
    with db._connect() as conn:
        conn.execute("CREATE TABLE t(x)")            # committed
    with pytest.raises(RuntimeError):
        with db._connect() as conn:
            conn.execute("INSERT INTO t VALUES (1)")
            raise RuntimeError("boom")               # -> rollback
    with db._connect() as c2:
        assert c2.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 0


async def test_containers_down_shows_duration(tmp_path, monkeypatch):
    """A configured container that's stopped shows as down with how long it's been
    down (from Docker's FinishedAt); a removed one (404) uses the monitor's tracked
    last-seen. Both keep appearing in the list — they don't silently vanish."""
    from collectors import containers as C
    from datetime import datetime, timezone, timedelta
    fin = (datetime.now(timezone.utc) - timedelta(seconds=200)) \
        .strftime("%Y-%m-%dT%H:%M:%S.%f000Z")
    seen_running = (datetime.now(timezone.utc) - timedelta(seconds=30)) \
        .strftime("%Y-%m-%dT%H:%M:%S.%f000Z")

    state = {"which": "stopped"}

    async def handler(req):
        name = req.match_info["name"]
        if name == "removed":
            return web.json_response({"message": "no such container"}, status=404)
        if name == "toggler" and state["which"] == "running":
            return web.json_response({"State": {
                "Running": True, "Status": "running", "StartedAt": seen_running}})
        return web.json_response({"State": {
            "Running": False, "Status": "exited", "StartedAt": seen_running,
            "FinishedAt": fin}})

    app = web.Application()
    app.router.add_get("/containers/{name}/json", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = str(tmp_path / "docker.sock")
    await web.UnixSite(runner, sock).start()
    try:
        monkeypatch.setattr(config, "DOCKER_SOCKET", sock)
        monkeypatch.setattr(config, "MONITOR_CONTAINERS", ["stopped", "removed", "toggler"])
        C._session = None
        C._last_seen.clear()
        # first: prime last-seen for 'toggler' while it's running
        state["which"] = "running"
        await C.sample()
        # now everything stopped/removed
        state["which"] = "stopped"
        out = await C.sample()
        by = {c["name"]: c for c in out["containers"]}
        # stopped -> down_s from FinishedAt (~200s), still listed, running False
        assert by["stopped"]["running"] is False
        assert 180 <= by["stopped"]["down_s"] <= 260
        # removed (404) -> down_s from tracked last-seen; still listed as not found
        assert by["removed"]["status"] == "not found"
        # toggler was seen running, now stopped -> down_s present
        assert by["toggler"]["running"] is False and by["toggler"]["down_s"] is not None
    finally:
        if C._session:
            await C._session.close()
        C._session = None
        C._last_seen.clear()
        await runner.cleanup()


def test_parse_spend_pure_aggregation():
    """_parse_spend is the CPU-bound core run off the event loop (F2). Unit-test
    it directly: correct window filtering, per-model/per-key aggregation, and the
    (fields, kept, total) contract."""
    now = 1_700_000_000.0
    window_start = now - 3600
    rows = [
        # in window: 2 reqs for gpt-4o (keys k1, k2), 1 for qwen (k1)
        {"startTime": now - 100, "endTime": now - 99, "model": "gpt-4o",
         "api_key": "k1", "total_tokens": 10, "response_cost": 0.01},
        {"startTime": now - 50, "endTime": now - 49, "model": "gpt-4o",
         "api_key": "k2", "total_tokens": 20, "response_cost": 0.02},
        {"startTime": now - 30, "endTime": now - 28, "model": "qwen",
         "api_key": "k1", "total_tokens": 5, "response_cost": 0.0},
        # out of window (older than window_start) -> dropped
        {"startTime": now - 99999, "endTime": now - 99998, "model": "old",
         "api_key": "kx"},
    ]
    res, kept, total = litellm._parse_spend(rows, window_start, max_rows=10_000)
    assert total == 4 and kept == 3
    assert res["requests_window"] == 3
    models = {m["model"] for m in res["per_model"]}
    assert models == {"gpt-4o", "qwen"}          # 'old' filtered out
    keys = {k["key"]: k["reqs"] for k in res["top_keys"]}
    assert keys == {"k1": 2, "k2": 1}
    assert round(res["cost_window"], 2) == 0.03


async def test_litellm_circuit_breaker_stops_hammering(monkeypatch):
    """After LITELLM_CB_THRESHOLD consecutive failures, the heavy call must stop
    firing (breaker OPEN) so the monitor can't keep hammering a struggling proxy —
    the freeze fix. Here /spend/logs always 500s; hits must cap at the threshold."""
    hits = {"spend": 0}

    async def _s(_r): hits["spend"] += 1; return web.Response(status=500)
    async def _live(_r): return web.json_response({"status": "healthy"})
    async def _models(_r): return web.json_response({"data": []})
    async def _b(_r): return web.json_response({"in_flight_requests": 0})

    app = web.Application()
    for p, fn in (("/health/liveliness", _live), ("/v1/models", _models),
                  ("/health/backlog", _b), ("/spend/logs", _s)):
        app.router.add_get(p, fn)
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LITELLM_BASE_URL",
                            str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 0)   # always attempt
        monkeypatch.setattr(config, "LITELLM_CB_THRESHOLD", 3)
        monkeypatch.setattr(config, "LITELLM_CB_COOLDOWN", 9999)   # stay open
        async with aiohttp.ClientSession() as s:
            for _ in range(8):
                await litellm.sample(s)
        assert hits["spend"] == 3, f"breaker should cap hits at threshold, got {hits['spend']}"
    finally:
        await srv.close()


async def test_litellm_spend_size_cap_refuses_huge_body(monkeypatch):
    """A /spend/logs response over LITELLM_SPEND_MAX_BYTES is refused before it's
    deserialized — protects the monitor's memory + event loop from a huge day."""
    big = "[" + ",".join('{"startTime":1,"endTime":2,"model":"m","api_key":"k"}'
                         for _ in range(2000)) + "]"

    async def _s(_r): return web.Response(text=big, content_type="application/json")
    async def _live(_r): return web.json_response({"status": "healthy"})
    async def _models(_r): return web.json_response({"data": []})
    async def _b(_r): return web.json_response({"in_flight_requests": 0})

    app = web.Application()
    for p, fn in (("/health/liveliness", _live), ("/v1/models", _models),
                  ("/health/backlog", _b), ("/spend/logs", _s)):
        app.router.add_get(p, fn)
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LITELLM_BASE_URL",
                            str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 0)
        monkeypatch.setattr(config, "LITELLM_SPEND_MAX_BYTES", 500)   # tiny cap
        async with aiohttp.ClientSession() as s:
            out = await litellm.sample(s)
        # refused before parse -> no latency data, but the collector stays alive
        assert out["available"] is True
        assert out["requests_window"] == 0
    finally:
        await srv.close()


async def test_litellm_spend_uses_longer_heavy_timeout(monkeypatch):
    """A slow /spend/logs (busy proxy) must use LITELLM_SPEND_TIMEOUT, not the
    short default HTTP_TIMEOUT — else it always times out and blanks the panels
    (F4). Stub delays past the default but within the heavy timeout."""
    async def _s(_r):
        await asyncio.sleep(0.5)
        return web.json_response([
            {"startTime": 1_700_000_000.0, "endTime": 1_700_000_000.2,
             "model": "m", "api_key": "k"}])
    async def _live(_r): return web.json_response({"status": "healthy"})
    async def _models(_r): return web.json_response({"data": []})
    async def _b(_r): return web.json_response({"in_flight_requests": 0})

    app = web.Application()
    for p, fn in (("/health/liveliness", _live), ("/v1/models", _models),
                  ("/health/backlog", _b), ("/spend/logs", _s)):
        app.router.add_get(p, fn)
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LITELLM_BASE_URL",
                            str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 0)
        monkeypatch.setattr(config, "LITELLM_SPEND_WINDOW_MIN", 60 * 24 * 3650)
        monkeypatch.setattr(config, "HTTP_TIMEOUT", 0.1)          # default too short
        monkeypatch.setattr(config, "LITELLM_SPEND_TIMEOUT", 5.0)  # heavy override
        async with aiohttp.ClientSession() as s:
            out = await litellm.sample(s)
        # would be 0 if the 0.1s default applied; the 5s override lets it complete
        assert out["requests_window"] == 1, out.get("requests_window")
    finally:
        await srv.close()


async def test_litellm_lite_spend_mode(monkeypatch):
    """LITELLM_SPEND_MODE=lite uses server-side aggregate endpoints (no raw
    /spend/logs pull → no CPU spike / freeze). Gives requests/tokens/per-model/
    top-keys; latency stays None. Stub the aggregate endpoints."""
    hits = {"spend_logs": 0}

    async def _act(_r): return web.json_response(
        {"daily_data": [], "sum_api_requests": 4200, "sum_total_tokens": 99000})
    async def _actm(_r): return web.json_response(
        [{"model": "qwen2.5", "sum_api_requests": 4000, "sum_total_tokens": 90000},
         {"model": "gpt-4o", "sum_api_requests": 200, "sum_total_tokens": 9000}])
    async def _keys(_r): return web.json_response(
        [{"api_key": "hash1", "key_alias": "team-a", "total_spend": 1.25},
         {"api_key": "hash2", "key_name": "sk-...xy", "total_spend": 0.4}])
    async def _spend_logs(_r): hits["spend_logs"] += 1; return web.json_response([])
    async def _live(_r): return web.json_response({"status": "healthy"})
    async def _models(_r): return web.json_response({"data": []})
    async def _b(_r): return web.json_response({"in_flight_requests": 0})

    app = web.Application()
    for p, fn in (("/health/liveliness", _live), ("/v1/models", _models),
                  ("/health/backlog", _b), ("/spend/logs", _spend_logs),
                  ("/global/activity", _act), ("/global/activity/model", _actm),
                  ("/global/spend/keys", _keys)):
        app.router.add_get(p, fn)
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LITELLM_BASE_URL",
                            str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 0)
        monkeypatch.setattr(config, "LITELLM_SPEND_ENABLED", True)
        monkeypatch.setattr(config, "LITELLM_SPEND_MODE", "lite")
        async with aiohttp.ClientSession() as s:
            out = await litellm.sample(s)
        # raw /spend/logs must NOT be hit in lite mode (that's the whole point)
        assert hits["spend_logs"] == 0
        assert out["spend_mode"] == "lite"
        assert out["requests_window"] == 4200 and out["tokens_today"] == 99000
        assert {m["model"] for m in out["per_model"]} == {"qwen2.5", "gpt-4o"}
        assert out["top_keys"][0]["alias"] == "team-a" and out["top_keys"][0]["cost"] == 1.25
        assert out["wait_avg_ms"] is None and out.get("p95_ms") is None   # no latency
    finally:
        await srv.close()


def test_load_per_core_helper():
    """_load_per_core = 1-min load / ncpu, and 0 when host data is missing."""
    import app as appmod
    assert appmod._load_per_core({"collectors": {"host": {"load": [80.0, 60, 40], "ncpu": 20}}}) == 4.0
    assert appmod._load_per_core({"collectors": {"host": {"load": [3.0, 1, 1], "ncpu": 4}}}) == 0.75
    assert appmod._load_per_core({"collectors": {"host": {}}}) == 0.0          # no data
    assert appmod._load_per_core({"collectors": {"host": {"load": [], "ncpu": 8}}}) == 0.0


async def test_litellm_load_shed_disabled_runs_heavy(monkeypatch):
    """With LITELLM_LOAD_SHED=0 (off), the heavy /spend/logs call runs even at high
    load — shedding must be strictly opt-in."""
    hits = {"spend": 0}

    async def _s(_r): hits["spend"] += 1; return web.json_response([])
    async def _live(_r): return web.json_response({"status": "healthy"})
    async def _models(_r): return web.json_response({"data": []})
    async def _b(_r): return web.json_response({"in_flight_requests": 0})

    app = web.Application()
    for p, fn in (("/health/liveliness", _live), ("/v1/models", _models),
                  ("/health/backlog", _b), ("/spend/logs", _s)):
        app.router.add_get(p, fn)
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LITELLM_BASE_URL",
                            str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 0)
        monkeypatch.setattr(config, "LITELLM_SPEND_MODE", "full")
        monkeypatch.setattr(config, "LITELLM_LOAD_SHED", 0.0)   # OFF
        async with aiohttp.ClientSession() as s:
            litellm.note_load(999.0)                            # extreme load
            await litellm.sample(s)
        assert hits["spend"] == 1, "shed off => heavy /spend runs"
    finally:
        litellm.note_load(0.0)
        await srv.close()


async def test_litellm_load_shedding(monkeypatch):
    """When host load-per-core >= LITELLM_LOAD_SHED, the monitor auto-skips the heavy
    /spend/logs pull — and resumes when load drops. Cheap backlog keeps running."""
    hits = {"spend": 0, "backlog": 0}

    async def _s(_r): hits["spend"] += 1; return web.json_response([])
    async def _b(_r): hits["backlog"] += 1; return web.json_response(
        {"in_flight_requests": 2})
    async def _live(_r): return web.json_response({"status": "healthy"})
    async def _models(_r): return web.json_response({"data": []})

    app = web.Application()
    for p, fn in (("/health/liveliness", _live), ("/v1/models", _models),
                  ("/health/backlog", _b), ("/spend/logs", _s)):
        app.router.add_get(p, fn)
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LITELLM_BASE_URL",
                            str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 0)
        monkeypatch.setattr(config, "LITELLM_SPEND_MODE", "full")
        monkeypatch.setattr(config, "LITELLM_LOAD_SHED", 4.0)
        async with aiohttp.ClientSession() as s:
            litellm.note_load(6.0)               # overloaded -> shed
            await litellm.sample(s)
            assert hits["spend"] == 0, "/spend must be shed under load"
            assert hits["backlog"] == 1, "cheap backlog keeps running under load"
            litellm.note_load(1.0)               # recovered -> resume
            await litellm.sample(s)
            assert hits["spend"] == 1, "/spend resumes when load drops"
    finally:
        litellm.note_load(0.0)
        await srv.close()


async def test_litellm_spend_can_be_disabled(monkeypatch):
    """Escape hatch for a busy proxy: LITELLM_SPEND_ENABLED=0 stops the heavy
    whole-day /spend/logs pull. Cheap backlog still works."""
    hits = {"spend": 0, "backlog": 0}

    async def _s(_r): hits["spend"] += 1; return web.json_response([])
    async def _b(_r): hits["backlog"] += 1; return web.json_response(
        {"in_flight_requests": 1})
    async def _live(_r): return web.json_response({"status": "healthy"})
    async def _models(_r): return web.json_response({"data": []})

    app = web.Application()
    for p, fn in (("/health/liveliness", _live), ("/v1/models", _models),
                  ("/health/backlog", _b), ("/spend/logs", _s)):
        app.router.add_get(p, fn)
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LITELLM_BASE_URL",
                            str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LITELLM_BACKLOG_PROBE_SELFCOUNT", False)
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 9999)
        monkeypatch.setattr(config, "LITELLM_SPEND_ENABLED", False)
        async with aiohttp.ClientSession() as s:
            out = await litellm.sample(s)
        assert hits["spend"] == 0, "spend/logs must not be hit when disabled"
        assert hits["backlog"] == 1, "backlog (cheap) still polls"
        assert out["available"] is True and out["backlog"] == 1
    finally:
        await srv.close()


async def test_litellm_off_mode_still_lists_keys_cheaply(monkeypatch):
    """Regression (live box: per-key charts empty): with SPEND_ENABLED=0 the HEAVY
    /spend/logs pull is off, but the per-key list must STILL populate from the cheap
    /global/spend/keys aggregate — so Top keys/users/over-time aren't blank on a
    freeze-safe (spend-off) config. /spend/logs must NOT be hit."""
    hits = {"logs": 0, "keys": 0}

    async def _logs(_r): hits["logs"] += 1; return web.json_response([])
    async def _keys(_r):
        hits["keys"] += 1
        return web.json_response([
            {"api_key": "hA", "key_alias": "alice", "total_spend": 5.0},
            {"api_key": "hB", "key_alias": "bob", "total_spend": 2.0}])
    async def _live(_r): return web.json_response({"status": "healthy"})
    async def _models(_r): return web.json_response({"data": []})
    async def _bk(_r): return web.json_response({"in_flight_requests": 0})

    app = web.Application()
    for p, fn in (("/health/liveliness", _live), ("/v1/models", _models),
                  ("/health/backlog", _bk), ("/spend/logs", _logs),
                  ("/global/spend/keys", _keys)):
        app.router.add_get(p, fn)
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LITELLM_BASE_URL", str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 9999)
        monkeypatch.setattr(config, "LITELLM_SPEND_ENABLED", False)   # → mode 'off'
        async with aiohttp.ClientSession() as s:
            out = await litellm.sample(s)
        assert hits["logs"] == 0, "heavy /spend/logs must NOT run in off mode"
        assert hits["keys"] == 1, "cheap /global/spend/keys must still run to list keys"
        tk = out.get("top_keys") or []
        assert {k["alias"] for k in tk} == {"alice", "bob"}, "per-key list must populate in off mode"
        assert all(k["reqs"] is None for k in tk)   # off/lite exposes spend, not requests
    finally:
        await srv.close()


def test_keyrequests_falls_back_to_spend_when_no_request_data(tmp_path, monkeypatch):
    """/api/keyrequests plots cumulative REQUESTS from the rollup; when that's empty
    (off/lite mode has no per-key request counts) it falls back to per-key cumulative
    SPEND from key_series (metric='spend') so the chart is never blank."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "kr.db"))
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    # no rollup rows (reqs) — but key_series has cumulative-spend snapshots (off/lite).
    # Span >1h so the 12mo fallback (which reads the 1h tier) has data after rollup().
    for i in range(80):
        db.insert_key_series(now - 80 * 90 + i * 90,
                             [{"key": "hA", "alias": "alice", "cost": 1.0 + i}])
    db.rollup()                       # populate key_series_1h (runs every 60s in prod)
    import asyncio

    class _Req:
        def __init__(self, q): self.query = q
    import app as _app
    monkeypatch.setattr(_app, "_q_end", lambda r: now)
    r = asyncio.run(_app.keyrequests_handler(_Req({})))
    import json as _json
    d = _json.loads(r.body.decode())
    assert d["metric"] == "spend", "must fall back to spend when no request data"
    assert "alice" in d["labels"] and d["points"], "fallback series must not be empty"


def test_keyrequests_spend_fallback_only_rises_when_counter_rebases(tmp_path, monkeypatch):
    """The 'Top 10 API keys over time' chart promises a running total that ONLY RISES.
    Its lite-mode fallback reads per-key cumulative spend from key_series — but LiteLLM's
    total_spend is NOT monotonic: it re-bases when a key is re-issued / a budget period
    rolls / a replica reports a different view (observed live dropping 697 -> 11), which
    made this 'only rises' line FALL. The fallback must sum positive steps (reset-safe),
    so the served series is monotonic non-decreasing regardless of the raw counter."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "kr2.db"))
    db.init()
    now = 1_800_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    # a re-basing cumulative counter spread over ~27 days (the 12mo chart reads the 1h
    # tier), climbing then re-basing DOWN twice — the live 697 -> 11 shape in miniature.
    seq = [100.0, 130.0, 160.0, 20.0, 45.0, 70.0, 5.0, 25.0, 40.0]
    db.known_keys_upsert({"key-r": "u-1"}, now)
    with db._connect() as conn:
        conn.executemany(
            "INSERT INTO key_series_1h(bucket,label,reqs) VALUES (?,?,?)",
            [(now - 86400 * 30 + i * 86400 * 3, "key-r", v) for i, v in enumerate(seq)])
    import asyncio, json as _json

    class _Req:
        def __init__(self, q): self.query = q
    import app as _app
    monkeypatch.setattr(_app, "_q_end", lambda r: now)
    d = _json.loads(asyncio.run(_app.keyrequests_handler(_Req({}))).body.decode())
    assert d["metric"] == "spend"
    vals = [p.get("key-r") for p in d["points"] if p.get("key-r") is not None]
    assert vals, "fallback must still produce the series"
    drops = [(a, b) for a, b in zip(vals, vals[1:]) if b < a - 1e-9]
    assert not drops, f"'only rises' chart fell on a re-basing counter: {drops}"
    assert vals[-1] > 0, "a key that kept spending must end above zero"


def test_concurrency_by_key_attribution_sums_to_aggregate(tmp_path, monkeypatch):
    """The 'Concurrent work / Backlog by key' stacked charts estimate per-key attribution:
    each bucket's bands must SUM to the real measured aggregate (conc/backlog), split by each
    key's key_series activity share. Guards the invariant that the stack height == the true
    total (only the split is inferred)."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "cbk.db"))
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)   # align wall-clock so age-aware _pick_tier reads raw
    for i in range(10):
        t = now - 600 + i * 60
        with db._connect() as c:
            c.execute("INSERT INTO metrics(ts,conc,backlog) VALUES (?,?,?)", (t, 10.0, 4.0))
        db.insert_key_series(t, [{"key": "hA", "alias": "alice", "reqs": 6},
                                 {"key": "hB", "alias": "bob", "reqs": 2}])
    out = db.concurrency_by_key("1h", "conc", end=now)
    assert {s["label"] for s in out["series"]} == {"alice", "bob"}
    last = {s["label"]: s["data"][-1] for s in out["series"]}
    assert last == {"alice": 7.5, "bob": 2.5}                 # 6/8 and 2/8 of conc=10
    assert round(sum(last.values()), 2) == 10.0               # bands sum to the real aggregate
    bk = {s["label"]: s["data"][-1] for s in db.concurrency_by_key("1h", "backlog", end=now)["series"]}
    assert round(sum(bk.values()), 2) == 4.0                  # sums to backlog=4
    assert db.concurrency_by_key("1h", "bogus", end=now)["series"] == []


def test_concurrency_by_key_unattributed_goes_to_other(tmp_path, monkeypatch):
    """When there's an aggregate but no per-key activity to attribute it to, the whole total
    goes to 'Other' — the stack height must still equal the real aggregate (never dropped)."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "cbk2.db"))
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)   # align wall-clock so age-aware _pick_tier reads raw
    for i in range(5):                       # metrics only, no key_series activity
        with db._connect() as c:
            c.execute("INSERT INTO metrics(ts,conc) VALUES (?,?)", (now - 300 + i * 60, 7.0))
    out = db.concurrency_by_key("1h", "conc", end=now)
    assert [s["label"] for s in out["series"]] == ["Other"]
    assert out["series"][0]["data"][-1] == 7.0               # unattributed total preserved


def test_concurrency_by_key_ranks_by_attributable_not_total_activity(tmp_path, monkeypatch):
    """Top-N named lanes must be the keys that actually CONTRIBUTE to the plotted aggregate,
    not the keys with the most total in-window activity. The aggregate (conc/backlog) is a
    sparse point-in-time gauge: a key can be very busy in buckets where it read 0 (and so draw
    a flat-zero lane) while a different key's single request coincides with the one nonzero
    bucket. Ranking by raw activity names the flat-zero key and folds the real contributor into
    'Other' — the live '/litellm shows all-Other with empty named lanes' bug. Rank by
    attributable share (aggregate x share, over drawn buckets) instead."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "cbk_rank.db"))
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)   # align wall-clock so _pick_tier reads raw
    # 'idle_big' is very busy early, when conc==0; 'active' makes one request in the single
    # bucket where conc==10. With top_n=1 the ranking metric decides which one is named.
    for i in range(9):
        t = now - 600 + i * 60
        with db._connect() as c:
            c.execute("INSERT INTO metrics(ts,conc) VALUES (?,?)", (t, 0.0))
        db.insert_key_series(t, [{"key": "hI", "alias": "idle_big", "reqs": 100}])
    with db._connect() as c:                # the one bucket with real concurrent work
        c.execute("INSERT INTO metrics(ts,conc) VALUES (?,?)", (now - 30, 10.0))
    db.insert_key_series(now - 30, [{"key": "hA", "alias": "active", "reqs": 3}])
    out = db.concurrency_by_key("1h", "conc", top_n=1, end=now)
    labels = [s["label"] for s in out["series"]]
    assert "active" in labels, f"active key folded into Other; got {labels}"
    named = {s["label"]: max(s["data"]) for s in out["series"] if s["label"] != "Other"}
    assert named.get("active", 0) == 10.0, f"active must carry the full conc=10 band: {named}"
    other = next((s for s in out["series"] if s["label"] == "Other"), None)
    assert other is None or max(other["data"]) == 0.0, "nothing real left for Other"


def test_model_conc_label_merges_gauge_with_litellm_label():
    """The vLLM real-time running/waiting gauge must reuse LiteLLM's OWN per_model label for the
    same model, so the 'Concurrent LLM work — by model' chart draws ONE lane, not two. Live bug:
    the gauge stored 'vllm/nvidia/Qwen3.6-35B-A3B-NVFP4' (vLLM's org-prefixed served name) while
    LiteLLM reqs used 'vllm/Qwen3.6-35B-A3B-NVFP4' — two lanes for one model, split into Other."""
    pm = [{"model": "vllm/Qwen3.6-35B-A3B-NVFP4"}, {"model": "azure_ai/gpt-5-mini"}]
    # org-prefixed served name maps onto the LiteLLM deployment label
    assert appmod._model_conc_label("nvidia/Qwen3.6-35B-A3B-NVFP4", pm) == "vllm/Qwen3.6-35B-A3B-NVFP4"
    # bare served name (no org) resolves to the same lane
    assert appmod._model_conc_label("Qwen3.6-35B-A3B-NVFP4", pm) == "vllm/Qwen3.6-35B-A3B-NVFP4"
    # a model LiteLLM has not reported → synthesized fallback, never merged onto another basename
    assert appmod._model_conc_label("mistral-7b", pm) == "vllm/mistral-7b"
    # must NOT swallow a same-basename model served under a DIFFERENT provider
    assert appmod._model_conc_label("gpt-5-mini", [{"model": "azure_ai/gpt-5-mini"}]) == "vllm/gpt-5-mini"


def test_key_series_window_delta_require_known_keeps_billed_unconfirmed(tmp_path, monkeypatch):
    """`require_known=False` keeps a key with real windowed activity even if /key/list hasn't
    confirmed it (master key / ephemeral virtual key) — the spend-context lite-mode fallback needs
    this to match the full-mode key_cost_window path. Default (True) still drops it."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "wd.db"))
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    for i in range(6):
        t = now - 300 + i * 60
        db.insert_key_series(t, [{"key": "hC", "alias": "confirmed", "reqs": 10 + i},
                                 {"key": "hU", "alias": "unconfirmed", "reqs": 5 + i}])
    db.known_keys_upsert({"confirmed": "u1"}, now)          # only 'confirmed' is /key/list-known
    default = db.key_series_window_delta("1h", 10, now)
    assert "unconfirmed" not in default["labels"], "default gating must drop the unconfirmed key"
    relaxed = db.key_series_window_delta("1h", 10, now, False)
    assert "unconfirmed" in relaxed["labels"] and "confirmed" in relaxed["labels"], \
        f"require_known=False must keep the billed-but-unconfirmed key: {relaxed['labels']}"


def test_concurrency_by_key_bridges_across_poll_jitter(tmp_path, monkeypatch):
    """The per-key spend poll fires every ~LITELLM_HEAVY_INTERVAL with jitter, so a conc bucket's
    nearest key sample can sit just past ONE interval. Bridging now spans ~TWO intervals, so that
    key's work is attributed (using its REAL nearest mix) instead of stranded in 'Other' — the 1h
    residual. Places a key sample ~1.8 intervals from the conc bucket: bridged, not Other."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "brg.db"))
    monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 60.0)
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    # window=1h, max_points=200 → bsize=18s. gap of ~108s = 6 buckets: >1x (5) but <2x (8) bridge.
    with db._connect() as c:
        c.execute("INSERT INTO metrics(ts,conc) VALUES (?,?)", (now - 100, 4.0))   # conc bucket
    db.insert_key_series(now - 208, [{"key": "hA", "alias": "jitterkey", "reqs": 7}])  # ~108s earlier
    out = db.concurrency_by_key("1h", "conc", end=now)
    labels = [s["label"] for s in out["series"]]
    assert "jitterkey" in labels, f"key ~1.8 poll-intervals away must be bridged, got {labels}"
    a = out.get("attribution") or {}
    assert a.get("other", 1) == 0.0, f"nothing should be left to Other after the 2x bridge: {a}"


@pytest.mark.asyncio
async def test_concurrency_by_key_endpoint_labels_basis():
    c = await _client()
    try:
        r = await c.get("/api/litellm/concurrency-by-key?metric=backlog&window=1h")
        assert r.status == 200
        d = await r.json()
        assert d["metric"] == "backlog" and "series" in d and "labels" in d
        assert d["weight_basis"] in ("requests", "spend")   # auto-labeled for honesty
        # unknown metric coerces to the default 'conc'
        assert (await (await c.get("/api/litellm/concurrency-by-key?metric=x")).json())["metric"] == "conc"
    finally:
        await c.close()


async def test_spend_backfill_skipped_when_spend_not_full(tmp_path, monkeypatch):
    """The one-time spend backfill is a multi-day /spend/logs pull — it MUST be skipped in
    off/lite spend mode (freeze safety) and must NOT mark itself done, so a later switch to
    full still backfills. Regression: an upgrade must never re-trigger the heavy pull on a
    box that disabled spend on purpose."""
    import app as _app
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "bf.db"))
    db.init()
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    monkeypatch.setattr(config, "SPEND_MU_BACKFILL_DAYS", 14)
    called = {"n": 0}

    async def _spy(session, days):
        called["n"] += 1
        return []
    monkeypatch.setattr(litellm, "model_user_backfill", _spy)

    # off mode → skip the heavy pull, do NOT mark done
    monkeypatch.setattr(config, "LITELLM_SPEND_ENABLED", False)     # → mode 'off'
    await _app._spend_mu_backfill_once(None)
    assert called["n"] == 0, "backfill must NOT pull /spend/logs in off mode"
    assert not db.settings_all().get("spend_mu_backfill"), "must not mark done when skipped"

    # lite mode → still skip
    monkeypatch.setattr(config, "LITELLM_SPEND_ENABLED", True)
    monkeypatch.setattr(config, "LITELLM_SPEND_MODE", "lite")
    await _app._spend_mu_backfill_once(None)
    assert called["n"] == 0, "backfill must NOT run in lite mode"


async def test_litellm_spend_row_cap(monkeypatch):
    """A huge day of logs is capped to the most-recent LITELLM_SPEND_MAX_ROWS
    before parsing, bounding CPU/memory on a busy proxy. The kept rows are the
    newest (highest startTime)."""
    now = 1_700_000_000.0
    # 50 rows, ascending time; only the newest 5 should be parsed, and all fall
    # inside a wide window so they all count.
    rows = [{"startTime": now - (50 - i), "endTime": now - (50 - i) + 0.1,
             "model": f"m{i}", "api_key": f"k{i}"} for i in range(50)]

    async def _s(_r): return web.json_response(rows)
    async def _live(_r): return web.json_response({"status": "healthy"})
    async def _models(_r): return web.json_response({"data": []})
    async def _b(_r): return web.json_response({"in_flight_requests": 0})

    app = web.Application()
    for p, fn in (("/health/liveliness", _live), ("/v1/models", _models),
                  ("/health/backlog", _b), ("/spend/logs", _s)):
        app.router.add_get(p, fn)
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LITELLM_BASE_URL",
                            str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 9999)
        monkeypatch.setattr(config, "LITELLM_SPEND_MAX_ROWS", 5)
        monkeypatch.setattr(config, "LITELLM_SPEND_WINDOW_MIN", 60 * 24 * 3650)
        async with aiohttp.ClientSession() as s:
            out = await litellm.sample(s)
        # capped to 5 most-recent rows -> exactly 5 counted
        assert out["requests_window"] == 5, out.get("requests_window")
        models = {m["model"] for m in out["per_model"]}
        assert models == {"m45", "m46", "m47", "m48", "m49"}, models
    finally:
        await srv.close()


# -------------------------------------------------------- top apps (procs) ----
def test_procs_collector_shape():
    procs.sample(5)              # first call primes the CPU deltas
    out = procs.sample(5)
    assert out["available"] is True
    assert len(out["top_cpu"]) <= 5 and len(out["top_ram"]) <= 5
    # this test process itself uses RAM, so top_ram is non-empty
    assert out["top_ram"] and "app" in out["top_ram"][0] and "ram" in out["top_ram"][0]
    for c in out["top_cpu"]:
        assert "app" in c and "cpu" in c


def test_procs_relabels_llm_servers_from_cmdline(monkeypatch):
    """vLLM / SGLang run under a generic `python`, and TGI's rust router comm truncates to
    'text-generation' — so `comm` alone can't attribute their CPU/RAM to the served model.
    _app_of peeks at the cmdline of interpreter-like comms and relabels them to the server
    (vllm / sglang / tgi) so the /litellm Per-model svc CPU/RAM + serving charts pick them up.
    A generic python (no LLM marker) and a non-interpreter comm are left untouched."""
    cmds = {
        1: "/usr/bin/python3 -m vllm.entrypoints.openai.api_server --model MiniMax-M2",
        2: "/venv/bin/python -m sglang.launch_server --model-path X",
        3: "text-generation-router --model-id bigscience/bloom",
        4: "/usr/bin/python3 /app/other_service.py",
    }
    monkeypatch.setattr(procs, "_cmdline", lambda pid: cmds.get(pid, ""))
    assert procs._app_of(1, "python3") == "vllm"
    assert procs._app_of(2, "python") == "sglang"
    assert procs._app_of(3, "text-generation") == "tgi"      # comm-truncated rust router
    assert procs._app_of(4, "python3") == "python3"          # generic python — unchanged
    assert procs._app_of(5, "postgres") == "postgres"        # non-interpreter — no cmdline read


def test_db_proc_series_multiline(tmp_path, monkeypatch):
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "ps.db"))
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    for t in range(600, 0, -30):
        db.insert_proc_series(now - t, "cpu", [
            {"app": "python", "cpu": 80}, {"app": "node", "cpu": 20},
            {"app": "idle", "cpu": 1}], "cpu")
        db.insert_proc_series(now - t, "ram", [
            {"app": "python", "ram": 500}, {"app": "node", "ram": 100}], "ram")
    cpu = db.proc_series("cpu", "15m", top_n=2)
    assert cpu["apps"][0] == "python"          # busiest first
    assert "idle" not in cpu["apps"]           # top_n=2 drops it
    assert cpu["points"] and "python" in cpu["points"][-1]
    ram = db.proc_series("ram", "15m", top_n=5)
    assert set(ram["apps"]) == {"python", "node"}


def test_db_cpu_core_series_windowed(tmp_path, monkeypatch):
    """Per-core CPU% is PERSISTED and read back per window, so the GPU/CPU grid can honour
    the window + pan controls. Regression: the grid used to buffer live samples in the
    browser and ignored the window entirely (picking 12:14–13:14 still showed 'now')."""
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "cc.db"))
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    for i in range(60):                                  # 1/min across a full hour
        db.insert_cpu_core_series(now - 3600 + i * 60, [float(i), 50.0, 90.0, 0.0])
    out = db.cpu_core_series("1h", max_points=12)
    assert out["cores"] == [0, 1, 2, 3]
    assert 2 <= len(out["points"]) <= 12                 # bucketed across the window
    assert all(abs(p["2"] - 90.0) < 0.1 for p in out["points"])   # flat core stays 90
    assert out["points"][0]["0"] < out["points"][-1]["0"]         # rising core rises
    # every bucket timestamp falls INSIDE the requested window (the actual bug)
    assert all(now - 3600 <= p["t"] <= now for p in out["points"])
    # panning to a window that ended before any data returns nothing (not "now")
    assert db.cpu_core_series("1h", end=now - 7200)["points"] == []
    # empty per-core (first tick / core-count change) is a no-op, never an exception
    db.insert_cpu_core_series(now, [])


def test_db_ncpu_counts_logical_cores_in_window(tmp_path, monkeypatch):
    """db.ncpu returns the logical-core count from per-core samples, so the client can
    normalize top-style per-process %CPU (÷ cores) and keep the stacked per-app chart
    ≤100%. 0 when the window holds no per-core data (caller then skips normalization)."""
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "nc.db"))
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    for i in range(30):
        db.insert_cpu_core_series(now - 1800 + i * 60, [10.0, 20.0, 30.0, 40.0])
    assert db.ncpu("1h") == 4                       # four distinct cores in window
    assert db.ncpu("1h", end=now - 7200) == 0       # window before any sample → 0
    assert db.ncpu("15m") == 4                       # shorter window still sees them


def test_procseries_cpu_exposes_ncpu_for_normalization(tmp_path, monkeypatch):
    """The /api/procseries cpu response carries `ncpu` so the stacked per-app CPU chart
    can divide each process %CPU by the core count and top out at 100%. RAM omits it."""
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "ps.db"))
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    for i in range(20):
        db.insert_cpu_core_series(now - 1200 + i * 60, [5.0, 5.0, 5.0, 5.0, 5.0, 5.0])
        db.insert_proc_series(now - 1200 + i * 60, "cpu",
                              [{"app": "proc", "cpu": 350.0}], "cpu")
    import app as _app

    class _Req:
        def __init__(self, q):
            self.query = q
    monkeypatch.setattr(_app, "_q_end", lambda r: now)
    import asyncio
    cpu = asyncio.run(_app.procseries_handler(_Req({"kind": "cpu", "window": "15m"})))
    import json as _json
    body = _json.loads(cpu.body.decode())
    assert body["ncpu"] == 6                          # six cores → divisor of 6
    ram = asyncio.run(_app.procseries_handler(_Req({"kind": "ram", "window": "15m"})))
    assert "ncpu" not in _json.loads(ram.body.decode())


def test_db_ncpu_reads_rollup_for_long_windows(tmp_path, monkeypatch):
    """ncpu tiers like cpu_core_series: a 24h+ window counts cores from the 1m/1h rollup,
    not the raw table (which a long window has aged out of), so the per-app normalization
    divisor is still correct over long ranges. Empty DB → 0 (caller skips normalization)."""
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "ncr.db"))
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    assert db.ncpu("1h") == 0                              # nothing recorded yet
    for i in range(120):
        db.insert_cpu_core_series(now - 3600 + i * 30, [25.0, 75.0, 50.0])
    db.rollup()                                            # populate the 1m rollup
    assert db.ncpu("24h") == 3                             # counted from the 1m rollup
    assert db.ncpu("12mo") == 3                            # 1h-rollup tier also sees them


def test_db_cpu_core_series_rollup_and_prune(tmp_path, monkeypatch):
    """Long windows read the 1m/1h rollups (not the raw table), and all three per-core
    tables are pruned on the same tiers as the other series."""
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "cc2.db"))
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    for i in range(120):
        db.insert_cpu_core_series(now - 3600 + i * 30, [25.0, 75.0])
    db.rollup()
    with db._connect() as c:
        assert c.execute("SELECT COUNT(*) FROM cpu_core_series_1m").fetchone()[0] > 0
    day = db.cpu_core_series("24h", max_points=10)       # served from the 1m rollup
    assert day["cores"] == [0, 1] and day["points"]
    db.prune_key_series()                                 # tiered prune covers all three
    with db._connect() as c:
        for t in ("cpu_core_series", "cpu_core_series_1m", "cpu_core_series_1h"):
            c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()


def test_db_cpu_core_series_prune_drops_old_and_keeps_recent(tmp_path, monkeypatch):
    """Retention actually DELETES: raw per-core rows past the raw horizon go, recent ones
    stay. (The earlier test only proved prune() didn't raise — that would still pass if
    the per-core tables were silently never pruned and grew forever.)"""
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "ccp.db"))
    db.init()
    now = 4_100_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    old_ts = now - (cfg.ROLLUP_RAW_HOURS * 3600) - 7200      # well past the raw horizon
    db.insert_cpu_core_series(old_ts, [11.0, 22.0])
    db.insert_cpu_core_series(now - 60, [33.0, 44.0])
    with db._connect() as c:
        assert c.execute("SELECT COUNT(*) FROM cpu_core_series").fetchone()[0] == 4
    db.prune_key_series()        # the TIERED series prune (db.prune() is samples-only)
    with db._connect() as c:
        left = c.execute("SELECT DISTINCT ts FROM cpu_core_series").fetchall()
    assert len(left) == 1 and abs(left[0][0] - (now - 60)) < 1, \
        "prune must drop rows past the raw horizon and keep recent ones"


def test_db_cpu_core_series_rollup_averages_per_core(tmp_path, monkeypatch):
    """The 1-minute rollup must average EACH CORE independently — a bug that averaged
    across cores would make every core read the same value on 24h+ windows."""
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "ccr.db"))
    db.init()
    now = 4_100_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    base = (now // 60) * 60                       # inside one 1-minute bucket
    for off in (5, 15, 25):                       # core0 -> 0/50/100 (avg 50), core1 flat 10
        db.insert_cpu_core_series(base + off, [{5: 0.0, 15: 50.0, 25: 100.0}[off], 10.0])
    db.rollup()
    with db._connect() as c:
        got = dict(c.execute(
            "SELECT core, pct FROM cpu_core_series_1m WHERE bucket=?", (base,)).fetchall())
    assert abs(got[0] - 50.0) < 0.01, f"core0 should average to 50, got {got.get(0)}"
    assert abs(got[1] - 10.0) < 0.01, f"core1 must stay 10, got {got.get(1)}"


def test_db_cpu_core_series_handles_core_count_change(tmp_path, monkeypatch):
    """Core count can change within a window (hotplug / container CPU-limit change). The
    reader must expose every core it saw and not crash or mis-align series."""
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "cch.db"))
    db.init()
    now = 4_100_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    for i in range(10):                            # first half: 2 cores
        db.insert_cpu_core_series(now - 1800 + i * 60, [10.0, 20.0])
    for i in range(10):                            # second half: 4 cores
        db.insert_cpu_core_series(now - 900 + i * 60, [10.0, 20.0, 30.0, 40.0])
    out = db.cpu_core_series("1h", max_points=20)
    assert out["cores"] == [0, 1, 2, 3]            # union of everything seen
    # cores 2/3 simply have no value in the early buckets — absent, never a wrong number
    early = [p for p in out["points"] if p["t"] < now - 1000]
    assert early and all("2" not in p for p in early)


async def test_cpuseries_endpoint_is_auth_gated(monkeypatch):
    """/api/cpuseries exposes host telemetry, so it must sit behind the same auth gate as
    the other /api/* endpoints — not be reachable anonymously."""
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "cpuseries-tok-123456")
    c = await _client()
    try:
        assert (await c.get("/api/cpuseries?window=1h")).status == 401
        assert (await c.get("/api/cpuseries?window=1h&token=WRONGWRONGWRONG")).status == 401
        ok = await c.get("/api/cpuseries?window=1h",
                         headers={"Authorization": "Bearer cpuseries-tok-123456"})
        assert ok.status == 200 and "cores" in await ok.json()
    finally:
        await c.close()


def test_perf_db_cpu_core_series_read_bounded(tmp_path, monkeypatch):
    """Per-core is the highest-cardinality series here (one row per core per tick). Guard
    the windowed read on a big-but-realistic table: 64 cores x 1500 ticks = 96k rows."""
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "ccperf.db"))
    db.init()
    now = time.time()
    rows = [(now - (1_500 - t) * 2.0, core, float((t + core) % 100))
            for t in range(1_500) for core in range(64)]
    with db._connect() as conn:
        conn.executemany(
            "INSERT INTO cpu_core_series(ts,core,pct) VALUES (?,?,?)", rows)
    el = _best(lambda: db.cpu_core_series("1h", max_points=200))
    out = db.cpu_core_series("1h", max_points=200)
    assert len(out["cores"]) == 64 and out["points"]
    assert el < 2.0, f"per-core windowed read over 96k rows too slow: {el:.3f}s"


def test_db_proc_series_densifies_absent_app_to_zero(tmp_path, monkeypatch):
    # an app present only in SOME buckets must read 0 (not be missing) in the others,
    # so the stacked chart draws a flat 0 instead of a phantom diagonal across the gap.
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "psd.db"))
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    for t in range(600, 0, -30):
        procs = [{"app": "steady", "cpu": 50}]
        if t <= 60:                                # 'blip' only in the last 2 buckets
            procs.append({"app": "blip", "cpu": 90})
        db.insert_proc_series(now - t, "cpu", procs, "cpu")
    out = db.proc_series("cpu", "15m", top_n=5)
    assert set(out["apps"]) == {"steady", "blip"}
    for p in out["points"]:                        # every bucket carries every app
        for app in out["apps"]:
            assert app in p, f"{app} not densified into a bucket"
    assert out["points"][0]["blip"] == 0           # absent -> 0, not a gap
    assert out["points"][0]["steady"] > 0


async def test_procseries_endpoint():
    c = await _client()
    try:
        for k in ("cpu", "ram"):
            r = await c.get(f"/api/procseries?kind={k}&window=1h")
            assert r.status == 200
            d = await r.json()
            assert d["kind"] == k and "apps" in d and "points" in d
        # bad kind falls back to cpu
        assert (await (await c.get("/api/procseries?kind=x")).json())["kind"] == "cpu"
    finally:
        await c.close()


async def test_cpuseries_endpoint():
    """/api/cpuseries serves the per-core series for a WINDOW (this is what makes the
    GPU/CPU grid respect the window + pan controls instead of showing live-only data)."""
    c = await _client()
    try:
        r = await c.get("/api/cpuseries?window=1h")
        assert r.status == 200
        d = await r.json()
        assert d["window"] == "1h" and "cores" in d and "points" in d
        # unknown window falls back to 1h rather than erroring
        assert (await (await c.get("/api/cpuseries?window=nope")).json())["window"] == "1h"
        # honours the pan offset without blowing up
        assert (await c.get("/api/cpuseries?window=1h&end=9000000")).status == 200
    finally:
        await c.close()


# --------------------------------------------------------------- host live ----
def test_host_sample_live():
    h = host.sample("/")
    assert h["available"] is True
    assert isinstance(h["cpu_pct"], (int, float))
    assert h["mem_total"] > 0
    assert 0 <= h["mem_pct"] <= 100
    assert h["ncpu"] >= 1


def test_host_per_core_cpu_delta():
    """host.sample exposes cpu_per_core: [] on the first tick (no delta yet), then one
    0–100 % value per logical CPU on the next tick. Feeds the GPU page's per-core grid."""
    host._prev_cpu_cores = None                      # force a clean first tick
    first = host.sample("/")
    assert first["cpu_per_core"] == []               # no previous sample to diff against
    second = host.sample("/")
    pc = second["cpu_per_core"]
    assert isinstance(pc, list) and len(pc) == second["ncpu"]
    assert all(isinstance(x, (int, float)) and 0 <= x <= 100 for x in pc)


def test_host_per_core_parses_proc_stat(monkeypatch):
    """_read_cpu_cores reads the cpuN lines (not the aggregate) and stops at the first
    non-cpu line; _per_core_pct diffs two snapshots into per-core %."""
    stat = ("cpu  100 0 100 800 0 0 0 0 0 0\n"      # aggregate — must be skipped
            "cpu0 10 0 10 80 0 0 0 0 0 0\n"
            "cpu1 20 0 20 60 0 0 0 0 0 0\n"
            "intr 12345\nctxt 999\n")               # non-cpu — must stop here
    import io
    monkeypatch.setattr("builtins.open", lambda *a, **k: io.StringIO(stat))
    cores = host._read_cpu_cores()
    assert len(cores) == 2                            # cpu0, cpu1 — not the aggregate
    host._prev_cpu_cores = [(50, 40), (50, 40)]       # prior totals/idle
    # cpu0 now (100,80): d_total=50, d_idle=40 → (1-40/50)*100 = 20%
    pct = host._per_core_pct(cores)
    assert pct[0] == 20.0


# --------------------------------------------------------------- gpu ----------
def test_gpu_collector_shape():
    out = gpu.sample()
    assert "available" in out
    if out["available"]:
        assert "util" in out and "vram_total" in out


def test_gpu_local_absence_is_unconfigured_not_down(monkeypatch):
    # no GPU CLI in local mode must read as "unconfigured" (hidden, no alert),
    # NOT a failure — else the backend-down alert false-fires (regression).
    monkeypatch.setattr(config, "GPU_SSH", None)
    monkeypatch.setattr(config, "GPU_METRICS_URL", None)
    monkeypatch.setattr(gpu.shutil, "which", lambda _: None)  # no nvidia/rocm
    out = gpu.sample()
    assert out["available"] is False and out["error"] == "unconfigured"
    # and alerts must NOT treat it as a backend-down breach
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    snap = {"ts": 0, "collectors": {"gpu": out}}
    assert not any(k == "down:gpu" for k, _ in alerts.evaluate(snap))


def test_gpu_http_rejects_nonhttp_scheme(monkeypatch):
    # SSRF/local-file guard: file:// (or any non-http) must be refused outright.
    monkeypatch.setattr(config, "GPU_SSH", None)
    monkeypatch.setattr(config, "GPU_METRICS_URL", "file:///etc/passwd")
    out = gpu.sample()
    assert out["available"] is False       # never opened the file:// url


async def test_cookie_session_strips_token_from_url(monkeypatch):
    # ?token= must convert to an HttpOnly cookie + redirect, so the secret
    # leaves the URL (history/logs/tunnel-inspector) after the first hit.
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "sesssecret123")
    # F3: cookie is Secure by default; the test client speaks plain HTTP and would
    # drop a Secure cookie, so opt into the insecure path to exercise the reuse flow.
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    c = await _client()
    try:
        r = await c.get("/?token=sesssecret123", allow_redirects=False)
        assert r.status == 302
        sc = r.headers.get("Set-Cookie", "")
        assert "aimon_session=" in sc and "HttpOnly" in sc and "SameSite=Strict" in sc
        # cookie now in the client jar → API works WITHOUT any ?token in the URL
        assert (await c.get("/")).status == 200
        assert (await c.get("/api/data")).status == 200
    finally:
        await c.close()


async def test_bad_cookie_rejected(monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "realtoken999")
    c = await _client()
    try:
        r = await c.get("/api/data", cookies={"aimon_session": "forged"})
        assert r.status == 401
    finally:
        await c.close()


async def test_security_headers_present():
    # pentest regression: clickjacking + MIME-sniff + fingerprint hardening
    c = await _client()
    try:
        r = await c.get("/healthz")
        assert r.headers["X-Frame-Options"] == "DENY"
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
        assert r.headers["Referrer-Policy"] == "no-referrer"
        assert "aiohttp" not in r.headers.get("Server", "")
    finally:
        await c.close()


# ── secure-review fixes (1.0.7): F1 docker-proxy · F2 no-open · F3 secure
#    cookie · F4 XFF last-hop · F5 nonce CSP ───────────────────────────────────
def test_f2_no_token_is_fatal_unless_allow_open(monkeypatch):
    monkeypatch.setattr(config, "MONITOR_PORT", 9925)
    monkeypatch.setattr(config, "SAMPLE_INTERVAL", 5.0)
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "")
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", None)
    monkeypatch.setattr(config, "ALLOW_OPEN", False)
    assert any("MONITOR_DASHBOARD_TOKEN" in e for e in config.validate()), \
        "missing token must be a fatal config error"
    monkeypatch.setattr(config, "ALLOW_OPEN", True)     # explicit opt-in clears it
    assert config.validate() == []


async def test_f3_session_cookie_secure_by_default(monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "sesssecret123")
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", False)
    c = await _client()
    try:
        r = await c.get("/?token=sesssecret123", allow_redirects=False)
        assert "Secure" in r.headers.get("Set-Cookie", ""), \
            "token-bearing cookie must be Secure by default"
    finally:
        await c.close()


def test_f4_client_ip_uses_rightmost_xff(monkeypatch):
    import app
    monkeypatch.setattr(config, "AUTH_TRUSTED_PROXY", True)

    class _Req:
        headers = {"X-Forwarded-For": "1.1.1.1, 2.2.2.2, 9.9.9.9"}
        remote = "10.0.0.1"
    # rightmost is appended by the trusted proxy; leftmost is client-spoofable
    assert app._client_ip(_Req()) == "9.9.9.9"


async def test_f5_page_uses_script_nonce_not_unsafe_inline(monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "")   # open so the page serves
    c = await _client()
    try:
        r = await c.get("/")
        body = await r.text()
        csp = r.headers["Content-Security-Policy"]
        m = re.search(r"script-src ([^;]+);", csp)
        assert m and "'nonce-" in m.group(1) and "'unsafe-inline'" not in m.group(1), \
            "script-src must use a nonce, not 'unsafe-inline'"
        nonce = re.search(r"'nonce-([^']+)'", m.group(1)).group(1)
        assert f'<script nonce="{nonce}"' in body, "inline <script> must carry the CSP nonce"
    finally:
        await c.close()


def test_f1_containers_uses_tcp_proxy_when_configured(monkeypatch):
    from collectors import containers
    monkeypatch.setattr(config, "DOCKER_API_URL", "http://docker-socket-proxy:2375")
    assert containers._base() == "http://docker-socket-proxy:2375"
    monkeypatch.setattr(config, "DOCKER_API_URL", None)
    assert containers._base() == "http://docker"    # legacy unix-socket dummy host


async def test_auth_uses_constant_time_compare(monkeypatch):
    # wrong-length and wrong-value tokens both rejected; correct accepted.
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "correcttoken123")
    c = await _client()
    try:
        assert (await c.get("/api/data")).status == 401                 # none
        assert (await c.get("/api/data?token=x")).status == 401         # short
        assert (await c.get("/api/data?token=wrongvaluewrong")).status == 401
        assert (await c.get("/api/data?token=correcttoken123")).status == 200
    finally:
        await c.close()


async def test_gpu_remote_http(monkeypatch):
    # GPU on a different box, reachable via an HTTP agent.
    srv = TestServer(_stub_app())
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "GPU_SSH", None)
        monkeypatch.setattr(config, "GPU_METRICS_URL", str(srv.make_url("/gpu")))
        # blocking urllib runs in a thread so it doesn't stall the test loop
        out = await asyncio.to_thread(gpu.sample)
        assert out["available"] is True
        assert out["mode"] == "http"
        assert out["count"] == 1
        assert out["util"] == 37.0
        assert out["vram_total"] == 24_000_000_000
    finally:
        await srv.close()


def test_gpu_ssh_mode_precedence_and_summary(monkeypatch):
    # Setting GPU_SSH selects ssh mode in the boot summary (no live SSH needed).
    monkeypatch.setattr(config, "GPU_SSH", "user@gpuhost")
    monkeypatch.setattr(config, "GPU_METRICS_URL", None)
    assert config.redacted_summary()["gpu_mode"] == "ssh:user@gpuhost"


# --------------------------------------------------------- series endpoint ----
def test_series_end_param_shifts_window(tmp_path, monkeypatch):
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "pan.db"))
    db.init()
    now = 3_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    # older data ~2h ago (cpu=10), recent data now (cpu=90)
    for t in range(7200, 6000, -30):
        db.insert_metrics(now - t, {"cpu": 10.0})
    for t in range(600, 0, -30):
        db.insert_metrics(now - t, {"cpu": 90.0})
    live = db.series("1h", 300)                       # ends now → sees 90s
    past = db.series("1h", 300, end=now - 6600)        # window ~1.8h ago → 10s
    assert any((p.get("cpu") or 0) > 50 for p in live)
    assert past and all((p.get("cpu") or 0) < 50 for p in past)


async def test_series_endpoint():
    c = await _client()
    try:
        r = await c.get("/api/series?window=15m")
        assert r.status == 200
        d = await r.json()
        assert d["window"] == "15m"
        assert set(d["windows"]) >= {"15m", "1h", "24h", "30d", "12mo"}
        assert isinstance(d["points"], list)
        # 12-month window is accepted and served (reads the 1-hour rollup tier)
        r12 = await c.get("/api/series?window=12mo")
        assert r12.status == 200
        d12 = await r12.json()
        assert d12["window"] == "12mo"
        assert isinstance(d12["points"], list)
        # bad window falls back to 1h, never errors
        r2 = await c.get("/api/series?window=bogus")
        assert (await r2.json())["window"] == "1h"
    finally:
        await c.close()


def test_db_metrics_migration_idempotent(tmp_path, monkeypatch):
    import sqlite3
    import time as _t
    import config as cfg
    dbf = tmp_path / "mig.db"
    # simulate an OLD metrics table created before disk/load1/tok existed
    con = sqlite3.connect(dbf)
    con.execute("CREATE TABLE metrics(ts REAL, cpu REAL, mem REAL, gpu REAL, "
                "vram_used REAL, vram_total REAL, wait REAL)")
    con.commit(); con.close()
    monkeypatch.setattr(cfg, "DB_PATH", str(dbf))
    db.init()   # must ALTER-add the missing columns
    db.init()   # idempotent second run must not error
    db.insert_metrics(_t.time(),
                      {"cpu": 1, "mem": 2, "disk": 3, "load1": 0.5, "tok": 9})
    pts = db.series("15m", 50)
    assert pts and pts[-1]["disk"] is not None and pts[-1]["tok"] is not None


def test_metrics_row_flattens_all_characteristics():
    import app as a
    snap = {"ts": 0, "collectors": {
        "host": {"available": True, "cpu_pct": 10, "mem_pct": 20,
                 "disk": {"pct": 30}, "load": [0.4, 0.1, 0.1]},
        "gpu": {"available": True, "util": 50,
                "vram_used": 100, "vram_total": 200},
        "ollama": {"available": False},
        "litellm": {"available": True, "wait_avg_ms": 123},
        "llamacpp": {"available": True, "predicted_per_second": 45}}}
    row = a._metrics_row(snap)
    assert (row["cpu"], row["mem"], row["disk"], row["load1"]) == (10, 20, 30, 0.4)
    assert (row["gpu"], row["vram_used"], row["vram_total"]) == (50, 100, 200)
    assert row["wait"] == 123 and row["tok"] == 45


def test_metrics_row_vram_falls_back_to_ollama():
    import app as a
    snap = {"ts": 0, "collectors": {
        "host": {"available": True, "cpu_pct": 1, "mem_pct": 1,
                 "disk": {"pct": 1}, "load": [0, 0, 0]},
        "gpu": {"available": False},
        "ollama": {"available": True, "vram_used": 777},
        "litellm": {"available": False},
        "llamacpp": {"available": False}}}
    row = a._metrics_row(snap)
    assert row["gpu"] is None
    assert row["vram_used"] == 777        # ollama size_vram fills the gap
    assert row["vram_total"] is None


def test_db_series_downsample(tmp_path, monkeypatch):
    import time as _t
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "m.db"))
    db.init()
    now = _t.time()
    for i in range(60):                       # 60 pts over 600s, all within 1h
        db.insert_metrics(now - 600 + i * 10,
                          {"cpu": float(i), "mem": 50.0, "gpu": None,
                           "vram_used": None, "vram_total": None, "wait": None})
    pts = db.series("1h", 30)
    assert len(pts) >= 1
    assert all("cpu" in p and "t" in p for p in pts)
    # averaging: overall cpu mean is 29.5, bucket means must stay in range
    assert all(0 <= p["cpu"] <= 59 for p in pts if p["cpu"] is not None)


# --------------------------------------------------------- alerting (T2) ------
def test_alert_evaluate_thresholds(monkeypatch):
    monkeypatch.setattr(config, "ALERT_CPU_PCT", 80.0)
    monkeypatch.setattr(config, "ALERT_VRAM_PCT", 90.0)
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_AFTER", 1)  # this test is about WHICH
    alerts.reset_down_streaks()                                # backends alarm, not the streak
    snap = {"ts": 0, "collectors": {
        "host": {"available": True, "cpu_pct": 95, "mem_pct": 10,
                 "disk": {"pct": 5}},
        "gpu": {"available": True, "util": 10,
                "vram_used": 95, "vram_total": 100},
        "ollama": {"available": False, "error": "conn: ClientError"},
        "litellm": {"available": False, "error": "unconfigured"}}}
    keys = {k for k, _ in alerts.evaluate(snap)}
    assert "cpu" in keys            # 95 >= 80
    assert "vram" in keys           # 95% >= 90
    assert "down:ollama" in keys    # configured-but-down
    assert "down:litellm" not in keys  # unconfigured != down


async def test_notifier_debounce_and_recovery(monkeypatch):
    monkeypatch.setattr(config, "ALERT_CPU_PCT", 50.0)
    monkeypatch.setattr(config, "ALERT_REPEAT_MIN", 9999)  # never repeat
    sent_log = []

    async def fake_fanout(self, session, text, recipients=None, akey=""):
        sent_log.append(text)
    monkeypatch.setattr(alerts.Notifier, "_fanout", fake_fanout)

    n = alerts.Notifier()
    hot = {"ts": 0, "collectors": {"host": {"available": True, "cpu_pct": 90,
                                            "mem_pct": 1, "disk": {"pct": 1}}}}
    cool = {"ts": 0, "collectors": {"host": {"available": True, "cpu_pct": 10,
                                             "mem_pct": 1, "disk": {"pct": 1}}}}
    async with aiohttp.ClientSession() as s:
        await n.process(s, hot, 1000)      # fires
        await n.process(s, hot, 1005)      # debounced (no repeat)
        await n.process(s, cool, 1010)     # recovery
    assert any("🔴" in m for m in sent_log)
    assert sum("🔴" in m for m in sent_log) == 1     # only once (debounced)
    assert any("🟢" in m and "back to normal" in m for m in sent_log)   # polished recovery line


# --------------------------------------------------- uptime / events (T2) -----
def test_db_uptime_and_events(tmp_path, monkeypatch):
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "u.db"))
    db.init()
    now = 1_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    # ollama down for 100s inside a 900s (15m) window
    db.record_event(now - 800, "ollama", True)
    db.record_event(now - 300, "ollama", False)
    db.record_event(now - 200, "ollama", True)
    up = db.uptime("15m")
    assert "ollama" in up
    assert up["ollama"]["outages"] == 1
    assert 80 <= up["ollama"]["uptime_pct"] <= 95   # ~100s down of 900s
    assert len(db.recent_events(10)) == 3


def test_model_events_kind_and_uptime_isolation(tmp_path, monkeypatch):
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "m.db"))
    db.init()
    now = 1_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    db.record_event(now - 500, "ollama", True)                          # state up
    db.record_event(now - 100, "ollama", True, "loaded qwen", kind="model")
    db.record_event(now - 50, "ollama", False, "unloaded qwen", kind="model")
    state = db.recent_events(20, kind="state")
    model = db.recent_events(20, kind="model")
    assert len(state) == 1 and len(model) == 2
    assert all(e["kind"] == "model" for e in model)
    # a model unload must NOT register as a downtime/outage in uptime
    up = db.uptime("15m")
    assert up["ollama"]["outages"] == 0
    assert up["ollama"]["uptime_pct"] == 100.0


def test_track_model_events_detects_load_unload(tmp_path, monkeypatch):
    import config as cfg
    import app as a
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    a._ollama_models = None
    a._llamacpp_model = None
    a._llamacpp_model_seen = False

    def snap(ts, models):
        return {"ts": ts, "collectors": {
            "ollama": {"available": True, "models": [{"name": m} for m in models]},
            "llamacpp": {"available": False}}}

    a._track_model_events(snap(1.0, ["qwen"]))            # baseline → no events
    assert db.recent_events(10, kind="model") == []
    a._track_model_events(snap(2.0, ["qwen", "gemma"]))   # gemma loaded
    a._track_model_events(snap(3.0, ["gemma"]))           # qwen unloaded
    seen = {(e["backend"], e["up"], e["detail"]) for e in db.recent_events(10, kind="model")}
    assert ("ollama", True, "loaded gemma") in seen
    assert ("ollama", False, "unloaded qwen") in seen


# ---- 1.8.16 "interesting logs": backend/model/alert/keylist/matrix/heartbeat -----------------
def test_backend_transition_logs_edge_only(tmp_path, monkeypatch, caplog):
    """#1 — _track_events logs the up/down EDGE (WARNING down, INFO recover) with a backend
    field, and NEVER per-poll: the baseline and steady state stay silent."""
    import config as cfg
    import app as a
    import logging
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    a._backend_state.clear()

    def snap(ts, up, err=""):
        return {"ts": ts, "collectors": {"litellm": {"available": up, "error": err}}}

    with caplog.at_level(logging.INFO, logger="aimon.sampler"):
        a._track_events(snap(1.0, True))          # baseline → DB event, but NO log line
        a._track_events(snap(2.0, True))          # unchanged → silent
        assert [r for r in caplog.records if r.name == "aimon.sampler"] == []
        a._track_events(snap(3.0, False, "timeout"))   # down edge → WARNING
        a._track_events(snap(4.0, True))               # recover edge → INFO
    recs = [r for r in caplog.records if r.name == "aimon.sampler"]
    down = [r for r in recs if r.levelno == logging.WARNING]
    up = [r for r in recs if r.levelno == logging.INFO]
    assert len(down) == 1 and getattr(down[0], "backend", None) == "litellm"
    assert getattr(down[0], "error", None) == "timeout"
    assert len(up) == 1 and "recovered" in up[0].getMessage()


def test_model_load_unload_logs_info(tmp_path, monkeypatch, caplog):
    """#2 — model load/unload emits an INFO with backend+model fields (alongside the DB event)."""
    import config as cfg
    import app as a
    import logging
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    a._ollama_models = None
    a._llamacpp_model = None
    a._llamacpp_model_seen = False

    def snap(ts, models):
        return {"ts": ts, "collectors": {
            "ollama": {"available": True, "models": [{"name": m} for m in models]},
            "llamacpp": {"available": False}}}

    with caplog.at_level(logging.INFO, logger="aimon.sampler"):
        a._track_model_events(snap(1.0, ["qwen"]))          # baseline → silent
        assert [r for r in caplog.records if r.name == "aimon.sampler"] == []
        a._track_model_events(snap(2.0, ["qwen", "gemma"]))  # gemma loaded
        a._track_model_events(snap(3.0, ["gemma"]))          # qwen unloaded
    recs = [r for r in caplog.records if r.name == "aimon.sampler"]
    loaded = [r for r in recs if "loaded" in r.getMessage() and "unloaded" not in r.getMessage()]
    unloaded = [r for r in recs if "unloaded" in r.getMessage()]
    assert any(getattr(r, "model", None) == "gemma" for r in loaded)
    assert any(getattr(r, "model", None) == "qwen" for r in unloaded)


def test_startup_backend_matrix_logs_once(monkeypatch, caplog):
    """#5 — _log_backend_matrix emits ONE INFO summary of up/down and never repeats."""
    import app as a
    import logging
    a._matrix_logged = False
    snap = {"ts": 1.0, "collectors": {
        "litellm": {"available": True}, "ollama": {"available": True},
        "vllm": {"available": False, "error": "conn refused"},
        "gpu": {"available": False, "error": "unconfigured"}}}   # unconfigured → omitted
    with caplog.at_level(logging.INFO, logger="aimon"):
        a._log_backend_matrix(snap)
        a._log_backend_matrix(snap)             # second call is a no-op
    recs = [r for r in caplog.records if r.name == "aimon" and "backends ready" in r.getMessage()]
    assert len(recs) == 1
    assert getattr(recs[0], "up", None) == "2/3"          # gpu(unconfigured) excluded from total


def test_backend_up_down_gates_unconfigured():
    """#5/#6 helper — unconfigured/starting backends are excluded from both up and down."""
    import app as a
    up, down = a._backend_up_down({"ts": 1.0, "collectors": {
        "litellm": {"available": True},
        "ollama": {"available": False, "error": "conn refused"},
        "vllm": {"available": False, "error": "unconfigured"},
        "gpu": {"available": False, "error": "starting"}}})
    assert up == ["litellm"] and down == ["ollama"]        # vllm/gpu gated out


async def test_alert_fire_recover_logs(monkeypatch, caplog):
    """#3 — Notifier logs a WARNING on fire and an INFO on recover, with the alert key."""
    import alerts
    import logging
    n = alerts.Notifier()

    async def _fanout(self, session, text, recipients, akey=""):    # stub: no real webhook
        return None

    async def _no_recipients(self):
        return []
    monkeypatch.setattr(alerts.Notifier, "_fanout", _fanout)
    monkeypatch.setattr(alerts.Notifier, "_recipients", _no_recipients)
    # evaluate() returns (key, msg) tuples
    monkeypatch.setattr(alerts, "evaluate", lambda snap: [("cpu", "cpu 95% >= 80%")])
    with caplog.at_level(logging.INFO, logger="aimon.alerts"):
        await n.process(None, {"ts": 1.0}, 1.0)            # breach → fire
        monkeypatch.setattr(alerts, "evaluate", lambda snap: [])
        await n.process(None, {"ts": 2.0}, 2.0)            # clears → recover
    recs = [r for r in caplog.records if r.name == "aimon.alerts"]
    fired = [r for r in recs if r.levelno == logging.WARNING and "fired" in r.getMessage()]
    recovered = [r for r in recs if r.levelno == logging.INFO and "recovered" in r.getMessage()]
    assert fired and getattr(fired[0], "key", None) == "cpu"
    assert recovered and getattr(recovered[0], "key", None) == "cpu"


async def test_key_list_degraded_logs_warning_transport_info_scope(monkeypatch, caplog):
    """#4 — /key/list failure reclassified out of DEBUG: a transport/parse failure (e.g. the
    JSONDecodeError firehose) is now a deduped WARNING; a 401/403 scope-limit stays INFO
    (benign — spend/teams/cost keep flowing). Logged once per error-state change, not per poll."""
    import logging
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-CHANGE_ME")
    monkeypatch.setattr(litellm, "_KEY_LIST_ERR", None)
    monkeypatch.setattr(litellm, "_KEY_BUDGETS_CACHE", None)
    monkeypatch.setattr(litellm, "_KEY_BUDGETS_TS", 0.0)

    async def _transport_fail(session, url, headers=None, timeout_s=None):
        return None, "JSONDecodeError: Expecting value"       # NOT an auth code
    monkeypatch.setattr(litellm, "fetch_json", _transport_fail)
    with caplog.at_level(logging.INFO, logger="aimon.litellm"):
        await litellm.key_budgets(None)
    recs = [r for r in caplog.records if r.name == "aimon.litellm"]
    warns = [r for r in recs if r.levelno == logging.WARNING and "degraded" in r.getMessage()]
    assert warns and getattr(warns[0], "fallback", None) == "MONITOR_KEY_BUDGETS"

    # A 403 scope-limit is INFO, not WARNING (reset error-state so it re-logs).
    monkeypatch.setattr(litellm, "_KEY_LIST_ERR", None)
    caplog.clear()

    async def _scope_fail(session, url, headers=None, timeout_s=None):
        return None, "403 Forbidden"
    monkeypatch.setattr(litellm, "fetch_json", _scope_fail)
    with caplog.at_level(logging.INFO, logger="aimon.litellm"):
        await litellm.key_budgets(None)
    recs = [r for r in caplog.records if r.name == "aimon.litellm"]
    assert any(r.levelno == logging.INFO and "scope-limited" in r.getMessage() for r in recs)
    assert not [r for r in recs if r.levelno == logging.WARNING]     # 403 is NOT a warning


async def test_events_endpoint_kind():
    c = await _client()
    try:
        d = await (await c.get("/api/events?kind=model")).json()
        assert d["kind"] == "model" and isinstance(d["events"], list)
        d2 = await (await c.get("/api/events?kind=bogus")).json()
        assert d2["kind"] == "model"          # invalid kind falls back to model
    finally:
        await c.close()


# ------------------------------------------------------- rollup (T4) ----------
def test_db_rollup_tiers(tmp_path, monkeypatch):
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "r.db"))
    db.init()
    base = 1_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: base + 3600)
    for i in range(120):
        db.insert_metrics(base + i * 30, {"cpu": float(i), "mem": 1})
    db.rollup()
    # 24h window reads metrics_1m rollup, not raw
    pts = db.series("24h", 300)
    assert pts and all("cpu" in p for p in pts)


# ----------------------------------------------------- gpu detail (T3) --------
def test_gpu_nvidia_parse_power_temp():
    row = ("NVIDIA RTX 4090, 42, 8000, 24000, 61, 320.5, 450, Active")
    gpus = gpu._parse_nvidia_csv(row)
    assert len(gpus) == 1
    assert gpus[0]["power"] == 320.5
    assert gpus[0]["temp"] == 61
    assert gpus[0]["throttled"] is True


# ---------------------------------------------- per-model + endpoints (T3) ----
async def test_litellm_failures_and_per_model_slo(monkeypatch):
    import time as _t
    now = _t.time()
    rows = [
        {"startTime": now - 3, "endTime": now - 1, "model": "fast",
         "status": "success", "api_key": "k", "total_tokens": 5},   # 2000ms
        {"startTime": now - 5, "endTime": now - 0.5, "model": "slow",
         "status": "success", "api_key": "k", "total_tokens": 5},   # 4500ms
        {"startTime": now - 2, "endTime": now - 1.9, "model": "fast",
         "status": "failure", "api_key": "kbad",
         "exception": "RateLimitError: 429", "total_tokens": 0},
    ]
    monkeypatch.setattr(config, "SLO_LATENCY_MS", 3000.0)
    out = await _sample_with_rows(monkeypatch, rows)
    # failed-request viewer (#2)
    f = out["recent_failures"]
    assert len(f) == 1 and f[0]["model"] == "fast"
    assert "RateLimitError" in f[0]["error"] and f[0]["key"] == "kbad"
    # per-model p95 + SLO (#3): 'slow' (4500ms) misses the 3000ms SLO
    pm = {m["model"]: m for m in out["per_model"]}
    assert pm["slow"]["p95_ms"] >= 4000 and pm["slow"]["slo_pct"] == 0.0
    assert pm["fast"]["slo_pct"] == 100.0     # 2000ms + the 100ms failure ≤ 3000


async def test_litellm_per_model_and_cost(monkeypatch):
    srv = TestServer(_stub_app())
    await srv.start_server()
    try:
        base = str(srv.make_url("")).rstrip("/")
        monkeypatch.setattr(config, "LITELLM_BASE_URL", base)
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_SPEND_WINDOW_MIN", 60 * 24 * 3650)
        async with aiohttp.ClientSession() as s:
            out = await litellm.sample(s)
        assert out["cost_window"] == pytest.approx(0.03, abs=1e-6)
        assert out["per_model"] and out["per_model"][0]["model"] == "gpt-4o"
        assert out["per_model"][0]["tokens"] == 150
    finally:
        await srv.close()


def test_pctile_math():
    from collectors import litellm as L
    vals = list(range(1, 101))          # 1..100 sorted
    assert L._pctile(vals, 50) == pytest.approx(50.5, abs=0.5)
    assert L._pctile(vals, 95) == pytest.approx(95.05, abs=0.5)
    assert L._pctile(vals, 99) == pytest.approx(99.01, abs=0.5)
    assert L._pctile([42], 95) == 42.0   # single value
    assert L._pctile([], 50) == 0.0      # empty


async def test_litellm_percentiles_and_slo(monkeypatch):
    # 100 requests with known durations → percentiles + SLO share
    now_rows = []
    import time as _t
    now = _t.time()
    for i in range(100):
        dur = (i + 1) / 1000.0           # 1ms .. 100ms
        now_rows.append({"startTime": now - 5, "endTime": now - 5 + dur,
                         "model": "m", "status": "success", "api_key": "k",
                         "total_tokens": 1})
    monkeypatch.setattr(config, "SLO_LATENCY_MS", 50.0)   # 50ms target
    out = await _sample_with_rows(monkeypatch, now_rows)
    assert out["p50_ms"] == pytest.approx(50.5, abs=1.5)
    assert out["p95_ms"] == pytest.approx(95, abs=2)
    assert out["p99_ms"] == pytest.approx(99, abs=2)
    # 50 of 100 requests <= 50ms → SLO 50%
    assert out["slo_target_ms"] == 50.0
    assert out["slo_pct"] == pytest.approx(50.0, abs=1.0)


async def test_litellm_tier_a_rates(monkeypatch):
    srv = TestServer(_stub_app())
    await srv.start_server()
    try:
        base = str(srv.make_url("")).rstrip("/")
        monkeypatch.setattr(config, "LITELLM_BASE_URL", base)
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_SPEND_WINDOW_MIN", 1)  # 60s window
        async with aiohttp.ClientSession() as s:
            out = await litellm.sample(s)
        # 2 reqs / 60s; 100 prompt / 50 completion tokens; 1 failure of 2 = 50%
        assert out["req_rate"] == pytest.approx(2 / 60, abs=1e-3)
        assert out["tok_in_rate"] == pytest.approx(100 / 60, abs=1e-2)
        assert out["tok_out_rate"] == pytest.approx(50 / 60, abs=1e-2)
        assert out["error_pct"] == 50.0
        assert out["cost_rate_hr"] == pytest.approx(0.03 * 60, abs=1e-3)  # $/h
        # new stats: TTFT (500ms on the one streaming row), cache hit 1/2=50%
        assert out["ttft_avg_ms"] == pytest.approx(500, abs=5)
        assert out["cache_hit_pct"] == 50.0
        assert out["cache_saved"] == pytest.approx(0.005, abs=1e-6)
        # top-10 keys: keyA (alias) and keyB, one request each
        tk = {k["key"]: k for k in out["top_keys"]}
        assert set(tk) == {"keyA", "keyB"}
        assert tk["keyA"]["alias"] == "team-alpha" and tk["keyA"]["reqs"] == 1
        assert len(out["top_keys"]) <= 10
    finally:
        await srv.close()


def _keys_stub_app(rows):
    """Minimal LiteLLM stub whose /spend/logs returns the given rows."""
    a = web.Application()

    async def live(_):
        return web.json_response({"status": "alive"})

    async def health(_):
        return web.json_response({"healthy_endpoints": [], "unhealthy_endpoints": []})

    async def models(_):
        return web.json_response({"data": []})

    async def spend(_):
        return web.json_response(rows)

    async def backlog(_):
        return web.json_response({"in_flight_requests": 0})

    a.router.add_get("/health/liveliness", live)
    a.router.add_get("/health", health)
    a.router.add_get("/v1/models", models)
    a.router.add_get("/spend/logs", spend)
    a.router.add_get("/health/backlog", backlog)
    return a


async def _sample_with_rows(monkeypatch, rows):
    srv = TestServer(_keys_stub_app(rows))
    await srv.start_server()
    try:
        base = str(srv.make_url("")).rstrip("/")
        monkeypatch.setattr(config, "LITELLM_BASE_URL", base)
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_SPEND_WINDOW_MIN", 60 * 24 * 3650)
        async with aiohttp.ClientSession() as s:
            return await litellm.sample(s)
    finally:
        await srv.close()


def _row(key, **extra):
    import time as _t
    now = _t.time()
    base = {"startTime": now - 2.0, "endTime": now - 1.0, "model": "m",
            "status": "success", "total_tokens": 10, "api_key": key}
    base.update(extra)
    return base


async def test_top_keys_truncates_to_10_and_sorted(monkeypatch):
    # 12 distinct keys, key_i sending (i+1) requests → key_11 busiest.
    rows = []
    for i in range(12):
        rows += [_row(f"key_{i}") for _ in range(i + 1)]
    out = await _sample_with_rows(monkeypatch, rows)
    tk = out["top_keys"]
    assert len(tk) == 10                          # truncated from 12
    assert tk[0]["key"] == "key_11" and tk[0]["reqs"] == 12   # busiest first
    assert tk[1]["key"] == "key_10"
    # requests strictly non-increasing (sorted desc)
    counts = [k["reqs"] for k in tk]
    assert counts == sorted(counts, reverse=True)
    # the two least-used keys (key_0=1req, key_1=2req) fell off the top-10
    assert "key_0" not in {k["key"] for k in tk}


async def test_top_keys_alias_and_id_fallbacks(monkeypatch):
    import time as _t
    now = _t.time()
    rows = [
        # alias from metadata.user_api_key_alias
        _row("hashA", metadata={"user_api_key_alias": "team-x"}),
        # key id falls back to metadata.user_api_key when api_key missing
        {"startTime": now - 2, "endTime": now - 1, "model": "m",
         "status": "success", "total_tokens": 5,
         "metadata": {"user_api_key": "hashB"}},
    ]
    out = await _sample_with_rows(monkeypatch, rows)
    tk = {k["key"]: k for k in out["top_keys"]}
    assert tk["hashA"]["alias"] == "team-x"
    assert "hashB" in tk                          # recovered from metadata


async def test_top_keys_aggregates_tokens_and_cost(monkeypatch):
    rows = [
        _row("k1", total_tokens=100, response_cost=0.02),
        _row("k1", total_tokens=50, response_cost=0.01),
        _row("k2", total_tokens=10, response_cost=0.005),
    ]
    out = await _sample_with_rows(monkeypatch, rows)
    k1 = next(k for k in out["top_keys"] if k["key"] == "k1")
    assert k1["reqs"] == 2 and k1["tokens"] == 150
    assert k1["cost"] == pytest.approx(0.03, abs=1e-6)


async def test_top_keys_absent_when_no_traffic(monkeypatch):
    out = await _sample_with_rows(monkeypatch, [])
    # no requests in window → no per-key breakdown emitted (KPIs stay clean)
    assert "top_keys" not in out or out.get("top_keys") in (None, [])


async def test_litellm_backlog(monkeypatch):
    srv = TestServer(_stub_app())
    await srv.start_server()
    try:
        base = str(srv.make_url("")).rstrip("/")
        monkeypatch.setattr(config, "LITELLM_BASE_URL", base)
        monkeypatch.setattr(config, "LITELLM_BACKLOG_PROBE_SELFCOUNT", False)  # test raw parse
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        async with aiohttp.ClientSession() as s:
            out = await litellm.sample(s)
        assert out["backlog"] == 7          # from /health/backlog {"backlog":7}
    finally:
        await srv.close()


def test_cache_hit_string_none_not_counted():
    # real LiteLLM serializes cache_hit to the spend DB as the string "None";
    # a naive truthy check would count it as a hit. Only true hits count.
    from collectors import litellm as L
    for val, expect_hit in [("None", 0), (None, 0), (True, 1),
                            ("true", 1), (False, 0), (1, 1)]:
        assert L._cache_is_hit(val) == bool(expect_hit), f"cache_hit={val!r}"


def test_backlog_extract_tolerant_shapes():
    from collectors import litellm as L
    assert L._extract_backlog({"in_flight_requests": 47}) == 47  # real shape
    assert L._extract_backlog({"backlog": 5}) == 5
    assert L._extract_backlog({"queue_size": 3}) == 3
    assert L._extract_backlog({"pending": [1, 2, 3, 4]}) == 4
    assert L._extract_backlog(9) == 9
    assert L._extract_backlog([1, 2]) == 2
    assert L._extract_backlog({"nope": 1}) is None


def test_backlog_alert(monkeypatch):
    monkeypatch.setattr(config, "ALERT_BACKLOG", 5.0)
    snap = {"ts": 0, "collectors": {
        "litellm": {"available": True, "backlog": 8}}}
    keys = {k for k, _ in alerts.evaluate(snap)}
    assert "backlog" in keys


async def test_llamacpp_kvcache_and_busy(monkeypatch):
    srv = TestServer(_stub_app())
    await srv.start_server()
    try:
        base = str(srv.make_url("")).rstrip("/")
        monkeypatch.setattr(config, "LLAMACPP_BASE_URL", base)
        monkeypatch.setattr(config, "LLAMACPP_API_KEY", None)
        async with aiohttp.ClientSession() as s:
            out = await llamacpp.sample(s)
        assert out["kv_cache_pct"] == 30.0        # (0.5+0.1)/2 * 100
        assert out["slots_busy_pct"] == 25.0      # 1 active / 4 slots
    finally:
        await srv.close()


async def test_llamacpp_reports_cpu_threads(monkeypatch):
    """/props carries the thread counts llama.cpp runs with, and they are what tell an
    operator whether idle CPU cores are idle BY DESIGN (layers on the GPU) or starved by a
    low --threads. llama.cpp has moved these between the top level,
    default_generation_settings and params across builds, so all three are read."""
    # "gen_params" and "deep" reproduce the live gap: /props parsed fine (model/ctx/
    # slots populated) yet the old fixed-path read returned None because this build
    # nests the counts under default_generation_settings.params — and a future move
    # would break it again, which the bounded deep walk (_deep_num) must absorb.
    for shape in ("top", "gen", "params", "gen_params", "deep"):
        async def health(_):
            return web.json_response({"status": "ok"})

        async def props(_, _shape=shape):
            body = {"total_slots": 1, "default_generation_settings": {"n_ctx": 4096}}
            vals = {"n_threads": 10, "n_threads_batch": 20}
            if _shape == "top":
                body.update(vals)
            elif _shape == "gen":
                body["default_generation_settings"].update(vals)
            elif _shape == "params":
                body["params"] = vals
            elif _shape == "gen_params":
                body["default_generation_settings"]["params"] = vals
            else:   # deep: some unforeseen future nesting
                body["cpu"] = {"runtime": vals}
            return web.json_response(body)

        async def slots(_):
            return web.json_response([])
        app = web.Application()
        app.router.add_get("/health", health)
        app.router.add_get("/props", props)
        app.router.add_get("/slots", slots)
        srv = TestServer(app)
        await srv.start_server()
        try:
            monkeypatch.setattr(config, "LLAMACPP_BASE_URL",
                                str(srv.make_url("")).rstrip("/"))
            monkeypatch.setattr(config, "LLAMACPP_API_KEY", None)
            async with aiohttp.ClientSession() as s:
                out = await llamacpp.sample(s)
            assert out["n_threads"] == 10, f"shape={shape}"
            assert out["n_threads_batch"] == 20, f"shape={shape}"
        finally:
            await srv.close()


async def test_llamacpp_threads_partial_and_absent(monkeypatch):
    """Real builds report these inconsistently. Only n_threads present must NOT suppress
    it, and a /props with neither must leave both None while the backend stays available —
    'unknown threads' is not 'backend down'."""
    async def health(_):
        return web.json_response({"status": "ok"})

    async def slots(_):
        return web.json_response([])

    async def props_partial(_):
        return web.json_response({"total_slots": 1, "n_threads": 10})   # no batch value

    async def props_none(_):
        return web.json_response({"total_slots": 1})                    # neither reported

    for handler, want_t, want_b in ((props_partial, 10, None), (props_none, None, None)):
        app = web.Application()
        app.router.add_get("/health", health)
        app.router.add_get("/props", handler)
        app.router.add_get("/slots", slots)
        srv = TestServer(app)
        await srv.start_server()
        try:
            monkeypatch.setattr(config, "LLAMACPP_BASE_URL",
                                str(srv.make_url("")).rstrip("/"))
            monkeypatch.setattr(config, "LLAMACPP_API_KEY", None)
            async with aiohttp.ClientSession() as s:
                out = await llamacpp.sample(s)
            assert out["available"] is True          # unknown threads ≠ unhealthy backend
            assert out["n_threads"] == want_t
            assert out["n_threads_batch"] == want_b
        finally:
            await srv.close()


async def test_llamacpp_threads_reach_api_data():
    """The KPI reads these off /api/data, so the fields must survive the snapshot into the
    endpoint — a collector field that never reaches the browser is invisible in practice."""
    # /api/data serves the SNAPSHOT (_latest), which _sample_once builds by copying each
    # backend's dict wholesale — so seed the snapshot the way the sampling loop would.
    appmod._latest = {"ts": 1.0, "collectors": {
        "host": {"available": True, "ncpu": 20, "cpu_pct": 1.0},
        "llamacpp": {"available": True, "status": "ok", "n_slots": 1, "slots_active": 0,
                     "ctx_size": 4096, "n_threads": 10, "n_threads_batch": 20}}}
    c = await _client()
    try:
        d = await (await c.get("/api/data")).json()
        lc = (d.get("latest") or {}).get("collectors", {}).get("llamacpp", {})
        assert lc.get("n_threads") == 10 and lc.get("n_threads_batch") == 20
        # host.ncpu is the other half of the comparison the KPI renders
        assert (d.get("latest") or {}).get("collectors", {}).get("host", {}).get("ncpu") == 20
    finally:
        await c.close()


def test_llamacpp_first_num_rejects_zero_and_junk():
    """A build that reports 0/null/"" threads has NOT reported a thread count; treating 0
    as a real reading would show "0 threads" and read as 'starved' when it is simply
    absent. Only a positive integer counts."""
    assert llamacpp._first_num(None, 0, "", 12) == 12      # skips the non-answers
    assert llamacpp._first_num(0) is None
    assert llamacpp._first_num(None, "abc") is None
    assert llamacpp._first_num("8") == 8                    # string digits are fine


def test_llamacpp_deep_num_finds_relocated_field():
    """Fallback for the live gap: /props is readable but the thread count sits at a
    path the fixed list doesn't know. A bounded deep walk must find the first
    positive value wherever this (or a future) build nests it, ignore zero/junk, and
    return None when it is genuinely absent — without looping on cyclic-looking data
    or scanning unbounded depth."""
    assert llamacpp._deep_num({"n_threads": 16}, "n_threads") == 16
    assert llamacpp._deep_num(
        {"default_generation_settings": {"params": {"n_threads": 16}}}, "n_threads") == 16
    assert llamacpp._deep_num({"a": [{"b": {"n_threads_batch": 32}}]}, "n_threads_batch") == 32
    assert llamacpp._deep_num({"n_threads": 0}, "n_threads") is None      # 0 is 'absent'
    assert llamacpp._deep_num({"model_path": "x", "n_ctx": 4096}, "n_threads") is None
    assert llamacpp._deep_num("not-a-container", "n_threads") is None
    # depth cap: a value buried past the cap is not found (kept cheap on huge blobs)
    deep = cur = {}
    for _ in range(8):
        cur["x"] = {}
        cur = cur["x"]
    cur["n_threads"] = 16
    assert llamacpp._deep_num(deep, "n_threads") is None


async def test_llamacpp_nested_timings_parsed(monkeypatch):
    # newer llama.cpp nests generation timings under a "timings" object instead
    # of the slot top level — the collector must read both (else tok/s + KV%
    # charts stay empty on current builds).
    async def health(_):
        return web.json_response({"status": "ok"})

    async def props(_):
        return web.json_response({"total_slots": 2,
                                  "default_generation_settings": {"n_ctx": 4096}})

    async def slots(_):
        return web.json_response([
            {"is_processing": True,
             "timings": {"predicted_per_second": 55.0,
                         "kv_cache_usage_ratio": 0.4}},
            {"is_processing": False,
             "timings": {"predicted_per_second": 0,
                         "kv_cache_usage_ratio": 0.2}},
        ])

    app = web.Application()
    app.router.add_get("/health", health)
    app.router.add_get("/props", props)
    app.router.add_get("/slots", slots)
    srv = TestServer(app)
    await srv.start_server()
    try:
        base = str(srv.make_url("")).rstrip("/")
        monkeypatch.setattr(config, "LLAMACPP_BASE_URL", base)
        monkeypatch.setattr(config, "LLAMACPP_API_KEY", None)
        async with aiohttp.ClientSession() as s:
            out = await llamacpp.sample(s)
        assert out["predicted_per_second"] == 55.0     # from timings.*
        assert out["kv_cache_pct"] == 30.0             # (0.4+0.2)/2 * 100
    finally:
        await srv.close()


async def test_llamacpp_extra_series_prefill_busy_context(monkeypatch):
    """The three added llama.cpp charts each need a source field. Prefill tok/s
    (prompt_per_second, top-level OR nested in timings), slot-busy % (active/total),
    and context-window fill % (used tokens / n_ctx, spelled n_past here) must all be
    derived from /slots. A build that reports none of them must leave them None while
    the backend stays available — an empty chart auto-hides, it is not an error."""
    async def health(_):
        return web.json_response({"status": "ok"})

    async def props(_):
        return web.json_response({"total_slots": 4,
                                  "default_generation_settings": {"n_ctx": 1000}})

    async def slots(_):
        return web.json_response([
            {"is_processing": True, "n_ctx": 1000, "n_past": 250,
             "prompt_per_second": 800.0,
             "timings": {"predicted_per_second": 40.0}},
            {"is_processing": True, "n_ctx": 1000, "n_past": 750,
             "timings": {"prompt_per_second": 600.0}},   # prefill nested in timings
            {"is_processing": False},
            {"is_processing": False},
        ])

    app = web.Application()
    for path, hdl in (("/health", health), ("/props", props), ("/slots", slots)):
        app.router.add_get(path, hdl)
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LLAMACPP_BASE_URL",
                            str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LLAMACPP_API_KEY", None)
        async with aiohttp.ClientSession() as s:
            out = await llamacpp.sample(s)
        assert out["prompt_per_second"] == 700.0        # (800 + 600) / 2
        assert out["slots_busy_pct"] == 50.0            # 2 active / 4 total
        assert out["ctx_used_pct"] == 50.0             # (250/1000 + 750/1000)/2 * 100
    finally:
        await srv.close()


async def test_llamacpp_extra_series_absent_stay_none(monkeypatch):
    """A minimal /slots (no prefill / no n_past) must not fabricate values: prefill and
    context stay None so their charts hide, busy% is still computable from counts."""
    async def health(_):
        return web.json_response({"status": "ok"})

    async def props(_):
        return web.json_response({"total_slots": 2})

    async def slots(_):
        return web.json_response([{"is_processing": False}, {"is_processing": False}])

    app = web.Application()
    for path, hdl in (("/health", health), ("/props", props), ("/slots", slots)):
        app.router.add_get(path, hdl)
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LLAMACPP_BASE_URL",
                            str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LLAMACPP_API_KEY", None)
        async with aiohttp.ClientSession() as s:
            out = await llamacpp.sample(s)
        assert out["available"] is True
        assert out["prompt_per_second"] is None
        assert out["ctx_used_pct"] is None
        assert out["slots_busy_pct"] == 0.0
    finally:
        await srv.close()


def test_metrics_row_concurrency():
    import app as a
    base = {"host": {"available": True, "cpu_pct": 1, "mem_pct": 1,
                     "disk": {"pct": 1}, "load": [0, 0, 0]},
            "gpu": {"available": False}, "ollama": {"available": False}}
    # litellm in-flight 3 + llama.cpp 2 active slots = 5 concurrent
    snap = {"ts": 0, "collectors": {**base,
            "litellm": {"available": True, "backlog": 3},
            "llamacpp": {"available": True, "slots_active": 2}}}
    assert a._metrics_row(snap)["conc"] == 5
    # only litellm available → just its in-flight
    snap2 = {"ts": 0, "collectors": {**base,
             "litellm": {"available": True, "backlog": 4},
             "llamacpp": {"available": False}}}
    assert a._metrics_row(snap2)["conc"] == 4
    # no LLM backend → None (chart shows gap)
    snap3 = {"ts": 0, "collectors": {**base,
             "litellm": {"available": False}, "llamacpp": {"available": False}}}
    assert a._metrics_row(snap3)["conc"] is None


def test_metrics_row_derived_vrampct_and_tokwatt():
    import app as a
    snap = {"ts": 0, "collectors": {
        "host": {"available": True, "cpu_pct": 1, "mem_pct": 1,
                 "disk": {"pct": 1}, "load": [0, 0, 0]},
        "gpu": {"available": True, "util": 50, "power": 200,
                "vram_used": 60, "vram_total": 240},
        "ollama": {"available": False},
        "litellm": {"available": True, "wait_avg_ms": 1, "req_rate": 0.5,
                    "tok_in_rate": 10, "tok_out_rate": 5, "error_pct": 0,
                    "cost_rate_hr": 1.2},
        "llamacpp": {"available": True, "predicted_per_second": 100,
                     "kv_cache_pct": 40}}}
    row = a._metrics_row(snap)
    assert row["vram_pct"] == 25.0            # 60/240
    assert row["tokwatt"] == 0.5              # 100 tok/s ÷ 200 W
    assert row["reqrate"] == 0.5 and row["kvcache"] == 40
    assert row["errrate"] == 0 and row["costrate"] == 1.2


def test_anomaly_spike_detection(monkeypatch):
    import anomaly
    monkeypatch.setattr(config, "ANOMALY_FACTOR", 4.0)
    monkeypatch.setattr(config, "ANOMALY_MIN_REQS", 20.0)
    monkeypatch.setattr(config, "ANOMALY_KEY_BUDGET_HR", 0.0)
    snap = {"available": True}
    baselines = {
        "busy": {"recent": 100.0, "baseline": 10.0},   # 10× → spike
        "steady": {"recent": 30.0, "baseline": 25.0},  # 1.2× → normal
        "tiny": {"recent": 5.0, "baseline": 0.0},      # below floor → ignore
        "new": {"recent": 50.0, "baseline": 0.0},      # no baseline, above floor
    }
    keys = {k.split(":", 1)[1] for k, _ in anomaly.detect(snap, baselines)}
    assert "busy" in keys and "new" in keys
    assert "steady" not in keys and "tiny" not in keys


def test_anomaly_budget_detection(monkeypatch):
    import anomaly
    monkeypatch.setattr(config, "ANOMALY_FACTOR", 0.0)          # spike off
    monkeypatch.setattr(config, "ANOMALY_KEY_BUDGET_HR", 1.0)   # $1/h cap
    # 15-min window; a key that spent $0.50 → $2/h → over the $1/h cap
    snap = {"available": True, "spend_window_min": 15,
            "top_keys": [{"key": "k1", "alias": "app-x", "cost": 0.5},
                         {"key": "k2", "cost": 0.10}]}   # $0.40/h → under
    msgs = dict(anomaly.detect(snap, {}))
    assert "budget:app-x" in msgs
    assert not any(k.startswith("budget:k2") for k in msgs)


def test_anomaly_disabled_when_zero(monkeypatch):
    import anomaly
    monkeypatch.setattr(config, "ANOMALY_FACTOR", 0.0)
    monkeypatch.setattr(config, "ANOMALY_KEY_BUDGET_HR", 0.0)
    snap = {"available": True, "top_keys": [{"key": "k", "cost": 999}]}
    assert anomaly.detect(snap, {"k": {"recent": 999, "baseline": 1}}) == []


def test_db_key_rate_baselines(tmp_path, monkeypatch):
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "bl.db"))
    db.init()
    now = 5_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    # older hour: label X ~10 reqs; last 5 min: X ~100 reqs (a spike)
    for t in range(3600, 300, -60):
        db.insert_key_series(now - t, [{"key": "X", "alias": "", "reqs": 10}])
    for t in range(240, 0, -30):
        db.insert_key_series(now - t, [{"key": "X", "alias": "", "reqs": 100}])
    bl = db.key_rate_baselines(recent_s=300, base_s=3600)
    assert "X" in bl
    assert bl["X"]["recent"] > bl["X"]["baseline"] * 5     # spike visible


def _hook_app():
    a = web.Application()

    async def hook(_):
        return web.json_response({"ok": True})
    a.router.add_post("/hook", hook)
    return a


def test_key_series_rollup_serves_year_window(tmp_path, monkeypatch):
    # per-key history must reach the 30d window via the 1-hour rollup, so 1-year
    # retention works without keeping raw rows.
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "roll.db"))
    db.init()
    now = 5_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    # 8 hourly points spanning 25h..40h ago: older than the 24h raw window, but
    # within the rollup lookback (prod rolls continuously, so all data is caught)
    for h in range(8):
        db.insert_key_series(now - 90000 - h * 7200,
                             [{"key": "A", "alias": "", "reqs": 5}])
    db.rollup()                                   # fold into 1m + 1h rollups
    # 30d window reads key_series_1h (raw is empty for >24h ago)
    out = db.key_series("30d", top_n=5)
    assert out["labels"] == ["A"]
    assert len(out["points"]) >= 5                # multiple hourly buckets
    # 12-month window reads the same 1-hour rollup tier (>24h → hourly table);
    # its buckets are far wider (~29h) so the same data folds into fewer points.
    out12 = db.key_series("12mo", top_n=5)
    assert out12["labels"] == ["A"] and len(out12["points"]) >= 1
    # raw-only 1h window has nothing that old → empty (proves it used rollup)
    assert db.key_series("1h", top_n=5)["labels"] == []


def test_proc_series_rollup_serves_year_window(tmp_path, monkeypatch):
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "rollp.db"))
    db.init()
    now = 5_100_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    for h in range(8):
        db.insert_proc_series(now - 90000 - h * 7200, "cpu",
                              [{"app": "svc", "cpu": 40}], "cpu")
    db.rollup()
    out = db.proc_series("cpu", "30d", top_n=5)
    assert out["apps"] == ["svc"] and out["points"]
    # 12-month window reads the same 1-hour rollup tier (>24h → hourly table)
    out12 = db.proc_series("cpu", "12mo", top_n=5)
    assert out12["apps"] == ["svc"] and out12["points"]


def test_series_returns_full_span_for_long_windows(tmp_path, monkeypatch):
    """The 30d + 12mo charts must render the FULL window span when the DB holds
    the history — the user-reported "only from the 1st of the month" was limited
    DB history, NOT a query clamp. Seed metrics_1h hourly across 400 days and
    assert db.series() spans ~30 days for 30d and ~a year for 12mo, all populated."""
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "span.db"))
    db.init()
    now = 1_700_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    cols = db._METRIC_COLS
    ph = ",".join("?" * len(cols))
    ins = f"INSERT OR REPLACE INTO metrics_1h(bucket,{','.join(cols)}) VALUES (?,{ph})"
    with db._connect() as conn:
        for h in range(400 * 24):                       # 400 days of hourly buckets
            b = int((now - h * 3600) / 3600) * 3600
            conn.execute(ins, (b, *[float(h % 97 + 1)] * len(cols)))

    def span(w):
        pts = db.series(w, 300)
        ts = [p["t"] for p in pts if p.get("t")]
        return ((max(ts) - min(ts)) / 86400, len(pts),
                all(p.get("cpu") is not None for p in pts))

    s30, n30, ok30 = span("30d")
    s12, n12, ok12 = span("12mo")
    assert s30 >= 28 and n30 >= 100 and ok30, f"30d span={s30:.1f}d pts={n30}"
    assert s12 >= 350 and n12 >= 100 and ok12, f"12mo span={s12:.1f}d pts={n12}"
    # 12mo must reach further back than 30d (proves the window drives the range)
    assert s12 > s30


def test_demo_seed_long_history_populates_rollup_tiers(tmp_path, monkeypatch):
    """demo_seed.seed_long_history fills the 1h + 1m rollup tiers directly so the
    demo showcases 30d/12mo out of the box. Run a small span (fast) and assert the
    tiers are populated and db.series reads them."""
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "demo.db"))
    monkeypatch.setenv("DEMO_HISTORY_DAYS", "8")
    monkeypatch.setenv("DEMO_HISTORY_MIN_DAYS", "1")
    monkeypatch.delenv("DEMO_FAST", raising=False)
    db.init()
    import scripts.demo_seed as ds
    now = 1_700_000_000.0
    ds.seed_long_history(now)
    with db._connect() as conn:
        n1h = conn.execute("SELECT COUNT(*) FROM metrics_1h").fetchone()[0]
        n1m = conn.execute("SELECT COUNT(*) FROM metrics_1m").fetchone()[0]
        nks = conn.execute("SELECT COUNT(*) FROM key_series_1h").fetchone()[0]
        nps = conn.execute("SELECT COUNT(*) FROM proc_series_1h").fetchone()[0]
    assert n1h >= 8 * 24 - 2, f"metrics_1h under-seeded: {n1h}"
    assert n1m >= 24 * 60 - 2, f"metrics_1m under-seeded: {n1m}"
    assert nks > 0 and nps > 0, f"key/proc 1h empty: {nks}/{nps}"
    # the seeded 1h tier is readable via the series API for a >24h window
    monkeypatch.setattr(db.time, "time", lambda: now)
    pts = db.series("30d", 300)
    assert pts and any(p.get("cpu") is not None for p in pts)


def test_key_series_end_param_pans(tmp_path, monkeypatch):
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "kpan.db"))
    db.init()
    now = 4_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    # old key "A" active ~2h ago; new key "B" active now
    for t in range(7200, 6000, -30):
        db.insert_key_series(now - t, [{"key": "A", "alias": "", "reqs": 9}])
    for t in range(300, 0, -30):
        db.insert_key_series(now - t, [{"key": "B", "alias": "", "reqs": 9}])
    live = db.key_series("1h", top_n=5)                 # ends now → sees B
    past = db.key_series("1h", top_n=5, end=now - 6600)  # ~1.8h ago → sees A
    assert live["labels"] == ["B"]
    assert past["labels"] == ["A"]


def test_proc_series_end_param_pans(tmp_path, monkeypatch):
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "ppan.db"))
    db.init()
    now = 4_100_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    for t in range(7200, 6000, -30):
        db.insert_proc_series(now - t, "cpu", [{"app": "old", "cpu": 50}], "cpu")
    for t in range(300, 0, -30):
        db.insert_proc_series(now - t, "cpu", [{"app": "new", "cpu": 50}], "cpu")
    assert db.proc_series("cpu", "1h")["apps"] == ["new"]
    assert db.proc_series("cpu", "1h", end=now - 6600)["apps"] == ["old"]


def test_nav_configured_down_backend_still_shown(monkeypatch):
    # a configured-but-DOWN backend (real error, not "unconfigured") keeps its
    # link — you still want to reach its dashboard to see the outage.
    import app as a
    monkeypatch.setattr(a, "_latest", {"ts": 1, "collectors": {
        "litellm": {"available": False, "error": "conn: ClientError"}}})
    assert a._configured("litellm", False) is True     # down != hidden
    monkeypatch.setattr(a, "_latest", {"ts": 1, "collectors": {
        "litellm": {"available": False, "error": "unconfigured"}}})
    assert a._configured("litellm", True) is False     # unconfigured → hidden


def test_nav_reflects_configured_backends(monkeypatch):
    # deterministic: test the _configured logic directly (the /api/nav endpoint
    # is exercised for shape by test_nav_endpoint_shape; asserting exact endpoint
    # values would race the background sampler that mutates app._latest).
    monkeypatch.setattr(appmod, "_latest", {"ts": 0, "collectors": {}})
    # no live sample → falls back to env presence
    assert appmod._configured("litellm", False) is False   # unconfigured → hidden
    assert appmod._configured("ollama", False) is False
    assert appmod._configured("gpu", False) is False
    assert appmod._configured("litellm", True) is True     # env URL set → shown
    assert appmod._configured("ollama", True) is True


async def test_nav_endpoint_shape():
    c = await _client()
    try:
        d = await (await c.get("/api/nav")).json()
        assert set(d) == {"litellm", "spend", "ollama", "llamacpp", "vllm", "gpu",
                          "network", "admin"}
        # host network page is a local /proc read → always shown, like GPU/CPU
        assert d["network"] is True
        assert all(isinstance(v, bool) for v in d.values())
        # GPU/CPU page hosts universal CPU views → the link is always shown, even with no
        # GPU configured (as here); only the on-page GPU cards degrade to "No GPU detected".
        assert d["gpu"] is True
    finally:
        await c.close()


async def test_alerts_endpoint_shape(monkeypatch):
    # alert config needs an interactive login — the shared URL master token is
    # withheld from Alerts — so log a user in and present the session.
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("alshape", "as@x.io", auth.hash_password("alshapepw1"),
                   "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "alshape", "password": "alshapepw1"})
        r = await c.get("/api/alerts")
        assert r.status == 200
        d = await r.json()
        assert "channels" in d and "thresholds" in d
        assert "active" in d and "history" in d
        ids = {ch["id"] for ch in d["channels"]}
        assert ids == {"webhook"}          # webhook-only
    finally:
        await c.close()


async def test_litellm_models_window_endpoint(monkeypatch):
    """Per-model table endpoint honors the window: the date range follows
    15m/1h/24h/30d/12mo (24h opens yesterday so prior-day records show), bad
    windows fall back to 24h, and it degrades cleanly when LiteLLM is unconfigured."""
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "modeltok-1")
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "")   # unconfigured in tests
    hdr = {"Authorization": "Bearer modeltok-1"}
    c = await _client()
    try:
        # gated like the rest of /api/
        assert (await c.get("/api/litellm/models")).status == 401
        r = await c.get("/api/litellm/models?window=24h", headers=hdr)
        assert r.status == 200
        d = await r.json()
        assert d["window"] == "24h"
        assert d["available"] is False and d["per_model"] == []   # unconfigured
        # 24h is day-granular and opens YESTERDAY, covering prior-day records
        y = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 86400))
        assert d["start_date"] == y and d["start_date"] < d["end_date"]
        # bad window falls back to 24h
        assert (await (await c.get("/api/litellm/models?window=bogus",
                                   headers=hdr)).json())["window"] == "24h"
        # 30d opens further back than 24h
        d30 = await (await c.get("/api/litellm/models?window=30d",
                                 headers=hdr)).json()
        assert d30["start_date"] < d["start_date"]
    finally:
        await c.close()


def test_spend_daily_parser_accepts_litellm_shapes():
    """LiteLLM nests daily rows under `daily_data` (not `data`) and field names vary
    by version. `_rows_of` + `_parse_daily` must handle every shape, and report
    whether a spend figure was actually present (it often is NOT on /global/activity)."""
    # /global/activity — rows under daily_data, requests+tokens but NO spend
    act = {"sum_api_requests": 10,
           "daily_data": [{"date": "2026-01-01", "api_requests": 5, "total_tokens": 90}]}
    rows = litellm._rows_of(act)
    assert rows and len(rows) == 1
    parsed, has_spend = litellm._parse_daily(rows)
    assert has_spend is False and parsed[0]["requests"] == 5 and parsed[0]["spend"] == 0
    # /global/spend/report — group_by_day + spend
    rep = [{"group_by_day": "2026-01-01T00:00:00", "spend": 12.5}]
    parsed2, has_spend2 = litellm._parse_daily(litellm._rows_of(rep))
    assert has_spend2 is True
    assert parsed2[0]["date"] == "2026-01-01" and parsed2[0]["spend"] == 12.5
    # legacy `data` key + total_spend/sum_* aliases still work
    legacy = {"data": [{"day": "2026-02-03", "total_spend": 4.0,
                        "sum_api_requests": 2, "sum_total_tokens": 7}]}
    parsed3, has_spend3 = litellm._parse_daily(litellm._rows_of(legacy))
    assert has_spend3 and parsed3[0]["spend"] == 4.0 and parsed3[0]["tokens"] == 7
    # unusable payloads
    assert litellm._rows_of({"nothing": 1}) is None
    # LiteLLM's /global/activity display format is `Jul 02` (month-abbrev, NO year) —
    # both the date PARSE and the activity↔report spend MERGE key it, so it must
    # normalize to canonical YYYY-MM-DD, else every row drops (the live empty-chart bug).
    assert litellm._norm_date("Jul 02").endswith("-07-02")
    assert litellm._norm_date("July 2").endswith("-07-02")
    assert litellm._norm_date("2026-07-02") == "2026-07-02"
    assert litellm._norm_date("2026/07/02") == "2026-07-02"
    assert litellm._norm_date("2026-07-02T00:00:00Z") == "2026-07-02"
    assert litellm._norm_date("bad") == "" and litellm._norm_date("") == ""
    disp, _ = litellm._parse_daily([{"date": "Jul 02", "api_requests": 147,
                                     "total_tokens": 20134827}])
    assert disp[0]["date"].endswith("-07-02")     # not the raw "Jul 02"
    # activity(no spend, display date) + report(spend, ISO date) MERGE on canonical date
    a, _ = litellm._parse_daily([{"date": "Jul 02", "api_requests": 5}])
    r, _ = litellm._parse_daily([{"date": "2026-07-02T00:00:00", "spend": 9.5}])
    assert a[0]["date"] == r[0]["date"]           # merge key now matches


def test_classify_model_internal_vs_external():
    """Self-hosted providers/open-weight families = reference; external hosted APIs =
    real; a blank/absent model is UNKNOWN (must never count as real external spend)."""
    for m in ("gpt-4o", "anthropic/claude-sonnet", "glm-4.7-flash",
              "azure_ai/gpt-5-mini", "gemini/gemini-2.0"):
        c = litellm.classify_model(m)
        assert c["internal"] is False and c["cost_kind"] == "real", m
    for m in ("ollama/qwen3", "llama-cpp/qwen", "gpt-oss:20b", "vllm/mixtral",
              "huggingface/x", "gemma4", "qwen2.5", "mistral-small"):
        c = litellm.classify_model(m)
        assert c["internal"] is True and c["cost_kind"] == "reference", m
    # blank / whitespace model → unknown, NOT real
    for m in ("", "  ", None):
        c = litellm.classify_model(m)
        assert c["internal"] is None and c["cost_kind"] == "unknown", repr(m)


def test_classify_model_admin_override_wins():
    """An admin per-model override flips the auto-detected kind, both directions, and
    is matched tolerant of a provider/model prefix."""
    # self-hosted model FORCED to real (e.g. an open weight served via a paid API)
    ov = {"gemma4": "real"}
    c = litellm.classify_model("gemma4", ov)
    assert c["cost_kind"] == "real" and c["internal"] is False and c["overridden"] is True
    # external model FORCED to reference (estimated)
    ov = {"gpt-4o": "reference"}
    c = litellm.classify_model("gpt-4o", ov)
    assert c["cost_kind"] == "reference" and c["internal"] is True and c["overridden"] is True
    # prefix-tolerant: override keyed bare, model reported with a provider prefix
    ov = {"qwen2.5": "real"}
    c = litellm.classify_model("ollama/qwen2.5", ov)
    assert c["cost_kind"] == "real" and c["overridden"] is True
    # a blank model is never overridden into a cost bucket
    assert litellm.classify_model("", {"": "real"})["cost_kind"] == "unknown"
    # no/empty override → heuristic default, overridden=False
    assert litellm.classify_model("gpt-4o")["overridden"] is False
    assert litellm.classify_model("gpt-4o", {})["cost_kind"] == "real"


async def test_per_model_daily_cost_attributes_by_actual_day(monkeypatch):
    """The accurate cost path: per-day per-model tokens × price, so an external model's
    cost lands ONLY on the days it ran — not smeared across the window."""
    async def fake_fetch(session, url, headers=None, timeout_s=None):
        # gpt-4o (external/real) ran only Jul 08-09; qwen (self-hosted) ran Jul 07-08
        return ([
            {"model": "gpt-4o", "daily_data": [
                {"date": "2026-07-08", "total_tokens": 1000},
                {"date": "2026-07-09", "total_tokens": 500}]},
            {"model": "ollama/qwen", "daily_data": [
                {"date": "2026-07-07", "total_tokens": 2000},
                {"date": "2026-07-08", "total_tokens": 3000}]},
        ], None)
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    prices = {"gpt-4o": 0.001, "ollama/qwen": 0.0001}
    dc = await litellm.per_model_daily_cost(None, "2026-07-01", "2026-07-10", prices)
    assert dc is not None
    # Jul 07: only self-hosted → real is ZERO (the whole point of the fix)
    assert dc["2026-07-07"]["real"] == 0.0
    assert round(dc["2026-07-07"]["est"], 4) == round(2000 * 0.0001, 4)
    # Jul 08: both ran
    assert round(dc["2026-07-08"]["real"], 4) == round(1000 * 0.001, 4)
    assert round(dc["2026-07-08"]["est"], 4) == round(3000 * 0.0001, 4)
    # Jul 09: only gpt-4o
    assert round(dc["2026-07-09"]["real"], 4) == round(500 * 0.001, 4)
    assert dc["2026-07-09"].get("est", 0.0) == 0.0


async def test_per_model_daily_cost_none_without_daily_breakdown(monkeypatch):
    """Falls back (None) when /global/activity/model gives only range totals, no daily_data."""
    async def fake_fetch(session, url, headers=None, timeout_s=None):
        return ([{"model": "gpt-4o", "sum_total_tokens": 1500}], None)   # no daily_data
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    dc = await litellm.per_model_daily_cost(None, "2026-07-01", "2026-07-10", {"gpt-4o": 0.001})
    assert dc is None


def test_apply_daily_cost_folds_onto_points_and_years():
    """apply_daily_cost maps accurate per-day costs onto day points + year totals, and a
    day with no real cost keeps real_cost 0 (the external model didn't run that day)."""
    t7 = appmod._date_epoch("2026-07-07")
    t8 = appmod._date_epoch("2026-07-08")
    series = {"granularity": "day",
              "points": [{"t": t7, "tokens": 2000}, {"t": t8, "tokens": 4000}],
              "years": [{"year": 2026, "tokens": 6000}]}
    daily_cost = {"2026-07-07": {"real": 0.0, "est": 0.20},
                  "2026-07-08": {"real": 1.00, "est": 0.30}}
    appmod.apply_daily_cost(series, daily_cost)
    assert series["points"][0]["real_cost"] == 0.0 and series["points"][0]["est_cost"] == 0.20
    assert series["points"][1]["real_cost"] == 1.00 and series["points"][1]["est_cost"] == 0.30
    assert series["years"][0]["real_cost"] == 1.00 and series["years"][0]["est_cost"] == 0.50
    assert series["real_cost_total"] == 1.00 and series["est_cost_total"] == 0.50
    assert series["cost_available"] is True


def test_apply_daily_cost_month_granularity():
    """12mo view: a point's `t` is a MONTH-start epoch, so every day in that month must
    sum into it (not just an exact-date match)."""
    tjun = appmod._date_epoch("2026-06-01")
    tjul = appmod._date_epoch("2026-07-01")
    series = {"granularity": "month",
              "points": [{"t": tjun, "tokens": 0}, {"t": tjul, "tokens": 0}],
              "years": [{"year": 2026}]}
    dc = {"2026-06-15": {"real": 1.0, "est": 2.0},
          "2026-07-03": {"real": 0.5, "est": 1.0},
          "2026-07-20": {"real": 0.25, "est": 0.5}}
    appmod.apply_daily_cost(series, dc)
    assert series["points"][0]["real_cost"] == 1.0 and series["points"][0]["est_cost"] == 2.0
    assert series["points"][1]["real_cost"] == 0.75 and series["points"][1]["est_cost"] == 1.5
    assert series["years"][0]["real_cost"] == 1.75 and series["years"][0]["est_cost"] == 3.5


def test_anchor_real_to_actual_overwrites_reconstruction_with_cash():
    """The real series must show LiteLLM's ACTUAL cash (`spend` on each point/year), not
    the tokens×price rebuild — else the card's real total won't match per-key spend. The
    estimated (self-hosted) series is untouched."""
    series = {"points": [{"spend": 2.00, "real_cost": 5.55, "est_cost": 0.40},
                         {"spend": 2.43, "real_cost": 6.66, "est_cost": 0.60}],
              "years": [{"year": 2026, "spend": 4.43, "real_cost": 12.21}],
              "est_cost_total": 1.00}
    appmod.anchor_real_to_actual(series)
    # real_cost is now the actual cash, NOT the 5.55/6.66 reconstruction
    assert series["points"][0]["real_cost"] == 2.00
    assert series["points"][1]["real_cost"] == 2.43
    assert series["real_cost_total"] == 4.43            # matches the real spend elsewhere
    assert series["years"][0]["real_cost"] == 4.43
    assert series["cost_basis"] == "actual-real"
    # estimated (self-hosted) reconstruction is left alone
    assert series["points"][0]["est_cost"] == 0.40 and series["points"][1]["est_cost"] == 0.60


def test_anchor_real_to_actual_noop_without_cash():
    """Free-tier LiteLLM reports no per-day $ (spend 0) — anchoring must NOT wipe the
    reconstruction to 0; the estimate is the only cost figure available, so keep it."""
    series = {"points": [{"spend": 0.0, "real_cost": 1.20, "est_cost": 0.30}],
              "years": [{"year": 2026, "spend": 0.0, "real_cost": 1.20}],
              "real_cost_total": 1.20, "est_cost_total": 0.30}
    appmod.anchor_real_to_actual(series)
    assert series["points"][0]["real_cost"] == 1.20     # reconstruction preserved
    assert series["real_cost_total"] == 1.20
    assert series.get("cost_basis") != "actual-real"


async def test_per_model_daily_cost_honors_override_and_normalizes_dates(monkeypatch):
    """per_model_daily_cost normalizes LiteLLM's `Jul 08` display date to canonical form
    and respects the admin cost-kind override (self-hosted → real moves it to the real
    bucket)."""
    async def fake_fetch(session, url, headers=None, timeout_s=None):
        return ([{"model": "ollama/qwen",
                  "daily_data": [{"date": "Jul 08", "total_tokens": 1000}]}], None)
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    prices = {"ollama/qwen": 0.002}
    dc = await litellm.per_model_daily_cost(None, "2026-07-01", "2026-07-10", prices)
    key = next(iter(dc))
    assert key.endswith("-07-08")                       # "Jul 08" → canonical YYYY-07-08
    assert dc[key]["est"] == 1000 * 0.002 and dc[key]["real"] == 0.0   # self-hosted default
    # override qwen → real: same tokens now land in the REAL bucket
    dc2 = await litellm.per_model_daily_cost(None, "2026-07-01", "2026-07-10", prices,
                                             {"ollama/qwen": "real"})
    key2 = next(iter(dc2))
    assert dc2[key2]["real"] == 1000 * 0.002 and dc2[key2]["est"] == 0.0


def test_cost_model_split_groups_by_kind():
    """cost_model_split buckets models by their (override-adjusted) cost_kind, biggest
    first, skipping zero-usage + unattributed — feeds the cost-over-time legend tooltip."""
    rows = [{"model": "gpt-4o", "tokens": 500, "cost_kind": "real"},
            {"model": "ollama/qwen", "tokens": 900, "cost_kind": "reference"},
            {"model": "claude", "tokens": 100, "cost_kind": "real"},
            {"model": "idle-model", "tokens": 0, "cost_kind": "real"},      # no usage → skip
            {"model": "(unattributed)", "tokens": 50, "cost_kind": "real"}]  # skip
    split = appmod.cost_model_split(rows)
    assert split["real"] == ["gpt-4o", "claude"]        # 500 before 100
    assert split["reference"] == ["ollama/qwen"]
    # an override that flips qwen → real lands it in the real bucket
    rows2 = [{"model": "ollama/qwen", "tokens": 900, "cost_kind": "real"}]
    assert appmod.cost_model_split(rows2)["real"] == ["ollama/qwen"]
    assert appmod.cost_model_split([]) == {"real": [], "reference": []}


def test_model_kind_db_roundtrip():
    """db.model_kind_set/overrides/delete round-trip; invalid kind refused."""
    now = time.time()
    assert db.model_kind_set("gpt-4o", "reference", now) is True
    assert db.model_kind_overrides().get("gpt-4o") == "reference"
    assert db.model_kind_set("gpt-4o", "real", now) is True        # upsert
    assert db.model_kind_overrides().get("gpt-4o") == "real"
    assert db.model_kind_set("gpt-4o", "bogus", now) is False      # invalid kind
    assert db.model_kind_set("", "real", now) is False            # empty model
    assert db.model_kind_delete("gpt-4o") is True
    assert "gpt-4o" not in db.model_kind_overrides()
    assert db.model_kind_delete("gpt-4o") is False                # already gone


async def test_per_model_range_applies_kind_override(monkeypatch):
    """per_model_range honours the admin override: each row's cost_kind flips and is
    flagged kind_overridden, so the Spend real-vs-estimated split follows the override."""
    async def fake_fetch(session, url, headers=None, timeout_s=None):
        return ([{"model": "gpt-4o", "sum_api_requests": 10, "sum_total_tokens": 100},
                 {"model": "ollama/qwen", "sum_api_requests": 5, "sum_total_tokens": 50}],
                None)
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    # no override: gpt-4o=real (external), ollama/qwen=reference (self-hosted)
    rows = await litellm.per_model_range(None, "2026-07-01", "2026-07-02")
    byname = {r["model"]: r for r in rows}
    assert byname["gpt-4o"]["cost_kind"] == "real"
    assert byname["ollama/qwen"]["cost_kind"] == "reference"
    assert byname["gpt-4o"]["kind_overridden"] is False
    # override flips both directions
    rows = await litellm.per_model_range(None, "2026-07-01", "2026-07-02",
                                         {"gpt-4o": "reference", "ollama/qwen": "real"})
    byname = {r["model"]: r for r in rows}
    assert byname["gpt-4o"]["cost_kind"] == "reference" and byname["gpt-4o"]["kind_overridden"] is True
    assert byname["ollama/qwen"]["cost_kind"] == "real" and byname["ollama/qwen"]["kind_overridden"] is True


def test_usage_split_by_tokens_and_requests():
    """The usage split (real/reference/unknown by tokens+requests) works without
    per-model cost — the lite-mode 'X% self-hosted' story. Unknown (blank model) is
    kept separate, never folded into real."""
    rows = [{"reqs": 3930, "tokens": 554_000_000, "internal": True},
            {"reqs": 258, "tokens": 500, "internal": None},
            {"reqs": 109, "tokens": 8_700_000, "internal": False}]
    u = appmod._usage_split(rows)
    assert u["reference"]["tokens"] == 554_000_000 and u["reference"]["reqs"] == 3930
    assert u["real"]["tokens"] == 8_700_000
    assert u["unknown"]["reqs"] == 258 and u["unknown"]["tokens"] == 500
    assert u["reference_token_pct"] > 98 and u["real_token_pct"] < 2
    assert u["tokens_total"] == 554_000_000 + 500 + 8_700_000


def test_bucket_spend_splits_real_vs_reference():
    """When daily rows carry a real/reference split, bucket_spend sums it per bucket
    + per year and reports totals; without it, split_available is False."""
    daily = [{"date": "2026-01-01", "spend": 100.0, "real": 60.0, "reference": 40.0,
              "requests": 1, "tokens": 1},
             {"date": "2026-01-02", "spend": 50.0, "real": 30.0, "reference": 20.0,
              "requests": 1, "tokens": 1}]
    out = appmod.bucket_spend(daily, "30d")
    assert out["split_available"] is True
    assert out["real_total"] == 90.0 and out["reference_total"] == 60.0
    assert out["points"][0]["real"] == 60.0 and out["points"][0]["reference"] == 40.0
    assert out["years"][0]["real"] == 90.0 and out["years"][0]["reference"] == 60.0
    # real + reference must ALWAYS add up to the total (reference = total − real)
    for p in out["points"]:
        assert round(p["real"] + p["reference"], 2) == p["spend"]
    for y in out["years"]:
        assert round(y["real"] + y["reference"], 2) == y["spend"]
    assert round(out["real_total"] + out["reference_total"], 2) == \
        round(sum(r["spend"] for r in daily), 2)
    # no split in the source → split_available False, no real/reference keys
    plain = appmod.bucket_spend([{"date": "2026-01-01", "spend": 10.0,
                                  "requests": 1, "tokens": 1}], "30d")
    assert plain["split_available"] is False and "real_total" not in plain


def test_window_and_years_totals_cover_full_year_not_window():
    """Regression: the per-year total must be year-to-date, NOT just the 30-day
    window's slice (the '2026 total was only 35 days' bug). Chart points still
    follow the window."""
    import time as _t
    now = _t.time()
    daily = []
    for i in range(400, 0, -1):                       # a full year of $10/day
        daily.append({"date": _t.strftime("%Y-%m-%d", _t.gmtime(now - i * 86400)),
                      "spend": 10.0, "requests": 1, "tokens": 1})
    out = appmod.window_and_years(daily, "30d", now)
    assert len(out["points"]) <= 31                    # chart = last ~30 days
    this_year = _t.strftime("%Y", _t.gmtime(now))
    yr = {str(y["year"]): y["spend"] for y in out["years"]}
    # the current year's total is far bigger than a 30-day slice ($300)
    assert yr[this_year] > 300


def test_spend_parsing_never_crashes_on_odd_shapes():
    """Regression: the Spend endpoint 500'd on real LiteLLM data. Odd date formats
    and non-numeric values must be coerced/skipped, never raise."""
    # date tolerance
    day = 1783641600.0     # 2026-07-10 00:00 UTC
    assert appmod._date_epoch("2026-07-10") == day
    assert appmod._date_epoch("2026/07/10") == day               # slashes
    assert appmod._date_epoch("2026-07-10T00:00:00Z") == day     # ISO datetime + Z
    assert appmod._date_epoch("2026-07-10 12:30:00") == day      # datetime → day start
    assert appmod._date_epoch(1783641600) == day                 # epoch seconds
    assert appmod._date_epoch(1783641600000) == day              # epoch millis
    for bad in ("not-a-date", "", None, "abc"):
        assert appmod._date_epoch(bad) is None
    # non-numeric spend/counts are coerced, unparseable rows dropped
    rows = [{"date": "2026-07-10", "spend": "12.5", "api_requests": "5",
             "total_tokens": "90"},
            {"date": "2026-07-11T00:00:00", "spend": 7.0},
            {"date": "bad-date", "spend": 1.0},        # dropped downstream
            {"no_date_field": 1}]                        # skipped in parse
    parsed, has_spend = litellm._parse_daily(rows)
    assert len(parsed) == 3 and has_spend is True
    assert parsed[0]["spend"] == 12.5 and parsed[0]["requests"] == 5
    out = appmod.bucket_spend(parsed, "30d")             # must not raise
    assert len(out["points"]) == 2                       # bad-date row dropped


def test_bucket_spend_day_month_and_years():
    """bucket_spend folds daily rows to day (30d) / month (12mo) and rolls up a
    per-calendar-year total for the 'spending per year' view."""
    daily = [{"date": "2025-12-30", "spend": 10.0, "requests": 1, "tokens": 5},
             {"date": "2025-12-31", "spend": 20.0, "requests": 2, "tokens": 6},
             {"date": "2026-01-01", "spend": 30.0, "requests": 3, "tokens": 7}]
    day = appmod.bucket_spend(daily, "30d")
    assert day["granularity"] == "day" and len(day["points"]) == 3
    mon = appmod.bucket_spend(daily, "12mo")
    assert mon["granularity"] == "month" and len(mon["points"]) == 2   # Dec + Jan
    assert mon["points"][0]["spend"] == 30.0                           # Dec = 10+20
    years = {y["year"]: y["spend"] for y in mon["years"]}
    assert years == {2025: 30.0, 2026: 30.0}


def test_bucket_model_series_windows_and_other():
    """bucket_model_series aligns each model's daily cost to a shared axis (30d daily /
    12mo monthly), ranks by windowed cost, and folds models past top_n into 'Other'."""
    import time as _t
    series = {"dates": ["2026-07-14", "2026-07-15", "2026-07-16"], "models": [
        {"model": "gpt-5-mini", "kind": "real", "daily": {"2026-07-15": 10.0, "2026-07-16": 20.0}},
        {"model": "local-llama", "kind": "reference", "daily": {"2026-07-14": 1.0, "2026-07-16": 2.0}},
    ]}
    import calendar
    # UTC epoch (timegm), NOT mktime: bucket_model_series now clamps its right edge to
    # gmtime(now), and the real handler passes a UTC epoch (time.time()/_q_end). mktime (local)
    # would skew the anchor date by the TZ offset and drop the boundary label in UTC+ zones.
    now = calendar.timegm(_t.strptime("2026-07-16", "%Y-%m-%d"))
    out = appmod.bucket_model_series(series, "30d", now)
    assert out["available"] is True and out["labels"] == series["dates"]
    top = out["models"][0]
    assert top["model"] == "gpt-5-mini" and top["kind"] == "real"      # ranked by cost
    assert top["costs"] == [0.0, 10.0, 20.0] and top["total"] == 30.0  # aligned to axis
    # top_n grouping: with a low cap the smaller model rolls into 'Other'
    out2 = appmod.bucket_model_series(series, "30d", now, top_n=1)
    assert out2["models"][0]["model"] == "gpt-5-mini"
    assert out2["models"][1]["model"].startswith("Other")
    # 12mo → monthly buckets
    mon = appmod.bucket_model_series(series, "12mo", now)
    assert mon["labels"][-1] == "2026-07"
    assert next(m for m in mon["models"] if m["model"] == "gpt-5-mini")["total"] == 30.0


async def test_spend_model_series_endpoint(monkeypatch):
    """/api/spend/model-series is LiteLLM-gated (404 without) and returns per-model
    cost-over-time (labels + one entry per model with its cost array)."""
    # gated: no LiteLLM → 404
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "")
    c = await _client()
    try:
        assert (await c.get("/api/spend/model-series")).status == 404
    finally:
        await c.close()
    # configured + mocked per-model daily series → shaped response
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")

    async def fake_prices(session):
        return {"gpt-5-mini": 2.25e-06}

    async def fake_series(session, start, end, prices, ov):
        return {"dates": ["2026-07-15", "2026-07-16"], "models": [
            {"model": "gpt-5-mini", "kind": "real", "total": 30.0,
             "daily": {"2026-07-15": 10.0, "2026-07-16": 20.0}}]}
    monkeypatch.setattr(litellm, "model_prices", fake_prices)
    monkeypatch.setattr(litellm, "per_model_daily_series", fake_series)
    c2 = await _client()
    try:
        d = await (await c2.get("/api/spend/model-series?window=30d")).json()
        assert d["available"] is True and d["labels"]
        m = d["models"][0]
        assert m["model"] == "gpt-5-mini" and m["kind"] == "real" and len(m["costs"]) == len(d["labels"])
    finally:
        await c2.close()


async def test_spend_series_endpoint(monkeypatch):
    """/api/spend/series is auth-gated, validates the window, and degrades cleanly
    when LiteLLM is unconfigured."""
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "sp-tok-123456")
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "")
    hdr = {"Authorization": "Bearer sp-tok-123456"}
    c = await _client()
    try:
        assert (await c.get("/api/spend/series")).status == 401      # gated
        d = await (await c.get("/api/spend/series?window=12mo", headers=hdr)).json()
        assert d["window"] == "12mo" and d["available"] is False
        assert d["points"] == [] and d["years"] == []
        # bad window falls back to 30d
        d2 = await (await c.get("/api/spend/series?window=nope", headers=hdr)).json()
        assert d2["window"] == "30d"
    finally:
        await c.close()


async def test_spend_series_is_cached_within_ttl(monkeypatch):
    """Tier-2 #16: /api/spend/series serves a short-TTL cache keyed on window, so its
    multi-round-trip LiteLLM fan-out runs once per window per TTL no matter how many tabs poll
    it; `?diag=1` bypasses the cache."""
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "sp-cache-1")
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    calls = {"n": 0}

    async def _daily(session, s, e):
        calls["n"] += 1
        return [{"date": "2026-07-01", "requests": 10, "tokens": 1000, "spend": 0.5}]

    async def _prices(session):
        return {"gpt-4o": 0.001}

    async def _permodel(session, s, e, ov=None):
        return [{"model": "gpt-4o", "tokens": 1000, "reqs": 10,
                 "internal": False, "cost_kind": "real"}]
    monkeypatch.setattr(litellm, "spend_activity", _daily)
    monkeypatch.setattr(litellm, "model_prices", _prices)
    monkeypatch.setattr(litellm, "per_model_range", _permodel)
    # Mock ALL upstream calls the handler makes (not just the ones we assert on) so the test is
    # deterministic — an unmocked call would hit the (unresolvable) proxy, and how that DNS
    # failure surfaces differs by libc (glibc NXDOMAIN vs musl EAI_AGAIN), which once made this
    # environment-fragile (passed on the host, failed in the Alpine build image).
    async def _none3(session, s, e, *a, **k):
        return None
    monkeypatch.setattr(litellm, "per_model_daily_cost", _none3)
    monkeypatch.setattr(litellm, "per_model_daily_tokens", _none3)

    async def _probe(session, s, e, *a, **k):
        return {}
    monkeypatch.setattr(litellm, "spend_report_probe", _probe)
    hdr = {"Authorization": "Bearer sp-cache-1"}
    c = await _client()
    try:
        assert (await (await c.get("/api/spend/series?window=30d", headers=hdr)).json())["available"]
        assert calls["n"] == 1
        await c.get("/api/spend/series?window=30d", headers=hdr)     # 2nd poll → cache hit
        assert calls["n"] == 1, "second poll within TTL must be served from cache"
        await c.get("/api/spend/series?window=30d&diag=1", headers=hdr)   # diag bypasses cache
        assert calls["n"] == 2, "?diag=1 must bypass the cache"
    finally:
        await c.close()


async def test_spend_series_attaches_cost_models(monkeypatch):
    """/api/spend/series attaches cost_models {real:[…],reference:[…]} so the
    cost-over-time legend can tooltip the models in each bucket."""
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "sp-tok-654321")
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")

    async def _daily(session, s, e):
        return [{"date": "2026-07-01", "requests": 10, "tokens": 1000, "spend": 0.0}]

    async def _prices(session):
        return {"gpt-4o": 0.001, "ollama/qwen": 0.0001}

    async def _permodel(session, s, e, ov=None):
        return [{"model": "gpt-4o", "tokens": 600, "reqs": 6,
                 "internal": False, "cost_kind": "real"},
                {"model": "ollama/qwen", "tokens": 400, "reqs": 4,
                 "internal": True, "cost_kind": "reference"}]
    monkeypatch.setattr(litellm, "spend_activity", _daily)
    monkeypatch.setattr(litellm, "model_prices", _prices)
    monkeypatch.setattr(litellm, "per_model_range", _permodel)
    hdr = {"Authorization": "Bearer sp-tok-654321"}
    c = await _client()
    try:
        d = await (await c.get("/api/spend/series?window=30d", headers=hdr)).json()
        assert d["available"] is True and d.get("cost_available") is True
        cm = d.get("cost_models")
        assert cm and cm["real"] == ["gpt-4o"] and cm["reference"] == ["ollama/qwen"]
        # per-year rollup carries real_cost + est_cost — the top-right year card's source
        yrs = d.get("years") or []
        assert yrs and all("real_cost" in y and "est_cost" in y for y in yrs)
    finally:
        await c.close()


# Two RECENT dates for the windowed spend-series tests. These used to be hardcoded
# ("2026-07-07"/"2026-07-08") which made them TIME BOMBS: /api/spend/series?window=30d
# correctly drops anything older than 30 days, so the fixtures silently fell out of the
# window as the calendar advanced and the assertions started KeyError-ing on a date the
# code was right to omit. Anchored to "now" they stay inside any window under test.
def _recent_days(n=2):
    import datetime as _dt
    today = _dt.datetime.now(_dt.timezone.utc).date()
    return [(today - _dt.timedelta(days=i)).isoformat() for i in range(n, 0, -1)]


async def test_spend_series_uses_per_day_cost_when_available(monkeypatch):
    """When LiteLLM gives a per-day per-model breakdown, the series uses it (cost_basis
    'per-day') so an external model's cost lands ONLY on days it ran — Jul 07 (self-hosted
    only) shows real_cost 0, which the old blended estimate wrongly smeared > 0."""
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "sp-tok-pd1")
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")

    D7, D8 = _recent_days()

    async def _daily(session, s, e):
        return [{"date": D7, "requests": 5, "tokens": 2000, "spend": 0.0},
                {"date": D8, "requests": 9, "tokens": 4000, "spend": 0.0}]

    async def _prices(session):
        return {"gpt-4o": 0.001, "ollama/qwen": 0.0001}

    async def _pm(session, s, e, ov=None):
        return [{"model": "gpt-4o", "tokens": 1000, "reqs": 4,
                 "internal": False, "cost_kind": "real"},
                {"model": "ollama/qwen", "tokens": 5000, "reqs": 10,
                 "internal": True, "cost_kind": "reference"}]

    async def _pmd(session, s, e, prices, ov=None):
        return {D7: {"real": 0.0, "est": 0.20},
                D8: {"real": 1.00, "est": 0.30}}
    monkeypatch.setattr(litellm, "spend_activity", _daily)
    monkeypatch.setattr(litellm, "model_prices", _prices)
    monkeypatch.setattr(litellm, "per_model_range", _pm)
    monkeypatch.setattr(litellm, "per_model_daily_cost", _pmd)
    hdr = {"Authorization": "Bearer sp-tok-pd1"}
    c = await _client()
    try:
        d = await (await c.get("/api/spend/series?window=30d", headers=hdr)).json()
        assert d.get("cost_basis") == "per-day"
        pts = {time.strftime("%Y-%m-%d", time.gmtime(p["t"])): p for p in d["points"]}
        assert pts[D7]["real_cost"] == 0.0      # external model didn't run → 0
        assert pts[D8]["real_cost"] == 1.00
        assert d["real_cost_total"] == 1.00
    finally:
        await c.close()


async def test_spend_series_real_anchored_to_actual_cash(monkeypatch):
    """When LiteLLM reports actual daily cash, the 'real (external)' series must equal that
    cash (so the card agrees with per-key spend / Cost-by-user), NOT the tokens×price
    reconstruction. The estimated (self-hosted) series stays the reconstruction."""
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "sp-tok-anc1")
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")

    D7, D8 = _recent_days()

    async def _daily(session, s, e):   # actual cash: 2.00 + 2.43 = 4.43
        return [{"date": D7, "requests": 5, "tokens": 2000, "spend": 2.00},
                {"date": D8, "requests": 9, "tokens": 4000, "spend": 2.43}]

    async def _prices(session):
        return {"gpt-4o": 0.001, "ollama/qwen": 0.0001}

    async def _pm(session, s, e, ov=None):
        return [{"model": "gpt-4o", "tokens": 1000, "cost_kind": "real"},
                {"model": "ollama/qwen", "tokens": 5000, "cost_kind": "reference"}]

    async def _pmd(session, s, e, prices, ov=None):   # reconstruction real would be 9.99
        return {D7: {"real": 4.44, "est": 0.20},
                D8: {"real": 5.55, "est": 0.30}}
    monkeypatch.setattr(litellm, "spend_activity", _daily)
    monkeypatch.setattr(litellm, "model_prices", _prices)
    monkeypatch.setattr(litellm, "per_model_range", _pm)
    monkeypatch.setattr(litellm, "per_model_daily_cost", _pmd)
    hdr = {"Authorization": "Bearer sp-tok-anc1"}
    c = await _client()
    try:
        d = await (await c.get("/api/spend/series?window=30d", headers=hdr)).json()
        assert d.get("cost_basis") == "actual-real"
        pts = {time.strftime("%Y-%m-%d", time.gmtime(p["t"])): p for p in d["points"]}
        assert pts[D7]["real_cost"] == 2.00     # actual cash, not 4.44 rebuild
        assert pts[D8]["real_cost"] == 2.43
        assert d["real_cost_total"] == 4.43               # == the real spend shown elsewhere
        assert d["real_cost_lifetime"] == 4.43            # all in 2026 → lifetime == window here
        # estimated (self-hosted) is still the reconstruction
        assert pts[D7]["est_cost"] == 0.20 and pts[D8]["est_cost"] == 0.30
    finally:
        await c.close()


async def test_spend_series_lifetime_exceeds_window_with_old_history(monkeypatch):
    """The 30d window can't show usage older than 30 days, but the lifetime real total sums
    the FULL pulled history — so a card whose window total is small still reconciles with
    per-key spend via `real_cost_lifetime`."""
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "sp-tok-life1")
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    today = time.strftime("%Y-%m-%d", time.gmtime())
    old = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 400 * 86400))  # >1yr ago

    async def _daily(session, s, e):     # 10.00 old + 2.43 recent = 12.43 lifetime
        return [{"date": old, "requests": 3, "tokens": 9000, "spend": 10.00},
                {"date": today, "requests": 9, "tokens": 4000, "spend": 2.43}]

    async def _prices(session):
        return {"gpt-4o": 0.001}

    async def _pm(session, s, e, ov=None):
        return [{"model": "gpt-4o", "tokens": 1000, "cost_kind": "real"}]

    async def _pmd(session, s, e, prices, ov=None):
        return {old: {"real": 10.00, "est": 0.0}, today: {"real": 2.43, "est": 0.0}}
    monkeypatch.setattr(litellm, "spend_activity", _daily)
    monkeypatch.setattr(litellm, "model_prices", _prices)
    monkeypatch.setattr(litellm, "per_model_range", _pm)
    monkeypatch.setattr(litellm, "per_model_daily_cost", _pmd)
    hdr = {"Authorization": "Bearer sp-tok-life1"}
    c = await _client()
    try:
        d = await (await c.get("/api/spend/series?window=30d", headers=hdr)).json()
        # 30d window sees only today's 2.43; lifetime sums both → 12.43 (matches per-key spend)
        assert d["real_cost_total"] == 2.43
        assert d["real_cost_lifetime"] == 12.43
    finally:
        await c.close()


async def test_spend_series_anchors_real_even_on_blended_fallback(monkeypatch):
    """No per-model daily breakdown → the code takes the BLENDED estimate path. Even there,
    the real series must still be anchored to actual cash (the blended rebuild only feeds
    the estimated/self-hosted series), and lifetime real must equal actual spend."""
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "sp-tok-bl1")
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")

    D7, D8 = _recent_days()

    async def _daily(session, s, e):     # actual cash 1.11 + 3.32 = 4.43
        return [{"date": D7, "requests": 5, "tokens": 2000, "spend": 1.11},
                {"date": D8, "requests": 9, "tokens": 4000, "spend": 3.32}]

    async def _prices(session):
        return {"gpt-4o": 0.001, "ollama/qwen": 0.0001}

    async def _pm(session, s, e, ov=None):   # gives a reference (self-hosted) rate for est
        return [{"model": "gpt-4o", "tokens": 1000, "cost_kind": "real"},
                {"model": "ollama/qwen", "tokens": 5000, "cost_kind": "reference"}]

    async def _no_daily_cost(session, s, e, prices, ov=None):
        return {}                            # → blended fallback
    monkeypatch.setattr(litellm, "spend_activity", _daily)
    monkeypatch.setattr(litellm, "model_prices", _prices)
    monkeypatch.setattr(litellm, "per_model_range", _pm)
    monkeypatch.setattr(litellm, "per_model_daily_cost", _no_daily_cost)
    hdr = {"Authorization": "Bearer sp-tok-bl1"}
    c = await _client()
    try:
        d = await (await c.get("/api/spend/series?window=30d", headers=hdr)).json()
        assert d.get("cost_basis") == "actual-real"       # anchored, despite blended est
        assert d["real_cost_total"] == 4.43               # actual cash, not blended rebuild
        assert d["real_cost_lifetime"] == 4.43
        assert d["est_cost_total"] > 0                     # self-hosted estimate still present
    finally:
        await c.close()


async def test_spend_page_served_and_gated(monkeypatch):
    """The Spend & Quota page renders open and is auth-gated once a token is set."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")  # spend needs LiteLLM
    c = await _client()
    try:
        r = await c.get("/spend")
        assert r.status == 200
        html = await r.text()
        assert "Spend &amp; Quota" in html and "/api/budgets" in html
        assert 'href="/spend"' in html            # sidebar self-link
        # Free-tier LiteLLM has no daily $ (that's Enterprise /global/spend/report), so
        # the timeline is a USAGE chart (requests + tokens), not an empty $ chart.
        assert "Usage over time" in html and "requests &amp; tokens per day" in html
        # cumulative cost horizontal bar chart (the $ that DOES exist, from
        # /global/spend/keys) — grouped by USER (main), with user/key/team toggle;
        # click a user bar to list the keys they used.
        assert "Cost by user" in html and "cost-chart" in html and "renderCostChart" in html
        assert 'data-by="user"' in html and "showCostKeys" in html
        assert "click a user to see the keys they used" in html
        # regression: the cost chart must show ALL rows, not a hardcoded top-12 slice
        assert ".slice(0,12)" not in html and "rows.length*24" in html
        # estimated cost over time — daily tokens × per-model price, real vs estimated.
        assert "Cost over time" in html and "cost-time-chart" in html and "renderCostTime" in html
        # top-right card: current-year estimated cost (real + estimated + total)
        assert "cost-time-year" in html and "renderYearCost" in html
        # custom HTML legend (model-list tooltip) + estimated series is GREY (--muted)
        assert "cost-time-legend" in html and "legendItem" in html
        assert '{label:"Estimated (self-hosted)"' in html
        assert 'estCol=cssv("--muted")' in html
    finally:
        await c.close()
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "tok-spend-1")
    c2 = await _client()
    try:
        r2 = await c2.get("/spend", allow_redirects=False)
        assert r2.status == 302 and "/login" in r2.headers.get("Location", "")
    finally:
        await c2.close()


async def test_spend_blocked_when_litellm_not_configured(monkeypatch):
    """No LiteLLM configured → Spend & Quota is unavailable: the nav flag is off (so
    the link is hidden) and the /spend page 404s even on a direct URL. The gate is
    env-keyed, so it's deterministic regardless of the background sampler."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "")
    c = await _client()
    try:
        nav = await (await c.get("/api/nav")).json()
        assert nav["spend"] is False                       # link hidden
        assert (await c.get("/spend")).status == 404       # page blocked server-side
    finally:
        await c.close()
    # and when LiteLLM IS configured, the page + nav flag come back
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    c2 = await _client()
    try:
        nav = await (await c2.get("/api/nav")).json()
        assert nav["spend"] is True
        assert (await c2.get("/spend")).status == 200
    finally:
        await c2.close()


def test_budget_rows_ranks_and_flags():
    """budget_rows computes % / burn / days-to-cap / projected and ranks
    critical → watch → on-track → unbudgeted (closest-to-cap first)."""
    top = [{"alias": "a", "cost": 950}, {"alias": "b", "cost": 700},
           {"alias": "c", "cost": 100}, {"alias": "d", "cost": 50}]
    bmap = {"a": 1000, "b": 1000, "c": 1000}   # d has NO budget
    rows = litellm.budget_rows(top, bmap, 15, 30)
    assert [r["key"] for r in rows] == ["a", "b", "c", "d"]   # d listed, ranked last
    assert [r["status"] for r in rows] == ["bad", "warn", "ok", "none"]
    # these keys carry no budget_duration, so LiteLLM never resets their spend: the cap
    # comparison is still valid (lifetime spend vs a lifetime cap) but the MONTHLY
    # projection is not, and is therefore withheld rather than invented.
    assert rows[0]["pct"] == 95.0 and rows[0]["projected"] is None
    assert rows[0]["cap_basis"] == "lifetime"
    # a key whose budget DOES reset gets the period figures
    per = litellm.budget_rows(
        [{"alias": "p", "cost": 10.0, "budget": 50.0, "budget_duration": "30d"}],
        {"p": 50.0}, 10, 30)[0]
    assert per["cap_basis"] == "window" and per["projected"] > 0 and per["burn"] > 0
    # days_to_cap needs a burn rate, which needs a period — None on lifetime keys
    assert rows[0]["days_to_cap"] is None and per["days_to_cap"] >= 0


def test_budget_rows_lists_every_key_no_top_n_cap():
    """Regression — the Spend 'Cost by key' chart hid keys past the top 12. budget_rows
    must return EVERY key handed to it (no top-N slice, no silent drop) so the chart can
    render them all."""
    keys = [{"alias": f"k{i:02d}", "cost": float(30 - i)} for i in range(20)]  # 20, all spend
    rows = litellm.budget_rows(keys, {}, 15, 30)
    assert len(rows) == 20                                  # ALL 20, not a top-N subset
    assert {r["key"] for r in rows} == {f"k{i:02d}" for i in range(20)}
    assert all(r["spent"] > 0 for r in rows)


async def test_lite_spend_keeps_all_keys_not_top_10(monkeypatch):
    """Regression — the /spend-lite snapshot capped top_keys at 10, so the fallback path
    of 'Cost by key' could only ever show 10. It must keep every key /global/spend/keys
    reports."""
    async def fake_fetch(session, url, headers=None, timeout_s=None):
        if "/global/activity/model" in url:
            return ([], None)
        if "/global/activity" in url:
            return ({"sum_api_requests": 0, "sum_total_tokens": 0}, None)
        if "/global/spend/keys" in url:
            return ([{"api_key": f"h{i}", "key_alias": f"k{i}", "total_spend": float(i + 1)}
                     for i in range(18)], None)
        return (None, "HTTP 404")
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    out = await litellm._lite_spend(None, "http://litellm:4000", {}, 1_700_000_000.0)
    assert len(out.get("top_keys", [])) == 18               # all 18, not capped at 10


def test_budget_rows_presents_keys_with_no_budget():
    """A key with no budget defined is NEVER dropped — its spend is shown, with no cap
    maths (budget/pct/days_to_cap None, status 'none'). `burn` is also None: this key's
    spend never resets, so an all-time total divided by the day of the month is not a
    $/day rate — reporting one was the bug, "—" is the honest answer."""
    rows = litellm.budget_rows([{"alias": "nobudget", "cost": 500}], {}, 10, 30)
    assert len(rows) == 1
    r = rows[0]
    assert r["key"] == "nobudget" and r["status"] == "none"
    assert r["budget"] is None and r["pct"] is None and r["days_to_cap"] is None
    assert r["spent"] == 500 and r["burn"] is None      # spend shown; no bogus $/day
    # summary counts the gap so it can be surfaced, not hidden
    s = appmod._budget_summary(rows)
    assert s["unbudgeted"] == 1 and s["unbudgeted_spend"] == 500
    assert s["budgeted"] == 0 and s["budget"] == 0 and s["pct"] == 0


async def test_per_model_series_prefers_actual_cash_over_price_estimate(monkeypatch):
    """The headline cost is LiteLLM's ACTUAL cash, so the per-model chart must use the
    reported per-model cash where it exists — otherwise it is a parallel tokens x price
    estimate that can never sum to the headline. Estimate only fills the gaps."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-CHANGE_ME")
    payload = [
        # reports real cash 7.77 — tokens x price would say 1000 * 0.001 = 1.00
        {"model": "gpt-4o", "daily_data": [
            {"date": "2026-07-01", "total_tokens": 1000, "spend": 7.77}]},
        # no cash reported, but priced → estimate is the correct fallback
        {"model": "ollama/qwen", "daily_data": [
            {"date": "2026-07-01", "total_tokens": 1000}]},
    ]

    async def _fetch(session, url, headers=None, timeout_s=None):
        return payload, None
    monkeypatch.setattr(litellm, "fetch_json", _fetch)
    out = await litellm.per_model_daily_series(
        None, "2026-07-01", "2026-07-02", {"gpt-4o": 0.001, "ollama/qwen": 0.0001})
    tot = {m["model"]: m["total"] for m in out["models"]}
    assert tot["gpt-4o"] == 7.77, "must use reported cash, not the price estimate"
    assert abs(tot["ollama/qwen"] - 0.10) < 0.001      # estimated fallback
    assert out["cost_basis"] == "mixed"


async def test_per_model_series_surfaces_unpriced_instead_of_dropping(monkeypatch):
    """A model with no known price and no reported cash used to be skipped entirely, so
    real money vanished from the chart while still counting in the headline — a direct
    cause of the breakdown not adding up. It must now be reported via `unpriced`."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-CHANGE_ME")
    payload = [
        {"model": "gpt-4o", "daily_data": [
            {"date": "2026-07-01", "total_tokens": 1000, "spend": 5.0}]},
        {"model": "mystery-model", "daily_data": [       # unpriced, no cash reported
            {"date": "2026-07-01", "total_tokens": 9999}]},
    ]

    async def _fetch(session, url, headers=None, timeout_s=None):
        return payload, None
    monkeypatch.setattr(litellm, "fetch_json", _fetch)
    out = await litellm.per_model_daily_series(
        None, "2026-07-01", "2026-07-02", {"gpt-4o": 0.001})
    assert "mystery-model" in out["unpriced"], "unvaluable model must be surfaced"
    assert all(m["model"] != "mystery-model" for m in out["models"])   # no fake $ invented


async def test_per_model_series_survives_a_transient_failure(monkeypatch):
    """FIELD BUG: the Spend 'Cost per model over time' card sometimes DISAPPEARED. It
    hides on an empty payload, and a single transient /global/activity/model failure
    (timeout / circuit-breaker cooldown / mid-reload) returned None → the whole card
    blinked off until the next good poll. A blip must now serve the LAST-GOOD series
    (same rule as the price cache), so the chart persists across it."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-CHANGE_ME")
    monkeypatch.setattr(litellm, "_MODEL_SERIES_CACHE", None)   # cold start
    good = [{"model": "gpt-4o", "daily_data": [
        {"date": "2026-07-01", "total_tokens": 1000, "spend": 5.0}]}]

    async def _ok(session, url, headers=None, timeout_s=None):
        return good, None
    monkeypatch.setattr(litellm, "fetch_json", _ok)
    first = await litellm.per_model_daily_series(
        None, "2026-07-01", "2026-07-02", {"gpt-4o": 0.001})
    assert first and [m["model"] for m in first["models"]] == ["gpt-4o"]

    # now the endpoint blips: a transient error (err != None)
    async def _fail(session, url, headers=None, timeout_s=None):
        return None, "timeout"
    monkeypatch.setattr(litellm, "fetch_json", _fail)
    during = await litellm.per_model_daily_series(
        None, "2026-07-01", "2026-07-02", {"gpt-4o": 0.001})
    assert during is not None, "a transient blip must NOT blank the chart"
    assert [m["model"] for m in during["models"]] == ["gpt-4o"], "must serve last-good"

    # an ANSWERED-but-empty poll (no priced data this tick) also keeps last-good
    async def _empty(session, url, headers=None, timeout_s=None):
        return [], None
    monkeypatch.setattr(litellm, "fetch_json", _empty)
    empty = await litellm.per_model_daily_series(
        None, "2026-07-01", "2026-07-02", {"gpt-4o": 0.001})
    assert empty is not None and empty["models"], "answered-empty must keep last-good too"


async def test_model_price_detail_lists_zero_rate_models_and_serves_last_good(monkeypatch):
    """The Settings model-costs card takes its model NAME list from /model/info via
    model_price_detail() — so it must list EVERY configured model, INCLUDING an all-unset
    ($0 self-hosted) one (as the docstring promises), and must serve the LAST-GOOD detail
    across a transient blip instead of returning empty. This is what stops the card from going
    blank whenever the sampler's /v1/models snapshot is momentarily absent — the reported
    'model costs only appear after a manual Refresh + browser reload' bug."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-CHANGE_ME")
    monkeypatch.setattr(litellm, "_DETAIL_CACHE", {})          # cold start
    good = {"data": [
        {"model_name": "azure_ai/gpt-5-mini",
         "litellm_params": {"input_cost_per_token": 1e-6, "output_cost_per_token": 2e-6}},
        {"model_name": "vllm/self-hosted", "litellm_params": {}},   # all-unset → $0, still lists
    ]}

    async def _ok(session, url, headers=None, timeout_s=None):
        return good, None
    monkeypatch.setattr(litellm, "fetch_json", _ok)
    d = await litellm.model_price_detail(None)
    assert set(d) == {"azure_ai/gpt-5-mini", "vllm/self-hosted"}, "every model listed, incl. $0"
    assert d["vllm/self-hosted"] == {"in": 0.0, "out": 0.0, "cache": 0.0}
    assert d["azure_ai/gpt-5-mini"]["in"] == 1.0 and d["azure_ai/gpt-5-mini"]["out"] == 2.0

    async def _fail(session, url, headers=None, timeout_s=None):   # transient blip
        return None, "timeout"
    monkeypatch.setattr(litellm, "fetch_json", _fail)
    during = await litellm.model_price_detail(None)
    assert set(during) == {"azure_ai/gpt-5-mini", "vllm/self-hosted"}, "blip must serve last-good"

    async def _empty(session, url, headers=None, timeout_s=None):  # answered but empty
        return {"data": []}, None
    monkeypatch.setattr(litellm, "fetch_json", _empty)
    empty = await litellm.model_price_detail(None)
    assert set(empty) == {"azure_ai/gpt-5-mini", "vllm/self-hosted"}, "answered-empty keeps last-good"


async def test_per_model_series_blank_before_first_success_still_hides(monkeypatch):
    """The persistence must not resurrect a card that never had data: with an empty
    cache (fresh deploy) a failing poll still returns None so the card stays hidden."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-CHANGE_ME")
    monkeypatch.setattr(litellm, "_MODEL_SERIES_CACHE", None)   # never succeeded yet

    async def _fail(session, url, headers=None, timeout_s=None):
        return None, "timeout"
    monkeypatch.setattr(litellm, "fetch_json", _fail)
    out = await litellm.per_model_daily_series(
        None, "2026-07-01", "2026-07-02", {"gpt-4o": 0.001})
    assert out is None, "no last-good yet → hide (don't invent an empty card)"


def test_bucket_model_series_carries_cost_provenance():
    """bucket_model_series dropped `cost_basis`/`unpriced`, so the UI could not tell an
    actual-cash breakdown from an estimate, nor that models were missing from it. Those
    signals must survive bucketing or the chart silently under-reports."""
    series = {
        "models": [{"model": "gpt-4o", "kind": "real", "total": 5.0,
                    "daily": {"2026-07-01": 5.0}}],
        "dates": ["2026-07-01"],
        "cost_basis": "mixed",
        "unpriced": ["mystery-model"],
    }
    out = appmod.bucket_model_series(series, "30d", appmod._date_epoch("2026-07-02"))
    assert out["cost_basis"] == "mixed"
    assert out["unpriced"] == ["mystery-model"]


def test_num_or_none_distinguishes_missing_from_zero(monkeypatch):
    """A reported 0.00 is a real zero (use it); an absent/blank field means 'not reported'
    (fall back to the estimate). Conflating them would either invent cost or hide it."""
    assert litellm._num_or_none(0) == 0.0            # real zero, not "missing"
    assert litellm._num_or_none("1.25") == 1.25
    assert litellm._num_or_none(None) is None
    assert litellm._num_or_none("") is None
    assert litellm._num_or_none("abc") is None


def test_budget_summary_month_figures_come_from_mtd_not_lifetime():
    """A key's LiteLLM `spend` is lifetime cumulative, so using it for the monthly summary
    reported the all-time total as "this month" and inflated burn / projected / budget-%
    by lifetime÷month. With a true month-to-date figure the month numbers derive from IT,
    and the all-time total is reported separately as `spent_lifetime`.

    Worked example: lifetime 100, of which 10 is this month; day 18 of 31; budget 50/mo."""
    rows = litellm.budget_rows([{"alias": "team-a", "cost": 100.0, "budget": 50.0}],
                               {"team-a": 50.0}, 18, 31)
    s = appmod._budget_summary(rows, mtd_real=10.0, month_day=18, month_len=31)
    assert s["basis"] == "mtd"
    assert s["spent"] == 10.0                 # the MONTH's cash, not the lifetime 100
    assert s["spent_lifetime"] == 100.0       # all-time still available for the sub-line
    assert abs(s["burn"] - 10.0 / 18) < 0.01          # was 100/18 = 5.56
    assert abs(s["projected"] - (10.0 / 18) * 31) < 0.1   # was 172.22
    assert abs(s["pct"] - 20.0) < 0.1                  # was 200% -> false "over budget"
    assert s["over"] is False


def test_budget_summary_falls_back_to_lifetime_and_says_so():
    """When the daily series is unavailable there is no way to know the month's share, so
    the summary keeps the lifetime total but flags basis='lifetime' — the UI then labels
    the card "all-time" instead of silently calling an all-time number "this month"."""
    rows = litellm.budget_rows([{"alias": "team-a", "cost": 100.0, "budget": 50.0}],
                               {"team-a": 50.0}, 18, 31)
    s = appmod._budget_summary(rows)                  # no mtd_real
    assert s["basis"] == "lifetime"
    assert s["spent"] == 100.0 and s["spent_lifetime"] == 100.0


async def test_mtd_real_spend_sums_only_the_current_month(monkeypatch):
    """_mtd_real_spend must total ONLY the current month's daily rows — pulling in
    previous months would recreate the very over-count it exists to fix."""
    now = time.time()
    this_month = time.strftime("%Y-%m", time.gmtime(now))
    prev = "2000-01"                                   # unambiguously a different month

    async def _daily(session, start, end):
        return [{"date": f"{prev}-15", "spend": 999.0, "requests": 1, "tokens": 1},
                {"date": f"{this_month}-01", "spend": 4.0, "requests": 1, "tokens": 1},
                {"date": f"{this_month}-02", "spend": 6.0, "requests": 1, "tokens": 1}]
    monkeypatch.setattr(litellm, "spend_activity", _daily)
    assert await appmod._mtd_real_spend(None, now) == 10.0     # 999 from Jan 2000 excluded

    async def _none(session, start, end):
        return None
    monkeypatch.setattr(litellm, "spend_activity", _none)
    assert await appmod._mtd_real_spend(None, now) is None      # -> caller falls back


def test_unbudgeted_keys_get_implied_baseline_from_top_spender():
    """A key with no budget is drawn against the month's TOP SPENDER as a reference
    baseline (so its bar renders), but that baseline is NOT a budget: budget/pct/
    days_to_cap stay None and the status stays 'none'."""
    top = [{"alias": "big", "cost": 1000}, {"alias": "small", "cost": 250},
           {"alias": "capped", "cost": 100}]
    rows = litellm.budget_rows(top, {"capped": 500}, 10, 30)
    by = {r["key"]: r for r in rows}
    # baseline = top spender across ALL keys
    assert by["big"]["implied_budget"] == 1000 and by["big"]["implied_pct"] == 100.0
    assert by["small"]["implied_budget"] == 1000 and by["small"]["implied_pct"] == 25.0
    # implied baseline never becomes a real budget / cap
    for k in ("big", "small"):
        assert by[k]["budget"] is None and by[k]["pct"] is None
        assert by[k]["days_to_cap"] is None and by[k]["status"] == "none"
    # a budgeted key is untouched by the baseline
    assert "implied_budget" not in by["capped"] and by["capped"]["pct"] == 20.0
    s = appmod._budget_summary(rows)
    assert s["top_spend"] == 1000 and s["unbudgeted"] == 2


def test_merge_key_budgets_litellm_then_env_override():
    """Budgets come from LiteLLM /key/list; MONITOR_KEY_BUDGETS overrides it.
    Without LiteLLM key data, fall back to the collector snapshot for spend."""
    live = {"k1": {"budget": 100.0, "spend": 40.0, "team": "T"},
            "k2": {"budget": 0.0, "spend": 10.0, "team": ""}}
    merged = appmod.merge_key_budgets(live, [], {"k1": 250.0})
    by = {m["alias"]: m for m in merged}
    assert by["k1"]["budget"] == 250.0 and by["k1"]["cost"] == 40.0   # env wins
    assert by["k2"]["budget"] == 0.0                                   # unbudgeted kept
    # no live key data → snapshot top_keys carry the spend
    snap = [{"alias": "s1", "cost": 7.0}]
    merged2 = appmod.merge_key_budgets(None, snap, {"s1": 50.0})
    assert merged2[0]["alias"] == "s1" and merged2[0]["budget"] == 50.0


def test_merge_key_budgets_unions_live_and_snapshot():
    """Regression — 'Cost by key' dropped keys that had spend in the snapshot but were
    absent from /key/list. merge_key_budgets must UNION the two sources (was live-OR-
    snapshot, so snapshot-only spenders vanished)."""
    live = {"kA": {"spend": 100.0, "team": "AppSec", "budget": 0.0},
            "kB": {"spend": 50.0, "team": "AppSec", "budget": 0.0}}
    snap = [{"alias": "kB", "cost": 55.0},     # already in live → merged, not duplicated
            {"alias": "kC", "cost": 30.0},     # snapshot-only spender → MUST appear
            {"key": "hash1", "cost": 5.0}]     # no alias → identified by its hash
    keys = appmod.merge_key_budgets(live, snap, {})
    ids = [(k.get("alias") or k.get("key")) for k in keys]
    assert set(ids) == {"kA", "kB", "kC", "hash1"} and len(keys) == 4    # all four, kB once


async def test_key_budgets_owner_from_created_by_or_nested(monkeypatch):
    """Bug fix — keys must resolve an owner even when LiteLLM leaves `user_id` NULL and puts
    the owner on `created_by` (a user_id) or the nested `created_by_user` object; otherwise
    every such key wrongly falls into 'Unassigned' on the by-user board."""
    from collectors import litellm as _ll
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-supersecretvalue")
    async def _dir(_session, _base):            # /user/list directory: user_id UUID -> email
        return ({}, {}, {"uid-rod": "rod@example.com"})
    monkeypatch.setattr(_ll, "_team_directory", _dir)
    rows = [
        {"key_alias": "RodKey", "user_id": None, "created_by": "uid-rod",   # via directory
         "spend": 5.0, "max_budget": 0},
        {"key_alias": "NestedKey", "user_id": None, "created_by": None,     # via nested object
         "created_by_user": {"user_email": "leo@example.com"}, "spend": 2.0, "max_budget": 0},
        {"key_alias": "Orphan", "user_id": None, "spend": 1.0, "max_budget": 0},   # truly none
    ]
    async def _fj(_session, url, **_kw):
        return ({"keys": rows, "total_count": len(rows)}, None) if "/key/list" in url else (None, "x")
    monkeypatch.setattr(_ll, "fetch_json", _fj)
    _ll._KEY_BUDGETS_CACHE = None
    out = await _ll.key_budgets(None)
    assert out["RodKey"]["user_name"] == "rod@example.com"       # created_by → /user/list join
    assert out["NestedKey"]["user_name"] == "leo@example.com"    # nested created_by_user email
    assert out["Orphan"]["user_name"] == ""                       # no owner anywhere → unassigned


def test_budget_rows_split_real_vs_reference():
    """Budgets cap REAL cash: only the real portion counts against the budget;
    self-hosted reference cost is carried alongside but doesn't drive %/status."""
    top = [{"alias": "k", "cost": 1000, "real": 400, "reference": 600}]
    rows = litellm.budget_rows(top, {"k": 1000}, 15, 30)
    r = rows[0]
    assert r["spent"] == 400 and r["reference"] == 600 and r["total"] == 1000
    assert r["pct"] == 40.0                       # 400/1000 real — NOT 1000/1000
    assert r["status"] == "ok"                    # real is well under cap
    # a key with no split treats all spend as real (back-compat)
    r2 = litellm.budget_rows([{"alias": "x", "cost": 900}], {"x": 1000}, 15, 30)[0]
    assert r2["spent"] == 900 and r2["reference"] == 0 and r2["pct"] == 90.0


async def test_budgets_endpoint(monkeypatch):
    """/api/budgets is auth-gated and degrades cleanly with no budgets configured."""
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "budgtok-123456")
    monkeypatch.setattr(config, "KEY_BUDGETS_JSON", "")
    hdr = {"Authorization": "Bearer budgtok-123456"}
    c = await _client()
    try:
        assert (await c.get("/api/budgets")).status == 401      # gated
        d = await (await c.get("/api/budgets", headers=hdr)).json()
        assert d["available"] is False and d["keys"] == []      # none configured
        assert "summary" in d
    finally:
        await c.close()


async def test_alerts_test_fire_reports_webhook(monkeypatch):
    # a configured webhook that succeeds
    srv = TestServer(_hook_app())
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "ALERT_WEBHOOK_URL", str(srv.make_url("/hook")))
        async with aiohttp.ClientSession() as s:
            res = await alerts.send_test(s)
        assert res["webhook"] == "ok"
    finally:
        await srv.close()


async def test_alerts_test_fire_unconfigured(monkeypatch):
    monkeypatch.setattr(config, "ALERT_WEBHOOK_URL", "")
    async with aiohttp.ClientSession() as s:
        res = await alerts.send_test(s)
    assert res["webhook"] == "not configured"


def test_alerts_history_persisted(tmp_path, monkeypatch):
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "al.db"))
    db.init()
    db.record_alert(1000.0, "cpu", "fire", "CPU 95% >= 80%")
    db.record_alert(1001.0, "cpu", "recover", "recovered: cpu")
    h = db.recent_alerts(10)
    assert len(h) == 2 and h[0]["kind"] == "recover"   # newest first


def test_channels_and_thresholds_status(monkeypatch):
    monkeypatch.setattr(config, "ALERT_WEBHOOK_URL", "http://hook/x")
    chans = {c["id"]: c["on"] for c in alerts.channels_status()}
    assert chans == {"webhook": True}      # webhook-only
    th = alerts.thresholds_status()
    assert "cpu_pct" in th and "anomaly_factor" in th


async def test_alerts_page_served_and_gated(monkeypatch):
    # alert config needs an interactive login: it serves WITH a user session and is
    # gated (redirect / 401) without one. The shared URL token cannot reach it.
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("alpage", "ap@x.io", auth.hash_password("alpagepw1"),
                   "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "alpage", "password": "alpagepw1"})
        r = await c.get("/alerts")
        assert r.status == 200
        html = await r.text()
        assert "Alerts" in html and "Send test alert" in html
    finally:
        await c.close()
    # gated without a credential (fresh client, no session)
    c2 = await _client()
    try:
        r2 = await c2.get("/alerts", allow_redirects=False)
        assert r2.status == 302 and "/login" in r2.headers.get("Location", "")
        assert (await c2.get("/api/alerts")).status == 401
    finally:
        await c2.close()


async def test_anomalies_endpoint():
    c = await _client()
    try:
        r = await c.get("/api/anomalies")
        assert r.status == 200
        d = await r.json()
        assert "active" in d and "history" in d
    finally:
        await c.close()


def test_db_key_series_multiline(tmp_path, monkeypatch):
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "ks.db"))
    db.init()
    now = 1_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    # 12 keys over the last 10 minutes; keyA busiest, keyL least
    for t in range(600, 0, -30):                    # every 30s for 10 min
        tk = [{"key": f"key{i}", "alias": "", "reqs": (12 - i)}
              for i in range(12)]
        db.insert_key_series(now - t, tk)
    out = db.key_series("15m", 50, top_n=10)
    assert len(out["labels"]) == 10                 # top-10 only
    assert out["labels"][0] == "key0"               # busiest first (reqs=12)
    assert "key11" not in out["labels"]             # least-used dropped
    # each point is a bucket with per-label values
    assert out["points"] and "t" in out["points"][0]
    assert any("key0" in p for p in out["points"])


def test_key_series_uses_alias_as_label(tmp_path, monkeypatch):
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "ks2.db"))
    db.init()
    now = 2_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    db.insert_key_series(now - 10, [{"key": "hashX", "alias": "team-y", "reqs": 5}])
    out = db.key_series("15m", 50)
    assert out["labels"] == ["team-y"]              # alias preferred over key id


async def test_keyseries_endpoint():
    c = await _client()
    try:
        r = await c.get("/api/keyseries?window=1h")
        assert r.status == 200
        d = await r.json()
        assert d["window"] == "1h"
        assert "labels" in d and "points" in d
        # bad window falls back
        assert (await (await c.get("/api/keyseries?window=x")).json())["window"] == "1h"
    finally:
        await c.close()


def test_key_cumulative_is_monotonic(tmp_path, monkeypatch):
    """The 'Top 10 API keys over time' chart plots CUMULATIVE requests per key from the daily
    rollup, so every line must only ever rise (never the rolling-window decay of the live
    request-rate view). Ranked by total requests; an idle day holds the running total flat.
    (metric='cost' folds the same way for the spend variant.)"""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "ks.db"))
    db.init()
    import calendar as _cal
    rows = [
        {"day": "2026-07-01", "model": "m", "key": "hA", "alias": "alice", "cost": 1.0, "tokens": 1, "reqs": 3},
        {"day": "2026-07-02", "model": "m", "key": "hA", "alias": "alice", "cost": 2.0, "tokens": 1, "reqs": 5},
        {"day": "2026-07-03", "model": "m", "key": "hA", "alias": "alice", "cost": 0.5, "tokens": 1, "reqs": 0},
        {"day": "2026-07-01", "model": "m", "key": "hB", "alias": "bob", "cost": 5.0, "tokens": 1, "reqs": 100},
    ]
    db.spend_model_user_upsert(rows, time.time())
    end = _cal.timegm(time.strptime("2026-07-04", "%Y-%m-%d"))
    out = db.key_cumulative(metric="reqs", days_back=3650, top_n=10, end=end)
    assert out["metric"] == "reqs"
    assert out["labels"] == ["bob", "alice"]          # ranked by total requests (100 > 8)
    pts = out["points"]
    assert [int(p["alice"]) for p in pts] == [3, 8, 8]      # rises, then flat (idle day)
    assert [int(p["bob"]) for p in pts] == [100, 100, 100]  # flat after day 1, never falls
    # monotonic non-decreasing for EVERY key across the whole series
    for lab in out["labels"]:
        seq = [p[lab] for p in pts]
        assert all(b >= a for a, b in zip(seq, seq[1:])), f"{lab} request line decreased"
    # the cost variant still works off the same rollup
    assert db.key_cumulative(metric="cost", end=end)["metric"] == "cost"
    assert db.key_cumulative(metric="bogus", end=end)["labels"] == []   # unknown metric → empty


async def test_spend_keycost_endpoint_windowed(tmp_path, monkeypatch):
    """/api/spend/keycost returns per-key spend WITHIN the window (alias→cost) so the
    Cost-by-user/key/team chart follows the page selector. db.key_cost_window excludes
    rows outside the window."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "kc.db"))
    db.init()
    import calendar as _cal
    now = _cal.timegm(time.strptime("2026-07-22", "%Y-%m-%d"))
    db.spend_model_user_upsert([
        {"day": "2026-07-21", "model": "m", "key": "hA", "alias": "alice", "cost": 3.0, "tokens": 1, "reqs": 1},
        {"day": "2026-06-01", "model": "m", "key": "hA", "alias": "alice", "cost": 9.0, "tokens": 1, "reqs": 1},
        {"day": "2026-07-20", "model": "m", "key": "hB", "alias": "bob", "cost": 1.0, "tokens": 1, "reqs": 1},
    ], time.time())
    assert db.key_cost_window(7, end=now) == {"alice": 3.0, "bob": 1.0}   # June row excluded
    assert db.key_cost_window(60, end=now)["alice"] == 12.0               # both rows in window


async def test_keyrequests_endpoint_shape():
    c = await _client()
    try:
        r = await c.get("/api/keyrequests")
        assert r.status == 200
        d = await r.json()
        assert "labels" in d and "points" in d and d.get("metric") == "reqs"
        # opt-in cost variant
        assert (await (await c.get("/api/keyrequests?metric=cost")).json()).get("metric") == "cost"
    finally:
        await c.close()


async def test_uptime_and_export_endpoints():
    c = await _client()
    try:
        u = await c.get("/api/uptime?window=24h")
        assert u.status == 200 and "uptime" in await u.json()
        e = await c.get("/api/export?window=1h&format=csv")
        assert e.status == 200
        assert "text/csv" in e.headers["Content-Type"]
        body = await e.text()
        assert body.split("\n")[0].startswith("t,cpu,mem")
        ej = await c.get("/api/export?window=1h&format=json")
        assert "points" in await ej.json()
    finally:
        await c.close()


# -------------------------------------------------- unconfigured degrade -------
async def test_collectors_unconfigured(monkeypatch):
    monkeypatch.setattr(config, "LITELLM_BASE_URL", None)
    monkeypatch.setattr(config, "OLLAMA_BASE_URL", None)
    monkeypatch.setattr(config, "LLAMACPP_BASE_URL", None)
    async with aiohttp.ClientSession() as s:
        for coll in (litellm, ollama, llamacpp):
            out = await coll.sample(s)
            assert out["available"] is False
            assert out["error"] == "unconfigured"


# ---------------------------------------------- stub backend + parsing --------
def _stub_app() -> web.Application:
    a = web.Application()

    # ollama
    async def ps(_):
        return web.json_response({"models": [
            {"name": "qwen3:8b", "size": 6_000_000_000, "size_vram": 5_000_000_000,
             "expires_at": "2026-07-02T18:00:00Z",
             "details": {"parameter_size": "8B", "quantization_level": "Q4_K_M",
                         "family": "qwen"}},
            {"name": "llama3:70b", "size": 40_000_000_000, "size_vram": 0,
             "details": {"parameter_size": "70B", "quantization_level": "Q4_0"}},
        ]})
    async def tags(_):
        return web.json_response({"models": [{"name": "a"}, {"name": "b"}, {"name": "c"}]})
    async def oversion(_):
        return web.json_response({"version": "0.5.7"})

    # /health is served by both llama.cpp and litellm in real life on separate
    # hosts; the single stub merges both response shapes so each collector reads
    # the fields it expects (llama.cpp: status; litellm: *_endpoints).
    async def health(_):
        return web.json_response({"status": "ok",
                                  "healthy_endpoints": [{"model": "x"}],
                                  "unhealthy_endpoints": []})
    async def props(_):
        return web.json_response({"model_path": "/m/qwen.gguf",
                                  "total_slots": 4,
                                  "default_generation_settings": {"n_ctx": 8192}})
    async def slots(_):
        return web.json_response([
            {"is_processing": True, "predicted_per_second": 42.0,
             "kv_cache_usage_ratio": 0.5},
            {"is_processing": False, "predicted_per_second": 0,
             "kv_cache_usage_ratio": 0.1},
        ])

    # litellm
    async def live(_):
        return web.json_response({"status": "alive"})
    async def models(_):
        return web.json_response({"data": [{"id": "gpt-4o"}, {"id": "qwen3"}]})
    async def spend(_):
        import time as _t
        now = _t.time()
        # recent epoch timestamps so a short rolling window still includes them;
        # durations preserved: 2000ms and 500ms.
        return web.json_response([
            {"startTime": now - 5, "endTime": now - 3,
             "completionStartTime": now - 4.5,  # TTFT = 500ms
             "model": "gpt-4o", "response_cost": 0.02, "total_tokens": 100,
             "prompt_tokens": 70, "completion_tokens": 30, "status": "success",
             "cache_hit": True, "saved_cache_cost": 0.005,
             "api_key": "keyA", "key_alias": "team-alpha"},
            {"startTime": now - 1.5, "endTime": now - 1.0,
             "model": "gpt-4o", "response_cost": 0.01, "total_tokens": 50,
             "prompt_tokens": 30, "completion_tokens": 20, "status": "failure",
             "cache_hit": False, "api_key": "keyB"},
        ])

    # remote GPU HTTP agent
    async def gpu_ep(_):
        return web.json_response({"vendor": "nvidia", "gpus": [
            {"name": "RTX 4090", "util": 37.0,
             "vram_used": 8_000_000_000, "vram_total": 24_000_000_000, "temp": 55},
        ]})

    a.router.add_get("/api/ps", ps)
    a.router.add_get("/api/version", oversion)
    a.router.add_get("/gpu", gpu_ep)
    a.router.add_get("/api/tags", tags)
    a.router.add_get("/health", health)
    a.router.add_get("/props", props)
    a.router.add_get("/slots", slots)
    a.router.add_get("/health/liveliness", live)
    async def backlog(_):
        # real LiteLLM shape: GET /health/backlog -> {"in_flight_requests": N}
        return web.json_response({"in_flight_requests": 7})

    a.router.add_get("/v1/models", models)
    a.router.add_get("/spend/logs", spend)
    a.router.add_get("/health/backlog", backlog)
    return a


async def test_ollama_parsing(monkeypatch):
    srv = TestServer(_stub_app())
    await srv.start_server()
    try:
        base = str(srv.make_url("")).rstrip("/")
        monkeypatch.setattr(config, "OLLAMA_BASE_URL", base)
        async with aiohttp.ClientSession() as s:
            out = await ollama.sample(s)
        assert out["available"] is True
        assert out["models_running"] == 2
        assert out["models_installed"] == 3
        assert out["ram_used"] == 46_000_000_000
        assert out["vram_used"] == 5_000_000_000
        # enriched: version, per-model params/quant, GPU-split
        assert out["version"] == "0.5.7"
        m0 = out["models"][0]
        assert m0["params"] == "8B" and m0["quant"] == "Q4_K_M"
        assert m0["gpu_pct"] == pytest.approx(83.3, abs=0.5)  # 5G/6G
        assert out["gpu_pct"] == pytest.approx(5 / 46 * 100, abs=0.5)
    finally:
        await srv.close()


async def test_llamacpp_parsing(monkeypatch):
    srv = TestServer(_stub_app())
    await srv.start_server()
    try:
        base = str(srv.make_url("")).rstrip("/")
        monkeypatch.setattr(config, "LLAMACPP_BASE_URL", base)
        monkeypatch.setattr(config, "LLAMACPP_API_KEY", None)
        async with aiohttp.ClientSession() as s:
            out = await llamacpp.sample(s)
        assert out["available"] is True
        assert out["n_slots"] == 4
        assert out["slots_active"] == 1
        assert out["predicted_per_second"] == 42.0
        assert out["ctx_size"] == 8192
    finally:
        await srv.close()


async def test_litellm_parsing(monkeypatch):
    srv = TestServer(_stub_app())
    await srv.start_server()
    try:
        base = str(srv.make_url("")).rstrip("/")
        monkeypatch.setattr(config, "LITELLM_BASE_URL", base)
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_SPEND_WINDOW_MIN", 60 * 24 * 3650)
        async with aiohttp.ClientSession() as s:
            out = await litellm.sample(s)
        assert out["available"] is True
        assert set(out["models"]) == {"gpt-4o", "qwen3"}
        assert out["requests_window"] == 2
        # waits: 2000ms and 500ms -> avg 1250, max 2000
        assert out["wait_max_ms"] == 2000.0
        assert out["wait_avg_ms"] == pytest.approx(1250.0, abs=1)
    finally:
        await srv.close()


async def test_litellm_liveliness_timeout_is_down_not_up(monkeypatch):
    """A /health/liveliness that TIMES OUT (or 5xx) must report the backend DOWN,
    not UP. Regression: the old code treated every non-'conn' error as reachable,
    so a saturated/timing-out proxy read as healthy and the heavy /spend call still
    fired at it — the exact hammering the anti-freeze redesign exists to prevent."""
    hit = {"spend": 0}

    async def _live(_r):
        await asyncio.sleep(3)                       # exceeds the tiny HTTP_TIMEOUT
        return web.json_response({"status": "healthy"})

    async def _s(_r):
        hit["spend"] += 1
        return web.json_response([])

    app = web.Application()
    app.router.add_get("/health/liveliness", _live)
    app.router.add_get("/spend/logs", _s)
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LITELLM_BASE_URL",
                            str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "HTTP_TIMEOUT", 0.5)
        async with aiohttp.ClientSession() as s:
            out = await litellm.sample(s)
        assert out["available"] is False, f"timeout must be DOWN, got {out}"
        assert hit["spend"] == 0, "heavy /spend must NOT fire when liveliness times out"
    finally:
        await srv.close()


async def test_containers_sample_concurrent_under_loop_bound(monkeypatch):
    """Many container inspects run CONCURRENTLY, so the aggregate sample time stays
    ~one timeout regardless of count and never blows the backend loop's wait_for
    bound. Regression: sequential inspects summed per-container timeouts and got
    cancelled mid-iteration on a busy host → permanently stale panel."""
    import collectors.containers as cont
    N = 12

    class _FakeResp:
        status = 200
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def json(self):
            await asyncio.sleep(0.3)                  # each inspect is "slow"
            return {"State": {"Running": True, "Status": "Up 1 min"}}

    import json as _json
    class _Content:               # the list read accumulates via r.content.iter_chunked()
        def iter_chunked(self, n):
            body = _json.dumps([{"Names": [f"/c{i}"]} for i in range(N)]).encode()
            async def _gen():      # yield in SEVERAL chunks so a single-read (bug) would truncate
                for i in range(0, len(body), 40):
                    yield body[i:i+40]
            return _gen()

    class _FakeSess:
        def get(self, url, **kw):
            if "containers/json?all=1" in url:
                class _L(_FakeResp):
                    content = _Content()
                return _L()
            return _FakeResp()

    monkeypatch.setattr(cont, "_sess", lambda: _fake_sess())
    async def _fake_sess(): return _FakeSess()
    monkeypatch.setattr(config, "MONITOR_CONTAINERS", [])
    loop = asyncio.get_event_loop()
    t0 = loop.time()
    out = await cont.sample(None)
    elapsed = loop.time() - t0
    assert out["available"] is True
    assert len(out["containers"]) == N
    # sequential would be N*0.3 = 3.6s; concurrent must be well under 1s.
    assert elapsed < 1.5, f"inspects not concurrent: {elapsed:.2f}s for {N} containers"


async def test_containers_auto_discover_flags_truncation_over_50(monkeypatch):
    """Review-fix (C7): auto-discover inspects at most 50 containers; when the host has more,
    the collector SURFACES the truncation (`truncated` + `total`) instead of silently dropping
    the rest, so the UI can say 'showing 50 of N'."""
    import collectors.containers as cont
    import json as _json
    M = 63

    class _Resp:
        status = 200
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def json(self): return {"State": {"Running": True, "Status": "Up"}}

    class _Content:
        def iter_chunked(self, n):
            body = _json.dumps([{"Names": [f"/c{i}"]} for i in range(M)]).encode()
            async def _gen():      # multi-chunk: a single-read regression would truncate + 404
                for i in range(0, len(body), 40):
                    yield body[i:i+40]
            return _gen()

    class _Sess:
        def get(self, url, **kw):
            if "containers/json?all=1" in url:
                class _L(_Resp):
                    content = _Content()
                return _L()
            return _Resp()

    async def _mk(): return _Sess()
    monkeypatch.setattr(cont, "_sess", lambda: _mk())
    monkeypatch.setattr(config, "MONITOR_CONTAINERS", [])
    out = await cont.sample(None)
    assert out["available"] is True
    assert len(out["containers"]) == 50               # capped
    assert out.get("truncated") is True and out.get("total") == M


async def test_key_budgets_serves_memo_within_ttl(monkeypatch):
    """Review-fix (C6): the ~100-page /key/list+/team/list+/user/list walk is invoked by the
    sampler AND 3 dashboard handlers. A short-TTL memo serves the last good walk to any caller
    within the window so concurrent refreshes don't each re-walk the management API."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    sentinel = {"alice": {"budget": 1.0, "spend": 0.5}}
    litellm._KEY_BUDGETS_CACHE = sentinel
    litellm._KEY_BUDGETS_TS = time.time()             # fresh → within TTL
    called = {"n": 0}

    async def _boom(*a, **k):
        called["n"] += 1
        return {}, None
    monkeypatch.setattr(litellm, "fetch_json", _boom)
    out = await litellm.key_budgets(None)
    assert out is sentinel and called["n"] == 0, "a fresh memo must be served with NO fetch"
    litellm._KEY_BUDGETS_TS = time.time() - litellm._KEY_BUDGETS_TTL - 1   # expire it
    await litellm.key_budgets(None)
    assert called["n"] > 0, "an expired memo must re-walk /key/list"


async def test_key_list_breaker_records_live_failure_not_cache_fallback(monkeypatch):
    """Review-fix: the private key_list breaker must reflect the LIVE /key/list walk, not the
    memoized cache-fallback RETURN (which is non-None whenever a warm cache exists, so it always
    read as 'success' and the breaker never opened). A real transport/5xx failure records a failure
    even with a warm cache; a fast auth/scope 403 must NOT trip it."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")

    async def _fail(session, url, headers=None, timeout_s=None):
        return None, "timeout"
    monkeypatch.setattr(litellm, "fetch_json", _fail)

    # (1) real transport failure WITH a warm cache → the live outcome is recorded as a failure
    monkeypatch.setattr(litellm, "_auth_err", lambda e: False)
    litellm._CB.pop("key_list", None)
    litellm._KEY_BUDGETS_CACHE = {"alice": {"spend": 0}}
    litellm._KEY_BUDGETS_TS = 0.0                       # memo expired → a live walk happens
    out = await litellm.key_budgets(None)
    assert out == {"alice": {"spend": 0}}              # still served the cache (return unchanged)
    assert litellm._CB.get("key_list", {}).get("fails", 0) >= 1, "live failure was not recorded"

    # (2) a scope-limit 403 (auth error) is fast, not a struggling API → must NOT trip the breaker
    monkeypatch.setattr(litellm, "_auth_err", lambda e: True)
    litellm._CB.pop("key_list", None)
    litellm._KEY_BUDGETS_TS = 0.0
    await litellm.key_budgets(None)
    assert litellm._CB.get("key_list", {}).get("fails", 0) == 0, "a fast 403 must not trip the breaker"


def test_userreqs_endpoint_gated_and_wired():
    """The users-over-time card (/litellm 'Request volume by user over time'): /api/userreqs
    carries per-user request attribution, so it's in the SPEND_REQUIRE_ADMIN-gated set; and the
    page reuses the existing key→owner fold + both views + the anti-blink keep-last."""
    import app as a
    import pathlib
    assert "/api/userreqs" in a._SPEND_SENSITIVE_API
    html = (pathlib.Path(a.__file__).parent / "web" / "litellm.html").read_text(encoding="utf-8")
    assert 'id="card-usertokens"' in html and "loadUserTokens" in html
    assert '/api/userreqs' in html and "userOf(" in html            # owner-fold reused
    assert "Usage by user over time" in html and 'id="ut-metric"' in html
    assert 'id="ut-stack"' in html and 'id="ut-grid"' in html       # both views present
    assert "utHas" in html and "if(!utHas)" in html                 # anti-blink keep-last
    assert 'data-q="top"' in html and 'data-q="all"' in html and 'data-q="none"' in html
    # dynamic writes route through the sanitized sink (single-innerHTML-sink invariant guarded
    # by test_litellm_page_exists_and_secure); confirm reuse here.
    assert "setHtml(rows," in html and "setHtml(lg," in html and "setHtml(grid," in html


async def test_userreqs_endpoint_mirrors_keytime_and_falls_back_in_lite(tmp_path, monkeypatch):
    """GET /api/userreqs returns per-key CUMULATIVE usage over time, un-capped (top_n=200) for
    owner-folding — exactly the 'Top 10 keys over time' path. In lite/off mode (no per-key request
    counts) it falls back to cumulative SPEND from key_series, so the card is never empty when the
    keys-over-time chart has data. Returns {metric, labels, points}."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "ureq.db"))
    db.init()
    now = time.time()
    # key_series only (no spend_model_user_daily rollup) → key_cumulative empty → SPEND fallback,
    # mirroring a lite-mode live box where keytime shows via the same fallback.
    for i in range(6):
        t = now - 3600 + i * 300
        db.insert_key_series(t, [{"key": "hA", "alias": "aliceKey", "reqs": 10 + i * 5},
                                 {"key": "hB", "alias": "bobKey", "reqs": 2 + i}])
    db.rollup()                       # 12mo reads the _1h tier — live has rollups; the test must too
    c = await _client()
    try:
        r = await c.get("/api/userreqs")
        assert r.status == 200
        j = await r.json()
        assert "labels" in j and "points" in j and j["metric"] in ("requests", "spend")
        assert {"aliceKey", "bobKey"} <= set(j["labels"])     # both keys ranked in
        assert j["points"], "must return series data via the spend fallback (lite mode)"
    finally:
        await c.close()


# ══════════════════════════════════════════════════════════════════════════════
# Extra QA — security · functional · unit · regression · performance
# ══════════════════════════════════════════════════════════════════════════════

# ── security ──────────────────────────────────────────────────────────────────
async def test_csp_locks_down_script_and_object_src():
    c = await _client()
    try:
        csp = (await c.get("/healthz")).headers.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp
        assert "object-src 'none'" in csp
        assert "base-uri" in csp
        # AU4: form-action does NOT inherit from default-src, so it must be set explicitly to
        # stop an injected <form action="//evil"> exfiltrating on submit.
        assert "form-action 'self'" in csp
    finally:
        await c.close()


async def test_session_cookie_is_httponly_and_strict(monkeypatch):
    import app as a
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "supersecrettoken1234")
    a._auth_fails.clear(); a._auth_locked_until.clear()
    c = await _client()
    try:
        r = await c.get("/?token=supersecrettoken1234", allow_redirects=False)
        assert r.status == 302
        sc = r.headers.get("Set-Cookie", "")
        assert "HttpOnly" in sc and "SameSite=Strict" in sc
    finally:
        a._auth_fails.clear(); a._auth_locked_until.clear()
        await c.close()


def test_gpu_http_agent_rejects_non_http_scheme(monkeypatch):
    # SSRF guard: a file:// or gopher:// GPU-agent URL must never be fetched
    monkeypatch.setattr(config, "GPU_METRICS_URL", "file:///etc/passwd")
    assert gpu._http() is None
    monkeypatch.setattr(config, "GPU_METRICS_URL", "gopher://evil/")
    assert gpu._http() is None


# ── functional ────────────────────────────────────────────────────────────────
async def test_export_csv_and_json_shapes():
    c = await _client()
    try:
        rc = await c.get("/api/export?window=1h&format=csv")
        assert rc.status == 200
        assert (await rc.text()).splitlines()[0].startswith("t,")   # header row
        d = await (await c.get("/api/export?window=1h&format=json")).json()
        assert "window" in d and "points" in d
    finally:
        await c.close()


async def test_series_extreme_points_is_robust():
    c = await _client()
    try:
        assert (await c.get("/api/series?window=1h&points=999999")).status == 200
        assert (await c.get("/api/series?window=1h&points=1")).status == 200
        assert (await c.get("/api/series?window=bogus")).status == 200
    finally:
        await c.close()


# ── unit ──────────────────────────────────────────────────────────────────────
def test_config_validate_clean(monkeypatch):
    monkeypatch.setattr(config, "MONITOR_PORT", 9925)
    monkeypatch.setattr(config, "SAMPLE_INTERVAL", 5.0)
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "")
    # F2: a token is valid config — but it must be long enough (>=16 chars), else
    # validate() now rejects it as brute-forceable (weak-token gate).
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "tok1234567890abcd")
    assert config.validate() == []


def test_parse_maintenance_windows_shapes():
    """'HH:MM-HH:MM,HH:MM-HH:MM' -> [(start_min, end_min), ...]; malformed entries
    are skipped rather than raising (validate() is what fails loud on those)."""
    assert config._parse_maintenance_windows("") == []
    assert config._parse_maintenance_windows("03:00-03:10") == [(180, 190)]
    assert config._parse_maintenance_windows("03:00-03:10,15:30-15:35") == \
        [(180, 190), (930, 935)]
    assert config._parse_maintenance_windows(" 03:00 - 03:10 ") == [(180, 190)], \
        "whitespace around the range/parts must be tolerated"
    assert config._parse_maintenance_windows("bogus") == [], "malformed entry dropped"
    assert config._parse_maintenance_windows("25:00-03:10") == [], "out-of-range hour dropped"
    assert config._parse_maintenance_windows("03:00-03:10,bogus,15:00-15:05") == \
        [(180, 190), (900, 905)], "one bad entry must not drop the good ones"


def test_in_maintenance_window_boundaries_and_wraparound(monkeypatch):
    monkeypatch.setitem(config.MAINTENANCE_WINDOWS, "vllm", [(180, 190)])  # 03:00-03:10
    day = 1785900000 - (1785900000 % 86400)  # any UTC midnight
    assert not config.in_maintenance_window("vllm", day + 179 * 60), "1 min before: outside"
    assert config.in_maintenance_window("vllm", day + 180 * 60), "start minute: inside (inclusive)"
    assert config.in_maintenance_window("vllm", day + 185 * 60), "middle: inside"
    assert not config.in_maintenance_window("vllm", day + 190 * 60), "end minute: outside (exclusive)"
    # midnight-crossing window: 23:50-00:10
    monkeypatch.setitem(config.MAINTENANCE_WINDOWS, "vllm", [(1430, 10)])
    assert config.in_maintenance_window("vllm", day + 1435 * 60), "23:55: inside the wrap"
    assert config.in_maintenance_window("vllm", day + 5 * 60), "00:05 next day: inside the wrap"
    assert not config.in_maintenance_window("vllm", day + 12 * 3600), "noon: outside the wrap"
    # unconfigured backend never suppresses
    monkeypatch.setitem(config.MAINTENANCE_WINDOWS, "litellm", [])
    assert not config.in_maintenance_window("litellm", day + 185 * 60)
    assert not config.in_maintenance_window("unknown-backend", day + 185 * 60)


def test_config_validate_rejects_malformed_maintenance_window(monkeypatch):
    monkeypatch.setattr(config, "MONITOR_PORT", 9925)
    monkeypatch.setattr(config, "SAMPLE_INTERVAL", 5.0)
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "")
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "tok1234567890abcd")
    monkeypatch.setitem(config.MAINTENANCE_RAW, "vllm", "not-a-window")
    errs = config.validate()
    assert any("MONITOR_MAINTENANCE_VLLM" in e and "not-a-window" in e for e in errs), errs
    monkeypatch.setitem(config.MAINTENANCE_RAW, "vllm", "03:00-03:10")
    assert config.validate() == [], "a well-formed window must not fail validation"


def test_redacted_summary_hides_key(monkeypatch):
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-supersecretvalue")
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "sometoken1234567")
    s = config.redacted_summary()
    assert isinstance(s, dict)
    assert "supersecret" not in repr(s)
    assert "sometoken" not in repr(s)


def test_parse_spend_bytes_tolerates_junk_and_shapes():
    import json as _j
    rows = [{"model": "m1", "total_tokens": 10, "spend": 0.1,
             "startTime": "2026-07-04T00:00:00"}]
    d, *_ = litellm._parse_spend_bytes(_j.dumps(rows).encode(), 0.0, 1000)
    assert isinstance(d, dict)
    # {"data":[...]} envelope is also accepted
    d2, *_ = litellm._parse_spend_bytes(_j.dumps({"data": rows}).encode(), 0.0, 1000)
    assert isinstance(d2, dict)
    # malformed bytes must never raise → empty result
    d3, *_ = litellm._parse_spend_bytes(b"<<not json>>", 0.0, 1000)
    assert d3 == {}


# ── regression ────────────────────────────────────────────────────────────────
async def test_litellm_down_on_liveliness_5xx(monkeypatch):
    # a 5xx/timeout on /health/liveliness = DOWN (else the heavy /spend call would
    # hammer an already-struggling proxy). Regression for the 1.0.2 fix.
    async def liveliness(_):
        return web.Response(status=503, text="overloaded")
    app = web.Application()
    app.router.add_get("/health/liveliness", liveliness)
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LITELLM_BASE_URL", str(srv.make_url("")).rstrip("/"))
        async with aiohttp.ClientSession() as s:
            out = await litellm.sample(s)
        assert out["available"] is False
    finally:
        await srv.close()


# ── performance ───────────────────────────────────────────────────────────────
def test_metrics_row_is_pure_and_fast():
    import time as _t
    import app as a
    snap = {"ts": 0, "collectors": {
        "host": {"available": True, "cpu_pct": 50, "mem_pct": 60,
                 "disk": {"pct": 40}, "load": [1, 1, 1]},
        "litellm": {"available": True, "backlog": 5,
                    "top_keys": [{"alias": f"k{i}", "reqs": i} for i in range(1000)]},
        "llamacpp": {"available": True, "slots_active": 2},
        "gpu": {"available": True, "util": 90}, "ollama": {"available": False}}}
    t = _t.time()
    row = {}
    for _ in range(500):
        row = a._metrics_row(snap)
    assert (_t.time() - t) < 2.0            # 500 pure builds well under 2s (no I/O)
    assert all(k in row for k in ("cpu", "gpu", "slots", "backlog"))


def test_key_series_falls_back_to_spend_in_lite(tmp_path, monkeypatch):
    # lite mode: top_keys carry spend but no reqs → key_series must store spend,
    # not zeros (else the "Top 10 keys over time" chart is empty). Regression.
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "k.db"))
    db.init()
    now = 1_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    # full-mode key (reqs) and lite-mode key (reqs=None, cost)
    db.insert_key_series(now, [{"alias": "full-key", "reqs": 42},
                               {"alias": "lite-key", "reqs": None, "cost": 3.5}])
    ks = db.key_series("15m")
    pts = ks.get("points", [])
    assert pts, "no key_series points"
    last = pts[-1]
    assert last.get("full-key") == 42        # requests preserved in full mode
    assert last.get("lite-key") == 3.5        # spend used when reqs is None


# ── multi-user login + admin user management (1.1.0) ──────────────────────────
def test_password_hash_roundtrip():
    h = auth.hash_password("s3cret-pw!")
    assert h.startswith("scrypt$") and "s3cret-pw!" not in h
    assert auth.verify_password("s3cret-pw!", h)
    assert not auth.verify_password("wrong", h)
    assert not auth.verify_password("s3cret-pw!", "garbage$$$")   # unparseable


def test_field_validation():
    assert auth.password_error("short") and auth.password_error("")
    assert auth.password_error("longenough8") is None
    assert auth.valid_username("alice.b_1") and not auth.valid_username("bad name")
    assert auth.valid_email("a@b.co") and not auth.valid_email("nope")


def test_db_user_crud_roundtrip():
    assert db.user_create("bob", "bob@x.io", "H", "viewer", time.time())
    assert not db.user_create("bob", "b2@x.io", "H2", "admin", time.time())  # dup name
    u = db.user_get("bob")
    assert u and u["email"] == "bob@x.io" and u["role"] == "viewer" and not u["disabled"]
    assert [x["name"] for x in db.user_list()] == ["bob"]
    assert db.user_count() == 1 and db.user_count("admin") == 0
    assert db.user_set_disabled("bob", True) and db.user_get("bob")["disabled"]
    assert db.user_delete("bob") and db.user_get("bob") is None


def test_bootstrap_admin(monkeypatch):
    monkeypatch.setattr(config, "ADMIN_USER", "root")
    monkeypatch.setattr(config, "ADMIN_PASSWORD", "rootpassword")
    monkeypatch.setattr(config, "ADMIN_EMAIL", "root@x.io")
    assert auth.bootstrap_admin() == "root"
    assert auth.bootstrap_admin() is None          # idempotent: users already exist
    u = db.user_get("root")
    assert u and u["role"] == "admin" and u["email"] == "root@x.io"


async def test_login_flow_and_session(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("alice", "a@x.io", auth.hash_password("alicepw12"), "viewer", time.time())
    c = await _client()
    try:
        r = await c.post("/login", data={"username": "alice", "password": "alicepw12"},
                         allow_redirects=False)
        assert r.status == 302
        assert "aimon_user=" in r.headers.get("Set-Cookie", "")
        assert (await c.get("/gpu")).status == 200          # cookie authenticates
        assert (await c.get("/api/data")).status == 200
        assert (await c.get("/admin/users")).status == 403  # viewer: no admin
    finally:
        await c.close()


async def test_token_auth_hides_alerts_link(monkeypatch):
    """Token/PAT access has no user identity to own alert config, so the sidebar
    Alerts link is stripped for it — while the JS alert-dot selector is kept and
    the other nav links remain."""
    TOK = "alerts-hide-tok-1234"
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", TOK)
    monkeypatch.setattr(config, "GPU_METRICS_URL", "http://gpu:9100/")  # so /gpu link stays
    monkeypatch.setattr(appmod, "_latest", {"ts": 0, "collectors": {}})  # env-based, deterministic
    c = await _client()
    try:
        # Bearer header authenticates as the master token and returns HTML
        # directly (no ?token= cookie redirect).
        r = await c.get("/", headers={"Authorization": "Bearer " + TOK})
        assert r.status == 200
        h = await r.text()
        assert 'Alerts</a>' not in h                        # visible link removed
        assert '<a href="/gpu">' in h                        # other nav intact (configured)
        assert 'a[href="/alerts"]' in h                      # alert-dot JS kept
    finally:
        await c.close()


async def test_user_session_keeps_alerts_link(monkeypatch):
    """A logged-in user (unlike a bare token) still sees the Alerts link."""
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("ally", "ally@x.io", auth.hash_password("allypw123"),
                   "viewer", time.time())
    c = await _client()
    try:
        r = await c.post("/login",
                         data={"username": "ally", "password": "allypw123"},
                         allow_redirects=False)
        assert r.status == 302
        h = await (await c.get("/")).text()
        assert 'Alerts</a>' in h                            # user keeps Alerts
    finally:
        await c.close()


async def test_pat_auth_hides_alerts_link(monkeypatch):
    """A personal access token is token-auth (sess is None) → Alerts hidden too."""
    db.user_create("pab", "pab@x.io", auth.hash_password("pabpw1234"),
                   "viewer", time.time())
    raw, tid, prefix = appmod._new_pat()
    assert db.api_token_create(tid, "pab", "viewer", "t",
                               appmod._hash_token(raw), prefix, time.time())
    c = await _client()
    try:
        r = await c.get("/", headers={"Authorization": "Bearer " + raw})
        assert r.status == 200
        assert 'Alerts</a>' not in (await r.text())
    finally:
        await c.close()


async def test_open_mode_denies_alerts():
    """Open mode (no token, no users) has no authentication, so alert config —
    webhook URLs, thresholds — must be denied, and its sidebar link hidden so
    there is no dead link that just 403s."""
    c = await _client()
    try:
        h = await (await c.get("/")).text()      # overview still open...
        assert 'Alerts</a>' not in h   # ...but Alerts link gone
        assert (await c.get("/alerts")).status == 403        # page denied
        assert (await c.get("/api/alerts")).status == 403    # API denied
        # a benign open endpoint is unaffected
        assert (await c.get("/healthz")).status == 200
    finally:
        await c.close()


async def test_token_mode_blocks_alerts_access(monkeypatch):
    """The shared master token (rides in the dashboard URL) is withheld from Alerts:
    the link is hidden AND the page + API are blocked in the backend — Alerts config
    (webhook URLs, thresholds) requires an interactive login, not the URL secret."""
    TOK = "alerts-access-tok-12"
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", TOK)
    c = await _client()
    try:
        hdr = {"Authorization": "Bearer " + TOK}
        assert (await c.get("/alerts", headers=hdr)).status == 403
        assert (await c.get("/api/alerts", headers=hdr)).status == 403
    finally:
        await c.close()


async def test_master_token_hides_and_blocks_alerts_and_settings(monkeypatch):
    """Full policy for the URL token: Alerts + Settings links are absent from the
    sidebar AND the pages/APIs are blocked in the backend — while a real admin
    login sees the links and reaches the surfaces."""
    TOK = "urltok-policy-12"
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", TOK)
    hdr = {"Authorization": "Bearer " + TOK}
    c = await _client()
    try:
        h = await (await c.get("/", headers=hdr)).text()
        assert ">Alerts</a>" not in h                 # alerts link stripped
        nav = await (await c.get("/api/nav", headers=hdr)).json()
        assert nav["admin"] is False                  # Settings link stays hidden
        # backend blocks — direct URL / API cannot reach either surface
        assert (await c.get("/alerts", headers=hdr)).status == 403
        assert (await c.get("/api/alerts", headers=hdr)).status == 403
        assert (await c.get("/settings", headers=hdr)).status == 403
        assert (await c.get("/api/admin/users", headers=hdr)).status == 403
        # dashboards the token IS meant to see still work
        assert (await c.get("/gpu", headers=hdr)).status == 200
        assert (await c.get("/api/data", headers=hdr)).status == 200
    finally:
        await c.close()
    # a real admin login keeps full access
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("realadm", "ra@x.io", auth.hash_password("realadmpw1"), "admin", time.time())
    c2 = await _client()
    try:
        await c2.post("/login", data={"username": "realadm", "password": "realadmpw1"})
        nav = await (await c2.get("/api/nav")).json()
        assert nav["admin"] is True
        assert (await c2.get("/settings")).status == 200
        assert (await c2.get("/api/alerts")).status == 200
    finally:
        await c2.close()


async def test_unconfigured_backend_links_stripped_serverside(monkeypatch):
    """Unconfigured-backend sidebar links (LiteLLM/Spend/Ollama/llama.cpp) are dropped
    SERVER-side, not only by the client /api/nav fetch — so a slow/failed fetch can't
    leave a dead link visible (the reported token-session symptom). The GPU/CPU link is
    EXEMPT — it hosts universal CPU views, so it's always shown even with no GPU. The
    Overview 'details →' /litellm link is anchored on its name and left intact."""
    TOK = "navstrip-tok-123"
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", TOK)
    for v in ("LITELLM_BASE_URL", "OLLAMA_BASE_URL", "LLAMACPP_BASE_URL",
              "GPU_SSH", "GPU_METRICS_URL"):
        monkeypatch.setattr(config, v, "")
    monkeypatch.setattr(appmod, "_latest", {"ts": 0, "collectors": {}})
    hdr = {"Authorization": "Bearer " + TOK}
    c = await _client()
    try:
        h = await (await c.get("/", headers=hdr)).text()
        assert "🔀 LiteLLM" not in h and "LiteLLM</a>" not in h   # sidebar link gone
        assert "Spend &amp; Quota</a>" not in h
        # backend nav LINKS stripped (anchor's class attr; the CSS rule `a.nl-ollama` stays)
        assert 'class="navlogo nl-ollama"' not in h and 'class="navlogo nl-llamacpp"' not in h
        assert "🖥️ GPU/CPU</a>" in h            # GPU/CPU always shown (universal CPU views)
        assert "details →" in h                                    # details link kept
    finally:
        await c.close()
    # configured → links come back
    for v in ("LITELLM_BASE_URL", "OLLAMA_BASE_URL", "LLAMACPP_BASE_URL"):
        monkeypatch.setattr(config, v, "http://backend:9000")
    monkeypatch.setattr(config, "GPU_METRICS_URL", "http://gpu:9100/")
    c2 = await _client()
    try:
        # Pin _latest to a configured snapshot: _configured() prefers the live
        # sample over the env URL, and the background sampler rebinds this module
        # global on its own cadence — without pinning, a slow tick can leave the
        # PART-1 "unconfigured" note in place and race the assertion (flaked the
        # in-image gate under QEMU). Configured URLs never resample to
        # "unconfigured", so this is deterministic.
        monkeypatch.setattr(appmod, "_latest", {"ts": 1, "collectors": {
            "litellm": {"available": True}, "ollama": {"available": True},
            "llamacpp": {"available": True}, "gpu": {"available": True}}})
        h2 = await (await c2.get("/", headers=hdr)).text()
        assert "🔀 LiteLLM" in h2 and 'class="navlogo nl-ollama"' in h2 and "🖥️ GPU/CPU</a>" in h2
        assert "Spend &amp; Quota</a>" in h2
    finally:
        await c2.close()


def test_apply_prefix_covers_form_action_and_js_redirect():
    """_apply_prefix must rewrite the login form POST target and the account
    page's JS root redirect, not just href/src/fetch — else they escape a
    reverse-proxy sub-path."""
    html = ('<a href="/x">|<form action="/login">|'
            'fetch("/api/a")|api("/api/b")|location.href="/";')
    out = appmod._apply_prefix(html, "/ai_monitoring")
    assert 'href="/ai_monitoring/x"' in out
    assert 'action="/ai_monitoring/login"' in out          # login POST
    assert 'fetch("/ai_monitoring/api/a"' in out
    assert 'api("/ai_monitoring/api/b"' in out
    assert 'location.href="/ai_monitoring/"' in out         # account redirect


def test_apply_cost_overrides_only_overridden(monkeypatch):
    """_apply_cost_overrides pins ONLY the models with an operator override; everything else
    keeps its LiteLLM /model/info price. (It no longer 'anchors' un-overridden models to total
    key-spend — that misattributed one model's spend to another.)"""
    monkeypatch.setattr(config, "MODEL_COSTS_JSON", '{"extern/model-a": 0.20}')  # $0.20/1M
    db.init(); db.model_cost_price_delete("extern/model-a"); db.model_cost_price_delete("extern/model-b")
    prices = {"extern/model-a": 0.00000225, "extern/model-b": 0.00000525}
    out = appmod._apply_cost_overrides(prices)
    assert out["extern/model-a"] == pytest.approx(0.20 / 1_000_000)   # override applied
    assert out["extern/model-b"] == 0.00000525                        # untouched (no override)


def test_model_cost_overrides_parses_usd_per_1m(monkeypatch):
    """MONITOR_MODEL_COSTS is JSON {model: USD per 1M tokens} → {model: USD per token};
    bad JSON / non-numeric values are ignored, not fatal."""
    monkeypatch.setattr(config, "MODEL_COSTS_JSON",
                        '{"extern/model-a": 0.20, "bad": "x"}')
    ov = appmod.model_cost_overrides()
    assert ov["extern/model-a"] == pytest.approx(0.20 / 1_000_000)
    assert "bad" not in ov
    monkeypatch.setattr(config, "MODEL_COSTS_JSON", "not-json")
    assert appmod.model_cost_overrides() == {}
    monkeypatch.setattr(config, "MODEL_COSTS_JSON", "")
    assert appmod.model_cost_overrides() == {}


def test_model_cost_price_db_roundtrip():
    """DB per-model cost override (the Settings-page store): set/read/delete USD-per-1M;
    negative / non-numeric values are rejected."""
    db.init()
    db.model_cost_price_delete("extern/model-a")
    assert db.model_cost_price_set("extern/model-a", 0.20, time.time()) is True
    assert db.model_cost_prices().get("extern/model-a") == 0.20
    assert db.model_cost_price_set("extern/model-a", -1, time.time()) is False   # negative
    assert db.model_cost_price_set("extern/model-a", "nope", time.time()) is False
    assert db.model_cost_price_delete("extern/model-a") is True
    assert "extern/model-a" not in db.model_cost_prices()


def test_fold_model_token_types_splits_input_cached_output():
    """1.8.8: /spend/logs fold splits per model into uncached-input / cached / output, honors
    the window start, drops the monitor's health-check key, and extracts cached tokens from
    either `cache_read_input_tokens` or `prompt_tokens_details.cached_tokens`."""
    import datetime as _dt
    start = _dt.datetime(2026, 7, 15, tzinfo=_dt.timezone.utc).timestamp()
    rows = [
        # cached via top-level field: input = 1000-600 = 400, cached 600, output 200
        {"startTime": "2026-07-20T10:00:00Z", "model": "m1", "prompt_tokens": 1000,
         "completion_tokens": 200, "cache_read_input_tokens": 600, "api_key": "k1"},
        # cached via prompt_tokens_details: input = 500-400 = 100, cached 400, output 100
        {"startTime": "2026-07-21T10:00:00Z", "model": "m1", "prompt_tokens": 500,
         "completion_tokens": 100, "prompt_tokens_details": {"cached_tokens": 400},
         "api_key": "k1"},
        # BEFORE the window → excluded entirely
        {"startTime": "2026-07-01T10:00:00Z", "model": "m1", "prompt_tokens": 9999,
         "completion_tokens": 9999, "api_key": "k1"},
        # health-check pseudo-key → dropped
        {"startTime": "2026-07-20T11:00:00Z", "model": "m1", "prompt_tokens": 50,
         "completion_tokens": 5, "api_key": "sk-litellm-service-account-health-check"},
    ]
    agg = litellm._fold_model_token_types(rows, start)
    assert agg["m1"] == {"input": 500, "cached": 1000, "output": 300, "total": 1800}


def test_classify_model_provider_prefix_beats_family_substring(monkeypatch):
    """Tier-1 #11: a provider-PREFIXED paid model whose name contains an open-weight family
    token must classify as REAL (external) spend, not reference — the family fallback only
    applies to a BARE name. Fixes real cost being dropped from budgets for vendor-hosted
    open-weight models."""
    monkeypatch.setattr(config, "INTERNAL_PROVIDERS", {"vllm", "llama-cpp", "ollama"})
    monkeypatch.setattr(config, "INTERNAL_MODEL_FAMILIES", {"qwen", "mistral", "gemma"})
    # external provider prefix + family token in the name → REAL, not reference
    assert litellm.classify_model("azure_ai/qwen-max")["cost_kind"] == "real"
    assert litellm.classify_model("openai/mistral-large")["cost_kind"] == "real"
    # genuinely self-hosted (internal provider prefix) → reference (unchanged)
    assert litellm.classify_model("vllm/Qwen3-Coder")["cost_kind"] == "reference"
    # bare open-weight name (no provider) → reference via the family heuristic (unchanged)
    assert litellm.classify_model("qwen3-coder")["cost_kind"] == "reference"
    # bare external name → real
    assert litellm.classify_model("gpt-5-mini")["cost_kind"] == "real"


def test_conftest_network_guard_blocks_external_allows_loopback():
    """The autouse hermeticity guard (conftest `_block_external_network`) must let loopback
    through (the aiohttp TestServer) but fail any external resolution deterministically — this
    is what stops an incompletely-mocked handler from hitting the real proxy and behaving
    differently under glibc vs musl (the fragility the in-image gate once caught)."""
    import socket
    socket.getaddrinfo("127.0.0.1", 80)          # loopback OK
    socket.getaddrinfo("localhost", 80)          # loopback OK
    for hostname in ("litellm", "example.com", "8.8.8.8"):   # not `host` — shadows the import
        with pytest.raises(socket.gaierror):
            socket.getaddrinfo(hostname, 80)


def test_match_model_is_provider_prefix_tolerant():
    """Tier-2 #17: the single `_match_model` helper (shared by price_for/detail_for) matches a
    model tolerant of a provider/ prefix on either side, and returns None on no match."""
    assert litellm._match_model("azure_ai/gpt-5-mini", {"gpt-5-mini": 3.0}) == 3.0   # bare key
    assert litellm._match_model("gpt-5-mini", {"azure_ai/gpt-5-mini": 4.0}) == 4.0   # prefixed key
    assert litellm._match_model("x/y", {"a/b": 1.0}) is None
    # price_for/detail_for defaults still differ (0.0 vs {})
    assert litellm.price_for("gpt-5-mini", {"azure_ai/gpt-5-mini": 2.0}) == 2.0
    assert litellm.price_for("nope", {"a": 1.0}) == 0.0
    assert litellm.detail_for("nope", {"a": {"in": 1}}) == {}


def test_rollup_incremental_skips_pre_hwm_raw(tmp_path, monkeypatch):
    """Tier-1 #8: after the first (full) rollup advances the high-water mark, a LATER rollup
    only re-aggregates recent raw — old raw inserted after the HWM is set is NOT folded (it
    would already be stored in prod), so the per-tick rollup stays a small scan."""
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "roll2.db"))
    db.init()
    now = 5_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    assert db._ROLLUP_HWM == 0.0                     # conftest reset → first run is FULL
    db.insert_key_series(now - 100, [{"key": "A", "alias": "", "reqs": 5}])  # recent
    db.rollup()
    assert db._ROLLUP_HWM == now                     # advanced on success
    assert db.key_series("24h", top_n=5)["labels"] == ["A"]
    # now insert raw 10h in the PAST and roll again — it's older than HWM-grace, so skipped
    db.insert_key_series(now - 36000, [{"key": "OLD", "alias": "", "reqs": 9}])
    db.rollup()
    lbls = db.key_series("30d", top_n=5)["labels"]
    assert "OLD" not in lbls, "incremental rollup must not re-scan pre-HWM raw"


async def test_db_error_counter_surfaces(monkeypatch):
    """Tier-3 #18: swallowed DB errors bump an observable counter exposed on /metrics
    (aimon_db_errors_total) and, for authed callers, /healthz — so silent persistence
    failure is visible instead of the ring making a broken box look healthy."""
    import metrics_prom
    before = db.db_error_stats()["count"]
    db._dberr(RuntimeError("disk full"))             # simulate a swallowed failure
    st = db.db_error_stats()
    assert st["count"] == before + 1 and "disk full" in st["last"]
    # prometheus text carries the gauge
    txt = metrics_prom.render({}, {"users": 0, "sessions": 0, "alerts": 0,
                                   "db_errors": st["count"]})
    assert "aimon_db_errors_total" in txt
    # /healthz exposes it to an authed caller only
    c = await _client()
    try:
        j = await (await c.get("/healthz")).json()
        assert "db_errors" not in j                   # anonymous → withheld (like version)
    finally:
        await c.close()


def test_fold_model_token_types_bounds_the_day(monkeypatch):
    """Tier-3 #24: the per-day fold must EXCLUDE rows at/after end_epoch so a boundary row
    isn't double-counted across two adjacent days' pulls."""
    import datetime as _dt
    start = _dt.datetime(2026, 7, 15, tzinfo=_dt.timezone.utc).timestamp()
    end = start + 86400
    rows = [
        {"startTime": "2026-07-15T23:59:00Z", "model": "m", "prompt_tokens": 10,
         "completion_tokens": 2, "api_key": "k"},                     # in-day → counted
        {"startTime": "2026-07-16T00:00:30Z", "model": "m", "prompt_tokens": 999,
         "completion_tokens": 999, "api_key": "k"},                   # next day → excluded
    ]
    agg = litellm._fold_model_token_types(rows, start, end)
    assert agg["m"] == {"input": 10, "cached": 0, "output": 2, "total": 12}


def test_row_cached_tokens_never_counts_cache_creation():
    """Cache-CREATION tokens are a write, not a read — they must NOT land in the cached (read)
    bucket, which maps to the discounted cached-input meter."""
    assert litellm._row_cached_tokens({"cache_creation_input_tokens": 999}) == 0
    assert litellm._row_cached_tokens({"cache_read_input_tokens": 42}) == 42
    assert litellm._row_cached_tokens(
        {"metadata": {"prompt_tokens_details": {"cached_tokens": 7}}}) == 7
    assert litellm._row_cached_tokens({}) == 0


def test_blend_1m_is_volume_weighted_when_volumes_given():
    """The per-type→blended derivation is total-cost ÷ total-tokens when volumes are supplied
    (so usd_1m·total matches the bill), and the legacy naive (in+out)/2 average otherwise."""
    # expensive output (30/1M) but tiny output volume → weighted ≈ input/cache dominated
    w = db._blend_1m(3.75, 30.0, 0.375, 445_000, 87_000, 7_090_000)
    assert w == pytest.approx(0.910, abs=0.01)
    # naive fallback (no volumes) over-weights output massively — the bug this guards
    assert db._blend_1m(3.75, 30.0) == pytest.approx(16.875)
    # single-sided naive: only input priced
    assert db._blend_1m(2.0, 0.0) == pytest.approx(2.0)


def test_model_cost_price_set_volume_weighted_usd_1m():
    """Pinning per-type rates WITH volumes stores a volume-weighted usd_1m (what the cost
    pipeline reads); the same rates WITHOUT volumes fall back to the naive average."""
    db.init()
    db.model_cost_price_delete("extern/vw")
    ok = db.model_cost_price_set("extern/vw", 0.0, time.time(),
                                 in_1m="3.75", out_1m="30", cache_1m="0.375",
                                 vol_in="445000", vol_out="87000", vol_cache="7090000")
    assert ok is True
    assert db.model_cost_prices()["extern/vw"] == pytest.approx(0.910, abs=0.01)
    det = db.model_cost_details()["extern/vw"]
    assert (det["in"], det["out"], det["cache"]) == (3.75, 30.0, 0.375)
    # without volumes → naive (in+out)/2
    db.model_cost_price_set("extern/vw", 0.0, time.time(), in_1m="3.75", out_1m="30")
    assert db.model_cost_prices()["extern/vw"] == pytest.approx(16.875)
    db.model_cost_price_delete("extern/vw")


async def test_per_model_token_types_endpoint(monkeypatch):
    """GET /api/admin/model-token-types (admin-gated) returns the per-model input/cached/output
    split from the collector; available=False when the pull yields None."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_ENABLED", True)

    seen = {}

    async def _fake(session, start_date, end_date=None):
        seen["start"], seen["end"] = start_date, end_date
        return {"per_model": {"azure_ai/m": {"input": 400, "cached": 600,
                                             "output": 200, "total": 1200}},
                "days_ok": 3, "total_days": 3, "days_failed": []}
    monkeypatch.setattr(litellm, "per_model_token_types", _fake)
    appmod._TT_CACHE.clear()            # deterministic: no cached window from a prior run
    c, _csrf = await _admin_client(monkeypatch)
    try:
        # explicit ?start=/?end= are honored verbatim (match an invoice's exact billing window)
        r = await c.get("/api/admin/model-token-types?start=2026-07-15&end=2026-07-24")
        assert r.status == 200
        body = await r.json()
        assert seen["start"] == "2026-07-15" and seen["end"] == "2026-07-24"
        assert body["start_date"] == "2026-07-15" and body["end_date"] == "2026-07-24"
        assert body["available"] is True and body["diag"]["days_ok"] == 3
        assert body["models"][0] == {"model": "azure_ai/m", "input": 400, "cached": 600,
                                     "output": 200, "total": 1200}

        # all days failed → available False but diag surfaces the reason
        async def _allfail(session, start_date, end_date=None):
            return {"per_model": {}, "days_ok": 0, "total_days": 2,
                    "days_failed": [{"day": "2026-07-15", "err": "too_big:>67108864"}]}
        monkeypatch.setattr(litellm, "per_model_token_types", _allfail)
        r2 = await c.get("/api/admin/model-token-types?start=2026-07-15")
        b2 = await r2.json()
        assert b2["available"] is False
        assert b2["diag"]["days_failed"][0]["err"].startswith("too_big")

        async def _none(session, start_date, end_date=None):
            return None
        monkeypatch.setattr(litellm, "per_model_token_types", _none)
        r3 = await c.get("/api/admin/model-token-types?window=month")
        assert (await r3.json())["available"] is False
    finally:
        await c.close()


async def test_per_model_token_types_chunks_by_day_and_surfaces_failures(monkeypatch):
    """The collector pulls /spend/logs ONE DAY AT A TIME (start_date=D&end_date=D), sums across
    days, and records a day whose pull errors (byte cap / timeout) instead of aborting all."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    # deterministic freeze-gate state regardless of test ordering
    litellm._CB.pop("spend", None)
    monkeypatch.setattr(litellm, "_AUTH_BAD", False)
    monkeypatch.setattr(litellm, "_LOAD_PER_CORE", 0.0)
    monkeypatch.setattr(config, "LITELLM_CB_THRESHOLD", 5)   # 1 failed day must NOT trip it
    calls = []
    # day 1 ok (1 row), day 2 byte-capped, day 3 ok (1 row)
    payloads = {
        "2026-07-15": b'[{"startTime":"2026-07-15T09:00:00Z","model":"m","prompt_tokens":100,'
                      b'"completion_tokens":20,"cache_read_input_tokens":40,"api_key":"k"}]',
        "2026-07-17": b'[{"startTime":"2026-07-17T09:00:00Z","model":"m","prompt_tokens":200,'
                      b'"completion_tokens":50,"api_key":"k"}]',
    }

    async def _fake_fetch(session, url, headers, timeout_s, max_bytes):
        day = url.split("start_date=")[1].split("&")[0]
        calls.append(day)
        if day == "2026-07-16":
            return None, "too_big:>67108864"
        return payloads.get(day, b"[]"), None
    monkeypatch.setattr(litellm, "_fetch_spend_raw", _fake_fetch)
    res = await litellm.per_model_token_types(None, "2026-07-15", "2026-07-17")
    assert calls == ["2026-07-15", "2026-07-16", "2026-07-17"]      # one call per day
    assert res["days_ok"] == 2 and res["total_days"] == 3
    assert res["days_failed"] == [{"day": "2026-07-16", "err": "too_big:>67108864"}]
    # summed across the two good days: in=(100-40)+200=260, cached=40, out=20+50=70
    assert res["per_model"]["m"] == {"input": 260, "cached": 40, "output": 70, "total": 370}


async def test_per_model_token_types_honors_freeze_gates(monkeypatch):
    """The heavy fan-out must SKIP up-front (no /spend/logs calls) when the spend circuit
    breaker is open, the key is known-bad, or the host is load-shedding — mirroring the
    sampler's _heavy_sample, so an HTTP handler can't hammer a struggling proxy."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    called = {"n": 0}

    async def _boom(*a, **k):
        called["n"] += 1
        return b"[]", None
    monkeypatch.setattr(litellm, "_fetch_spend_raw", _boom)

    # circuit open
    litellm._CB["spend"] = {"fails": 99, "until": 9e18}
    monkeypatch.setattr(litellm, "_AUTH_BAD", False)
    monkeypatch.setattr(litellm, "_LOAD_PER_CORE", 0.0)
    r = await litellm.per_model_token_types(None, "2026-07-15", "2026-07-17")
    assert r["aborted"] == "circuit_open" and called["n"] == 0
    litellm._CB.pop("spend", None)

    # bad key
    monkeypatch.setattr(litellm, "_AUTH_BAD", True)
    r = await litellm.per_model_token_types(None, "2026-07-15", "2026-07-17")
    assert r["aborted"] == "auth_bad" and called["n"] == 0
    monkeypatch.setattr(litellm, "_AUTH_BAD", False)

    # host load-shed
    monkeypatch.setattr(config, "LITELLM_LOAD_SHED", 1.0)
    monkeypatch.setattr(litellm, "_LOAD_PER_CORE", 5.0)
    r = await litellm.per_model_token_types(None, "2026-07-15", "2026-07-17")
    assert r["aborted"] == "load_shed" and called["n"] == 0


async def test_token_types_failures_use_private_breaker_not_shared_spend(monkeypatch):
    """Regression (review #12): the on-demand token-types fan-out must NOT feed the shared
    'spend' breaker — its heavy multi-day pull fails on modes specific to it (byte cap, time
    budget on a big window) that don't mean the always-on sampler's light /spend/logs poll is
    down. Failing days must trip its PRIVATE 'token_types' breaker only, leaving 'spend' intact."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    litellm._CB.pop("spend", None)
    litellm._CB.pop("token_types", None)
    monkeypatch.setattr(litellm, "_AUTH_BAD", False)
    monkeypatch.setattr(litellm, "_LOAD_PER_CORE", 0.0)
    monkeypatch.setattr(config, "LITELLM_CB_THRESHOLD", 2)

    async def _all_fail(session, url, headers, timeout_s, max_bytes):
        return None, "too_big:>67108864"
    monkeypatch.setattr(litellm, "_fetch_spend_raw", _all_fail)
    r = await litellm.per_model_token_types(None, "2026-07-15", "2026-07-20")
    assert r["aborted"] == "circuit_open"                      # its own breaker stopped the fan-out
    assert litellm._CB.get("token_types", {}).get("fails", 0) >= 2   # private breaker took the hits
    assert not litellm._cb_open("spend", time.time()), "shared spend breaker must stay closed"
    litellm._CB.pop("token_types", None)


def test_tt_cache_store_is_bounded():
    """Regression (review #6): _TT_CACHE must not grow without bound — a run of distinct ?start=
    windows (one entry each) is capped, evicting expired-then-oldest."""
    appmod._TT_CACHE.clear()
    now = 1_000_000.0
    for i in range(appmod._TT_MAX * 3):
        appmod._tt_cache_store((f"2026-01-{i:04d}", ""), now, {"available": True, "models": []})
    assert len(appmod._TT_CACHE) <= appmod._TT_MAX
    appmod._TT_CACHE.clear()


def test_model_cost_overrides_db_beats_env(monkeypatch):
    """The Settings-page (DB) cost override wins over the MONITOR_MODEL_COSTS env value."""
    db.init()
    db.model_cost_price_delete("extern/model-a")
    monkeypatch.setattr(config, "MODEL_COSTS_JSON", '{"extern/model-a": 0.50}')
    assert appmod.model_cost_overrides()["extern/model-a"] == pytest.approx(0.50 / 1_000_000)
    db.model_cost_price_set("extern/model-a", 0.20, time.time())      # admin UI edit
    assert appmod.model_cost_overrides()["extern/model-a"] == pytest.approx(0.20 / 1_000_000)
    db.model_cost_price_delete("extern/model-a")


def test_gpu_http_collector_refuses_redirects():
    """SSRF guard: the GPU HTTP collector's redirect handler returns None so
    urllib raises on any 3xx instead of chasing the Location header."""
    h = gpu._NoRedirect()
    assert h.redirect_request(None, None, 302, "Found", {}, "http://evil/") is None
    assert h.redirect_request(None, None, 301, "Moved", {}, "http://x/") is None


async def test_login_bad_password_and_lockout(monkeypatch):
    monkeypatch.setattr(config, "AUTH_MAX_FAILS", 3)
    db.user_create("carol", "c@x.io", auth.hash_password("carolpw12"), "viewer", time.time())
    c = await _client()
    try:
        for _ in range(3):
            r = await c.post("/login", data={"username": "carol", "password": "nope"},
                             allow_redirects=False)
            assert r.status == 302 and "e=1" in r.headers.get("Location", "")
        r = await c.post("/login", data={"username": "carol", "password": "carolpw12"},
                         allow_redirects=False)
        assert "e=locked" in r.headers.get("Location", "")   # locked despite right pw
    finally:
        await c.close()


async def test_disabled_user_denied_next_request(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("dan", "d@x.io", auth.hash_password("danpw1234"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "dan", "password": "danpw1234"})
        assert (await c.get("/gpu")).status == 200
        db.user_set_disabled("dan", True)                    # no session drop —
        r = await c.get("/gpu", allow_redirects=False)       # per-request DB recheck
        assert r.status == 302 and "/login" in r.headers.get("Location", "")
    finally:
        await c.close()


async def test_admin_manages_users_with_csrf(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("adm", "adm@x.io", auth.hash_password("admpw1234"), "admin", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "adm", "password": "admpw1234"})
        d = await (await c.get("/api/admin/users")).json()
        csrf = d["csrf"]
        assert csrf and d["me"] == "adm"
        # create without CSRF token -> 403
        r = await c.post("/api/admin/users",
                         data={"username": "newv", "email": "n@x.io",
                               "password": "newvpw12", "role": "viewer"})
        assert r.status == 403
        # with CSRF -> created
        r = await c.post("/api/admin/users",
                         data={"username": "newv", "email": "n@x.io",
                               "password": "newvpw12", "role": "viewer"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200
        d2 = await (await c.get("/api/admin/users")).json()
        assert any(u["name"] == "newv" and u["email"] == "n@x.io" for u in d2["users"])
        # bad email rejected
        r = await c.post("/api/admin/users",
                         data={"username": "bad", "email": "nope", "password": "x2345678",
                               "role": "viewer"}, headers={"X-CSRF-Token": csrf})
        assert r.status == 400
    finally:
        await c.close()


async def test_viewer_cannot_reach_admin(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("vv", "v@x.io", auth.hash_password("vvpw1234"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "vv", "password": "vvpw1234"})
        assert (await c.get("/api/admin/users")).status == 403
        assert (await c.get("/admin/users")).status == 403
    finally:
        await c.close()


async def test_last_admin_cannot_be_removed(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("solo", "s@x.io", auth.hash_password("solopw12"), "admin", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "solo", "password": "solopw12"})
        csrf = (await (await c.get("/api/admin/users")).json())["csrf"]
        r = await c.post("/api/admin/users/action",
                         data={"username": "solo", "action": "delete"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 400   # refuse to remove the last admin
    finally:
        await c.close()


async def test_admin_can_update_user_profile(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("adm2", "adm2@x.io", auth.hash_password("adm2pw12"), "admin", time.time())
    db.user_create("bob", "bob@x.io", auth.hash_password("bobpw123"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "adm2", "password": "adm2pw12"})
        csrf = (await (await c.get("/api/admin/users")).json())["csrf"]
        # update needs CSRF
        r = await c.post("/api/admin/users/action",
                         data={"username": "bob", "action": "update",
                               "email": "bob2@x.io", "role": "admin"})
        assert r.status == 403
        # change email + role (viewer -> admin)
        r = await c.post("/api/admin/users/action",
                         data={"username": "bob", "action": "update",
                               "email": "bob2@x.io", "role": "admin"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200
        u = db.user_get("bob")
        assert u["email"] == "bob2@x.io" and u["role"] == "admin"
        # invalid email rejected
        r = await c.post("/api/admin/users/action",
                         data={"username": "bob", "action": "update",
                               "email": "nope", "role": "viewer"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 400
        # invalid role rejected
        r = await c.post("/api/admin/users/action",
                         data={"username": "bob", "action": "update",
                               "email": "bob2@x.io", "role": "superuser"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 400
    finally:
        await c.close()


async def test_last_admin_cannot_be_demoted(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("solo2", "s2@x.io", auth.hash_password("solo2pw1"), "admin", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "solo2", "password": "solo2pw1"})
        csrf = (await (await c.get("/api/admin/users")).json())["csrf"]
        r = await c.post("/api/admin/users/action",
                         data={"username": "solo2", "action": "update",
                               "email": "s2@x.io", "role": "viewer"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 400                      # can't demote the last admin
        assert db.user_get("solo2")["role"] == "admin"
    finally:
        await c.close()


async def test_user_update_drops_sessions_only_on_role_change(monkeypatch):
    """Review-fix: the admin `update` action must drop the target's sessions ONLY when their role
    actually changes (a demotion needs the fresh role) — an email-only edit must NOT log them out,
    and it uses sessions_drop_user_except so an admin editing their OWN profile isn't self-locked."""
    c, csrf = await _admin_client(monkeypatch, user="acting", pw="actingpw1")
    try:
        # a second admin as the target, so demoting them isn't blocked by the last-admin guard
        db.user_create("tgt", "tgt@x.io", auth.hash_password("tgtpw123"), "admin", time.time())
        sid1, _ = auth.session_new("tgt", "admin")
        assert auth.session_get(sid1) is not None
        # (1) email-only edit, role unchanged → session SURVIVES (no forced logout)
        r = await c.post("/api/admin/users/action",
                         data={"username": "tgt", "action": "update",
                               "email": "tgt2@x.io", "role": "admin"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200
        assert auth.session_get(sid1) is not None, "email-only edit must NOT drop the user's session"
        # (2) role change → the target's sessions are DROPPED (fresh role applies at once)
        sid2, _ = auth.session_new("tgt", "admin")
        r = await c.post("/api/admin/users/action",
                         data={"username": "tgt", "action": "update",
                               "email": "tgt2@x.io", "role": "viewer"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200
        assert auth.session_get(sid2) is None, "role change must drop the target's sessions"
    finally:
        await c.close()


def test_last_admin_guard_is_live_counted_not_stale():
    # F1 regression: the last-admin rail must re-count admins INSIDE each mutation
    # (atomic), not from a value read earlier. With two admins, demoting the first
    # is allowed; demoting the second must be refused because only one admin then
    # remains — even though a count taken before either call would have said "2".
    db.user_create("gr1", "gr1@x.io", auth.hash_password("gr1pw123"), "admin", time.time())
    db.user_create("gr2", "gr2@x.io", auth.hash_password("gr2pw123"), "admin", time.time())
    assert db.user_count("admin") >= 2
    assert db.user_update_guarded("gr1", "gr1@x.io", "viewer") is True     # one admin left
    assert db.user_update_guarded("gr2", "gr2@x.io", "viewer") is False    # rail blocks
    assert db.user_get("gr2")["role"] == "admin"
    assert db.user_count("admin") == 1
    # delete + disable guards enforce the same invariant on the survivor
    assert db.user_delete_guarded("gr2") is False
    assert db.user_disable_guarded("gr2") is False
    assert db.user_count("admin") == 1


def test_last_admin_guard_survives_concurrent_demote():
    # F1 (TOCTOU): two demotions fired at once must never leave zero admins. The
    # pre-fix handler read admin_count once and both requests passed a stale "2".
    # The guard now lives in the atomic write, so SQLite serialises the two and the
    # loser's WHERE (re-count > 1) fails — at least one admin always remains.
    import threading
    db.user_create("cc1", "cc1@x.io", auth.hash_password("cc1pw123"), "admin", time.time())
    db.user_create("cc2", "cc2@x.io", auth.hash_password("cc2pw123"), "admin", time.time())
    start = threading.Barrier(2)

    def demote(u):
        start.wait()                                  # maximise overlap
        db.user_update_guarded(u, u + "@x.io", "viewer")

    t1 = threading.Thread(target=demote, args=("cc1",))
    t2 = threading.Thread(target=demote, args=("cc2",))
    t1.start(); t2.start(); t1.join(); t2.join()
    assert db.user_count("admin") >= 1, "TOCTOU: concurrent demotes removed all admins"


async def _admin_client(monkeypatch, user="sadm", pw="sadmpw12"):
    """A logged-in admin TestClient + its CSRF token."""
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create(user, f"{user}@x.io", auth.hash_password(pw), "admin", time.time())
    c = await _client()
    await c.post("/login", data={"username": user, "password": pw})
    csrf = (await (await c.get("/api/me")).json())["csrf"]
    return c, csrf


async def test_settings_get_set_reset_live_apply(monkeypatch):
    c, csrf = await _admin_client(monkeypatch)
    try:
        r = await c.get("/api/admin/settings")
        assert r.status == 200
        names = {s["name"] for s in (await r.json())["settings"]}
        assert "ALERT_CPU_PCT" in names and "SAMPLE_INTERVAL" in names
        # set → applied live (module constant) + persisted
        r = await c.post("/api/admin/settings",
                         data={"action": "set", "name": "ALERT_CPU_PCT", "value": "85"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200 and (await r.json())["overridden"] is True
        assert config.tunable("ALERT_CPU_PCT") == 85.0 and config.ALERT_CPU_PCT == 85.0
        assert db.settings_all().get("ALERT_CPU_PCT") == "85.0"
        # reset → back to env default, override cleared
        r = await c.post("/api/admin/settings",
                         data={"action": "reset", "name": "ALERT_CPU_PCT"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200 and (await r.json())["overridden"] is False
        assert config.tunable("ALERT_CPU_PCT") == 0.0
        assert "ALERT_CPU_PCT" not in db.settings_all()
    finally:
        config.clear_override("ALERT_CPU_PCT")
        await c.close()


async def test_settings_validation_and_csrf(monkeypatch):
    c, csrf = await _admin_client(monkeypatch)
    try:
        r = await c.post("/api/admin/settings",
                         data={"action": "set", "name": "ALERT_CPU_PCT", "value": "999"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 400                       # out of range
        r = await c.post("/api/admin/settings",
                         data={"action": "set", "name": "MONITOR_DASHBOARD_TOKEN", "value": "x"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 400                       # not a tunable (secret) → refused
        r = await c.post("/api/admin/settings",
                         data={"action": "set", "name": "ALERT_CPU_PCT", "value": "50"})
        assert r.status == 403                       # missing CSRF
    finally:
        await c.close()


async def test_settings_and_teams_are_admin_only(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("sad", "sad@x.io", auth.hash_password("sadpw123"), "admin", time.time())
    db.user_create("svw", "svw@x.io", auth.hash_password("svwpw123"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "svw", "password": "svwpw123"})
        assert (await c.get("/api/admin/settings")).status == 403
        assert (await c.get("/api/admin/teams")).status == 403
        # /settings is a registered admin page → middleware blocks a viewer with a
        # 403 (same as /admin/users), gated by ROLE not username.
        assert (await c.get("/settings")).status == 403
    finally:
        await c.close()


async def test_team_sync_overwrites_override_with_detected(monkeypatch):
    """⟳ (per-key sync) re-detects from LiteLLM and lets it WIN: it drops any admin team
    override so the freshly detected team is what shows (overwrites the defined name)."""
    c, csrf = await _admin_client(monkeypatch, user="syncadm", pw="syncadm1")
    try:
        r = await c.post("/api/admin/teams", data={"key": "kSync", "team": "AI team"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200 and db.team_overrides().get("kSync") == "AI team"

        async def _fake_detect(session, force):
            appmod._TEAMS_DETECT_CACHE["kSync"] = {
                "detected": "Platform", "user": "", "budget": 0.0, "spent": 0.0}
            return appmod._TEAMS_DETECT_CACHE, "litellm"
        monkeypatch.setattr(appmod, "_detect_teams", _fake_detect)
        r = await c.post("/api/admin/teams/sync", data={"key": "kSync"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200
        j = await r.json()
        assert j["team"] == "Platform" and j["overridden"] is False
        assert "kSync" not in db.team_overrides()      # override dropped — LiteLLM wins
    finally:
        appmod._TEAMS_DETECT_CACHE.pop("kSync", None)
        await c.close()


async def test_team_override_get_set_reset(monkeypatch):
    c, csrf = await _admin_client(monkeypatch, user="tadm", pw="tadmpw12")
    try:
        r = await c.post("/api/admin/teams",
                         data={"key": "langgraph-agent", "team": "Platform"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200 and (await r.json())["overridden"] is True
        assert db.team_overrides().get("langgraph-agent") == "Platform"
        rows = (await (await c.get("/api/admin/teams")).json())["keys"]
        assert any(k["key"] == "langgraph-agent" and k["team"] == "Platform" for k in rows)
        # the override wins over LiteLLM's reported team in the budget rollup
        keys = [{"alias": "langgraph-agent", "team": "reported", "cost": 1.0, "budget": 0.0}]
        appmod._apply_team_overrides(keys)
        assert keys[0]["team"] == "Platform"
        r = await c.post("/api/admin/teams",
                         data={"action": "reset", "key": "langgraph-agent"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200 and (await r.json())["overridden"] is False
        assert "langgraph-agent" not in db.team_overrides()
    finally:
        await c.close()


def test_budgets_applies_user_override_so_by_user_charts_name_the_owner(monkeypatch):
    """Regression: a key reassigned to a user on the Settings board (db.key_user_overrides)
    showed correctly on the board but fell into "Unassigned" on the /litellm by-user charts.
    Those charts build their owner map ONLY from /api/budgets' `email` field, and budgets_handler
    applied the TEAM override but not the USER override (the board applied both). So a manual
    reassignment — or a key whose live /user/list email blipped empty — never reached the charts.
    `_apply_user_overrides` now overlays it on the budgets path too, keyed on the same canonical
    label the board uses, so the two can no longer diverge."""
    monkeypatch.setattr(db, "key_user_overrides",
                        lambda: {"kA": "pedro.tarrinho@example.com"})
    # kA has a BLANK live owner (the exact "live resolution came back empty" case); kB is untouched
    keys = [{"alias": "kA", "user_name": ""},
            {"alias": "kB", "user_name": "sam@example.com"}]
    appmod._apply_user_overrides(keys)
    assert keys[0]["user_name"] == "pedro.tarrinho@example.com", "override must name the owner"
    assert keys[1]["user_name"] == "sam@example.com", "un-overridden key keeps its live owner"
    # and it surfaces as the budget row's `email` — the exact field buildKeyUser() reads, so the
    # by-user charts now group kA under pedro.tarrinho instead of "Unassigned".
    rows = litellm.budget_rows(keys, {}, 1, 30)
    email_of = {r["key"]: r["email"] for r in rows}
    assert email_of.get("kA") == "pedro.tarrinho@example.com", \
        f"reassigned key would still show Unassigned in the charts: {email_of}"
    assert email_of.get("kB") == "sam@example.com"


def test_stored_owner_name_survives_a_user_list_blip_and_backs_budgets_fallback():
    """Resilience: LiteLLM's /user/list is flaky, so a key that IS owned can carry a BLANK live
    email on a given poll — and the by-user charts would then drop it to "Unassigned" for that
    view. known_keys now persists the resolved owner EMAIL (owner_name), HELD through such a blip
    (cleared only when the owner id itself clears via the streak), and budgets_handler falls back
    to it. Mirrors the streak-buffered resilience the by-key path already has for the owner id."""
    db.init()
    labs = ("blipA", "blipB")

    def _clear():
        with db._connect() as conn:
            conn.execute("DELETE FROM known_keys WHERE label IN (?,?)", labs)

    _clear()
    try:
        t = 1_000_000.0
        # a good poll: blipA resolves owner-id + email; blipB is owned but LiteLLM gave no email
        db.known_keys_upsert({"blipA": "uid-A", "blipB": "uid-B"}, t,
                             {"blipA": "pedro.tarrinho@example.com", "blipB": ""})
        assert db.known_owner_names().get("blipA") == "pedro.tarrinho@example.com"
        assert "blipB" not in db.known_owner_names()          # no email → nothing to persist
        # next poll: blipA's live email blips EMPTY while its owner-id is still present → name HELD
        db.known_keys_upsert({"blipA": "uid-A"}, t + 60, {"blipA": ""})
        assert db.known_owner_names().get("blipA") == "pedro.tarrinho@example.com", \
            "a one-off /user/list blip must not blank the persisted owner name"
        # budgets fallback: a key whose live user_name is empty gets the stored email (blipB, which
        # never had a name, stays empty → still 'Unassigned', correctly)
        keys = [{"alias": "blipA", "user_name": ""}, {"alias": "blipB", "user_name": ""}]
        appmod._apply_stored_owner_names(keys)
        assert keys[0]["user_name"] == "pedro.tarrinho@example.com", "owned key must not read Unassigned on a blip"
        assert keys[1]["user_name"] == "", "a key with no known email stays unnamed"
        # a resolved live name is NEVER overridden by the fallback (precedence: override > live > stored)
        keys2 = [{"alias": "blipA", "user_name": "fresh@example.com"}]
        appmod._apply_stored_owner_names(keys2)
        assert keys2[0]["user_name"] == "fresh@example.com"
        # when the owner truly clears (streak met), the persisted name clears too — no stale owner
        for i in range(db.OWNER_BLANK_THRESHOLD + 1):
            db.known_keys_upsert({"blipA": ""}, t + 120 + i, {"blipA": ""})
        assert "blipA" not in db.known_owner_names(), "a genuinely un-assigned key must not keep a stale name"
    finally:
        _clear()          # don't leak blipA/blipB into the shared known_keys table


async def test_teams_detection_cached_and_sticky(monkeypatch):
    """The Teams board caches LiteLLM's flaky team detection: a normal load serves the
    cache (no re-fetch), ?refresh=1 re-polls, and a team already detected STAYS even if
    a later poll returns empty — fixing the 'team shows, then blank' flicker."""
    calls = {"n": 0}

    async def flaky_kb(session):
        calls["n"] += 1
        team = "AppSec" if calls["n"] == 1 else ""   # detected once, then flaky-empty
        return {"k1": {"team": team, "user": "u1", "budget": 0.0, "spend": 5.0}}

    monkeypatch.setattr(litellm, "key_budgets", flaky_kb)
    monkeypatch.setattr(appmod, "_TEAMS_DETECT_CACHE", {}, raising=False)
    monkeypatch.setattr(appmod, "_backend_latest", {"litellm": {"top_keys": []}})
    c, csrf = await _admin_client(monkeypatch, user="tcadm", pw="tcadmpw1")
    try:
        r1 = await (await c.get("/api/admin/teams?refresh=1")).json()   # forced fetch
        assert r1["source"] == "litellm"
        assert any(k["key"] == "k1" and k["detected"] == "AppSec" for k in r1["keys"])
        n_after_first = calls["n"]
        r2 = await (await c.get("/api/admin/teams")).json()             # cached: no fetch
        assert r2["cached"] is True and calls["n"] == n_after_first     # did NOT re-poll
        r3 = await (await c.get("/api/admin/teams?refresh=1")).json()   # re-poll (now empty)
        assert calls["n"] == n_after_first + 1
        assert any(k["key"] == "k1" and k["detected"] == "AppSec" for k in r3["keys"])  # sticky
    finally:
        await c.close()


async def test_teams_detection_persists_and_reloads_from_db(monkeypatch):
    """Detected teams are written to db.team_detect and reloaded into the cache on a cold
    start — so after a restart the board shows teams WITHOUT re-polling LiteLLM."""
    async def kb(session):
        return {"Rodolfo": {"team": "AppSec", "user": "u1", "budget": 200.0, "spend": 728.0}}
    monkeypatch.setattr(litellm, "key_budgets", kb)
    monkeypatch.setattr(appmod, "_TEAMS_DETECT_CACHE", {}, raising=False)
    monkeypatch.setattr(appmod, "_TEAMS_LOADED", False, raising=False)
    monkeypatch.setattr(appmod, "_backend_latest", {"litellm": {"top_keys": []}})
    await appmod._detect_teams(None, True)                     # detect → persists to DB
    assert db.team_detect_all().get("Rodolfo", {}).get("detected") == "AppSec"
    # simulate a restart: empty cache, LiteLLM must NOT be polled
    monkeypatch.setattr(appmod, "_TEAMS_DETECT_CACHE", {}, raising=False)
    monkeypatch.setattr(appmod, "_TEAMS_LOADED", False, raising=False)
    async def boom(session):
        raise AssertionError("must not poll LiteLLM on restart when DB has teams")
    monkeypatch.setattr(litellm, "key_budgets", boom)
    detected, src = await appmod._detect_teams(None, False)
    assert src == "cache" and detected["Rodolfo"]["detected"] == "AppSec"


async def test_teams_empty_keylist_team_filled_from_snapshot(monkeypatch):
    """A key whose /key/list row has an EMPTY team must be filled from the spend
    snapshot (which resolved it) — not left blank because /key/list was seen first.
    This is why big-spender keys showed no team on the board but were teamed elsewhere."""
    async def kb(session):        # /key/list: key present but team blank
        return {"BigSpender": {"team": "", "user": "", "budget": 200.0, "spend": 728.0}}
    monkeypatch.setattr(litellm, "key_budgets", kb)
    monkeypatch.setattr(appmod, "_TEAMS_DETECT_CACHE", {}, raising=False)
    monkeypatch.setattr(appmod, "_backend_latest",
                        {"litellm": {"top_keys": [{"key": "BigSpender",
                                                   "team": "AppSec", "cost": 728.0}]}})
    detected, _src = await appmod._detect_teams(None, True)
    assert detected["BigSpender"]["detected"] == "AppSec"    # filled from snapshot, not blank
    assert detected["BigSpender"]["budget"] == 200.0 and detected["BigSpender"]["spent"] == 728.0


async def test_model_kinds_get_set_reset(monkeypatch):
    c, csrf = await _admin_client(monkeypatch, user="mkadm", pw="mkadmpw1")
    try:
        # set an override → the model appears on the board as 'real', overridden, while
        # its auto-detected default stays 'reference' (gemma family = self-hosted).
        r = await c.post("/api/admin/model-kinds",
                         data={"action": "set", "model": "gemma-self", "kind": "real"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200 and (await r.json())["overridden"] is True
        assert db.model_kind_overrides().get("gemma-self") == "real"
        j = await (await c.get("/api/admin/model-kinds")).json()
        row = next(m for m in j["models"] if m["model"] == "gemma-self")
        assert row["kind"] == "real" and row["overridden"] is True
        assert row["default_kind"] == "reference"
        # invalid kind refused
        r = await c.post("/api/admin/model-kinds",
                         data={"action": "set", "model": "gemma-self", "kind": "nope"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 400
        # missing CSRF refused
        r = await c.post("/api/admin/model-kinds",
                         data={"action": "set", "model": "gemma-self", "kind": "real"})
        assert r.status == 403
        # reset → override cleared, auto-detect restored
        r = await c.post("/api/admin/model-kinds",
                         data={"action": "reset", "model": "gemma-self"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200 and (await r.json())["overridden"] is False
        assert "gemma-self" not in db.model_kind_overrides()
    finally:
        db.model_kind_delete("gemma-self")
        await c.close()


async def test_model_kinds_ordered_by_usage(monkeypatch):
    """The Model costs board ranks models by 30-day usage (most → least); each row
    carries its token count so the ordering is meaningful/visible."""
    async def fake_range(session, start, end, ov):
        return [{"model": "mc-low", "tokens": 100},
                {"model": "mc-high", "tokens": 900000},
                {"model": "mc-mid", "tokens": 5000}]
    monkeypatch.setattr(litellm, "per_model_range", fake_range)
    c, csrf = await _admin_client(monkeypatch, user="mkord", pw="mkordpw1")
    try:
        j = await (await c.get("/api/admin/model-kinds")).json()
        idx = {m["model"]: i for i, m in enumerate(j["models"])}
        # most-used first (relative order, robust to any other models present)
        assert idx["mc-high"] < idx["mc-mid"] < idx["mc-low"]
        hi = next(m for m in j["models"] if m["model"] == "mc-high")
        assert hi["tokens"] == 900000            # usage exposed for the ranking
    finally:
        await c.close()


async def test_model_kinds_admin_only(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("mkv", "mkv@x.io", auth.hash_password("mkvpw123"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "mkv", "password": "mkvpw123"})
        assert (await c.get("/api/admin/model-kinds")).status == 403
        assert (await c.post("/api/admin/model-kinds",
                data={"action": "set", "model": "x", "kind": "real"})).status == 403
    finally:
        await c.close()


async def test_key_budget_override_set_reset(monkeypatch):
    c, csrf = await _admin_client(monkeypatch, user="badm", pw="badmpw12")
    try:
        # set a monthly budget for a key (with a team in the same save)
        r = await c.post("/api/admin/teams",
                         data={"key": "coder-ide", "team": "Platform", "budget": "250"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200
        body = await r.json()
        assert body["budget"] == 250.0 and body["budget_overridden"] is True
        assert db.key_budget_overrides().get("coder-ide") == 250.0
        # the override feeds the budget map used by the Spend rollup
        assert appmod._key_budget_map().get("coder-ide") == 250.0
        # it shows on the board with the flag
        rows = (await (await c.get("/api/admin/teams")).json())["keys"]
        row = next(k for k in rows if k["key"] == "coder-ide")
        assert row["budget"] == 250.0 and row["budget_overridden"] is True
        # negative rejected
        r = await c.post("/api/admin/teams",
                         data={"key": "coder-ide", "budget": "-5"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 400
        # reset clears BOTH team + budget
        r = await c.post("/api/admin/teams",
                         data={"action": "reset", "key": "coder-ide"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200
        assert "coder-ide" not in db.key_budget_overrides()
        assert "coder-ide" not in db.team_overrides()
    finally:
        await c.close()


async def test_team_budget_inherited_by_members(monkeypatch):
    c, csrf = await _admin_client(monkeypatch, user="tbadm", pw="tbadmpw1")
    try:
        # set a team budget every member inherits
        r = await c.post("/api/admin/team-budget",
                         data={"team": "AppSec", "budget": "200"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200 and (await r.json())["budget"] == 200.0
        assert db.team_budgets().get("AppSec") == 200.0
        # a key in AppSec with no per-key override inherits 200; an override wins
        keys = [{"alias": "alice", "team": "AppSec", "budget": 0.0},
                {"alias": "bob", "team": "AppSec", "budget": 0.0},
                {"alias": "carol", "team": "Other", "budget": 0.0}]
        db.key_budget_set("bob", 500.0, time.time())          # bob bumped above team
        bmap = appmod._resolve_budget_map(keys)
        assert bmap["alice"] == 200.0                          # inherits team budget
        assert bmap["bob"] == 500.0                            # per-key override wins
        assert "carol" not in bmap                             # no team budget, no override
        # negative team budget rejected; reset clears
        assert (await c.post("/api/admin/team-budget",
                             data={"team": "AppSec", "budget": "-1"},
                             headers={"X-CSRF-Token": csrf})).status == 400
        r = await c.post("/api/admin/team-budget",
                         data={"action": "reset", "team": "AppSec"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200 and "AppSec" not in db.team_budgets()
    finally:
        db.key_budget_delete("bob")
        await c.close()


async def test_litellm_auth_failure_reported_clearly(monkeypatch, caplog):
    # A rejected master key (401/403) must be reported CLEARLY in the log ("the
    # token is invalid/expired") and set an auth_error on the collector — not just a
    # bare "HTTP 401", and it must short-circuit the key-gated /spend calls.
    import logging
    litellm._AUTH_BAD = False

    async def fake_fetch(session, url, headers=None, timeout_s=None):
        if "liveliness" in url:
            return ("I'm alive!", None)
        return (None, "HTTP 401")             # models / spend / everything → 401
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-wrong")
    with caplog.at_level(logging.INFO, logger="aimon.litellm"):
        out = await litellm.sample(None)
    assert out.get("auth_error") is True
    assert "master key rejected" in (out.get("error") or "")
    log = " ".join(r.getMessage() for r in caplog.records if r.name == "aimon.litellm")
    assert "AUTH FAILED" in log and ("invalid" in log and "expired" in log)
    litellm._AUTH_BAD = False                  # reset shared state for other tests


def test_note_auth_one_shot_and_recovery(caplog):
    """_note_auth logs the failure ONCE (not every poll), stays quiet while still bad,
    then logs a single AUTH OK on recovery and clears the flag."""
    import logging
    litellm._AUTH_BAD = False
    with caplog.at_level(logging.INFO, logger="aimon.litellm"):
        assert litellm._note_auth("http://litellm:4000", "HTTP 401") is True   # bad → log
        assert litellm._AUTH_BAD is True
        assert litellm._note_auth("http://litellm:4000", "HTTP 403") is True   # still bad → quiet
        m1 = [r.getMessage() for r in caplog.records if r.name == "aimon.litellm"]
        assert sum("AUTH FAILED" in m for m in m1) == 1 and not any("AUTH OK" in m for m in m1)
        caplog.clear()
        assert litellm._note_auth("http://litellm:4000", None) is False        # recovered
        assert litellm._AUTH_BAD is False
        m2 = [r.getMessage() for r in caplog.records if r.name == "aimon.litellm"]
        assert sum("AUTH OK" in m for m in m2) == 1
        # a clean tick while already-good logs nothing
        caplog.clear()
        assert litellm._note_auth("http://litellm:4000", None) is False
        assert [r for r in caplog.records if r.name == "aimon.litellm"] == []
    litellm._AUTH_BAD = False


async def test_key_team_resolved_via_team_id_and_user(monkeypatch):
    # Regression: a key's team must resolve key -> team_id -> USER. LiteLLM often
    # carries only a team_id UUID on the key, or attaches the team to the user, not
    # the key. key_budgets() must surface a readable team either way.
    async def fake_fetch(session, url, headers=None, timeout_s=None):
        if "/key/list" in url:
            return ({"keys": [
                {"key_alias": "kA", "team_id": "t1", "spend": 1.0, "max_budget": 0},
                {"key_alias": "kB", "user_id": "u9", "spend": 2.0, "max_budget": 0},
                {"key_alias": "kC", "team_alias": "Direct", "spend": 3.0, "max_budget": 0},
            ]}, None)
        if "/team/list" in url:
            return ([{"team_id": "t1", "team_alias": "AppSec",
                      "members_with_roles": [{"user_id": "u9"}]}], None)
        if "/user/list" in url:
            return ({"users": [{"user_id": "u9", "teams": [{"team_alias": "AppSec"}]}]}, None)
        return (None, "HTTP 404")
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-master")
    out = await litellm.key_budgets(None)
    assert out["kA"]["team"] == "AppSec"        # team_id UUID -> alias
    assert out["kB"]["team"] == "AppSec"        # no key team -> resolved via user
    assert out["kB"]["user"] == "u9"
    assert out["kC"]["team"] == "Direct"        # explicit key team wins


async def test_key_budgets_walks_all_pages_when_server_caps_page_size(monkeypatch):
    """Regression (the '10 teamed / 6 not' bug): LiteLLM caps /key/list at ~10 per page
    and returns NO total_pages, ignoring our size=100. The walker must keep paging — a
    full small page is not the last page — or every key past page 1 silently loses its
    team/budget and falls back to the team-less spend snapshot."""
    import re
    all_keys = [{"key_alias": f"k{i:02d}", "team_alias": "AppSec", "user_id": f"u{i}",
                 "max_budget": 0, "spend": 0.0} for i in range(16)]

    async def fake_fetch(session, url, headers=None, timeout_s=None):
        if "/key/list" in url:
            m = re.search(r"[?&]page=(\d+)", url)
            p = int(m.group(1)) if m else 1
            return ({"keys": all_keys[(p - 1) * 10:(p - 1) * 10 + 10]}, None)  # cap 10, no totals
        if "/team/list" in url:
            return ({"teams": []}, None)
        if "/user/list" in url:
            return ({"users": []}, None)
        return (None, "HTTP 404")
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-master")
    litellm._KEY_BUDGETS_CACHE = None
    out = await litellm.key_budgets(None)
    assert out is not None and len(out) == 16       # ALL 16 keys, not just page 1's 10
    assert all(v["team"] == "AppSec" for v in out.values())


async def test_key_budgets_partial_walk_keeps_last_good(monkeypatch):
    """Regression ('top spenders sometimes disappear'): when a LATER /key/list page
    times out mid-walk, the partial page-1 set must NOT shrink the board or poison the
    cache — the fuller last-good result is reused instead."""
    import re
    state = {"fail_page2": False}
    full = [{"key_alias": f"k{i:02d}", "team_alias": "T", "user_id": f"u{i}",
             "max_budget": 0, "spend": float(i)} for i in range(16)]

    async def fake_fetch(session, url, headers=None, timeout_s=None):
        if "/key/list" in url:
            m = re.search(r"[?&]page=(\d+)", url)
            p = int(m.group(1)) if m else 1
            if p == 2 and state["fail_page2"]:
                return (None, "Timeout")               # a later page fails mid-walk
            return ({"keys": full[(p - 1) * 10:(p - 1) * 10 + 10]}, None)  # cap 10, no totals
        if "/team/list" in url:
            return ({"teams": []}, None)
        if "/user/list" in url:
            return ({"users": []}, None)
        return (None, "HTTP 404")
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    litellm._KEY_BUDGETS_CACHE = None
    assert len(await litellm.key_budgets(None)) == 16      # healthy walk primes the cache
    state["fail_page2"] = True
    out2 = await litellm.key_budgets(None)
    assert len(out2) == 16                                 # NOT 10 — reused last-good set
    assert len(litellm._KEY_BUDGETS_CACHE) == 16           # cache not poisoned by the partial
    litellm._KEY_BUDGETS_CACHE = None


def test_is_team_id_recognizes_uuids():
    assert litellm._is_team_id("8b1f7f4a-1ee7-412a-bf89-c7a0f7010532")
    assert not litellm._is_team_id("AppSec")
    assert not litellm._is_team_id("Celfocus-general")
    assert not litellm._is_team_id("") and not litellm._is_team_id(None)


def test_email_pick_helpers():
    assert litellm._email_like("bruno.ribeiro@example.com")
    assert not litellm._email_like("bruno") and not litellm._email_like("")
    assert not litellm._email_like("8b1f7f4a-1ee7-412a-bf89-c7a0f7010532")
    assert litellm._pick_email("", "not-an-email", "x@y.io") == "x@y.io"
    assert litellm._pick_email("nope", "also-nope") == ""


async def test_keys_diag_locates_email_field_redacted(monkeypatch):
    """keys_diag reports WHICH /key/list + /user/list fields hold an email, values
    redacted — used to locate the email field when it doesn't show on the board."""
    async def fake_fetch(session, url, headers=None, timeout_s=None):
        if "/key/list" in url:
            return ({"keys": [
                {"key_alias": "kA", "user_id": "u1", "created_by": "alice.a@example.com"},
                {"key_alias": "kB", "user_id": "u2", "user_email": "bob.b@example.com"}]}, None)
        if "/user/list" in url:
            return ({"users": [{"user_id": "u1", "user_email": "alice.a@example.com"}]}, None)
        return (None, "HTTP 404")
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    d = await litellm.keys_diag(None)
    assert d["available"] is True
    assert "created_by" in d["key_list"]["email_fields_found"]
    assert "user_email" in d["key_list"]["email_fields_found"]
    assert "user_email" in d["user_list"]["email_fields_found"]
    samp = list(d["key_list"]["per_row"][0]["email_samples"].values())[0]
    assert "…@example.com" in samp and "alice.a@" not in samp    # redacted local-part


async def test_key_budgets_reads_user_email_from_key_row(monkeypatch):
    """LiteLLM carries the user's email on the key row (the 'User'/'Created By' columns),
    so the board's identity picks it up even when /user/list returns no email."""
    litellm._TEAM_DIR_CACHE = ({}, {}, {})

    async def fake_fetch(session, url, headers=None, timeout_s=None):
        if "/key/list" in url:
            return ({"keys": [
                {"key_alias": "brlribeiro",
                 "user_id": "64938f26-1b87-4405-93a9-f368672756ed",
                 "created_by": "bruno.ribeiro@example.com", "spend": 1.0, "max_budget": 0},
                {"key_alias": "svc", "user_id": "u2",
                 "user_email": "pedro.tarrinho@example.com", "spend": 0, "max_budget": 0},
            ]}, None)
        if "/team/list" in url:
            return ({"teams": []}, None)
        if "/user/list" in url:
            return ({"users": []}, None)          # NO email from /user/list
        return (None, "HTTP 404")
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    litellm._KEY_BUDGETS_CACHE = None
    out = await litellm.key_budgets(None)
    assert out["brlribeiro"]["user_name"] == "bruno.ribeiro@example.com"   # from created_by
    assert out["svc"]["user_name"] == "pedro.tarrinho@example.com"         # from user_email
    litellm._TEAM_DIR_CACHE = ({}, {}, {})


async def test_key_budgets_never_surfaces_raw_team_id(monkeypatch):
    """When /team/list can't resolve a key's team_id to an alias, the team is BLANK —
    never the raw UUID (which would render as a 'strange number' on the board)."""
    litellm._TEAM_DIR_CACHE = ({}, {}, {})            # no cached aliases

    async def fake_fetch(session, url, headers=None, timeout_s=None):
        if "/key/list" in url:
            return ({"keys": [{"key_alias": "kX",
                               "team_id": "8b1f7f4a-1ee7-412a-bf89-c7a0f7010532",
                               "spend": 1.0, "max_budget": 0}]}, None)
        if "/team/list" in url:
            return ({"teams": []}, None)          # no alias resolves
        if "/user/list" in url:
            return ({"users": []}, None)
        return (None, "HTTP 404")
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    litellm._KEY_BUDGETS_CACHE = None
    out = await litellm.key_budgets(None)
    assert out["kX"]["team"] == ""                # BLANK, not the UUID
    litellm._TEAM_DIR_CACHE = ({}, {}, {})


async def test_team_directory_reuses_cache_when_team_list_fails(monkeypatch):
    """A transient /team/list failure reuses the last-good alias map instead of emptying
    it (which would make every team resolve to a UUID)."""
    litellm._TEAM_DIR_CACHE = ({"t1": "AppSec"}, {"u9": "AppSec"}, {})

    async def fake_fetch(session, url, headers=None, timeout_s=None):
        return (None, "Timeout")                  # /team/list AND /user/list fail
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    by_id, by_user, _names = await litellm._team_directory(None, "http://litellm:4000")
    assert by_id.get("t1") == "AppSec" and by_user.get("u9") == "AppSec"
    litellm._TEAM_DIR_CACHE = ({}, {}, {})


def test_merge_team_ignores_raw_team_id():
    """The sticky detection cache must never store a raw team_id as the team name."""
    appmod._TEAMS_DETECT_CACHE.pop("kZ", None)
    appmod._merge_team("kZ", "8b1f7f4a-1ee7-412a-bf89-c7a0f7010532", "u1", 0.0, 5.0)
    assert appmod._TEAMS_DETECT_CACHE["kZ"]["detected"] == ""      # UUID rejected
    appmod._merge_team("kZ", "AppSec", "u1", 0.0, 5.0)
    assert appmod._TEAMS_DETECT_CACHE["kZ"]["detected"] == "AppSec"  # real alias kept
    appmod._TEAMS_DETECT_CACHE.pop("kZ", None)


# ---------------------------------------------- teams: username resolution ----
async def test_team_directory_resolves_user_name(monkeypatch):
    """`_team_directory` maps user_id → a human name (user_email preferred, then
    user_alias) so the Teams board can group by user instead of raw UUIDs."""
    litellm._TEAM_DIR_CACHE = ({}, {}, {})

    async def fake_fetch(session, url, headers=None, timeout_s=None):
        if "/team/list" in url:
            return ({"teams": [{"team_id": "t1", "team_alias": "AppSec"}]}, None)
        if "/user/list" in url:
            return ({"users": [{"user_id": "u1", "user_email": "ric@example.com"},
                               {"user_id": "u2", "user_alias": "mariana"},
                               {"user_id": "u3"}]}, None)   # u3 has no name
        return (None, "HTTP 404")
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    _by_id, _by_user, by_name = await litellm._team_directory(None, "http://litellm:4000")
    assert by_name.get("u1") == "ric@example.com"      # email preferred
    assert by_name.get("u2") == "mariana"               # alias fallback
    assert "u3" not in by_name                           # no name → not mapped
    litellm._TEAM_DIR_CACHE = ({}, {}, {})


async def test_key_budgets_attaches_resolved_user_name(monkeypatch):
    """Each key from /key/list carries a resolved `user_name` (via the directory), so
    the board groups keys under their user's email/alias, not the user_id UUID."""
    litellm._TEAM_DIR_CACHE = ({}, {}, {})
    litellm._KEY_BUDGETS_CACHE = None

    async def fake_fetch(session, url, headers=None, timeout_s=None):
        if "/key/list" in url:
            return ({"keys": [{"key_alias": "kA", "user_id": "u1", "team_id": "t1",
                               "spend": 3.0, "max_budget": 0}]}, None)
        if "/team/list" in url:
            return ({"teams": [{"team_id": "t1", "team_alias": "AppSec"}]}, None)
        if "/user/list" in url:
            return ({"users": [{"user_id": "u1", "user_email": "ric@example.com"}]}, None)
        return (None, "HTTP 404")
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    out = await litellm.key_budgets(None)
    assert out["kA"]["user_name"] == "ric@example.com"
    assert out["kA"]["team"] == "AppSec" and out["kA"]["user"] == "u1"
    litellm._TEAM_DIR_CACHE = ({}, {}, {})


def test_team_detect_persists_user_name_roundtrip(tmp_path, monkeypatch):
    """db.team_detect_set/all round-trips the resolved username so the user-grouped
    board survives a restart without a LiteLLM re-poll."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "td.db"))
    db.init()
    assert db.team_detect_set("kA", "AppSec", "u1", "ric@example.com", 200.0, 3.0, 1_700_000_000.0)
    row = db.team_detect_all()["kA"]
    assert row["detected"] == "AppSec" and row["user"] == "u1"
    assert row["user_name"] == "ric@example.com" and row["budget"] == 200.0


async def test_teams_board_returns_user_name_and_sync(tmp_path, monkeypatch):
    """The admin Teams API returns `user_name` per key (for grouping), and the per-key
    /api/admin/teams/sync endpoint re-detects one key and echoes its resolved row."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "board.db"))  # isolate DB state
    db.init()
    async def kb(session):
        return {"kA": {"team": "AppSec", "user": "u1", "user_name": "ric@example.com",
                       "budget": 0.0, "spend": 3.0}}
    monkeypatch.setattr(litellm, "key_budgets", kb)
    monkeypatch.setattr(appmod, "_TEAMS_DETECT_CACHE", {}, raising=False)
    monkeypatch.setattr(appmod, "_TEAMS_LOADED", False, raising=False)
    # setitem (not setattr) so the running collector's other backends stay intact
    monkeypatch.setitem(appmod._backend_latest, "litellm", {"top_keys": []})
    c, csrf = await _admin_client(monkeypatch, user="ugadm", pw="ugadmpw1")
    try:
        rows = (await (await c.get("/api/admin/teams?refresh=1")).json())["keys"]
        row = next(k for k in rows if k["key"] == "kA")
        assert row["user_name"] == "ric@example.com" and row["team"] == "AppSec"
        r = await c.post("/api/admin/teams/sync", data={"key": "kA"},
                         headers={"X-CSRF-Token": csrf})
        j = await r.json()
        assert r.status == 200 and j["ok"] and j["user_name"] == "ric@example.com"
        # sync without CSRF is rejected
        r2 = await c.post("/api/admin/teams/sync", data={"key": "kA"})
        assert r2.status == 403
    finally:
        await c.close()


async def test_key_user_override_reassigns_and_regroups(tmp_path, monkeypatch):
    """The Teams key popup sets a per-key user/email override: it wins for display
    (user_name) AND grouping (user_grp), and reset clears it. Admin + CSRF."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "ku.db"))
    db.init()
    async def kb(session):
        return {"kA": {"team": "AppSec", "user": "u1", "user_name": "old@example.com",
                       "budget": 0.0, "spend": 3.0}}
    monkeypatch.setattr(litellm, "key_budgets", kb)
    monkeypatch.setattr(appmod, "_TEAMS_DETECT_CACHE", {}, raising=False)
    monkeypatch.setattr(appmod, "_TEAMS_LOADED", False, raising=False)
    monkeypatch.setitem(appmod._backend_latest, "litellm", {"top_keys": []})
    c, csrf = await _admin_client(monkeypatch, user="kuadm", pw="kuadmpw1")
    try:
        r = await c.post("/api/admin/key-user",
                         data={"key": "kA", "user": "new@example.com"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200 and (await r.json())["overridden"] is True
        assert db.key_user_overrides().get("kA") == "new@example.com"
        row = next(k for k in (await (await c.get("/api/admin/teams")).json())["keys"]
                   if k["key"] == "kA")
        assert row["user_name"] == "new@example.com"        # override wins for display
        assert row["user_grp"] == "new@example.com"         # ...and regroups the key
        assert row["user_overridden"] is True
        # reset → back to LiteLLM-detected user
        r = await c.post("/api/admin/key-user", data={"action": "reset", "key": "kA"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200 and "kA" not in db.key_user_overrides()
        # CSRF required
        assert (await c.post("/api/admin/key-user",
                             data={"key": "kA", "user": "x@example.com"})).status == 403
    finally:
        await c.close()


async def test_key_user_reassign_only_existing_users(tmp_path, monkeypatch):
    """A key can only be reassigned to an EXISTING user — an email LiteLLM never reported
    is rejected (400); a known one is accepted (200)."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "kuv.db"))
    db.init()
    # known-users set = the emails LiteLLM reported (the detection cache)
    monkeypatch.setattr(appmod, "_TEAMS_DETECT_CACHE",
                        {"kA": {"detected": "AppSec", "user": "u1",
                                "user_name": "ricardo.morim@example.com",
                                "budget": 0.0, "spent": 0.0}}, raising=False)
    c, csrf = await _admin_client(monkeypatch, user="kuvadm", pw="kuvadmp1")
    try:
        # a made-up user → rejected
        r = await c.post("/api/admin/key-user",
                         data={"key": "kA", "user": "stranger@example.com"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 400 and "existing user" in (await r.json())["error"]
        assert "kA" not in db.key_user_overrides()
        # an existing user → accepted
        r = await c.post("/api/admin/key-user",
                         data={"key": "kA", "user": "ricardo.morim@example.com"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200 and (await r.json())["overridden"] is True
        assert db.key_user_overrides().get("kA") == "ricardo.morim@example.com"
    finally:
        await c.close()


async def test_ui_layout_persists_card_grid(tmp_path, monkeypatch):
    """The free-form Settings board layout (per-card {x,y,w,h}) is persisted server-side
    (DB) via /api/admin/ui-layout: GET returns the grid, POST saves + clamps it, unknown
    names + non-JSON are rejected, and CSRF is required."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "lay.db"))
    db.init()
    c, csrf = await _admin_client(monkeypatch, user="layadm", pw="layadmpw1")
    try:
        assert (await (await c.get("/api/admin/ui-layout?name=settings_cards")).json())["grid"] == {}
        r = await c.post("/api/admin/ui-layout",
                         data={"name": "settings_cards",
                               "grid": '{"g:LiteLLM":{"x":1,"y":1,"w":4,"h":8},'
                                       '"l:teams":{"x":5,"y":1,"w":8,"h":14}}'},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200
        grid = (await (await c.get("/api/admin/ui-layout?name=settings_cards")).json())["grid"]
        assert grid["g:LiteLLM"] == {"x": 1, "y": 1, "w": 4, "h": 8}
        assert grid["l:teams"]["x"] == 5 and grid["l:teams"]["w"] == 8
        assert db.ui_layout_get("settings_cards")["grid"]["g:LiteLLM"]["h"] == 8
        # x+w clamped to the 12-col grid (x=10, w=8 → w=3)
        r2 = await c.post("/api/admin/ui-layout",
                          data={"name": "settings_cards", "grid": '{"k":{"x":10,"y":1,"w":8,"h":4}}'},
                          headers={"X-CSRF-Token": csrf})
        assert (await r2.json())["grid"]["k"]["w"] == 3
        # unknown layout name + bad payload rejected; no CSRF rejected
        assert (await c.get("/api/admin/ui-layout?name=nope")).status == 400
        assert (await c.post("/api/admin/ui-layout",
                             data={"name": "settings_cards", "grid": "notjson"},
                             headers={"X-CSRF-Token": csrf})).status == 400
        assert (await c.post("/api/admin/ui-layout",
                             data={"name": "settings_cards", "grid": "{}"})).status == 403
    finally:
        await c.close()


# ---------------------------------------------- spend: estimated cost split ---
def test_cost_rates_prices_real_and_reference_separately():
    """cost_rates returns per-token $ for REAL (external) and REFERENCE (self-hosted)
    models separately, from windowed per-model tokens × LiteLLM prices."""
    per_model = [{"model": "azure_ai/gpt-5-mini", "tokens": 1_000_000, "cost_kind": "real"},
                 {"model": "llama-cpp/Qwen3", "tokens": 1_000_000, "cost_kind": "reference"},
                 {"model": "(unattributed)", "tokens": 0, "cost_kind": "unknown"}]
    prices = {"azure_ai/gpt-5-mini": 2e-06, "llama-cpp/Qwen3": 1e-05}
    real_cpt, ref_cpt = appmod.cost_rates(per_model, prices)
    # real cost = 1M×2e-6 = $2 over 2M total tokens → $1e-6/token; ref = 1M×1e-5/2M = 5e-6
    assert round(real_cpt, 9) == 1e-06 and round(ref_cpt, 9) == 5e-06
    assert appmod.cost_rates([], prices) == (0.0, 0.0)      # nothing priced


def test_add_estimated_cost_splits_and_totals():
    """add_estimated_cost attaches real_cost/est_cost per point + year and totals, and
    flags cost_available only when a rate exists."""
    series = {"points": [{"tokens": 1_000_000}, {"tokens": 2_000_000}],
              "years": [{"tokens": 3_000_000}]}
    out = appmod.add_estimated_cost(series, 1e-06, 5e-06)
    assert out["cost_available"] is True
    assert out["points"][0]["real_cost"] == 1.0 and out["points"][0]["est_cost"] == 5.0
    assert out["real_cost_total"] == 3.0 and out["est_cost_total"] == 15.0
    # no rate → not available
    assert appmod.add_estimated_cost({"points": [{"tokens": 5}], "years": []},
                                     0.0, 0.0)["cost_available"] is False


async def test_model_prices_parses_model_info(monkeypatch):
    """litellm.model_prices reads input+output cost per token from /model/info, AVERAGES
    them (not sum — the anti-double-count fix), and only keeps models with a non-zero price."""
    async def fake_fetch(session, url, headers=None, timeout_s=None):
        return ({"data": [
            {"model_name": "azure_ai/gpt-5-mini",
             "litellm_params": {"input_cost_per_token": 1e-06, "output_cost_per_token": 1.25e-06}},
            {"model_name": "free-local", "litellm_params": {}},
        ]}, None)
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    pr = await litellm.model_prices(None)
    assert round(pr["azure_ai/gpt-5-mini"], 12) == 1.125e-06   # (in + out) / 2
    assert "free-local" not in pr                             # 0-priced dropped
    assert litellm.price_for("gpt-5-mini", pr) == pr["azure_ai/gpt-5-mini"]   # prefix-tolerant


async def test_model_prices_reuses_last_good_when_endpoint_blips(monkeypatch):
    """/model/info blips empty/errors intermittently on a busy proxy. model_prices must
    reuse the last-good prices so estimated cost stays > 0 — otherwise the Spend
    'Cost over time' card flickers off (cost_available flips false). Regression."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")

    async def good(session, url, headers=None, timeout_s=None):
        return ({"data": [{"model_name": "azure_ai/gpt-5-mini",
                           "litellm_params": {"input_cost_per_token": 1e-06,
                                              "output_cost_per_token": 1.25e-06}}]}, None)
    monkeypatch.setattr(litellm, "fetch_json", good)
    warm = await litellm.model_prices(None)
    assert warm.get("azure_ai/gpt-5-mini")                    # priced, cached

    # 1) transient ERROR → last-good, not empty
    async def erred(session, url, headers=None, timeout_s=None):
        return (None, "timeout")
    monkeypatch.setattr(litellm, "fetch_json", erred)
    assert await litellm.model_prices(None) == warm

    # 2) endpoint answers but prices NOTHING (mid-reload) → still last-good
    async def empty(session, url, headers=None, timeout_s=None):
        return ({"data": []}, None)
    monkeypatch.setattr(litellm, "fetch_json", empty)
    assert await litellm.model_prices(None) == warm


async def test_paginate_stops_when_endpoint_ignores_page(monkeypatch):
    """_paginate must not loop when an endpoint ignores page= and returns the same rows
    every time — it de-dupes by id and stops as soon as a page adds nothing new."""
    calls = {"n": 0}

    async def fake_fetch(session, url, headers=None, timeout_s=None):
        calls["n"] += 1
        return ({"users": [{"user_id": "a"}, {"user_id": "b"}]}, None)  # same, no totals
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    out = await litellm._paginate(None, "http://x/user/list", ("users", "data"),
                                  "user_id", 5.0)
    assert len(out) == 2 and calls["n"] <= 3        # deduped, did not walk 50 pages


async def test_paginate_uses_page_size_the_server_accepts(monkeypatch):
    """Regression: LiteLLM's /user/list returns HTTP 422 for page_size=500 — _paginate
    must request a size the server accepts (100), or the user→email map came back empty
    and no emails showed on the Teams board."""
    seen = []

    async def fake_fetch(session, url, headers=None, timeout_s=None):
        seen.append(url)
        return ({"users": [{"user_id": "u1", "user_email": "a@example.com"}],
                 "total_pages": 1}, None)
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    out = await litellm._paginate(None, "http://x/user/list", ("users", "data"),
                                  "user_id", 5.0)
    assert out and out[0]["user_email"] == "a@example.com"
    assert all("size=500" not in u for u in seen)        # never the 422-triggering size
    assert any("page_size=100" in u for u in seen)


async def test_paginate_walks_via_total_pages(monkeypatch):
    """_paginate follows the server's total_pages across all pages and stops at the last."""
    import re
    pages = {1: {"users": [{"user_id": "a"}, {"user_id": "b"}], "total_pages": 2},
             2: {"users": [{"user_id": "c"}], "total_pages": 2}}

    async def fake_fetch(session, url, headers=None, timeout_s=None):
        m = re.search(r"[?&]page=(\d+)", url)
        p = int(m.group(1)) if m else 1
        return (pages.get(p, {"users": []}), None)
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    out = await litellm._paginate(None, "http://x/user/list", ("users", "data"),
                                  "user_id", 5.0)
    assert [u["user_id"] for u in out] == ["a", "b", "c"]


async def test_master_token_blocked_from_admin(monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "master-tok-123")
    c = await _client()
    try:
        # the shared URL token is NOT admin: admin pages/APIs (Settings, Users) are
        # blocked for it — those need an interactive login or a scoped admin PAT.
        assert (await c.get("/api/admin/users?token=master-tok-123")).status == 403
        assert (await c.get("/settings?token=master-tok-123")).status == 403
    finally:
        await c.close()


async def test_admin_sidebar_link_role_gated(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("adm2", "a2@x.io", auth.hash_password("adm2pw12"), "admin", time.time())
    db.user_create("vw2", "v2@x.io", auth.hash_password("vw2pw123"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "adm2", "password": "adm2pw12"})
        h = await (await c.get("/")).text()
        assert "/admin/users" in h and "Logout" in h        # admin sees Users link
    finally:
        await c.close()
    c2 = await _client()
    try:
        await c2.post("/login", data={"username": "vw2", "password": "vw2pw123"})
        h2 = await (await c2.get("/")).text()
        assert "/admin/users" not in h2 and "Logout" in h2  # viewer: logout only
    finally:
        await c2.close()


# ── audit trail (1.2.0) ───────────────────────────────────────────────────────
def test_audit_db_roundtrip():
    db.audit_add(time.time(), "admin", "user.create", target="bob", ip="1.2.3.4", detail="viewer")
    db.audit_add(time.time(), "alice", "login.ok", ip="5.6.7.8")
    rows = db.audit_list(50)
    assert len(rows) == 2 and rows[0]["action"] == "login.ok"      # newest first
    assert [r["action"] for r in db.audit_list(50, "user")] == ["user.create"]
    assert db.audit_prune(time.time() + 1) == 2 and db.audit_list(50) == []


async def test_audit_records_login_success_and_failure(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("eve", "e@x.io", auth.hash_password("evepw1234"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "eve", "password": "wrong"})
        await c.post("/login", data={"username": "eve", "password": "evepw1234"})
    finally:
        await c.close()
    acts = [r["action"] for r in db.audit_list(50)]
    assert "login.ok" in acts and "login.fail" in acts
    ok = next(r for r in db.audit_list(50) if r["action"] == "login.ok")
    assert ok["actor"] == "eve" and ok["ip"]


async def test_audit_records_user_management_and_admin_can_view(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("boss", "b@x.io", auth.hash_password("bosspw123"), "admin", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "boss", "password": "bosspw123"})
        csrf = (await (await c.get("/api/admin/users")).json())["csrf"]
        await c.post("/api/admin/users",
                     data={"username": "newbie", "email": "n@x.io",
                           "password": "newbiepw1", "role": "viewer"},
                     headers={"X-CSRF-Token": csrf})
        await c.post("/api/admin/users/action",
                     data={"username": "newbie", "action": "disable"},
                     headers={"X-CSRF-Token": csrf})
        d = await (await c.get("/api/admin/audit")).json()
        actions = [(e["action"], e["target"], e["actor"]) for e in d["events"]]
        assert ("user.create", "newbie", "boss") in actions
        assert ("user.disable", "newbie", "boss") in actions
        # prefix filter
        d2 = await (await c.get("/api/admin/audit?action=user")).json()
        assert all(e["action"].startswith("user.") for e in d2["events"])
    finally:
        await c.close()


async def test_audit_endpoint_is_admin_only(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("peon", "p@x.io", auth.hash_password("peonpw123"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "peon", "password": "peonpw123"})
        assert (await c.get("/api/admin/audit")).status == 403
    finally:
        await c.close()


# ── multi-user + audit: edge cases (QA hardening) ─────────────────────────────
def test_session_expiry_invalidates(monkeypatch):
    sid, _csrf = auth.session_new("u1", "viewer")
    assert auth.session_get(sid) is not None
    auth._sessions[sid]["expiry"] = 0.0          # force-expire
    assert auth.session_get(sid) is None
    assert sid not in auth._sessions             # expired session dropped


def test_sessions_drop_user_and_count():
    auth.session_new("multi", "viewer")
    auth.session_new("multi", "viewer")
    auth.session_new("other", "viewer")
    n = auth.sessions_drop_user("multi")
    assert n == 2
    assert all(v["user"] != "multi" for v in auth._sessions.values())


def test_valid_username_and_email_bounds():
    assert auth.valid_username("a") and auth.valid_username("A-b_.9")
    assert not auth.valid_username("x" * 33)        # >32
    assert not auth.valid_username("has space") and not auth.valid_username("bad/slash")
    assert not auth.valid_username("")
    assert auth.valid_email("a.b+c@sub.example.co")
    assert not auth.valid_email("no-at") and not auth.valid_email("a@b") and not auth.valid_email("")


def test_bootstrap_admin_rejects_weak_or_missing(monkeypatch):
    monkeypatch.setattr(config, "ADMIN_USER", "root")
    monkeypatch.setattr(config, "ADMIN_PASSWORD", "short")     # < 8 chars
    monkeypatch.setattr(config, "ADMIN_EMAIL", "r@x.io")
    assert auth.bootstrap_admin() is None and db.user_count() == 0
    monkeypatch.setattr(config, "ADMIN_PASSWORD", "")           # missing
    assert auth.bootstrap_admin() is None
    monkeypatch.setattr(config, "ADMIN_PASSWORD", "goodpassword")
    monkeypatch.setattr(config, "ADMIN_EMAIL", "not-an-email")  # bad email
    assert auth.bootstrap_admin() is None and db.user_count() == 0


async def test_login_cookie_is_httponly(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("hh", "h@x.io", auth.hash_password("hhpw1234"), "viewer", time.time())
    c = await _client()
    try:
        r = await c.post("/login", data={"username": "hh", "password": "hhpw1234"},
                         allow_redirects=False)
        sc = r.headers.get("Set-Cookie", "")
        assert "aimon_user=" in sc and "HttpOnly" in sc and "SameSite=Strict" in sc
    finally:
        await c.close()


async def test_login_next_is_open_redirect_safe(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("nn", "n@x.io", auth.hash_password("nnpw1234"), "viewer", time.time())
    c = await _client()
    try:
        # a local next is honoured
        r = await c.post("/login", data={"username": "nn", "password": "nnpw1234", "next": "/gpu"},
                         allow_redirects=False)
        assert r.headers.get("Location") == "/gpu"
    finally:
        await c.close()
    c2 = await _client()
    try:
        # an off-site next is rejected -> home
        r = await c2.post("/login", data={"username": "nn", "password": "nnpw1234",
                                          "next": "//evil.example"}, allow_redirects=False)
        assert r.headers.get("Location") == "/"
    finally:
        await c2.close()


async def test_logout_invalidates_session(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("lo", "l@x.io", auth.hash_password("lopw1234"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "lo", "password": "lopw1234"})
        assert (await c.get("/gpu")).status == 200
        await c.get("/logout")
        r = await c.get("/gpu", allow_redirects=False)
        assert r.status == 302 and "/login" in r.headers.get("Location", "")
    finally:
        await c.close()


async def test_password_reset_forces_relogin(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("adm", "adm@x.io", auth.hash_password("admpw1234"), "admin", time.time())
    db.user_create("usr", "usr@x.io", auth.hash_password("oldpw1234"), "viewer", time.time())
    admin = await _client()
    victim = await _client()
    try:
        await admin.post("/login", data={"username": "adm", "password": "admpw1234"})
        await victim.post("/login", data={"username": "usr", "password": "oldpw1234"})
        assert (await victim.get("/gpu")).status == 200
        csrf = (await (await admin.get("/api/admin/users")).json())["csrf"]
        r = await admin.post("/api/admin/users/action",
                             data={"username": "usr", "action": "reset", "password": "newpw5678"},
                             headers={"X-CSRF-Token": csrf})
        assert r.status == 200
        # old session no longer valid
        rr = await victim.get("/gpu", allow_redirects=False)
        assert rr.status == 302
        # old password no longer works, new one does
        assert not auth.verify_password("oldpw1234", db.user_get("usr")["pw_hash"])
        assert auth.verify_password("newpw5678", db.user_get("usr")["pw_hash"])
    finally:
        await admin.close()
        await victim.close()


async def test_disable_then_enable_restores_access(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("adm", "adm@x.io", auth.hash_password("admpw1234"), "admin", time.time())
    db.user_create("flip", "f@x.io", auth.hash_password("flippw12"), "viewer", time.time())
    admin = await _client()
    try:
        await admin.post("/login", data={"username": "adm", "password": "admpw1234"})
        csrf = (await (await admin.get("/api/admin/users")).json())["csrf"]
        for action, expect in (("disable", False), ("enable", True)):
            r = await admin.post("/api/admin/users/action",
                                 data={"username": "flip", "action": action},
                                 headers={"X-CSRF-Token": csrf})
            assert r.status == 200
            v = await _client()
            try:
                lr = await v.post("/login", data={"username": "flip", "password": "flippw12"},
                                  allow_redirects=False)
                ok = "aimon_user=" in lr.headers.get("Set-Cookie", "")
                assert ok is expect
            finally:
                await v.close()
    finally:
        await admin.close()


async def test_disable_last_admin_rejected(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("only", "o@x.io", auth.hash_password("onlypw12"), "admin", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "only", "password": "onlypw12"})
        csrf = (await (await c.get("/api/admin/users")).json())["csrf"]
        r = await c.post("/api/admin/users/action",
                         data={"username": "only", "action": "disable"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 400          # can't disable the last admin
    finally:
        await c.close()


async def test_create_rejects_bad_role_and_dup_and_weak_pw(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("adm", "adm@x.io", auth.hash_password("admpw1234"), "admin", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "adm", "password": "admpw1234"})
        csrf = (await (await c.get("/api/admin/users")).json())["csrf"]
        base = {"email": "z@x.io", "password": "goodpw123"}
        h = {"X-CSRF-Token": csrf}
        assert (await c.post("/api/admin/users", data={**base, "username": "z", "role": "root"}, headers=h)).status == 400
        assert (await c.post("/api/admin/users", data={"username": "z2", "email": "z@x.io", "password": "sh", "role": "viewer"}, headers=h)).status == 400
        assert (await c.post("/api/admin/users", data={**base, "username": "adm", "role": "viewer"}, headers=h)).status == 409  # dup
    finally:
        await c.close()


async def test_admin_pat_write_is_csrf_exempt(monkeypatch):
    """Admin writes over Bearer auth are CSRF-exempt (not a browser cookie). The
    master token is now blocked from admin, so this uses a scoped admin PAT — the
    supported way to script admin actions — which stays allowed + CSRF-exempt."""
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("patadm", "pa@x.io", auth.hash_password("patadmpw1"), "admin", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "patadm", "password": "patadmpw1"})
        csrf = (await (await c.get("/api/me")).json())["csrf"]
        j = await (await c.post("/api/account/tokens",
                                data={"label": "adm", "role": "admin"},
                                headers={"X-CSRF-Token": csrf})).json()
        tok = j["token"]
    finally:
        await c.close()
    c2 = await _client()
    try:
        # Bearer admin PAT → no CSRF token needed, admin write succeeds
        r = await c2.post("/api/admin/users",
                          headers={"Authorization": "Bearer " + tok},
                          data={"username": "viaTok", "email": "t@x.io",
                                "password": "tokpw1234", "role": "viewer"})
        assert r.status == 200 and db.user_get("viaTok") is not None
    finally:
        await c2.close()


async def test_audit_logs_logout_and_reset_and_lockout(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    monkeypatch.setattr(config, "AUTH_MAX_FAILS", 2)
    db.user_create("adm", "adm@x.io", auth.hash_password("admpw1234"), "admin", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "adm", "password": "admpw1234"})
        await c.get("/logout")
    finally:
        await c.close()
    # trigger a lockout from a fresh client
    c2 = await _client()
    try:
        for _ in range(2):
            await c2.post("/login", data={"username": "adm", "password": "bad"})
    finally:
        await c2.close()
    acts = {r["action"] for r in db.audit_list(200)}
    assert "logout" in acts and "login.lockout" in acts


def test_audit_never_stores_passwords():
    db.audit_add(time.time(), "adm", "user.create", target="x", ip="1.1.1.1", detail="viewer")
    for r in db.audit_list(50):
        assert "pw" not in (r.get("detail") or "").lower()
        assert "scrypt" not in (r.get("detail") or "")


async def test_audit_limit_is_bounded(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("adm", "adm@x.io", auth.hash_password("admpw1234"), "admin", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "adm", "password": "admpw1234"})
        d = await (await c.get("/api/admin/audit?limit=999999")).json()   # over-cap
        assert isinstance(d["events"], list)          # bounded, not an error
        d2 = await (await c.get("/api/admin/audit?limit=notanint")).json()
        assert isinstance(d2["events"], list)          # bad param -> default, no 500
    finally:
        await c.close()


# ============================================================================
# Unit tests — pure collector / alert / anomaly / config logic. No network, no
# app, no DB. Fast, deterministic, one behaviour per test.
# ============================================================================
def test_unit_fnum_parses_tolerantly():
    assert gpu._fnum("72.5") == 72.5
    assert gpu._fnum("[N/A]") is None       # GB10 reports [N/A] for absent metrics
    assert gpu._fnum(None) is None
    assert gpu._fnum("") is None
    assert gpu._fnum(3) == 3.0


def test_unit_parse_nvidia_csv_unified_memory_and_throttle():
    # GB10 unified-memory row: VRAM columns are [N/A] -> None (not 0, not dropped).
    out = ("NVIDIA GB10, 77.7, [N/A], [N/A], 61, 210, 250, Active\n"
           "bad, only, three\n")                     # <5 fields -> skipped
    g = gpu._parse_nvidia_csv(out)
    assert len(g) == 1
    row = g[0]
    assert row["name"] == "NVIDIA GB10"
    assert row["util"] == 77.7 and row["temp"] == 61.0 and row["power"] == 210.0
    assert row["vram_used"] is None and row["vram_total"] is None   # unified memory
    assert row["throttled"] is True                                 # "Active"


def test_unit_parse_nvidia_csv_discrete_vram_mib_to_bytes():
    g = gpu._parse_nvidia_csv("RTX 4090, 40, 1024, 24576, 55, 300, 450, Not Active")
    assert g[0]["vram_used"] == 1024 * gpu._MiB
    assert g[0]["vram_total"] == 24576 * gpu._MiB
    assert g[0]["throttled"] is False


def test_unit_alerts_pct_guards_zero_and_none():
    assert alerts._pct(None, 100) is None
    assert alerts._pct(50, 0) is None          # div-by-zero -> None, never raises
    assert alerts._pct(50, None) is None
    assert alerts._pct(50, 200) == 25.0


def test_unit_alerts_evaluate_fires_host_thresholds(monkeypatch):
    monkeypatch.setattr(config, "ALERT_CPU_PCT", 90)
    monkeypatch.setattr(config, "ALERT_DISK_PCT", 95)
    snap = {"collectors": {"host": {"available": True, "cpu_pct": 96,
                                    "disk": {"pct": 97}}}}
    keys = {k for k, _ in alerts.evaluate(snap)}
    assert "cpu" in keys and "disk" in keys


def test_unit_alerts_backend_down_but_not_unconfigured(monkeypatch):
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_AFTER", 1)  # this test is about WHICH
    alerts.reset_down_streaks()                                # backends alarm, not the streak
    snap = {"collectors": {
        "litellm": {"available": False, "error": "conn refused"},   # real outage
        "ollama":  {"available": False, "error": "unconfigured"},   # never alerts
    }}
    keys = {k for k, _ in alerts.evaluate(snap)}
    assert "down:litellm" in keys
    assert "down:ollama" not in keys           # unconfigured != down


def test_unit_anomaly_spike_on_zero_baseline(monkeypatch):
    monkeypatch.setattr(config, "ANOMALY_FACTOR", 3.0)
    monkeypatch.setattr(config, "ANOMALY_MIN_REQS", 5)
    # baseline 0 with real traffic -> treated as an infinite spike (leaked key).
    res = anomaly.detect({"available": True},
                         {"leaked-key": {"recent": 200.0, "baseline": 0.0}})
    assert any(k == "spike:leaked-key" for k, _ in res)


def test_unit_anomaly_ignores_low_volume(monkeypatch):
    monkeypatch.setattr(config, "ANOMALY_FACTOR", 3.0)
    monkeypatch.setattr(config, "ANOMALY_MIN_REQS", 50)
    # huge ratio but below the min-reqs floor -> not a spike (noise suppression).
    assert anomaly.detect({"available": True},
                          {"k": {"recent": 10.0, "baseline": 0.1}}) == []


def test_unit_anomaly_budget_breach(monkeypatch):
    monkeypatch.setattr(config, "ANOMALY_KEY_BUDGET_HR", 1.0)
    snap = {"available": True, "spend_window_min": 60,
            "top_keys": [{"alias": "spender", "cost": 5.0}]}   # $5/h >= $1/h
    assert any(k == "budget:spender" for k, _ in anomaly.detect(snap, {}))


def test_unit_anomaly_empty_when_backend_unavailable():
    assert anomaly.detect({"available": False},
                          {"k": {"recent": 9e9, "baseline": 0.0}}) == []


def test_unit_redacted_summary_never_leaks_secret_values(monkeypatch):
    # use the gate-whitelisted synthetic key so the publish secret-scan doesn't
    # flag this fixture as a real sk- leak (deploy/publish-github.sh rule 3).
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-supersecretvalue")
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "tok-placeholderval")
    s = config.redacted_summary()
    assert s["litellm_key"] == "set" and s["dashboard_auth"] == "token"
    blob = repr(s)
    assert "supersecret" not in blob and "placeholderval" not in blob


def test_unit_validate_flags_fully_open_dashboard(monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "")
    monkeypatch.setattr(config, "ALLOW_OPEN", False)
    assert any("no auth configured" in e for e in config.validate(user_count=0))
    # a user account counts as configured auth -> no open-auth error
    assert not any("no auth configured" in e
                   for e in config.validate(user_count=1))


# ============================================================================
# Performance guards — CPU-bound hot paths must scale ~linearly and stay under a
# generous ceiling. Assertions are RELATIVE (hardware-independent, survive the
# emulated cross-arch build gate); the absolute caps are loose smoke checks that
# still catch a quadratic regression (which blows past them by orders).
# ============================================================================
def _spend_rows(n, now):
    return [{"startTime": now - 10, "endTime": now - 9,
             "model": f"m{i % 20}", "api_key": f"k{i % 200}",
             "total_tokens": 10, "response_cost": 0.001} for i in range(n)]


def _best(fn, reps=3):
    best = float("inf")
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    return best


def test_perf_parse_spend_scales_subquadratically():
    now = 1_700_000_000.0
    ws = now - 3600
    small = _spend_rows(5_000, now)
    big = _spend_rows(20_000, now)                    # 4x the rows
    t_small = _best(lambda: litellm._parse_spend(small, ws, max_rows=10**9))
    t_big = _best(lambda: litellm._parse_spend(big, ws, max_rows=10**9))
    # linear => ~4x; O(n^2) => ~16x. Fail well before quadratic (8x slack + floor).
    assert t_big < (t_small * 8) + 0.05, \
        f"parse_spend scaling looks super-linear: {t_small:.4f}s -> {t_big:.4f}s"


def test_perf_parse_spend_large_payload_bounded():
    # 50k rows ~ a full busy day of /spend/logs — the freeze scenario. The fix runs
    # this pure aggregation off the event loop; it must stay cheap and correct.
    now = 1_700_000_000.0
    rows = _spend_rows(50_000, now)
    t = _best(lambda: litellm._parse_spend(rows, now - 3600, max_rows=10**9), reps=1)
    assert t < 20.0, f"parse_spend on 50k rows too slow: {t:.2f}s"
    res, kept, total = litellm._parse_spend(rows, now - 3600, max_rows=10**9)
    assert total == 50_000 and kept == 50_000 and res["requests_window"] == 50_000


def test_perf_evaluate_and_detect_stay_cheap(monkeypatch):
    monkeypatch.setattr(config, "ANOMALY_FACTOR", 3.0)
    monkeypatch.setattr(config, "ANOMALY_MIN_REQS", 5)
    monkeypatch.setattr(config, "ALERT_CPU_PCT", 90)
    snap = {"collectors": {"host": {"available": True, "cpu_pct": 50,
                                    "disk": {"pct": 10}}}}
    ll = {"available": True}
    base = {f"key{i}": {"recent": float(i), "baseline": 1.0} for i in range(2_000)}
    t = _best(lambda: (alerts.evaluate(snap), anomaly.detect(ll, base)))
    assert t < 1.0, f"evaluate+detect over 2k keys too slow: {t:.3f}s"


def test_perf_db_series_read_bounded(tmp_path, monkeypatch):
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "perf.db"))
    db.init()
    now = time.time()
    cols = list(db._METRIC_COLS)
    ph = ",".join("?" for _ in ("ts", *cols))
    # 5k raw metric rows, all inside the 1h window (0.5s apart) -> max aggregation.
    rows = [tuple([now - (5_000 - i) * 0.5] + [10.0 + (i % 40)] * len(cols))
            for i in range(5_000)]
    with db._connect() as conn:
        conn.executemany(
            f"INSERT INTO metrics(ts,{','.join(cols)}) VALUES({ph})", rows)
    t = _best(lambda: db.series("1h", max_points=300))
    assert isinstance(db.series("1h", max_points=300), list)
    assert t < 2.0, f"series read over 5k rows too slow: {t:.3f}s"


# ── self-service password change (1.2.1) ──────────────────────────────────────
async def _login_get_csrf(c, user, pw):
    await c.post("/login", data={"username": user, "password": pw})
    return (await (await c.get("/api/me")).json())["csrf"]


async def test_me_endpoint_gives_session_csrf(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("vw", "v@x.io", auth.hash_password("vwpw1234"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "vw", "password": "vwpw1234"})
        d = await (await c.get("/api/me")).json()
        assert d["user"] == "vw" and d["role"] == "viewer" and d["csrf"]
    finally:
        await c.close()


async def test_account_page_requires_login(monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "tk-acc")
    c = await _client()
    try:
        r = await c.get("/account", allow_redirects=False)
        assert r.status == 302 and "/login" in r.headers.get("Location", "")
    finally:
        await c.close()


async def test_change_own_password_requires_current(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("carl", "c@x.io", auth.hash_password("oldpw1234"), "viewer", time.time())
    c = await _client()
    try:
        csrf = await _login_get_csrf(c, "carl", "oldpw1234")
        # wrong current password -> rejected
        r = await c.post("/api/account/password",
                         data={"current": "WRONG", "new": "brandnew99"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 400 and "current password" in (await r.json())["error"]
        # correct current -> changed
        r = await c.post("/api/account/password",
                         data={"current": "oldpw1234", "new": "brandnew99"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200
        u = db.user_get("carl")
        assert auth.verify_password("brandnew99", u["pw_hash"])
        assert not auth.verify_password("oldpw1234", u["pw_hash"])
    finally:
        await c.close()


async def test_change_password_rejects_weak_and_same(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("deb", "d@x.io", auth.hash_password("currentpw1"), "viewer", time.time())
    c = await _client()
    try:
        csrf = await _login_get_csrf(c, "deb", "currentpw1")
        assert (await c.post("/api/account/password",
                data={"current": "currentpw1", "new": "short"},
                headers={"X-CSRF-Token": csrf})).status == 400          # weak
        assert (await c.post("/api/account/password",
                data={"current": "currentpw1", "new": "currentpw1"},
                headers={"X-CSRF-Token": csrf})).status == 400          # unchanged
    finally:
        await c.close()


async def test_change_password_needs_csrf_and_session(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("ede", "e@x.io", auth.hash_password("edepw1234"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "ede", "password": "edepw1234"})
        # no CSRF header -> 403
        r = await c.post("/api/account/password",
                         data={"current": "edepw1234", "new": "newpw5678"})
        assert r.status == 403
    finally:
        await c.close()
    # token-only auth (no session) cannot change an account password
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "tk-acc2")
    c2 = await _client()
    try:
        r = await c2.post("/api/account/password?token=tk-acc2",
                          data={"current": "x", "new": "newpw5678"})
        assert r.status == 401
    finally:
        await c2.close()


async def test_change_password_invalidates_other_sessions(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("fin", "f@x.io", auth.hash_password("finpw1234"), "viewer", time.time())
    dev1 = await _client()
    dev2 = await _client()
    try:
        await dev1.post("/login", data={"username": "fin", "password": "finpw1234"})
        await dev2.post("/login", data={"username": "fin", "password": "finpw1234"})
        assert (await dev2.get("/gpu")).status == 200
        csrf = (await (await dev1.get("/api/me")).json())["csrf"]
        r = await dev1.post("/api/account/password",
                            data={"current": "finpw1234", "new": "finnew5678"},
                            headers={"X-CSRF-Token": csrf})
        assert r.status == 200
        # the OTHER device's session is now invalid; the current one still works
        assert (await dev1.get("/gpu")).status == 200
        r2 = await dev2.get("/gpu", allow_redirects=False)
        assert r2.status == 302
    finally:
        await dev1.close()
        await dev2.close()


async def test_change_password_is_audited(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("gus", "g@x.io", auth.hash_password("guspw1234"), "viewer", time.time())
    c = await _client()
    try:
        csrf = await _login_get_csrf(c, "gus", "guspw1234")
        await c.post("/api/account/password",
                     data={"current": "guspw1234", "new": "gusnew5678"},
                     headers={"X-CSRF-Token": csrf})
    finally:
        await c.close()
    assert "account.password" in {r["action"] for r in db.audit_list(50)}


# ============================================================================
# Security-fix regression — one guard per finding from the code review, so a
# future edit can't silently reopen it. All values are synthetic placeholders.
# ============================================================================
def test_sec_open_redirect_backslash_blocked():
    # `/\evil.com` is normalised by browsers to `//evil.com` (protocol-relative)
    # → off-site redirect. _safe_path must reject backslash, not just `//`.
    import app as a
    assert a._safe_path("/\\evil.com") == "/"
    assert a._safe_path("//evil.com") == "/"
    assert a._safe_path("/dashboard") == "/dashboard"      # legit local path kept


def test_sec_weak_token_rejected_by_validate(monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "short")
    assert any("too short" in e for e in config.validate())
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "a" * 16)   # >=16 ok
    assert not any("too short" in e for e in config.validate())


def test_sec_ssh_prefix_rejects_dash_and_uses_separator(monkeypatch):
    from collectors import gpu
    # a '-'-prefixed host would be parsed by ssh as an option (arg injection)
    monkeypatch.setattr(config, "GPU_SSH", "-oProxyCommand=touch /tmp/x")
    monkeypatch.setattr(config, "GPU_SSH_KEY", "")
    monkeypatch.setattr(config, "GPU_SSH_PORT", 22)
    assert gpu._ssh_prefix() is None
    monkeypatch.setattr(config, "GPU_SSH", "user@gpuhost")
    pre = gpu._ssh_prefix()
    assert pre is not None and pre[-2:] == ["--", "user@gpuhost"]   # '--' guards host


async def test_sec_legacy_token_cookie_is_opaque(monkeypatch):
    # the aimon_session cookie must be an opaque session id, NOT the raw token.
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "longenoughtoken1234")
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    c = await _client()
    try:
        r = await c.get("/?token=longenoughtoken1234", allow_redirects=False)
        assert r.status == 302
        sc = r.headers.get("Set-Cookie", "")
        assert "aimon_session=" in sc
        assert "aimon_session=longenoughtoken1234" not in sc     # raw token NOT stored
        assert (await c.get("/api/data")).status == 200          # opaque cookie auths
    finally:
        await c.close()


async def test_sec_alerts_test_requires_admin(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("vic", "vic@x.io", auth.hash_password("vicpw1234"), "viewer",
                   time.time())
    c = await _client()
    try:
        r = await c.post("/login", data={"username": "vic", "password": "vicpw1234"},
                         allow_redirects=False)
        assert r.status == 302
        assert (await c.post("/api/alerts/test")).status == 403   # viewer forbidden
    finally:
        await c.close()


async def test_sec_fetch_json_caps_oversized_body(monkeypatch):
    import collectors
    monkeypatch.setattr(config, "HTTP_MAX_BYTES", 1024)

    async def big(_request):
        return web.Response(body=b'{"x":"' + b"A" * 5000 + b'"}',
                            content_type="application/json")

    app = web.Application()
    app.router.add_get("/big", big)
    srv = TestServer(app)
    await srv.start_server()
    try:
        async with aiohttp.ClientSession() as s:
            data, err = await collectors.fetch_json(s, str(srv.make_url("/big")))
        assert data is None and err and "too large" in err
    finally:
        await srv.close()


# ── per-user alert webhook (1.2.2) ────────────────────────────────────────────
def test_webhook_db_crud():
    db.user_create("wu", "w@x.io", auth.hash_password("wupw1234"), "viewer", time.time())
    assert db.user_get_webhook("wu") == {"url": "", "enabled": False}
    assert db.user_set_webhook("wu", "https://hooks.example.com/x", True)
    assert db.user_get_webhook("wu") == {"url": "https://hooks.example.com/x", "enabled": True}
    assert [r["user"] for r in db.user_webhooks_enabled()] == ["wu"]
    # disabling the account removes it from the fan-out recipient list
    db.user_set_disabled("wu", True)
    assert db.user_webhooks_enabled() == []


async def test_webhook_ssrf_validation(monkeypatch):
    # No test relies on real DNS (the in-image gate has no network): private targets
    # are IP LITERALS (getaddrinfo returns them verbatim), and the "public passes"
    # cases use ALLOW_PRIVATE + an explicit allow-list, which skips the resolve step.
    monkeypatch.setattr(config, "WEBHOOK_HTTPS_ONLY", False)
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_HOSTS", "")
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_PRIVATE", False)
    for bad in ("http://169.254.169.254/latest/meta", "http://127.0.0.1:9000/x",
                "http://10.1.2.3/hook", "http://[::1]/x", "ftp://host/x", "notaurl"):
        assert await alerts.validate_webhook_url(bad) is not None, bad
    # ALLOW_PRIVATE now skips the resolve ONLY together with an allow-list (T-9 hardening)
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_HOSTS", "hooks.slack.com")
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_PRIVATE", True)   # + allow-list → skip DNS/IP check
    assert await alerts.validate_webhook_url("https://hooks.slack.com/services/x") is None
    monkeypatch.setattr(config, "WEBHOOK_HTTPS_ONLY", True)      # rejects http
    assert await alerts.validate_webhook_url("http://hooks.slack.com/x") is not None
    monkeypatch.setattr(config, "WEBHOOK_HTTPS_ONLY", False)
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_HOSTS", "hooks.slack.com,discord.com")
    assert await alerts.validate_webhook_url("https://evil.example.com/x") is not None
    assert await alerts.validate_webhook_url("https://team.discord.com/x") is None   # subdomain ok


async def test_account_webhook_get_set(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_HOSTS", "hooks.example.test")   # allow-list gates the skip
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_PRIVATE", True)      # + allow-list → allow test host
    db.user_create("wv", "v@x.io", auth.hash_password("wvpw1234"), "viewer", time.time())
    c = await _client()
    try:
        csrf = await _login_get_csrf(c, "wv", "wvpw1234")
        assert (await (await c.get("/api/account/webhook")).json())["url"] == ""
        r = await c.post("/api/account/webhook",
                         data={"url": "https://hooks.example.test/mine", "enabled": "1"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200
        d = await (await c.get("/api/account/webhook")).json()
        assert d["url"] == "https://hooks.example.test/mine" and d["enabled"] is True
    finally:
        await c.close()


async def test_account_webhook_rejects_ssrf_and_needs_csrf(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_PRIVATE", False)
    db.user_create("ws", "s@x.io", auth.hash_password("wspw1234"), "viewer", time.time())
    c = await _client()
    try:
        csrf = await _login_get_csrf(c, "ws", "wspw1234")
        # private/loopback URL is refused
        r = await c.post("/api/account/webhook",
                         data={"url": "http://127.0.0.1:8080/x", "enabled": "1"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 400
        # missing CSRF -> 403
        r = await c.post("/api/account/webhook",
                         data={"url": "https://hooks.slack.com/x", "enabled": "1"})
        assert r.status == 403
    finally:
        await c.close()


async def test_notifier_fans_out_to_user_webhooks(monkeypatch):
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_HOSTS", "hooks.example.test")   # allow-list gates the skip
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_PRIVATE", True)
    monkeypatch.setattr(config, "ALERT_CPU_PCT", 50.0)
    monkeypatch.setattr(config, "ALERT_REPEAT_MIN", 9999)
    db.user_create("wf", "f@x.io", auth.hash_password("wfpw1234"), "viewer", time.time())
    db.user_set_webhook("wf", "https://hooks.example.test/mine", True)
    posted = []

    async def fake_post(self, session, url, payload, akey=""):
        posted.append(url)
    monkeypatch.setattr(alerts.Notifier, "_post_json", fake_post)
    n = alerts.Notifier()
    hot = {"ts": 0, "collectors": {"host": {"available": True, "cpu_pct": 90,
                                            "mem_pct": 1, "disk": {"pct": 1}}}}
    async with aiohttp.ClientSession() as s:
        await n.process(s, hot, 1000)
    assert "https://hooks.example.test/mine" in posted
    # a disabled webhook is not a recipient
    db.user_set_webhook("wf", "https://hooks.example.test/mine", False)
    assert "https://hooks.example.test/mine" not in await alerts.Notifier()._recipients()


def test_webhook_payload_teams_url_gets_adaptive_card(monkeypatch):
    """MS Teams (Power Automate / O365) URLs auto-get the Adaptive-Card message envelope the stock
    'when a webhook request is received' flow renders — so the operator changes nothing on the Teams
    side. Slack/other URLs keep the generic {source,text}. Overridable via MONITOR_WEBHOOK_FORMAT."""
    teams = "https://prod-9.westeurope.logic.azure.com:443/workflows/ab/triggers/manual/paths/invoke?sig=x"
    office = "https://acme.webhook.office.com/webhookb2/xyz"
    slack = "https://hooks.slack.com/services/T/B/z"
    generic = "https://example.com/hook"
    assert alerts._is_teams_url(teams) and alerts._is_teams_url(office)
    assert not alerts._is_teams_url(slack) and not alerts._is_teams_url(generic)
    monkeypatch.setattr(config, "WEBHOOK_FORMAT", "auto")
    card = alerts._webhook_payload("boom", teams)
    assert card["type"] == "message"
    att = card["attachments"][0]
    assert att["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert att["content"]["body"][0]["text"] == "boom"      # the message text lands inside the card
    # non-teams under auto → generic {source,text} (unchanged for every existing receiver)
    assert alerts._webhook_payload("boom", generic) == {"source": "AI-Monitoring", "text": "boom"}
    # explicit overrides win
    monkeypatch.setattr(config, "WEBHOOK_FORMAT", "generic")
    assert alerts._webhook_payload("x", teams) == {"source": "AI-Monitoring", "text": "x"}
    monkeypatch.setattr(config, "WEBHOOK_FORMAT", "slack")
    assert alerts._webhook_payload("x", generic) == {"text": "x"}
    monkeypatch.setattr(config, "WEBHOOK_FORMAT", "teams")
    assert alerts._webhook_payload("x", generic)["type"] == "message"


async def test_send_test_posts_teams_card_to_a_teams_url(monkeypatch):
    """'Send alert test' (send_test) posts the Adaptive-Card body when ALERT_WEBHOOK_URL is a Teams
    URL — the fix for 'delivered but nothing shows' (Teams 202s a bare {text} then silently drops it)."""
    monkeypatch.setattr(config, "WEBHOOK_FORMAT", "auto")
    monkeypatch.setattr(config, "ALERT_WEBHOOK_URL",
                        "https://prod-1.westeurope.logic.azure.com/workflows/x/triggers/manual/paths/invoke?sig=y")
    captured = {}

    async def fake_try_post(self, session, url, payload):
        captured["url"] = url
        captured["payload"] = payload
        return "ok"
    monkeypatch.setattr(alerts.Notifier, "_try_post", fake_try_post)
    res = await alerts.send_test(None)
    assert res["webhook"] == "ok"
    assert captured["payload"]["type"] == "message"          # card envelope, not {source,text}
    assert captured["payload"]["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"


def _fake_webhook_session(status=None, exc=None):
    """Minimal aiohttp-session stand-in: `async with session.post(...) as r` yields an object with
    `.status`, or raises `exc` on enter (transport error)."""
    class _CM:
        async def __aenter__(self):
            if exc:
                raise exc
            r = type("R", (), {})()
            r.status = status
            return r
        async def __aexit__(self, *a):
            return False
    class _S:
        def post(self, *a, **k):
            return _CM()
    return _S()


async def test_webhook_result_is_logged_without_leaking_the_url_secret(caplog):
    """Every webhook POST result is written to the log (aimon.alerts): delivered→INFO with the HTTP
    status, rejected/failed→WARNING. The URL is logged HOST-ONLY so the secret in its path/query
    (Teams `sig=`, Slack token) never reaches the log."""
    import logging
    n = alerts.Notifier()
    url = "https://prod-1.westeurope.logic.azure.com/workflows/x/triggers/manual/paths/invoke?sig=TOPSECRETSIG"
    with caplog.at_level(logging.INFO, logger="aimon.alerts"):
        await n._post_json(_fake_webhook_session(202), url, {"x": 1})            # delivered
        await n._post_json(_fake_webhook_session(403), url, {"x": 1})            # rejected
        await n._post_json(_fake_webhook_session(exc=RuntimeError("boom")), url, {"x": 1})  # failed
    recs = [r for r in caplog.records if r.name == "aimon.alerts"]
    # the secret must appear NOWHERE (message or the structured url field)
    assert all("TOPSECRETSIG" not in r.getMessage() and "TOPSECRETSIG" not in str(getattr(r, "url", ""))
               for r in recs), "webhook secret leaked into the log"
    deliv = [r for r in recs if "delivered" in r.getMessage()]
    assert deliv and getattr(deliv[0], "status", None) == 202
    assert getattr(deliv[0], "url", None) == "https://prod-1.westeurope.logic.azure.com"   # host only
    warns = [r for r in recs if r.levelno == logging.WARNING]
    assert any(getattr(r, "status", None) == 403 for r in warns)          # non-2xx → WARNING
    assert any(getattr(r, "error", None) == "RuntimeError" for r in warns)  # transport error → WARNING


async def test_alert_message_includes_machine_tool_service_and_reason(monkeypatch):
    """Every alert line carries the machine name, the tool (AI-Monitoring), and — for a backend —
    which service is on/off and WHY. A down→up cycle reads naturally ('vLLM is DOWN — …' / 'vLLM
    is back UP'). Threshold alerts get the same [machine] AI-Monitoring prefix."""
    monkeypatch.setattr(config, "INSTANCE_NAME", "")            # force hostname path
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    monkeypatch.setattr(config, "ALERT_CPU_PCT", 0)            # isolate the backend alert
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_AFTER", 1)  # this test is about WHICH
    monkeypatch.setattr(config, "ALERT_BACKEND_UP_AFTER", 1)    # backends alarm + the message text,
    alerts.reset_down_streaks()                                # not the flap hysteresis
    sent = []

    async def fake_fanout(self, session, text, recipients=None, akey=""):
        sent.append(text)
    monkeypatch.setattr(alerts.Notifier, "_fanout", fake_fanout)
    n = alerts.Notifier()
    down = {"ts": 0, "collectors": {"host": {"available": True, "hostname": "gpu-box-01"},
                                    "vllm": {"available": False, "error": "connection refused"}}}
    up = {"ts": 0, "collectors": {"host": {"available": True, "hostname": "gpu-box-01"},
                                  "vllm": {"available": True}}}
    async with aiohttp.ClientSession() as s:
        await n.process(s, down, 1000)     # vLLM down → fire
        await n.process(s, up, 1010)       # vLLM back → recover
    fire = next(m for m in sent if "🔴" in m)
    rec = next(m for m in sent if "🟢" in m)
    for token in ("gpu-box-01", "AI-Monitoring", "vLLM", "DOWN", "connection refused"):
        assert token in fire, f"{token!r} missing from {fire!r}"
    assert "gpu-box-01" in rec and "vLLM is back UP" in rec
    # the machine-name override wins when set
    monkeypatch.setattr(config, "INSTANCE_NAME", "prod-eu-1")
    assert alerts._machine(down) == "prod-eu-1"


def test_backend_down_recovery_needs_stable_up_no_flap(monkeypatch):
    """Anti-flap hysteresis: once latched DOWN, a SINGLE good poll must NOT clear it — that would
    emit a recovery and let the next failure re-fire immediately, bypassing the cooldown and
    spamming the channel (the down:litellm flood). Recovery only after ALERT_BACKEND_UP_AFTER
    consecutive good polls; the message keeps the real reason during the up-grace window."""
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_AFTER", 2)
    monkeypatch.setattr(config, "ALERT_BACKEND_UP_AFTER", 3)
    alerts.reset_down_streaks()
    bad = {"collectors": {"litellm": {"available": False, "error": "TimeoutError"}}}
    good = {"collectors": {"litellm": {"available": True}}}

    def k(snap):
        return [x for x, _ in alerts.evaluate(snap)]
    assert k(bad) == []                    # 1 fail — quiet
    assert k(bad) == ["down:litellm"]      # 2 fails — latched DOWN
    assert k(good) == ["down:litellm"]     # 1 good — flap IGNORED, still down
    assert k(bad) == ["down:litellm"]      # fails again — no recover/re-fire churn
    assert k(good) == ["down:litellm"]     # up-streak 1
    assert k(good) == ["down:litellm"]     # up-streak 2
    assert k(good) == []                   # up-streak 3 — finally recovered
    # reason survives the grace window (b['error'] is None on a good poll)
    alerts.reset_down_streaks()
    k(bad); k(bad)
    assert "TimeoutError" in dict(alerts.evaluate(good))["down:litellm"]


def test_delivery_card_collapses_consecutive_repeats(tmp_path, monkeypatch):
    """A repeating alert must not fill the whole Recent-deliveries list. recent_webhook_sends
    collapses consecutive-identical runs into one row (n=count), so distinct sends (a test click,
    another alert) stay visible instead of being crowded off by 30× down:litellm."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "wl.db"))
    db.init()
    t = 1000.0
    for i in range(30):
        db.record_webhook_send(t + i, "webhook", "down:litellm", 202, True, 5.0)
    db.record_webhook_send(t + 30, "test", "test", 200, True, 4.0)
    for i in range(5):
        db.record_webhook_send(t + 31 + i, "webhook", "down:litellm", 202, True, 5.0)
    got = db.recent_webhook_sends(10)
    assert [g["akey"] for g in got] == ["down:litellm", "test", "down:litellm"]   # newest first
    assert [g["n"] for g in got] == [5, 1, 30]        # runs collapsed with their counts
    assert got[0]["ts"] == t + 35                       # newest ts of the run is shown


async def test_real_alert_fanout_posts_teams_card_to_global_url(monkeypatch):
    """The REAL alert path (`_fanout`, not just the Send-test button) also shapes the global
    ALERT_WEBHOOK_URL body as a Teams card when that URL is a Teams URL — so live alerts render too."""
    monkeypatch.setattr(config, "WEBHOOK_FORMAT", "auto")
    monkeypatch.setattr(config, "ALERT_WEBHOOK_URL",
                        "https://prod-2.westeurope.logic.azure.com/workflows/z/triggers/manual/paths/invoke?sig=s")
    captured = {}

    async def fake_post(self, session, url, payload, akey=""):
        captured["url"] = url
        captured["payload"] = payload
    monkeypatch.setattr(alerts.Notifier, "_post_json", fake_post)
    await alerts.Notifier()._fanout(None, "🔴 CPU 95%", [])
    assert captured["payload"]["type"] == "message"                       # card envelope
    assert captured["payload"]["attachments"][0]["content"]["body"][0]["text"] == "🔴 CPU 95%"


async def test_webhook_set_is_audited(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_HOSTS", "hooks.example.test")   # allow-list gates the skip
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_PRIVATE", True)
    db.user_create("wa", "a@x.io", auth.hash_password("wapw1234"), "viewer", time.time())
    c = await _client()
    try:
        csrf = await _login_get_csrf(c, "wa", "wapw1234")
        await c.post("/api/account/webhook",
                     data={"url": "https://hooks.example.test/x", "enabled": "1"},
                     headers={"X-CSRF-Token": csrf})
    finally:
        await c.close()
    assert "webhook.set" in {r["action"] for r in db.audit_list(50)}


# ── webhook SSRF hardening (manual-review findings M1 + L1) ───────────────────
def test_sec_webhook_ip_blocked_covers_cgnat_and_mapped():
    import alerts
    # L1: RFC 6598 CGNAT / shared space must be blocked (is_private misses it <3.13)
    assert alerts._ip_blocked("100.64.0.1")
    assert alerts._ip_blocked("100.127.255.254")
    # IPv4-mapped IPv6 collapses to v4 → internal targets can't hide in v6
    assert alerts._ip_blocked("::ffff:169.254.169.254")
    assert alerts._ip_blocked("::ffff:100.64.0.1")
    # public still allowed
    assert not alerts._ip_blocked("8.8.8.8")
    assert not alerts._ip_blocked("1.1.1.1")


async def test_sec_webhook_resolver_pins_validated_ip(monkeypatch):
    # M1: the SSRF resolver must REFUSE to hand aiohttp a blocked address, even if
    # the hostname (re)resolves to one at connect time (DNS-rebinding TOCTOU).
    import alerts
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_PRIVATE", False)
    r = alerts._SSRFResolver()

    def _info(ip):
        async def _f(*a, **k):
            return [{"hostname": "h", "host": ip, "port": 0,
                     "family": 2, "proto": 0, "flags": 0}]
        return _f
    try:
        monkeypatch.setattr(r._base, "resolve", _info("127.0.0.1"))
        with pytest.raises(OSError):
            await r.resolve("rebind.evil.test")            # rebound to loopback → refused
        monkeypatch.setattr(r._base, "resolve", _info("169.254.169.254"))
        with pytest.raises(OSError):
            await r.resolve("metadata.evil.test")          # metadata IP → refused
        monkeypatch.setattr(r._base, "resolve", _info("8.8.8.8"))
        out = await r.resolve("good.test")                 # public → passes through
        assert out and out[0]["host"] == "8.8.8.8"
    finally:
        await r.close()


async def test_sec_webhook_resolver_respects_allow_private(monkeypatch):
    # the operator opt-in (ALLOW_PRIVATE + an explicit allow-list) must still reach a LAN host
    # (resolver mustn't over-block once the target is allow-list-pinned)
    import alerts
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_HOSTS", "lan.internal")
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_PRIVATE", True)
    r = alerts._SSRFResolver()

    async def _priv(*a, **k):
        return [{"hostname": "h", "host": "10.0.0.5", "port": 0,
                 "family": 2, "proto": 0, "flags": 0}]
    try:
        monkeypatch.setattr(r._base, "resolve", _priv)
        out = await r.resolve("lan.internal")
        assert out and out[0]["host"] == "10.0.0.5"        # allowed with opt-in
    finally:
        await r.close()


async def test_sec_webhook_recipients_timeboxed(monkeypatch):
    # §6: a slow-resolving user webhook must NOT hang the alert tick (which would
    # wedge the sampling loop) — it is dropped within HTTP_TIMEOUT, not awaited fully.
    import alerts
    monkeypatch.setattr(config, "HTTP_TIMEOUT", 0.2)

    async def _hang(url):
        await asyncio.sleep(5)
        return None
    monkeypatch.setattr(alerts, "validate_webhook_url", _hang)
    monkeypatch.setattr(alerts.db, "user_webhooks_enabled",
                        lambda: [{"name": "u", "url": "http://slow.test/"}])
    t0 = time.perf_counter()
    out = await alerts.Notifier()._recipients()
    assert out == [] and (time.perf_counter() - t0) < 2.0   # bounded, not 5s


async def test_sec_webhook_recipients_capped(monkeypatch):
    # a large user base can't make the fan-out unbounded — capped per tick.
    import alerts
    monkeypatch.setattr(config, "WEBHOOK_MAX_RECIPIENTS", 3)

    async def _ok(url):
        return None                                        # every URL "valid"
    monkeypatch.setattr(alerts, "validate_webhook_url", _ok)
    monkeypatch.setattr(alerts.db, "user_webhooks_enabled",
                        lambda: [{"name": f"u{i}", "url": f"http://h{i}.test/"}
                                 for i in range(10)])
    out = await alerts.Notifier()._recipients()
    assert len(out) == 3                                    # capped at MAX_RECIPIENTS


# ── Prometheus /metrics export (1.3.0) ────────────────────────────────────────
def test_metrics_prom_render_format():
    import metrics_prom
    snap = {"ts": 1000, "collectors": {
        "host": {"available": True, "cpu_pct": 42.0, "mem_pct": 50.0, "load": [1.0], "ncpu": 8},
        "gpu": {"available": True, "gpus": [{"name": "GB10", "util": 80.0, "vram_used": 5, "vram_total": 10}]},
        "litellm": {"available": False}, "ollama": {"available": False},
        "llamacpp": {"available": False},
        "containers": {"available": True, "containers": [{"name": "x", "running": True}]}}}
    out = metrics_prom.render(snap, {"users": 2, "sessions": 1, "alerts": 0})
    assert "# TYPE aimon_up gauge" in out and "\naimon_up 1\n" in out
    assert 'aimon_backend_up{backend="gpu"} 1' in out
    assert 'aimon_backend_up{backend="litellm"} 0' in out
    assert 'aimon_gpu_utilization_percent{gpu="0",name="GB10"} 80' in out
    assert 'aimon_container_up{name="x"} 1' in out
    assert "aimon_users_total 2" in out
    # each metric family declares TYPE exactly once (grouped)
    assert out.count("# TYPE aimon_backend_up gauge") == 1
    # no None/blank values leak
    assert "None" not in out


async def test_metrics_endpoint_auth_and_content(monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "metricstok123456")
    c = await _client()
    try:
        # gated: no credential -> 401 (not a login redirect)
        r = await c.get("/metrics", allow_redirects=False)
        assert r.status == 401
        # dashboard token works
        r = await c.get("/metrics?token=metricstok123456")
        assert r.status == 200
        assert "text/plain" in r.headers["Content-Type"]
        assert "aimon_up 1" in await r.text()
    finally:
        await c.close()


async def test_metrics_dedicated_scrape_token(monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "dashtok1234567890")
    monkeypatch.setattr(config, "METRICS_TOKEN", "scrapetok123456")
    c = await _client()
    try:
        # scrape token is accepted (least-privilege) …
        assert (await c.get("/metrics?token=scrapetok123456")).status == 200
        assert (await c.get("/metrics", headers={"Authorization": "Bearer scrapetok123456"})).status == 200
        # … a wrong token is not
        assert (await c.get("/metrics?token=nope")).status == 401
    finally:
        await c.close()


async def test_metrics_open_when_auth_disabled(monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "")
    monkeypatch.setattr(config, "ALLOW_OPEN", True)
    c = await _client()
    try:
        assert (await c.get("/metrics")).status == 200
    finally:
        await c.close()


async def test_metrics_can_be_disabled(monkeypatch):
    monkeypatch.setattr(config, "METRICS_ENABLED", False)
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "")
    monkeypatch.setattr(config, "ALLOW_OPEN", True)
    c = await _client()
    try:
        assert (await c.get("/metrics")).status == 404
    finally:
        await c.close()


# ── metrics hardening fixes (1.3.1) ───────────────────────────────────────────
def test_metrics_skips_non_finite_values():
    import metrics_prom
    snap = {"ts": 1, "collectors": {"litellm": {"available": True,
            "req_rate": float("inf"), "error_pct": float("nan"), "cost_rate_hr": 1.5}}}
    out = metrics_prom.render(snap)
    # inf/nan lines would break the whole Prometheus scrape — must be dropped
    assert " inf" not in out and " nan" not in out and "Inf" not in out and "NaN" not in out
    assert "aimon_litellm_cost_rate_hourly 1.5" in out       # finite value still emitted


async def test_metrics_endpoint_enforces_lockout(monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "realmetricstoken1")
    monkeypatch.setattr(config, "AUTH_MAX_FAILS", 3)
    c = await _client()
    try:
        # presented-but-wrong token counts as a brute-force strike
        for _ in range(3):
            assert (await c.get("/metrics?token=wrong")).status == 401
        # now the IP is locked out even for the correct token
        r = await c.get("/metrics?token=realmetricstoken1")
        assert r.status == 429
    finally:
        await c.close()


# ── server error logging → obslog access/auth loggers (never the 200s) ─────────
async def test_server_logs_failed_login(caplog):
    import logging
    db.user_create("le", "l@x.io", auth.hash_password("lepw1234"), "viewer", time.time())
    c = await _client()
    try:
        with caplog.at_level(logging.WARNING, logger="aimon.auth"):
            await c.post("/login", data={"username": "le", "password": "WRONG"})
    finally:
        await c.close()
    msgs = [r.getMessage() for r in caplog.records if r.name == "aimon.auth"]
    assert any("login FAILED" in m and "le" in m for m in msgs)


async def test_server_logs_denied_admin_action(monkeypatch, caplog):
    import logging
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("vw", "v@x.io", auth.hash_password("vwpw1234"), "viewer", time.time())
    c = await _client()
    try:
        with caplog.at_level(logging.WARNING, logger="aimon.access"):
            await c.post("/login", data={"username": "vw", "password": "vwpw1234"})
            await c.get("/api/admin/users")           # viewer -> 403
    finally:
        await c.close()
    msgs = [r.getMessage() for r in caplog.records if r.name == "aimon.access"]
    assert any("denied" in m and "403" in m for m in msgs)


async def test_server_does_not_log_normal_200(monkeypatch, caplog):
    import logging
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "")
    monkeypatch.setattr(config, "ALLOW_OPEN", True)
    c = await _client()
    try:
        with caplog.at_level(logging.INFO, logger="aimon.access"):
            assert (await c.get("/healthz")).status == 200
            assert (await c.get("/gpu")).status == 200
    finally:
        await c.close()
    msgs = [r.getMessage() for r in caplog.records if r.name == "aimon.access"]
    assert not any("healthz" in m or "/gpu" in m for m in msgs)   # no 200 noise


async def test_log_mw_logs_unhandled_exception_with_traceback(caplog):
    import logging

    class _Req:
        method = "GET"
        path = "/api/boom"

    async def boom(_r):
        raise ValueError("kaboom")
    with caplog.at_level(logging.ERROR, logger="aimon.access"):
        with pytest.raises(ValueError):
            await appmod._log_mw(_Req(), boom)
    # .exception() attaches exc_info → the formatter renders the traceback into caplog.text
    assert "500" in caplog.text and "Traceback" in caplog.text and "kaboom" in caplog.text


# ── forced first-login password change (1.3.2) ────────────────────────────────
async def test_admin_created_user_must_change_password(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("padm", "pa@x.io", auth.hash_password("padmpw12"), "admin", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "padm", "password": "padmpw12"})
        csrf = (await (await c.get("/api/admin/users")).json())["csrf"]
        r = await c.post("/api/admin/users",
                         data={"username": "fresh", "email": "f@x.io",
                               "password": "freshpw1", "role": "viewer"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200
    finally:
        await c.close()
    assert db.user_get("fresh")["must_change_pw"] is True


async def test_must_change_user_is_gated_to_account(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("gate", "g@x.io", auth.hash_password("gatepw12"), "viewer",
                   time.time(), must_change_pw=True)
    c = await _client()
    try:
        r = await c.post("/login", data={"username": "gate", "password": "gatepw12"},
                         allow_redirects=False)
        assert r.status == 302 and "/account" in r.headers.get("Location", "")
        r = await c.get("/gpu", allow_redirects=False)          # page -> /account
        assert r.status == 302 and "/account" in r.headers.get("Location", "")
        assert (await c.get("/api/nav")).status == 403          # api -> 403
        me = await (await c.get("/api/me")).json()              # allowlisted
        assert me["must_change"] is True
        assert (await c.get("/account")).status == 200          # reachable
    finally:
        await c.close()


async def test_changing_password_lifts_the_gate(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("lift", "l@x.io", auth.hash_password("liftpw12"), "viewer",
                   time.time(), must_change_pw=True)
    c = await _client()
    try:
        await c.post("/login", data={"username": "lift", "password": "liftpw12"})
        csrf = (await (await c.get("/api/me")).json())["csrf"]
        r = await c.post("/api/account/password",
                         data={"current": "liftpw12", "new": "liftNEW123"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200
        assert (await c.get("/gpu")).status == 200              # gate lifted
        assert db.user_get("lift")["must_change_pw"] is False
        assert (await (await c.get("/api/me")).json())["must_change"] is False
    finally:
        await c.close()


async def test_normal_user_not_gated(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("norm", "n@x.io", auth.hash_password("normpw12"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "norm", "password": "normpw12"})
        assert (await c.get("/gpu")).status == 200
        assert (await (await c.get("/api/me")).json())["must_change"] is False
    finally:
        await c.close()


async def test_admin_reset_forces_password_change(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("radm", "r@x.io", auth.hash_password("radmpw12"), "admin", time.time())
    db.user_create("victim", "v@x.io", auth.hash_password("victpw12"), "viewer", time.time())
    assert db.user_get("victim")["must_change_pw"] is False
    c = await _client()
    try:
        await c.post("/login", data={"username": "radm", "password": "radmpw12"})
        csrf = (await (await c.get("/api/admin/users")).json())["csrf"]
        r = await c.post("/api/admin/users/action",
                         data={"username": "victim", "action": "reset",
                               "password": "temp1234"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200
    finally:
        await c.close()
    assert db.user_get("victim")["must_change_pw"] is True


# ── per-account login lockout (1.3.2) ─────────────────────────────────────────
async def test_account_locks_after_max_failed_attempts(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    monkeypatch.setattr(config, "AUTH_MAX_FAILS", 10_000)     # isolate the per-USER lock
    monkeypatch.setattr(config, "AUTH_USER_MAX_FAILS", 10)
    monkeypatch.setattr(config, "AUTH_USER_LOCKOUT_S", 300.0)
    db.user_create("lockme", "lm@x.io", auth.hash_password("goodpw123"), "viewer", time.time())
    appmod._user_fails.pop("lockme", None)
    appmod._user_locked_until.pop("lockme", None)
    c = await _client()
    try:
        for _ in range(config.AUTH_USER_MAX_FAILS):
            r = await c.post("/login", data={"username": "lockme", "password": "WRONG"},
                             allow_redirects=False)
            assert r.status == 302
        # account now locked — even the CORRECT password is refused with e=locked
        r = await c.post("/login", data={"username": "lockme", "password": "goodpw123"},
                         allow_redirects=False)
        assert r.status == 302 and "e=locked" in r.headers.get("Location", "")
        assert appmod._user_locked_until.get("lockme", 0) > time.time()
    finally:
        await c.close()


async def test_account_lock_is_per_user_not_ip(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    monkeypatch.setattr(config, "AUTH_MAX_FAILS", 10_000)     # no per-IP lock in this test
    monkeypatch.setattr(config, "AUTH_USER_MAX_FAILS", 10)
    db.user_create("victimA", "a@x.io", auth.hash_password("apw12345"), "viewer", time.time())
    db.user_create("otherB", "b@x.io", auth.hash_password("bpw12345"), "viewer", time.time())
    for n in ("victimA", "otherB"):
        appmod._user_fails.pop(n, None)
        appmod._user_locked_until.pop(n, None)
    c = await _client()
    try:
        for _ in range(10):
            await c.post("/login", data={"username": "victimA", "password": "WRONG"},
                         allow_redirects=False)
        r = await c.post("/login", data={"username": "victimA", "password": "apw12345"},
                         allow_redirects=False)
        assert "e=locked" in r.headers.get("Location", "")            # A locked
        # same IP, different account is unaffected -> logs in (redirect to "/")
        r = await c.post("/login", data={"username": "otherB", "password": "bpw12345"},
                         allow_redirects=False)
        loc = r.headers.get("Location", "")
        assert r.status == 302 and "/login" not in loc and "e=locked" not in loc
    finally:
        await c.close()


async def test_successful_login_resets_account_fail_counter(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    monkeypatch.setattr(config, "AUTH_MAX_FAILS", 10_000)
    monkeypatch.setattr(config, "AUTH_USER_MAX_FAILS", 10)
    db.user_create("resetme", "r@x.io", auth.hash_password("okpw1234"), "viewer", time.time())
    appmod._user_fails.pop("resetme", None)
    appmod._user_locked_until.pop("resetme", None)
    c = await _client()
    try:
        for _ in range(9):                                   # 9 < 10 -> not locked yet
            await c.post("/login", data={"username": "resetme", "password": "WRONG"},
                         allow_redirects=False)
        r = await c.post("/login", data={"username": "resetme", "password": "okpw1234"},
                         allow_redirects=False)
        assert "e=locked" not in r.headers.get("Location", "")
        assert "resetme" not in appmod._user_fails            # counter cleared on success
    finally:
        await c.close()


# ── admin "Force reset" action (1.3.2) ────────────────────────────────────────
async def test_admin_force_reset_flags_user(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("fadm", "fa@x.io", auth.hash_password("fadmpw12"), "admin", time.time())
    db.user_create("frtarget", "t@x.io", auth.hash_password("frtpw123"), "viewer", time.time())
    assert db.user_get("frtarget")["must_change_pw"] is False
    c = await _client()
    try:
        await c.post("/login", data={"username": "fadm", "password": "fadmpw12"})
        csrf = (await (await c.get("/api/admin/users")).json())["csrf"]
        r = await c.post("/api/admin/users/action",
                         data={"username": "frtarget", "action": "force_reset"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200
    finally:
        await c.close()
    assert db.user_get("frtarget")["must_change_pw"] is True   # flagged, password unchanged


async def test_admin_clear_reset_cancels_pending_requirement(monkeypatch):
    """Admin can CANCEL a pending forced reset ('reset pending'): clear_reset lifts the
    must_change flag and the target logs in normally (no /account gate)."""
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("cadm", "ca@x.io", auth.hash_password("cadmpw12"), "admin", time.time())
    db.user_create("crtarget", "ct@x.io", auth.hash_password("crtpw123"), "viewer",
                   time.time(), must_change_pw=True)          # starts 'reset pending'
    assert db.user_get("crtarget")["must_change_pw"] is True
    c = await _client()
    try:
        await c.post("/login", data={"username": "cadm", "password": "cadmpw12"})
        csrf = (await (await c.get("/api/admin/users")).json())["csrf"]
        r = await c.post("/api/admin/users/action",
                         data={"username": "crtarget", "action": "clear_reset"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200
    finally:
        await c.close()
    assert db.user_get("crtarget")["must_change_pw"] is False  # requirement cancelled
    # target now logs in WITHOUT being gated to /account
    c2 = await _client()
    try:
        r2 = await c2.post("/login", data={"username": "crtarget", "password": "crtpw123"},
                           allow_redirects=False)
        assert r2.status == 302 and "/account?force=1" not in r2.headers.get("Location", "")
    finally:
        await c2.close()


async def test_force_reset_gates_target_on_next_login(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("fadm2", "fa2@x.io", auth.hash_password("fadm2pw1"), "admin", time.time())
    db.user_create("victimF", "vf@x.io", auth.hash_password("victimFpw"), "viewer", time.time())
    ca = await _client()
    try:
        await ca.post("/login", data={"username": "fadm2", "password": "fadm2pw1"})
        csrf = (await (await ca.get("/api/admin/users")).json())["csrf"]
        r = await ca.post("/api/admin/users/action",
                          data={"username": "victimF", "action": "force_reset"},
                          headers={"X-CSRF-Token": csrf})
        assert r.status == 200
    finally:
        await ca.close()
    # target logs in with their UNCHANGED password -> still forced to /account
    cv = await _client()
    try:
        r = await cv.post("/login", data={"username": "victimF", "password": "victimFpw"},
                          allow_redirects=False)
        assert r.status == 302 and "/account" in r.headers.get("Location", "")
        assert (await cv.get("/api/nav")).status == 403        # rest of app blocked
    finally:
        await cv.close()


# ── per-user API tokens (1.3.2) ───────────────────────────────────────────────
async def test_viewer_creates_viewer_token_that_authenticates(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("vtok", "v@x.io", auth.hash_password("vtokpw12"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "vtok", "password": "vtokpw12"})
        csrf = (await (await c.get("/api/me")).json())["csrf"]
        r = await c.post("/api/account/tokens", data={"label": "mytok"},
                         headers={"X-CSRF-Token": csrf})
        j = await r.json()
        assert r.status == 200 and j["role"] == "viewer"
        tok = j["token"]
        assert tok.startswith("aimon_pat_")
        lst = await (await c.get("/api/account/tokens")).json()
        assert lst["tokens"] and all("token" not in t and "token_hash" not in t
                                     for t in lst["tokens"])       # no secret leak
    finally:
        await c.close()
    c2 = await _client()                                            # fresh, no cookie
    try:
        assert (await c2.get("/api/nav",
                             headers={"Authorization": "Bearer " + tok})).status == 200
        # a viewer token cannot reach the admin API
        assert (await c2.get("/api/admin/users",
                             headers={"Authorization": "Bearer " + tok})).status == 403
    finally:
        await c2.close()


async def test_viewer_cannot_mint_admin_token(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("vt2", "v2@x.io", auth.hash_password("vt2pw123"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "vt2", "password": "vt2pw123"})
        csrf = (await (await c.get("/api/me")).json())["csrf"]
        j = await (await c.post("/api/account/tokens",
                                data={"label": "x", "role": "admin"},
                                headers={"X-CSRF-Token": csrf})).json()
        assert j["role"] == "viewer"                                # privilege guard downgrades
    finally:
        await c.close()


async def test_admin_mints_admin_token_reaching_admin_api(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("atok", "a@x.io", auth.hash_password("atokpw12"), "admin", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "atok", "password": "atokpw12"})
        csrf = (await (await c.get("/api/me")).json())["csrf"]
        j = await (await c.post("/api/account/tokens",
                                data={"label": "adm", "role": "admin"},
                                headers={"X-CSRF-Token": csrf})).json()
        assert j["role"] == "admin"
        tok = j["token"]
    finally:
        await c.close()
    c2 = await _client()
    try:
        assert (await c2.get("/api/admin/users",
                             headers={"Authorization": "Bearer " + tok})).status == 200
    finally:
        await c2.close()


async def test_token_create_requires_csrf(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("ctok", "c@x.io", auth.hash_password("ctokpw12"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "ctok", "password": "ctokpw12"})
        r = await c.post("/api/account/tokens", data={"label": "nocsrf"})   # no CSRF header
        assert r.status == 403
    finally:
        await c.close()


async def test_token_revoke_stops_it(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    db.user_create("rtok", "r@x.io", auth.hash_password("rtokpw12"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "rtok", "password": "rtokpw12"})
        csrf = (await (await c.get("/api/me")).json())["csrf"]
        j = await (await c.post("/api/account/tokens", data={"label": "z"},
                                headers={"X-CSRF-Token": csrf})).json()
        tok, tid = j["token"], j["id"]
        c2 = await _client()
        assert (await c2.get("/api/nav",
                             headers={"Authorization": "Bearer " + tok})).status == 200
        await c2.close()
        assert (await c.post("/api/account/tokens/revoke", data={"id": tid},
                             headers={"X-CSRF-Token": csrf})).status == 200
    finally:
        await c.close()
    c3 = await _client()
    try:
        assert (await c3.get("/api/nav",
                             headers={"Authorization": "Bearer " + tok})).status == 401
    finally:
        await c3.close()


def test_user_delete_cascades_api_tokens():
    import hashlib
    db.user_create("cdel", "c@x.io", auth.hash_password("cdelpw12"), "viewer", time.time())
    raw = "aimon_pat_" + "y" * 20
    db.api_token_create("tidC", "cdel", "viewer", "l",
                        hashlib.sha256(raw.encode()).hexdigest(), "p", time.time())
    assert db.api_token_count("cdel") == 1
    db.user_delete("cdel")
    assert db.api_token_count("cdel") == 0


def test_api_token_role_capped_at_current_user_role(tmp_path, monkeypatch):
    """Review-fix (privilege persistence): a PAT carries its OWN stored role, so a user who
    minted an admin PAT and is later DEMOTED to viewer must not keep admin via that token.
    api_token_lookup returns the LOWER of the token role and the owner's CURRENT role, capping
    the token at read time without having to mutate every PAT on a role change."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "patcap.db"))
    db.init()
    # two admins so demoting one doesn't trip the last-admin guard
    db.user_create("adm1", "a1@example.com", auth.hash_password("pw-abcdef12"), "admin", 1.0)
    db.user_create("adm2", "a2@example.com", auth.hash_password("pw-abcdef34"), "admin", 1.0)
    h = "tokhash-" + "a" * 24
    db.api_token_create("tidP", "adm1", "admin", "lbl", h, "pfx", 1.0)
    assert db.api_token_lookup(h)["role"] == "admin"          # admin owner → admin PAT
    assert db.user_update_guarded("adm1", "a1@example.com", "viewer")   # demote
    assert db.api_token_lookup(h)["role"] == "viewer"         # PAT capped to current role
    # re-promote → the same token regains admin (role is derived live, not frozen)
    assert db.user_update_guarded("adm1", "a1@example.com", "admin")
    assert db.api_token_lookup(h)["role"] == "admin"


async def test_gpu_sample_skips_when_probe_threads_wedged(monkeypatch):
    """Review-fix: a wedged nvidia-smi (D-state, unkillable) must not starve the SHARED thread
    pool. The GPU probe runs on a dedicated 2-thread executor gated by a BoundedSemaphore; when
    both permits are held (two threads already stuck), _gpu_sample returns a 'wedged' sentinel
    WITHOUT submitting a third probe — so the executor queue can't grow and the shared pool
    (host/procs/persist/rollup) is never touched."""
    import app as a
    called = {"n": 0}
    monkeypatch.setattr(a.gpu, "sample", lambda: called.__setitem__("n", called["n"] + 1) or {})
    assert a._GPU_SEM.acquire(blocking=False)      # simulate two wedged probe threads
    assert a._GPU_SEM.acquire(blocking=False)
    try:
        out = await a._gpu_sample(None)
        assert out == {"available": False, "error": "gpu probe wedged"}
        assert called["n"] == 0, "submitted a 3rd GPU probe while 2 were wedged"
    finally:
        a._GPU_SEM.release()
        a._GPU_SEM.release()


async def test_gpu_sample_releases_permit_if_submit_fails(monkeypatch):
    """Review-fix: if _GPU_EXECUTOR.submit raises (only reachable at executor shutdown), the
    permit acquired just before it must be RELEASED, not leaked — else every later GPU probe would
    read as permanently 'wedged'. Uses a fresh semaphore so the check is isolated from other tests."""
    import app as a
    import threading as _t

    class _BoomExec:
        def submit(self, *args):
            raise RuntimeError("executor shut down")

    monkeypatch.setattr(a, "_GPU_EXECUTOR", _BoomExec())
    monkeypatch.setattr(a, "_GPU_SEM", _t.BoundedSemaphore(2))    # isolated 2-permit semaphore
    with pytest.raises(RuntimeError):
        await a._gpu_sample(None)
    # both permits must still be free (the failed submit released the one it took)
    assert a._GPU_SEM.acquire(blocking=False)
    assert a._GPU_SEM.acquire(blocking=False), "submit-failure leaked a GPU permit"
    a._GPU_SEM.release()
    a._GPU_SEM.release()


# ── Top-10 keys "requests in window" delta chart (1.3.2) ──────────────────────
def _clear_key_series():
    """Isolate per-key delta tests from cross-run pollution (the shared test DB is
    not reset for key_series between runs). Also clears `known_keys`: these tests seed
    key_series with their own labels but never register them as /key/list-confirmed, and
    `key_series_window_delta`/`key_delta_series`/`concurrency_by_key` fold any UNKNOWN label
    into "Other" once known_keys is non-empty (permissive only while it's empty). A handler
    test that populates known_keys — e.g. the board write-through, `_store_owners_from_live` —
    would otherwise strip these labels and the read comes back empty."""
    db.init()
    with db._connect() as conn:
        conn.execute("DELETE FROM key_series")
        conn.execute("DELETE FROM key_series_1m")
        conn.execute("DELETE FROM key_series_1h")
        conn.execute("DELETE FROM known_keys")


def test_key_series_window_delta_computes_net_requests():
    _clear_key_series()
    now = time.time()
    # ZED: 1000 -> 1000 (no new requests) => delta 0; ACT: 100 -> 600 => 500
    db.insert_key_series(now - 1800, [{"key": "kz", "alias": "ZED_delta", "reqs": 1000},
                                      {"key": "ka", "alias": "ACT_delta", "reqs": 100}])
    db.insert_key_series(now - 60,   [{"key": "kz", "alias": "ZED_delta", "reqs": 1000},
                                      {"key": "ka", "alias": "ACT_delta", "reqs": 600}])
    res = db.key_series_window_delta("1h")
    m = dict(zip(res["labels"], res["deltas"]))
    assert m.get("ACT_delta") == 500
    assert m.get("ZED_delta") == 0                         # matches the user's example
    assert res["labels"].index("ACT_delta") < res["labels"].index("ZED_delta")  # ranked by delta


def test_key_series_window_delta_is_reset_safe():
    """A counter that resets mid-window still reports the work done AFTER the reset,
    and never a negative delta.

    The window delta sums POSITIVE STEPS across the samples rather than comparing only
    the endpoints, because two endpoints cannot distinguish "reset to 0, then 50 real
    requests" from "baseline re-based to 50 with no traffic" — both read 900 → 50. The
    sampler runs every few seconds, so a real reset always leaves the intermediate
    samples that tell them apart; this test now supplies them, as production would.
    See test_key_series_window_delta_ignores_a_plateau_drop_plateau for the other half.
    """
    _clear_key_series()
    now = time.time()
    for ts, v in ((now - 1800, 900), (now - 1500, 900),   # steady before the reset
                  (now - 1200, 0),                        # daily reset
                  (now - 900, 20), (now - 600, 35), (now - 60, 50)):   # work after it
        db.insert_key_series(ts, [{"key": "kr", "alias": "RST_delta", "reqs": v}])
    res = db.key_series_window_delta("1h")
    m = dict(zip(res["labels"], res["deltas"]))
    assert m.get("RST_delta") == 50            # the 50 done after the reset, never negative


def test_key_series_window_delta_ignores_a_plateau_drop_plateau():
    """The live regression: a key's cumulative value sat flat, re-based DOWNWARD, then
    sat flat again — no traffic anywhere in the window. Crediting the new end value (the
    old endpoints-only fallback) charged it a full band of phantom activity on an idle
    proxy, and ranked it into the top-N. A series that only ever plateaus scores 0."""
    _clear_key_series()
    now = time.time()
    for ts, v in ((now - 1800, 2.72), (now - 1500, 2.72), (now - 1200, 2.72),
                  (now - 900, 0.86), (now - 600, 0.86), (now - 60, 0.86)):
        db.insert_key_series(ts, [{"key": "kq", "alias": "QUIET_delta", "reqs": v}])
    res = db.key_series_window_delta("1h")
    m = dict(zip(res["labels"], res["deltas"]))
    assert m.get("QUIET_delta") == 0.0, "idle key charged phantom activity by a re-base"


def test_key_delta_series_is_cumulative_timeline():
    _clear_key_series()
    now = time.time()
    # counter 100 -> 100 -> 400 : cumulative-in-window climbs 0 -> 0 -> 300
    db.insert_key_series(now - 2400, [{"key": "kt", "alias": "TL_delta", "reqs": 100}])
    db.insert_key_series(now - 1200, [{"key": "kt", "alias": "TL_delta", "reqs": 100}])
    db.insert_key_series(now - 30,   [{"key": "kt", "alias": "TL_delta", "reqs": 400}])
    res = db.key_delta_series("1h")
    assert "TL_delta" in res["labels"]
    series = [p.get("TL_delta") for p in res["points"] if "TL_delta" in p]
    assert series[0] == 0                        # starts at 0 (window start)
    assert series == sorted(series)              # monotonic non-decreasing (cumulative)
    assert series[-1] == 300                     # ends at the window total


async def test_keydelta_endpoint_returns_timeline(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_OPEN", True)
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "")
    _clear_key_series()
    c = await _client()
    try:
        now = time.time()
        db.insert_key_series(now - 1800, [{"key": "ek", "alias": "EP_delta", "reqs": 10}])
        db.insert_key_series(now - 30,   [{"key": "ek", "alias": "EP_delta", "reqs": 40}])
        d = await (await c.get("/api/keydelta?window=1h")).json()
        assert d["window"] == "1h" and "labels" in d and "points" in d
        series = [p.get("EP_delta") for p in d["points"] if "EP_delta" in p]
        assert series[-1] == 30                 # cumulative ends at the window total
    finally:
        await c.close()


# ── cost per model & user over time: rollup + backfill + series endpoint ─────────
def test_fold_model_user_aggregates_and_drops_healthcheck():
    """_fold_model_user sums cost/tokens per (day,model,key), keeps the alias, and drops
    the monitor's own /health-check pseudo-key (would otherwise dominate)."""
    now = time.time()
    logs = [
        {"startTime": now, "api_key": "hA", "key_alias": "pedro", "model": "gpt-5-mini",
         "response_cost": 0.10, "total_tokens": 1000},
        {"startTime": now, "api_key": "hA", "key_alias": "pedro", "model": "gpt-5-mini",
         "response_cost": 0.05, "total_tokens": 500},
        {"startTime": now, "api_key": "hB", "key_alias": "ana", "model": "gpt-5.4-mini",
         "response_cost": 0.02, "total_tokens": 200},
        {"startTime": now, "api_key": "litellm-health-check-x", "model": "gpt-5-mini",
         "response_cost": 9.9, "total_tokens": 9},
    ]
    rows = litellm._fold_model_user(logs)
    by = {(r["model"], r["alias"]): r for r in rows}
    assert by[("gpt-5-mini", "pedro")]["cost"] == 0.15
    assert by[("gpt-5-mini", "pedro")]["tokens"] == 1500
    assert by[("gpt-5.4-mini", "ana")]["cost"] == 0.02
    assert not any("health-check" in r["key"] for r in rows)


def test_key_excluded_matches_hash_alias_or_user(monkeypatch):
    """config.key_excluded hides the monitor's own key/user from every graph — matching a
    key hash, key alias, or resolved owner (case-insensitive, exact on the whole value)."""
    monkeypatch.setattr(config, "EXCLUDE_KEYS", {"monitoring", "hz", "bot@demo.local"})
    assert config.key_excluded("hz")                       # by key hash
    assert config.key_excluded("x", "Monitoring")          # by alias, case-insensitive
    assert config.key_excluded(None, None, "bot@demo.local")  # by resolved owner
    assert not config.key_excluded("hA", "pedro", "ana@demo.local")
    monkeypatch.setattr(config, "EXCLUDE_KEYS", set())     # empty list → never excludes
    assert not config.key_excluded("monitoring", "hz")


def test_fold_model_user_drops_excluded_key(monkeypatch):
    """_fold_model_user drops an operator-excluded key (by alias or hash), same as it drops
    the health-check key — so the monitor's own traffic never enters the model×user rollup."""
    monkeypatch.setattr(config, "EXCLUDE_KEYS", {"monitor-key"})
    now = time.time()
    logs = [
        {"startTime": now, "api_key": "hA", "key_alias": "pedro", "model": "gpt-5-mini",
         "response_cost": 0.10, "total_tokens": 1000},
        {"startTime": now, "api_key": "hZ", "key_alias": "monitor-key", "model": "gpt-5-mini",
         "response_cost": 5.0, "total_tokens": 99999},
    ]
    rows = litellm._fold_model_user(logs)
    assert any(r["alias"] == "pedro" for r in rows)
    assert not any(r["alias"] == "monitor-key" for r in rows)   # excluded → gone


def test_key_series_read_hides_excluded_label(tmp_path, monkeypatch):
    """The persisted per-key over-time chart (key_series) drops an excluded label at READ
    time, so historical rows for the monitor's own key vanish from the chart too — and a
    full top-N is still returned (the excluded key doesn't eat a slot)."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "ks.db"))
    monkeypatch.setattr(config, "EXCLUDE_KEYS", {"monitor-key"})
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    for i in range(30):
        db.insert_key_series(now - 1800 + i * 60, [
            {"key": "hA", "alias": "pedro", "reqs": 100 + i},
            {"key": "hZ", "alias": "monitor-key", "reqs": 99999},   # would rank #1
        ])
    out = db.key_series("1h", top_n=10)
    assert "pedro" in out["labels"]
    assert "monitor-key" not in out["labels"]          # excluded even though it ranked top
    dl = db.key_series_window_delta("1h", top_n=10)
    assert "monitor-key" not in dl["labels"]


def test_concurrency_by_key_hides_excluded_label(tmp_path, monkeypatch):
    """Regression — 'Concurrent LLM work / Backlog — by key' was the one by-key chart
    that never called config.key_excluded(): key_series()/key_series_window_delta()
    already drop an operator-excluded label (e.g. the monitor's own probe/self-traffic
    key) at READ time so it can't leak through even from rows recorded before it was
    excluded, but concurrency_by_key() had no such filter — an excluded key with
    disproportionate activity (like a constant self-probe baseline) still surfaced as
    its own named band instead of folding into 'Other'. Its weight must still count
    toward the split denominator (so real keys' shares aren't inflated) — only its
    OWN labelled band must disappear, with that share landing in 'Other'."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "cbk3.db"))
    monkeypatch.setattr(config, "EXCLUDE_KEYS", {"monitor-key"})
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)   # align wall-clock so age-aware _pick_tier reads raw
    for i in range(10):
        t = now - 600 + i * 60
        with db._connect() as c:
            c.execute("INSERT INTO metrics(ts,conc,backlog) VALUES (?,?,?)", (t, 10.0, 4.0))
        db.insert_key_series(t, [
            {"key": "hA", "alias": "alice", "reqs": 3},
            {"key": "hZ", "alias": "monitor-key", "reqs": 9999},   # would rank #1
        ])
    out = db.concurrency_by_key("1h", "conc", end=now)
    labels = {s["label"] for s in out["series"]}
    assert "monitor-key" not in labels                 # never its own band
    assert "alice" in labels and "Other" in labels
    last = {s["label"]: s["data"][-1] for s in out["series"]}
    assert round(sum(last.values()), 2) == 10.0        # bands still sum to the real total
    # alice's tiny real share (3 reqs) vs monitor-key's excluded 9999 must NOT inflate
    # alice's band to the whole aggregate — the excluded weight still counts in the
    # split denominator, so alice gets only her true (small) proportional share.
    assert last["alice"] < 1.0


def test_known_keys_upsert_and_set_roundtrip(tmp_path, monkeypatch):
    """db.known_keys_upsert() persists labels LiteLLM's /key/list confirmed valid;
    known_keys_set() reads them back. Re-upserting (a later poll re-confirming the
    same key) must NOT create duplicate rows or drop an already-known label — the
    table only ever grows (see the known_keys schema comment: history for a
    rotated/deleted key must survive)."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "kk.db"))
    db.init()
    assert db.known_keys_set() == set()               # nothing confirmed yet
    db.known_keys_upsert(["alex-batista", "claude-code"], 1000.0)
    assert db.known_keys_set() == {"alex-batista", "claude-code"}
    # a later poll re-confirms one key and adds a new one — old one must persist
    db.known_keys_upsert(["claude-code", "key-r-santos"], 2000.0)
    assert db.known_keys_set() == {"alex-batista", "claude-code", "key-r-santos"}
    db.known_keys_upsert([], 3000.0)                    # empty poll is a no-op, never wipes
    assert db.known_keys_set() == {"alex-batista", "claude-code", "key-r-santos"}


def test_spend_model_user_upsert_is_idempotent(tmp_path, monkeypatch):
    """The sampler re-aggregates the whole day each tick and UPSERT-REPLACEs, so applying
    the same rows twice must NOT double-count (that's the no-high-water-mark guarantee)."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "mu.db"))
    db.init()
    now = time.time()
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    rows = [{"day": day, "model": "gpt-5-mini", "key": "hA", "alias": "pedro",
             "cost": 0.15, "tokens": 1500}]
    db.spend_model_user_upsert(rows, now)
    db.spend_model_user_upsert(rows, now)                    # twice
    got = db.spend_model_user_rows(3, now)
    assert round(sum(r["cost"] for r in got), 6) == 0.15     # replaced, not summed


def test_bucket_model_user_series_topn_and_owner_resolution(tmp_path, monkeypatch):
    """bucket_model_user_series resolves key→owner (admin override > live email > alias),
    builds one shared label axis, folds beyond top-N into 'Other', and derives cost as
    tokens × the OVERRIDE-aware price (not the stored response_cost)."""
    now = time.time()
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    # tokens carry the cost; response_cost deliberately WRONG to prove it's ignored
    rows = [
        {"day": day, "model": "gpt-5-mini", "key": "hA", "alias": "pedro-key",
         "cost": 999.0, "tokens": 1_000_000},
        {"day": day, "model": "gpt-5.4-mini", "key": "hB", "alias": "ana-key",
         "cost": 999.0, "tokens": 2_000_000},
    ]
    prices = {"gpt-5-mini": 2e-6, "gpt-5.4-mini": 1e-6}          # $/token
    kind_ov = {"gpt-5-mini": "real", "gpt-5.4-mini": "real"}
    omap = {"ovr": {"ana-key": "ana@x.io"}, "live": {"pedro-key": "pedro@x.io"}}
    out = appmod.bucket_model_user_series(rows, omap, prices, kind_ov, "14d", now)
    assert out["available"] is True and out["labels"] == [day]
    by = {s["label"]: s for s in out["series"]}
    assert "gpt-5-mini · pedro@x.io" in by                       # live email resolved
    assert "gpt-5.4-mini · ana@x.io" in by                       # admin override wins
    assert by["gpt-5-mini · pedro@x.io"]["total"] == 2.0         # 1e6 tok × 2e-6, NOT 999
    assert by["gpt-5.4-mini · ana@x.io"]["total"] == 2.0         # 2e6 tok × 1e-6
    # top-N fold
    many = [{"day": day, "model": f"m{i}", "key": f"k{i}", "alias": f"a{i}",
             "cost": 0.0, "tokens": (i + 1) * 1_000_000} for i in range(20)]
    p2 = {f"m{i}": 1e-6 for i in range(20)}
    k2 = {f"m{i}": "real" for i in range(20)}
    o2 = appmod.bucket_model_user_series(many, {"ovr": {}, "live": {}}, p2, k2, "14d", now, top_n=12)
    assert len(o2["series"]) == 13 and o2["series"][-1]["model"] == "Other"


def test_bucket_model_user_series_excludes_reference_and_unpriced(tmp_path):
    """A stacked cost view shows REAL (paid) models only — self-hosted/reference cost is
    imputed and would dominate — and drops unpriced models (rate 0)."""
    day = "2026-07-10"
    now = time.mktime(time.strptime(day, "%Y-%m-%d")) + 86400
    rows = [
        {"day": day, "model": "azure/real", "key": "k1", "alias": "u1", "cost": 0.0, "tokens": 1_000_000},
        {"day": day, "model": "llama/ref", "key": "k2", "alias": "u2", "cost": 0.0, "tokens": 50_000_000},
        {"day": day, "model": "azure/unpriced", "key": "k3", "alias": "u3", "cost": 0.0, "tokens": 1_000_000},
    ]
    prices = {"azure/real": 1e-6, "llama/ref": 1e-5}            # unpriced absent → rate 0
    kind_ov = {"azure/real": "real", "llama/ref": "reference", "azure/unpriced": "real"}
    out = appmod.bucket_model_user_series(rows, {"ovr": {}, "live": {}}, prices, kind_ov, "14d", now)
    models = {s["model"] for s in out["series"]}
    assert models == {"azure/real"}                            # ref + unpriced excluded


def test_bucket_model_user_series_share_axis(tmp_path):
    """The chart's % share is derived client-side; the endpoint always returns absolute €
    costs on a stable axis so both abs and share views work off one payload."""
    day = "2026-07-10"
    rows = [
        {"day": day, "model": "m", "key": "k1", "alias": "u1", "cost": 0.0, "tokens": 3_000_000},
        {"day": day, "model": "m", "key": "k2", "alias": "u2", "cost": 0.0, "tokens": 1_000_000},
    ]
    out = appmod.bucket_model_user_series(
        rows, {"ovr": {}, "live": {"u1": "u1", "u2": "u2"}},   # owners resolved (F5: ownerless → 'Unassigned')
        {"m": 1e-6}, {"m": "real"}, "14d",
        time.mktime(time.strptime(day, "%Y-%m-%d")) + 86400)
    costs = {s["user"]: s["costs"][0] for s in out["series"]}
    assert costs["u1"] == 3.0 and costs["u2"] == 1.0        # absolute, not normalized


def test_owner_of_folds_ownerless_to_unassigned_not_alias():
    """F5: a key with no resolved owner folds to 'Unassigned' — never its raw alias or a short
    key hash — so the Spend model×user chart groups ownerless keys the SAME way the /litellm
    by-user charts (userOf) do, and per-user totals reconcile across the two pages."""
    omap = {"ovr": {"k-ovr": "reassigned@example.com"}, "live": {"k-live": "owner@example.com"}}
    assert appmod._owner_of({"alias": "k-ovr"}, omap) == "reassigned@example.com"   # override wins
    assert appmod._owner_of({"alias": "k-live"}, omap) == "owner@example.com"       # resolved owner
    assert appmod._owner_of({"alias": "nameless-key"}, omap) == "Unassigned"        # ownerless → Unassigned
    assert appmod._owner_of({"alias": "", "key": "sk-abc123"}, omap) == "Unassigned"  # no alias either


def test_owner_of_uses_persisted_store_when_live_poll_blips():
    """The Spend model×user chart must survive a flaky LiteLLM /key/list+/user/list poll: when the
    LIVE owner map is empty (blip), the PERSISTED last-known owner (`known_owner_names`) keeps the
    key named instead of collapsing the whole chart to 'Unassigned' — same warm-owner fallback the
    Cost-by-user chart beside it uses. Precedence: override > live > stored > Unassigned."""
    # live blipped empty; stored still knows the owner
    blip = {"ovr": {}, "live": {}, "stored": {"alice-key": "alice@example.com"}}
    assert appmod._owner_of({"alias": "alice-key"}, blip) == "alice@example.com"
    # live present wins over stored; override wins over both
    full = {"ovr": {"k": "boss@example.com"}, "live": {"k": "live@example.com"}, "stored": {"k": "old@example.com"}}
    assert appmod._owner_of({"alias": "k"}, full) == "boss@example.com"
    assert appmod._owner_of({"alias": "j"}, {"ovr": {}, "live": {"j": "live@example.com"}, "stored": {"j": "old@example.com"}}) == "live@example.com"
    # unknown everywhere → Unassigned
    assert appmod._owner_of({"alias": "ghost"}, blip) == "Unassigned"


def test_prune_spend_model_user(tmp_path, monkeypatch):
    """Rows older than the 1-year retention are pruned; recent rows stay."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "mu2.db"))
    db.init()
    now = time.time()
    old = time.strftime("%Y-%m-%d", time.gmtime(now - 400 * 86400))
    new = time.strftime("%Y-%m-%d", time.gmtime(now))
    db.spend_model_user_upsert(
        [{"day": old, "model": "m", "key": "k", "alias": "u", "cost": 1.0, "tokens": 1},
         {"day": new, "model": "m", "key": "k", "alias": "u", "cost": 2.0, "tokens": 1}], now)
    removed = db.prune_spend_model_user()
    left = db.spend_model_user_rows(500, now)
    assert removed == 1 and [r["day"] for r in left] == [new]


async def test_model_user_series_endpoint(monkeypatch):
    """/api/spend/model-user-series serves the stacked series from the local rollup, with
    NO /spend/logs pull at render (reads DB + a cached owner map)."""
    monkeypatch.setattr(appmod, "_litellm_configured", lambda: True)

    async def _fake_owner_map(_session):
        return {"ovr": {}, "live": {"pedro-key": "pedro@x.io"}}
    monkeypatch.setattr(appmod, "_key_owner_map", _fake_owner_map)

    async def _fake_prices(_session):
        return {"gpt-5-mini": 2e-6}                       # $/token (override-aware upstream)
    monkeypatch.setattr(litellm, "model_prices", _fake_prices)
    appmod._MU_SERIES_CACHE.clear()                       # module-level cache: isolate test
    now = time.time()
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    db.init()
    db.spend_model_user_upsert(
        [{"day": day, "model": "gpt-5-mini", "key": "hA", "alias": "pedro-key",
          "cost": 999.0, "tokens": 1_000_000}], now)      # cost wrong on purpose
    c = await _client()
    try:
        d = await (await c.get("/api/spend/model-user-series?window=14d")).json()
        assert d["available"] is True
        s = next(s for s in d["series"] if s["label"].startswith("gpt-5-mini · pedro@x.io"))
        assert s["total"] == 2.0                          # 1e6 tok × 2e-6, not response_cost
        # F3: result is TTL-cached — adding usage does NOT change the reply within the TTL,
        # but clearing the cache reflects it (the 5s poll can't rescan the window each time).
        db.spend_model_user_upsert(
            [{"day": day, "model": "gpt-5-mini", "key": "hZ", "alias": "pedro-key",
              "cost": 0.0, "tokens": 5_000_000}], now)
        d2 = await (await c.get("/api/spend/model-user-series?window=14d")).json()
        assert next(x["total"] for x in d2["series"]
                    if x["label"].startswith("gpt-5-mini · pedro@x.io")) == 2.0   # cached
        appmod._MU_SERIES_CACHE.clear()
        d3 = await (await c.get("/api/spend/model-user-series?window=14d")).json()
        assert next(x["total"] for x in d3["series"]
                    if x["label"].startswith("gpt-5-mini · pedro@x.io")) == 12.0  # 6e6 × 2e-6
    finally:
        await c.close()


# ── F1: optional admin-gate on the Spend surface (MONITOR_SPEND_REQUIRE_ADMIN) ──
def test_hidden_nav_hides_spend_for_nonadmin_when_required(monkeypatch):
    """With SPEND_REQUIRE_ADMIN on, the Spend sidebar link is stripped for non-admins
    (no dead 403 link); admins keep it. Off = never hidden on that account."""
    monkeypatch.setattr(appmod, "_litellm_configured", lambda: True)
    monkeypatch.setattr(config, "SPEND_REQUIRE_ADMIN", True)
    assert "/spend" in appmod._hidden_nav_paths("viewer")
    assert "/spend" not in appmod._hidden_nav_paths("admin")
    monkeypatch.setattr(config, "SPEND_REQUIRE_ADMIN", False)
    assert "/spend" not in appmod._hidden_nav_paths("viewer")   # default: viewers keep it


async def test_spend_require_admin_gates_viewer(monkeypatch):
    """MONITOR_SPEND_REQUIRE_ADMIN=1: a logged-in VIEWER is 403'd on /spend and
    /api/spend/*; default off leaves viewers with access."""
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    monkeypatch.setattr(appmod, "_litellm_configured", lambda: True)
    db.user_create("vv", "v@x.io", auth.hash_password("viewerpw12"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "vv", "password": "viewerpw12"},
                     allow_redirects=False)
        # default off: viewer reaches the Spend API (not 403)
        monkeypatch.setattr(config, "SPEND_REQUIRE_ADMIN", False)
        assert (await c.get("/api/spend/model-user-series")).status != 403
        # turned on: viewer is forbidden on both page and API
        monkeypatch.setattr(config, "SPEND_REQUIRE_ADMIN", True)
        assert (await c.get("/api/spend/model-user-series")).status == 403
        assert (await c.get("/spend")).status == 403
        # T0-3: the sibling per-key COST + owner-email endpoints (outside the /api/spend/
        # prefix) must ALSO be gated — else the flag is trivially bypassed.
        for ep in ("/api/budgets", "/api/keyrequests", "/api/keyrequests?metric=cost",
                   "/api/keyseries", "/api/keydelta", "/api/litellm/models",
                   "/api/litellm/concurrency-by-key"):
            assert (await c.get(ep)).status == 403, f"{ep} must be admin-gated when SPEND_REQUIRE_ADMIN"
        # flag off again → those endpoints are reachable by a viewer (unchanged default)
        monkeypatch.setattr(config, "SPEND_REQUIRE_ADMIN", False)
        assert (await c.get("/api/budgets")).status != 403
    finally:
        await c.close()


def test_litellm_persistence_not_nested_under_vllm_guard():
    """T0-1: the LiteLLM spend rollup + known-keys upserts must persist independently of vLLM.
    They were mis-nested under the single-model-vLLM guard, so on a LiteLLM-only or
    multi-model-vLLM stack they never ran from live samples (silent data loss)."""
    import inspect
    import app as a
    # Per-tick writes were extracted into the sync _persist_tick helper (run off-loop via
    # asyncio.to_thread); the mis-nesting invariant now lives THERE. Both upserts must sit at
    # helper-body indent (4 spaces), NOT inside the 8-space single-model-vLLM `if`.
    persist = inspect.getsource(a._persist_tick)
    assert "\n    if mu_rows:\n        db.spend_model_user_upsert(" in persist
    assert '\n    if _ll.get("known_keys"):' in persist
    assert "\n        if mu_rows:" not in persist, "spend upsert must NOT be nested under vLLM"


def test_heavy_fetchers_refuse_redirects():
    """T0-4 (SSRF): the master-key-authed /spend/logs reader and the vLLM /metrics reader must
    set allow_redirects=False so a 3xx can't bounce them (and the bearer token) to an internal
    target — matching fetch_json's existing guard."""
    import pathlib
    ll = pathlib.Path(litellm.__file__).read_text(encoding="utf-8")
    fsr = ll.split("async def _fetch_spend_raw", 1)[1].split("\nasync def ", 1)[0]
    assert "allow_redirects=False" in fsr, "_fetch_spend_raw must not follow redirects"
    import collectors.vllm as _vll
    vl = pathlib.Path(_vll.__file__).read_text(encoding="utf-8")
    ft = vl.split("async def fetch_text", 1)[1].split("\nasync def ", 1)[0]
    assert "allow_redirects=False" in ft, "vllm.fetch_text must not follow redirects"


def test_stream_handler_redacts_containers_for_non_admin():
    """T0-2: the SSE stream must run _snapshot_for_display through _redact_containers (with the
    connection role) exactly like /api/data — otherwise a viewer streaming here bypasses the
    MONITOR_CONTAINERS_ADMIN_ONLY host-topology redaction on a sibling route."""
    import pathlib
    src = pathlib.Path(appmod.__file__).read_text(encoding="utf-8")
    body = src.split("async def stream_handler", 1)[1].split("\nasync def ", 1)[0]
    assert "_redact_containers(_snapshot_for_display(_latest)" in body, \
        "stream_handler must redact the snapshot with the role"
    assert "_auth_ctx(request)" in body, "stream_handler must resolve the role at connect"


async def test_open_mode_denies_user_management(monkeypatch):
    """T0-6: in open (no-auth) mode the middleware skips the admin gate, so the user-management
    endpoints (create/DELETE admin users) must be denied explicitly — an anonymous caller must
    not be able to bootstrap/remove admins."""
    monkeypatch.setattr(appmod, "_auth_enabled", lambda: False)
    c = await _client()
    try:
        # user-management is denied outright in open mode …
        assert (await c.get("/api/admin/users")).status == 403
        assert (await c.post("/api/admin/users",
                             data={"username": "x", "email": "x@y.z",
                                   "password": "pw12345678", "role": "admin"})).status == 403
        assert (await c.post("/api/admin/users/action", data={})).status == 403
        # … while a normal dashboard data route stays open (open mode = intended)
        assert (await c.get("/api/data")).status == 200
    finally:
        await c.close()




async def test_model_prices_averages_input_output_not_doubled(monkeypatch):
    """model_prices AVERAGES input+output per-token cost (not SUM): a model priced with
    input==output (one blended rate the operator set) reads ONCE, not doubled — the fix for
    the 'costs show doubled' bug. A model with only one side priced keeps that value."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://x")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "k")
    payload = {"data": [
        {"model_name": "blend",
         "model_info": {"input_cost_per_token": 2e-7, "output_cost_per_token": 2e-7}},
        {"model_name": "inonly",
         "model_info": {"input_cost_per_token": 1.2e-5, "output_cost_per_token": 0}},
        {"model_name": "real",
         "model_info": {"input_cost_per_token": 1.4e-6, "output_cost_per_token": 2.2e-6}},
    ]}

    async def _fake(session, url, **kw):
        return payload, None
    monkeypatch.setattr(litellm, "fetch_json", _fake)
    litellm._PRICES_CACHE = {}
    p = await litellm.model_prices(None)
    assert p["blend"] == 2e-7                      # averaged (was 4e-7 doubled)
    assert p["inonly"] == 1.2e-5                   # single side kept (not halved)
    assert abs(p["real"] - 1.8e-6) < 1e-15         # (1.4+2.2)/2 e-6


async def test_model_kinds_in_out_cache_survive_a_provider_prefix_mismatch(monkeypatch):
    """The Settings model-costs card's IN/OUT/CCH columns read permanently blank live, even
    for models LiteLLM clearly prices (a nonzero eff_cost_1m). Root cause: model_prices()
    (which price_for() reads, tolerant of provider/model prefixes) and model_price_detail()
    key their dicts differently — LiteLLM's own /model/info model_name doesn't always carry
    the same prefix as the canonical name used elsewhere (activity reports, prices). The
    handler's old `detail.get(name)` was an EXACT lookup with no such tolerance, so it
    silently returned {} whenever the two disagreed — which, live, was every single model.
    Reproduces that exact mismatch: prices/activity use the prefixed name, detail uses the
    bare one (as LiteLLM's /model/info often does for a custom/Azure deployment)."""
    monkeypatch.setattr(appmod, "_litellm_configured", lambda: True)
    NAME = "azure_ai/gpt-5-mini"          # what prices/activity/the models list all use
    BARE = "gpt-5-mini"                    # what /model/info's model_name actually is here

    async def _prices(_s):
        return {NAME: 0.194e-6}

    async def _detail(_s):                 # keyed by the BARE name — the live mismatch
        return {BARE: {"in": 0.1, "out": 0.3, "cache": 0.02}}

    async def _range(_s, *a, **k):
        return [{"model": NAME, "tokens": 1_000_000, "reqs": 5}]
    monkeypatch.setattr(litellm, "model_prices", _prices)
    monkeypatch.setattr(litellm, "model_price_detail", _detail)
    monkeypatch.setattr(litellm, "per_model_range", _range)
    db.init()
    c = await _client()
    try:
        d = await (await c.get("/api/admin/model-kinds")).json()
        m = next(x for x in d["models"] if x["model"] == NAME)
        assert m["in_1m"] == 0.1 and m["out_1m"] == 0.3 and m["cache_1m"] == 0.02, (
            f"prefix-mismatched detail lookup lost the per-type rates: {m}")
    finally:
        await c.close()


def test_detail_for_is_prefix_tolerant_like_price_for():
    """Unit-level pin of the tolerant lookup itself, mirroring the existing price_for()
    tolerance test — both directions (bare query / prefixed dict key, and vice versa)."""
    detail = {"azure_ai/gpt-5-mini": {"in": 1.0, "out": 2.0, "cache": 0.1}}
    assert litellm.detail_for("gpt-5-mini", detail) == {"in": 1.0, "out": 2.0, "cache": 0.1}
    detail2 = {"gpt-5-mini": {"in": 1.0, "out": 2.0, "cache": 0.1}}
    assert litellm.detail_for("azure_ai/gpt-5-mini", detail2) == {"in": 1.0, "out": 2.0, "cache": 0.1}
    assert litellm.detail_for("nonexistent", detail) == {}
    assert litellm.detail_for("anything", {}) == {}


# ── QA: cost controls end-to-end (the doubling fix + overrides + per-type display) ──
async def test_cost_controls_no_double_end_to_end(monkeypatch):
    """QA of the Model-costs controls: LiteLLM priced input==output==X ⇒ the card shows the
    three per-type rates AND a blended effective rate of X (NOT 2X), and est cost =
    tokens × X. A pinned override wins. Guards the whole cost path against the doubling bug."""
    monkeypatch.setattr(appmod, "_litellm_configured", lambda: True)
    X = 0.257e-6                                   # €0.257 / 1M tokens (per token)
    NAME = "azure_ai/gpt-5.4-mini"

    async def _prices(_s):                         # model_prices already AVERAGES upstream
        return {NAME: X}

    async def _detail(_s):                         # the 3 raw per-type rates (per 1M)
        return {NAME: {"in": 0.257, "out": 0.257, "cache": 0.257}}

    async def _range(_s, *a, **k):
        return [{"model": NAME, "tokens": 6_000_000, "reqs": 10}]
    monkeypatch.setattr(litellm, "model_prices", _prices)
    monkeypatch.setattr(litellm, "model_price_detail", _detail)
    monkeypatch.setattr(litellm, "per_model_range", _range)
    db.init()
    c = await _client()
    try:
        d = await (await c.get("/api/admin/model-kinds")).json()
        m = next(x for x in d["models"] if x["model"] == NAME)
        # per-type breakdown shown (un-doubled)
        assert m["in_1m"] == 0.257 and m["out_1m"] == 0.257 and m["cache_1m"] == 0.257
        # blended effective rate = X, NOT 2X (the doubling fix)
        assert round(m["eff_cost_1m"], 3) == 0.257
        # est cost = tokens × rate = 6M × 0.257/1M = €1.542 (not €3.084 doubled)
        assert abs(6_000_000 * m["eff_cost_1m"] / 1e6 - 1.542) < 1e-6
    finally:
        await c.close()


async def test_cost_controls_override_pins_rate(monkeypatch):
    """A pinned per-model cost override wins over LiteLLM's price (bypasses it entirely) —
    the escape hatch when LiteLLM's price is wrong. eff_cost_1m reflects the override."""
    monkeypatch.setattr(appmod, "_litellm_configured", lambda: True)
    NAME = "azure_ai/gpt-5-mini"

    async def _prices(_s):
        return {NAME: 0.194e-6}                    # LiteLLM says 0.194/1M

    async def _range(_s, *a, **k):
        return [{"model": NAME, "tokens": 22_000_000, "reqs": 30}]
    monkeypatch.setattr(litellm, "model_prices", _prices)
    monkeypatch.setattr(litellm, "model_price_detail", lambda _s: _aret({}))
    monkeypatch.setattr(litellm, "per_model_range", _range)
    db.init()
    db.model_cost_price_set(NAME, 0.30, time.time())    # pin €0.30/1M
    c = await _client()
    try:
        d = await (await c.get("/api/admin/model-kinds")).json()
        m = next(x for x in d["models"] if x["model"] == NAME)
        assert m["cost_overridden"] is True and m["cost_1m"] == 0.30
        assert round(m["eff_cost_1m"], 3) == 0.30       # override wins over LiteLLM's 0.194
    finally:
        await c.close()
        db.model_cost_price_delete(NAME)


async def _aret(v):
    return v


# ── vLLM backend ──────────────────────────────────────────────────────────────
def _vllm_stub_app(metrics_text: str | None = None, models_ok: bool = True):
    app = web.Application()

    async def health(_):
        return web.Response(text="")                 # vLLM returns an EMPTY 200 body

    async def models(_):
        if not models_ok:
            return web.Response(status=500)
        return web.json_response({"data": [{"id": "Qwen/Qwen3-Coder"}]})
    app.router.add_get("/health", health)
    app.router.add_get("/v1/models", models)
    if metrics_text is not None:
        async def metrics(_):
            return web.Response(text=metrics_text, content_type="text/plain")
        app.router.add_get("/metrics", metrics)
    return app


_VLLM_METRICS = (
    'vllm:num_requests_running{model_name="Q"} 3.0\n'
    'vllm:num_requests_waiting{model_name="Q"} 7.0\n'
    'vllm:gpu_cache_usage_perc{model_name="Q"} 0.42\n'
    'vllm:time_to_first_token_seconds_sum{model_name="Q"} 12.5\n'
    'vllm:time_to_first_token_seconds_count{model_name="Q"} 50.0\n'
    'vllm:num_preemptions_total{model_name="Q"} 2\n'
    'this line is malformed\n'
)


def test_vllm_parse_prom_sums_and_skips_junk():
    """The parser must fold label sets together and SKIP unparseable lines — a metrics
    format change has to degrade the panel, never raise and kill the collector loop."""
    m = vllm.parse_prom('a{x="1"} 2\na{x="2"} 3\nbroken\n# comment\nb 5\n')
    assert m["a"] == 5.0            # summed across label sets
    assert m["b"] == 5.0
    assert "broken" not in m
    assert vllm.parse_prom("") == {}


def test_vllm_parse_prom_skips_non_finite():
    """Review-fix (C5): Prometheus legitimately emits NaN / +Inf for un-observed gauges/summaries
    on some builds. float() accepts them, but they'd flow into the KPIs and then json.dumps emits
    bare `NaN`/`Infinity` tokens the browser's JSON.parse REJECTS — killing the whole vLLM panel.
    parse_prom must drop non-finite values (and still keep the finite ones)."""
    m = vllm.parse_prom('kv{} NaN\nwait{} +Inf\nneg{} -Inf\nrun{} 3.5\n')
    assert m.get("run") == 3.5
    assert "kv" not in m and "wait" not in m and "neg" not in m
    import math
    assert all(math.isfinite(v) for v in m.values())


def test_prune_uses_short_samples_retention_window(tmp_path, monkeypatch):
    """Review-fix (S1): `samples` is read only by db.recent() at startup, so it prunes on the
    short SAMPLES_RETENTION_HOURS window (capped by DB_RETENTION_HOURS) instead of keeping ~518k
    blobs at the full 720h — a row older than the samples window is dropped even though the raw
    metrics retention is far longer."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "prune.db"))
    monkeypatch.setattr(config, "DB_RETENTION_HOURS", 720)
    monkeypatch.setattr(config, "SAMPLES_RETENTION_HOURS", 6)
    db.init()
    now = time.time()
    with db._connect() as c:
        c.execute("INSERT INTO samples(ts, payload) VALUES (?, ?)", (now - 3 * 3600, "{}"))    # 3h — kept
        c.execute("INSERT INTO samples(ts, payload) VALUES (?, ?)", (now - 10 * 3600, "{}"))   # 10h — pruned
    removed = db.prune()
    assert removed == 1
    with db._connect() as c:
        assert c.execute("SELECT COUNT(*) FROM samples").fetchone()[0] == 1


def test_config_apply_refuses_non_scalar_tunable():
    """Review-fix (A6): config._apply must REFUSE (return without rebinding) a non-scalar
    tunable rather than just warn — a compound global mutated in place across the to_thread
    boundary is exactly the torn-read race the scalar-only invariant exists to prevent."""
    import inspect
    src = inspect.getsource(config._apply)
    i_check = src.index("isinstance(v, (int, float, bool, str))")
    i_bind = src.index("globals()[name] = v")
    assert "return" in src[i_check:i_bind], \
        "a non-scalar tunable must be refused (return) BEFORE the globals() rebind"


def test_vllm_avg_and_pick_helpers():
    """Histogram average comes from the _sum/_count pair; _pick accepts vLLM's renamed
    series (the V1 engine dropped the `vllm:` prefix on some) instead of pinning one."""
    m = {"h_sum": 12.5, "h_count": 50.0, "num_requests_running": 4.0}
    assert vllm._avg(m, "h") == 0.25
    assert vllm._avg({"h_sum": 1.0, "h_count": 0.0}, "h") is None   # no divide-by-zero
    assert vllm._pick(m, "vllm:num_requests_running", "num_requests_running") == 4.0
    assert vllm._pick(m, "nope") is None


async def test_vllm_sample_reads_metrics(monkeypatch):
    srv = TestServer(_vllm_stub_app(_VLLM_METRICS))
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "VLLM_BASE_URL", str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "VLLM_API_KEY", None)
        monkeypatch.setattr(config, "VLLM_METRICS_ENABLED", True)
        async with aiohttp.ClientSession() as s:
            out = await vllm.sample(s)
        assert out["available"] is True and out["metrics_available"] is True
        assert out["model"] == "Qwen/Qwen3-Coder"
        assert out["running"] == 3.0 and out["waiting"] == 7.0
        assert out["kv_cache_pct"] == 42.0          # 0-1 fraction rendered as a percent
        assert out["ttft_avg"] == 0.25
        assert out["preemptions"] == 2.0
    finally:
        await srv.close()


async def test_vllm_metrics_disabled_or_absent_still_available(monkeypatch):
    """VLLM_METRICS_ENABLED=0, or a server with no /metrics, must still report the backend
    as UP with its model — 'no live counters' is not 'backend down'. metrics_available
    tells the UI to explain the sparse panel instead of showing a wall of dashes."""
    # (a) flag off
    srv = TestServer(_vllm_stub_app(_VLLM_METRICS))
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "VLLM_BASE_URL", str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "VLLM_API_KEY", None)
        monkeypatch.setattr(config, "VLLM_METRICS_ENABLED", False)
        async with aiohttp.ClientSession() as s:
            out = await vllm.sample(s)
        assert out["available"] is True and out["metrics_available"] is False
        assert out["model"] == "Qwen/Qwen3-Coder" and out["waiting"] is None
    finally:
        await srv.close()
    # (b) no /metrics route at all
    srv2 = TestServer(_vllm_stub_app(None))
    await srv2.start_server()
    try:
        monkeypatch.setattr(config, "VLLM_BASE_URL", str(srv2.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "VLLM_METRICS_ENABLED", True)
        async with aiohttp.ClientSession() as s:
            out = await vllm.sample(s)
        assert out["available"] is True and out["metrics_available"] is False
    finally:
        await srv2.close()


async def test_vllm_unconfigured_and_down(monkeypatch):
    """No URL -> unconfigured (link hidden, not an error). URL set but unreachable ->
    available False with a real error, never an exception."""
    monkeypatch.setattr(config, "VLLM_BASE_URL", None)
    async with aiohttp.ClientSession() as s:
        assert (await vllm.sample(s)).get("available") is False
    monkeypatch.setattr(config, "VLLM_BASE_URL", "http://127.0.0.1:59996")
    monkeypatch.setattr(config, "VLLM_METRICS_ENABLED", True)
    async with aiohttp.ClientSession() as s:
        out = await vllm.sample(s)
    assert out["available"] is False and "conn" in str(out.get("error"))


async def test_vllm_page_and_nav(monkeypatch):
    """The /vllm page is auth-gated like every other dashboard, and its nav entry appears
    only when a base URL is configured (same auto-hide contract as ollama/llamacpp)."""
    monkeypatch.setattr(config, "VLLM_BASE_URL", "http://vllm:8000")
    c = await _client()
    try:
        assert (await c.get("/vllm")).status == 200
        nav = await (await c.get("/api/nav")).json()
        assert nav.get("vllm") is True
    finally:
        await c.close()
    monkeypatch.setattr(config, "VLLM_BASE_URL", None)
    appmod._backend_latest["vllm"] = {"available": False, "error": "unconfigured"}
    c2 = await _client()
    try:
        assert (await (await c2.get("/api/nav")).json()).get("vllm") is False
    finally:
        await c2.close()


def test_vllm_series_are_separate_from_llamacpp():
    """REGRESSION: the vLLM page was seeded from the llama.cpp template and inherited its
    tok/slots/kvcache series, so with BOTH engines running it plotted llama.cpp's numbers
    under a vLLM label. vLLM must own vrun/vwait/vkv, and the two must not cross."""
    snap = {"collectors": {
        "llamacpp": {"available": True, "predicted_per_second": 99.0,
                     "slots_active": 1, "kv_cache_pct": 11.0},
        "vllm": {"available": True, "running": 3, "waiting": 7, "kv_cache_pct": 42.0}}}
    row = appmod._metrics_row(snap)
    assert (row["vrun"], row["vwait"], row["vkv"]) == (3, 7, 42.0)   # vLLM's own
    assert row["tok"] == 99.0 and row["kvcache"] == 11.0             # llama.cpp untouched
    assert row["vkv"] != row["kvcache"], "vLLM must not chart llama.cpp's KV cache"


def test_vllm_metrics_row_none_when_down():
    """A down/unconfigured vLLM must yield None (a gap in the chart), never 0 — a real 0
    queue and 'no data' mean opposite things to anyone reading the graph."""
    row = appmod._metrics_row({"collectors": {"vllm": {"available": False}}})
    assert row["vrun"] is None and row["vwait"] is None and row["vkv"] is None


def test_vllm_metric_columns_persist_and_read_back(tmp_path, monkeypatch):
    """The new columns must exist on the raw + rollup tables (via the idempotent
    ALTER-TABLE migration) and survive a write/read round-trip, or the page's charts stay
    empty no matter what the collector reports."""
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", str(tmp_path / "v.db"))
    db.init()
    for col in ("vrun", "vwait", "vkv"):
        assert col in db._METRIC_COLS
        for tbl in ("metrics", "metrics_1m", "metrics_1h"):
            with db._connect() as conn:
                cols = {r[1] for r in conn.execute(f"PRAGMA table_info({tbl})")}
            assert col in cols, f"{col} missing from {tbl}"
    now = time.time()
    db.insert_metrics(now, {"vrun": 3, "vwait": 7, "vkv": 42.0})
    pts = db.series("1h", max_points=10)
    assert pts and any(p.get("vwait") == 7 for p in pts)


async def test_vllm_exported_to_prometheus():
    """vLLM must appear in /metrics: the up-gauge plus the queue/cache/latency series an
    external alert would actually fire on."""
    import metrics_prom
    snap = {"ts": 1.0, "collectors": {"vllm": {
        "available": True, "running": 3, "waiting": 7, "kv_cache_pct": 42.0,
        "ttft_avg": 0.25, "preemptions": 2}}}
    body = metrics_prom.render(snap, {"users": 0, "sessions": 0, "alerts": 0})
    assert "aimon_vllm_requests_waiting 7" in body
    assert "aimon_vllm_kv_cache_percent 42" in body
    assert "aimon_vllm_preemptions_total 2" in body
    assert 'aimon_backend_up{backend="vllm"} 1' in body or "vllm" in body


async def test_vllm_v1_metric_names_resolve(monkeypatch):
    """FIELD BUG: on a live vLLM V1 engine kv_cache_pct and tpot_avg came back None while
    ttft_avg worked — V1 renamed gpu_cache_usage_perc -> kv_cache_usage_perc and
    time_per_output_token_seconds -> inter_token_latency_seconds. Both spellings must
    resolve, or those KPIs read '—' against a perfectly healthy server."""
    v1 = ('vllm:kv_cache_usage_perc{model_name="Q"} 0.37\n'
          'vllm:inter_token_latency_seconds_sum{model_name="Q"} 5.0\n'
          'vllm:inter_token_latency_seconds_count{model_name="Q"} 100.0\n'
          'vllm:e2e_request_latency_seconds_sum{model_name="Q"} 210.0\n'
          'vllm:e2e_request_latency_seconds_count{model_name="Q"} 100.0\n'
          'vllm:prefix_cache_queries_total{model_name="Q"} 200.0\n'
          'vllm:prefix_cache_hits_total{model_name="Q"} 150.0\n')
    srv = TestServer(_vllm_stub_app(v1))
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "VLLM_BASE_URL", str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "VLLM_API_KEY", None)
        monkeypatch.setattr(config, "VLLM_METRICS_ENABLED", True)
        async with aiohttp.ClientSession() as s:
            out = await vllm.sample(s)
        assert out["kv_cache_pct"] == 37.0, "V1 kv_cache_usage_perc must resolve"
        assert out["tpot_avg"] == 0.05, "V1 inter_token_latency_seconds must resolve"
        assert out["e2e_avg"] == 2.1
        assert out["prefix_hit_pct"] == 75.0        # 150/200 counters, not a gauge
    finally:
        await srv.close()


async def test_vllm_v0_names_still_work(monkeypatch):
    """The V1 aliases must not break a V0 engine — both generations have to parse."""
    v0 = ('vllm:gpu_cache_usage_perc{model_name="Q"} 0.5\n'
          'vllm:time_per_output_token_seconds_sum{model_name="Q"} 4.0\n'
          'vllm:time_per_output_token_seconds_count{model_name="Q"} 100.0\n')
    srv = TestServer(_vllm_stub_app(v0))
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "VLLM_BASE_URL", str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "VLLM_METRICS_ENABLED", True)
        async with aiohttp.ClientSession() as s:
            out = await vllm.sample(s)
        assert out["kv_cache_pct"] == 50.0 and out["tpot_avg"] == 0.04
    finally:
        await srv.close()


def test_vllm_latency_series_persisted():
    """The new latency/cache charts need their own columns, else the graphs stay empty."""
    for col in ("vttft", "vtpot", "ve2e", "vqueue", "vhit"):
        assert col in db._METRIC_COLS, f"{col} missing from the metrics schema"
    row = appmod._metrics_row({"collectors": {"vllm": {
        "available": True, "ttft_avg": 0.25, "tpot_avg": 0.05,
        "e2e_avg": 2.1, "queue_avg": 0.01, "prefix_hit_pct": 75.0}}})
    assert row["vttft"] == 0.25 and row["ve2e"] == 2.1 and row["vhit"] == 75.0


def test_vllm_kv_cache_scales_without_guessing_units():
    """vLLM documents its *_perc cache series as a 0-1 FRACTION ("1 means 100 percent"),
    so a known series is scaled unconditionally. The previous magnitude guess (`<= 1.5`)
    turned a genuine 0.5 reading into 50% — a silent 100x error in the alarming
    direction."""
    src = (ROOT_DIR / "collectors" / "vllm.py").read_text(encoding="utf-8")
    # check the ASSIGNMENT, not the file: the comment above it deliberately names the
    # old `<= 1.5` guess to explain why it is gone, so a naive substring search matches
    # the explanation and passes/fails for the wrong reason.
    line = next(ln for ln in src.splitlines() if 'out["kv_cache_pct"]' in ln)
    assert "1.5" not in line, f"magnitude guess is back: {line.strip()}"
    assert "min(kv, 1.0) * 100" in line, f"fraction not scaled unconditionally: {line.strip()}"


def test_vllm_token_rates_from_cumulative_counters():
    """Token counters are cumulative since server start — they only rise and say nothing
    about now. They must be differentiated into tokens/sec, with no rate on the first
    sample (no baseline) and NONE on a counter reset (vLLM restart), never a negative."""
    vllm._prev_tokens.update({"ts": None, "prompt": None, "gen": None})
    assert vllm._token_rates(1000, 100) == (None, None)      # first sample: no baseline
    vllm._prev_tokens["ts"] -= 10.0                          # pretend 10s elapsed
    p, g = vllm._token_rates(1500, 200)
    assert p is not None and 40 < p < 60, p                  # ~500 tok / 10s
    assert g is not None and 5 < g < 15, g
    vllm._prev_tokens["ts"] -= 10.0
    assert vllm._token_rates(5, 1) == (None, None)           # counter reset -> no spike


async def test_vllm_multi_model_is_disclosed(monkeypatch):
    """parse_prom SUMS across label sets. That is right for one model and silently
    merges two, so the collector reports which models it saw and flags multi_model —
    otherwise a blended figure reads as a single model's."""
    two = ('vllm:num_requests_running{model_name="A"} 1.0\n'
           'vllm:num_requests_running{model_name="B"} 2.0\n')
    srv = TestServer(_vllm_stub_app(two))
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "VLLM_BASE_URL", str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "VLLM_METRICS_ENABLED", True)
        async with aiohttp.ClientSession() as s:
            out = await vllm.sample(s)
        assert out["running"] == 3.0                    # summed, as before
        assert out["multi_model"] is True
        assert out["metrics_models"] == ["A", "B"]      # and says which
    finally:
        await srv.close()
    one = 'vllm:num_requests_running{model_name="A"} 1.0\n'
    srv2 = TestServer(_vllm_stub_app(one))
    await srv2.start_server()
    try:
        monkeypatch.setattr(config, "VLLM_BASE_URL", str(srv2.make_url("")).rstrip("/"))
        async with aiohttp.ClientSession() as s:
            out = await vllm.sample(s)
        assert out["multi_model"] is False
    finally:
        await srv2.close()


def test_vllm_queue_depth_alert():
    """`waiting` is the saturation signal (running = busy, waiting = queued), so it needs
    a threshold — a dashboard only helps if someone is looking at it."""
    import alerts as _alerts
    snap = {"collectors": {"vllm": {"available": True, "waiting": 7.0}}}
    config.ALERT_VLLM_WAITING = 5.0
    try:
        keys = [k for k, _ in _alerts.evaluate(snap)]
        assert "vllm_queue" in keys
        snap["collectors"]["vllm"]["waiting"] = 2.0
        assert "vllm_queue" not in [k for k, _ in _alerts.evaluate(snap)]
        config.ALERT_VLLM_WAITING = 0.0                 # 0 disables, like the others
        snap["collectors"]["vllm"]["waiting"] = 999.0
        assert "vllm_queue" not in [k for k, _ in _alerts.evaluate(snap)]
    finally:
        config.ALERT_VLLM_WAITING = 0.0


async def test_vllm_awaiting_traffic_distinguished_from_broken(monkeypatch):
    """FIELD CASE: after a vLLM restart with no requests served, /metrics exposes only
    GAUGES — Prometheus clients create counters/histograms on first observation. Every
    token/latency/cache field then reads None, which is indistinguishable from a broken
    exporter if the UI just prints "—". The collector must flag the difference: one means
    "wait for a request", the other means "go debug"."""
    gauges_only = ('vllm:num_requests_running{model_name="Q"} 0.0\n'
                   'vllm:num_requests_waiting{model_name="Q"} 0.0\n')
    srv = TestServer(_vllm_stub_app(gauges_only))
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "VLLM_BASE_URL", str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "VLLM_METRICS_ENABLED", True)
        async with aiohttp.ClientSession() as s:
            out = await vllm.sample(s)
        assert out["available"] is True and out["metrics_available"] is True
        assert out["awaiting_traffic"] is True          # idle, NOT broken
        assert out["running"] == 0.0 and out["ttft_avg"] is None
    finally:
        await srv.close()
    # once traffic has flowed the counters exist and the flag clears
    with_traffic = gauges_only + 'vllm:prompt_tokens_total{model_name="Q"} 500\n'
    srv2 = TestServer(_vllm_stub_app(with_traffic))
    await srv2.start_server()
    try:
        monkeypatch.setattr(config, "VLLM_BASE_URL", str(srv2.make_url("")).rstrip("/"))
        async with aiohttp.ClientSession() as s:
            out = await vllm.sample(s)
        assert out["awaiting_traffic"] is False and out["prompt_tokens"] == 500
    finally:
        await srv2.close()


# ------------------------------------------------------------- network collector
def test_network_collector_rates_filter_and_totals(monkeypatch):
    """The Ethernet dashboard needs down/up RATES differentiated from the cumulative
    /proc/net/dev byte counters, virtual/overlay interfaces skipped by default, a
    'primary' NIC pick, and lifetime totals. First sample has no rate (no baseline);
    the second yields bytes/sec; a counter RESET (cur < prev) drops back to None
    rather than rendering a bogus negative spike."""
    # reset module delta state so the test is order-independent
    network._prev = {"ts": None, "ifaces": {}}
    t = {"v": 1000.0}
    monkeypatch.setattr(network.time, "time", lambda: t["v"])

    dev1 = {
        "lo":     {"rx_bytes": 5, "rx_packets": 0, "rx_errs": 0, "rx_drop": 0,
                   "tx_bytes": 5, "tx_packets": 0, "tx_errs": 0, "tx_drop": 0},
        "veth0":  {"rx_bytes": 9, "rx_packets": 0, "rx_errs": 0, "rx_drop": 0,
                   "tx_bytes": 9, "tx_packets": 0, "tx_errs": 0, "tx_drop": 0},
        "eth0":   {"rx_bytes": 1000, "rx_packets": 10, "rx_errs": 1, "rx_drop": 2,
                   "tx_bytes": 500, "tx_packets": 5, "tx_errs": 0, "tx_drop": 0},
    }
    monkeypatch.setattr(network, "_read_net_dev", lambda: dev1)
    monkeypatch.setattr(config, "NETWORK_IFACES", None)
    s1 = network.sample()
    assert s1["available"] is True
    names = [i["name"] for i in s1["interfaces"]]
    assert names == ["eth0"], f"virtual/loopback not filtered: {names}"
    assert s1["primary"] == "eth0"
    assert s1["rx_rate_total"] is None and s1["tx_rate_total"] is None  # first sample

    # +10s, eth0 +2000 rx / +1000 tx  -> 200 / 100 bytes/sec
    t["v"] = 1010.0
    dev2 = {k: dict(v) for k, v in dev1.items()}
    dev2["eth0"]["rx_bytes"] = 3000
    dev2["eth0"]["tx_bytes"] = 1500
    monkeypatch.setattr(network, "_read_net_dev", lambda: dev2)
    s2 = network.sample()
    assert s2["rx_rate_total"] == 200.0 and s2["tx_rate_total"] == 100.0
    eth = s2["interfaces"][0]
    assert eth["rx_rate"] == 200.0 and eth["tx_rate"] == 100.0
    assert eth["rx_errs"] == 1 and eth["rx_drop"] == 2
    assert s2["rx_bytes_total"] == 3000 and s2["tx_bytes_total"] == 1500

    # counter reset (reboot): cur < prev -> rate None, not a huge negative
    t["v"] = 1020.0
    dev3 = {k: dict(v) for k, v in dev2.items()}
    dev3["eth0"]["rx_bytes"] = 10
    dev3["eth0"]["tx_bytes"] = 4
    monkeypatch.setattr(network, "_read_net_dev", lambda: dev3)
    s3 = network.sample()
    assert s3["interfaces"][0]["rx_rate"] is None


def test_network_iface_whitelist_overrides_autoselect(monkeypatch):
    """NETWORK_IFACES pins an exact set — including one that autoselect would skip."""
    network._prev = {"ts": None, "ifaces": {}}
    dev = {"eth0": {"rx_bytes": 1, "rx_packets": 0, "rx_errs": 0, "rx_drop": 0,
                    "tx_bytes": 1, "tx_packets": 0, "tx_errs": 0, "tx_drop": 0},
           "tailscale0": {"rx_bytes": 7, "rx_packets": 0, "rx_errs": 0, "rx_drop": 0,
                          "tx_bytes": 7, "tx_packets": 0, "tx_errs": 0, "tx_drop": 0}}
    monkeypatch.setattr(network, "_read_net_dev", lambda: dev)
    monkeypatch.setattr(config, "NETWORK_IFACES", "tailscale0")
    s = network.sample()
    assert [i["name"] for i in s["interfaces"]] == ["tailscale0"]


def test_network_unavailable_when_proc_missing(monkeypatch):
    monkeypatch.setattr(network, "_read_net_dev", lambda: {})
    s = network.sample()
    assert s["available"] is False and "error" in s


def test_network_prefers_host_netns_pid1(monkeypatch):
    """To monitor the HOST from inside a container, the collector reads PID 1's netns
    (/proc/1/net/dev) first — that is the host root netns under `pid: host` / bare metal —
    then falls back to its own netns. An explicit MONITOR_NET_DEV overrides both."""
    monkeypatch.setattr(config, "NET_DEV_PATH", "")
    cands = network._net_dev_candidates()
    assert cands[0] == ("/proc/1/net/dev", "host"), "must try the host (PID 1) netns first"
    assert ("/proc/net/dev", "container") in cands, "must fall back to the container netns"
    monkeypatch.setattr(config, "NET_DEV_PATH", "/host/proc/1/net/dev")
    assert network._net_dev_candidates() == [("/host/proc/1/net/dev", "host")]


def test_network_read_sets_scope_and_falls_back(monkeypatch, tmp_path):
    """_read_net_dev records which source it read (host vs container) so the dashboard can
    label it, and skips an unreadable candidate to try the next."""
    host = tmp_path / "hostnet"
    host.write_text(
        "Inter-|   Receive                    |  Transmit\n"
        " face |bytes packets errs drop fifo frame compressed multicast|"
        "bytes packets errs drop fifo colls carrier compressed\n"
        "  eth0: 100 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0\n")
    # first candidate unreadable, second (our stand-in "host") readable → scope carried
    monkeypatch.setattr(network, "_net_dev_candidates",
                        lambda: [("/nonexistent/x/net/dev", "host"), (str(host), "container")])
    network._prev = {"ts": None, "ifaces": {}}
    dev = network._read_net_dev()
    assert "eth0" in dev and dev["eth0"]["rx_bytes"] == 100
    assert network._source["scope"] == "container"
    s = network.sample()
    assert s["available"] is True and s["scope"] == "container"


def test_network_series_columns_and_row():
    """net_down/net_up must be persisted metric columns fed by _metrics_row, or the
    Download/Upload charts plot nothing."""
    assert "net_down" in db._METRIC_COLS and "net_up" in db._METRIC_COLS
    snap = {"ts": 0, "collectors": {
        "host": {"available": True, "cpu_pct": 1, "mem_pct": 1,
                 "disk": {"pct": 1}, "load": [0, 0, 0]},
        "gpu": {"available": False}, "ollama": {"available": False},
        "litellm": {"available": False},
        "network": {"available": True, "rx_rate_total": 1234.0, "tx_rate_total": 56.0}}}
    row = appmod._metrics_row(snap)
    assert row["net_down"] == 1234.0 and row["net_up"] == 56.0
    snap["collectors"]["network"] = {"available": False}
    assert appmod._metrics_row(snap)["net_down"] is None


async def test_network_page_served_and_gated(monkeypatch):
    """/network is a first-class page: served in open mode, gated to /login when a
    token is set, and it carries the Download/Upload chart keys that map to the
    net_down/net_up columns."""
    monkeypatch.setattr(appmod, "_latest", {"ts": 0, "collectors": {}})
    c = await _client()
    try:
        r = await c.get("/network")
        assert r.status == 200
        html = await r.text()
        assert "Network" in html and "chart-grid" in html
        assert 'id="l-kpis"' in html and 'id="l-ifaces"' in html
        assert 'key:"net_down"' in html and 'key:"net_up"' in html
        assert 'href="/network"' in html
    finally:
        await c.close()
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "tok-net-1")
    c2 = await _client()
    try:
        r2 = await c2.get("/network", allow_redirects=False)
        assert r2.status == 302 and "/login" in r2.headers.get("Location", "")
        r = await c2.get("/network?token=tok-net-1", allow_redirects=False)
        assert r.status == 302
    finally:
        await c2.close()


# ───────────────── Spend history persistence (past LiteLLM's 7-day cap) ─────────
def test_spend_daily_upsert_range_prune_idempotent():
    """db.spend_daily is the store that lets the Spend chart outlast LiteLLM's 7-day
    /global/activity window. UPSERT must REPLACE a day (source reports the whole day —
    never additive), range must filter by date, prune must drop past the horizon."""
    db.init()
    with db._connect() as conn:
        conn.execute("DELETE FROM spend_daily")
    db.spend_daily_upsert([
        {"date": "2026-05-10", "requests": 100, "tokens": 1_000_000, "real_cost": 1.5,
         "est_cost": 0.5, "tokens_ext": 600_000, "tokens_int": 400_000},
        {"date": "2026-05-11", "requests": 120, "tokens": 1_200_000},
    ], 1.0)
    # re-report the same day with new totals → REPLACE, not add
    db.spend_daily_upsert([{"date": "2026-05-10", "requests": 175, "tokens": 1_750_000}], 2.0)
    rows = db.spend_daily_range("2026-05-01", "2026-05-31")
    assert len(rows) == 2
    r0 = next(r for r in rows if r["date"] == "2026-05-10")
    assert r0["requests"] == 175 and r0["tokens"] == 1_750_000, "upsert must overwrite"
    assert db.spend_daily_range("2026-05-11", "2026-05-11") == \
        [r for r in rows if r["date"] == "2026-05-11"]
    # a blank date is skipped, never crashes
    db.spend_daily_upsert([{"date": "", "requests": 9}], 3.0)
    assert len(db.spend_daily_range("2026-05-01", "2026-05-31")) == 2


async def test_spend_series_merges_stored_history_beyond_live_window(monkeypatch):
    """The core fix: LiteLLM only returns the last few days live, but the chart must show
    the full stored history. Seed spend_daily with a day 20 days back, have LiteLLM return
    ONLY today — the 30d series must include BOTH, and today's live values must be written
    through to the store."""
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "sp-hist-123456")
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    now = time.time()
    today = time.strftime("%Y-%m-%d", time.gmtime(now))
    old = time.strftime("%Y-%m-%d", time.gmtime(now - 20 * 86400))

    db.init()
    with db._connect() as conn:
        conn.execute("DELETE FROM spend_daily")
    # stored history LiteLLM no longer returns (20 days ago)
    db.spend_daily_upsert([{"date": old, "requests": 500, "tokens": 9_000_000,
                            "real_cost": 4.0, "est_cost": 1.0,
                            "tokens_ext": 5_000_000, "tokens_int": 4_000_000}], now)

    async def _daily(session, s, e):          # LiteLLM live window: ONLY today
        return [{"date": today, "requests": 30, "tokens": 300_000, "spend": 0.0}]

    async def _prices(session):
        return {"gpt-4o": 0.001}

    async def _permodel(session, s, e, ov=None):
        return [{"model": "gpt-4o", "tokens": 300_000, "reqs": 30,
                 "internal": False, "cost_kind": "real"}]

    async def _daily_cost(session, s, e, prices, ov=None):
        return {today: {"real": 0.30, "est": 0.0}}

    async def _daily_tok(session, s, e, ov=None):
        return {today: {"ext": 300_000, "int": 0}}
    monkeypatch.setattr(litellm, "spend_activity", _daily)
    monkeypatch.setattr(litellm, "model_prices", _prices)
    monkeypatch.setattr(litellm, "per_model_range", _permodel)
    monkeypatch.setattr(litellm, "per_model_daily_cost", _daily_cost)
    monkeypatch.setattr(litellm, "per_model_daily_tokens", _daily_tok)

    hdr = {"Authorization": "Bearer sp-hist-123456"}
    c = await _client()
    try:
        d = await (await c.get("/api/spend/series?window=30d", headers=hdr)).json()
        assert d["available"] is True
        dates = {time.strftime("%Y-%m-%d", time.gmtime(p["t"])) for p in d["points"]}
        assert old in dates, f"stored history missing from chart: {sorted(dates)}"
        assert today in dates
        # the old day's tokens (stored) are present — proof the merge fed the buckets
        oldpt = next(p for p in d["points"]
                     if time.strftime("%Y-%m-%d", time.gmtime(p["t"])) == old)
        assert oldpt["tokens"] == 9_000_000
        # write-through: today's live values were persisted for next time
        stored_today = [r for r in db.spend_daily_range(today, today)]
        assert stored_today and stored_today[0]["requests"] == 30
    finally:
        await c.close()
        with db._connect() as conn:
            conn.execute("DELETE FROM spend_daily")


async def test_capture_spend_daily_persists_without_page_view(monkeypatch):
    """'Store everything from now on': the background sampler must capture the day into
    db.spend_daily on its own cadence — NOT only when someone opens /spend. Drive the
    capture helper directly with mocked LiteLLM and assert the rows land in the store."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    db.init()
    with db._connect() as conn:
        conn.execute("DELETE FROM spend_daily")

    async def _daily(session, s, e):
        return [{"date": "2026-07-02", "requests": 42, "tokens": 2_000_000, "spend": 0.0},
                {"date": "2026-07-03", "requests": 55, "tokens": 3_000_000, "spend": 0.0}]

    async def _prices(session):
        return {"gpt-4o": 0.001}

    async def _dc(session, s, e, prices, ov=None):
        return {"2026-07-02": {"real": 0.20, "est": 0.0}}

    async def _dt(session, s, e, ov=None):
        return {"2026-07-02": {"ext": 2_000_000, "int": 0}}
    monkeypatch.setattr(litellm, "spend_activity", _daily)
    monkeypatch.setattr(litellm, "model_prices", _prices)
    monkeypatch.setattr(litellm, "per_model_daily_cost", _dc)
    monkeypatch.setattr(litellm, "per_model_daily_tokens", _dt)

    await appmod._capture_spend_daily(None, time.time())
    rows = {r["date"]: r for r in db.spend_daily_range("2026-07-01", "2026-07-31")}
    assert set(rows) == {"2026-07-02", "2026-07-03"}, "background capture must store every live day"
    assert rows["2026-07-02"]["requests"] == 42 and rows["2026-07-02"]["real_cost"] == 0.20
    assert rows["2026-07-03"]["tokens"] == 3_000_000       # persisted even with no cost row
    with db._connect() as conn:
        conn.execute("DELETE FROM spend_daily")


async def test_capture_spend_daily_noop_without_litellm(monkeypatch):
    """No LiteLLM configured → capture is a clean no-op (no crash, nothing written)."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "")
    await appmod._capture_spend_daily(None, time.time())   # must not raise


async def test_litellm_lite_derives_throughput_rates(monkeypatch):
    """Lite mode has no per-request rows, but /global/activity gives the day's running
    totals — so req/s and total tok/s are derived as the delta between polls (the fix for
    the empty /litellm throughput charts in lite mode). First poll has no baseline → no
    rate; a UTC-midnight reset (totals roll back) suppresses the rate, not a huge spike.
    Prompt/completion split + latency stay unavailable in lite (no per-request data)."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://x")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk")
    litellm._prev_lite = {"ts": None, "requests": None, "tokens": None}
    act = {"v": {"sum_api_requests": 1000, "sum_total_tokens": 50000}}

    async def _fj(session, url, headers=None, timeout_s=None):
        if "/global/activity/model" in url:
            return ([], None)
        if "/global/activity" in url:
            return (act["v"], None)
        return ([], None)                       # /global/spend/keys
    monkeypatch.setattr(litellm, "fetch_json", _fj)

    o1 = await litellm._lite_spend(None, "http://x", {}, 1000.0)   # first: no baseline
    assert "req_rate" not in o1 and "tok_total_rate" not in o1
    assert o1["requests_window"] == 1000 and o1["tokens_today"] == 50000

    act["v"] = {"sum_api_requests": 1600, "sum_total_tokens": 80000}  # +600 req / +30k tok in 60s
    o2 = await litellm._lite_spend(None, "http://x", {}, 1060.0)
    assert o2["req_rate"] == 10.0              # 600 / 60
    assert o2["tok_total_rate"] == 500.0       # 30000 / 60
    assert o2.get("tok_in_rate") is None and o2.get("wait_avg_ms") is None  # no split/latency

    act["v"] = {"sum_api_requests": 5, "sum_total_tokens": 100}     # midnight reset
    o3 = await litellm._lite_spend(None, "http://x", {}, 1120.0)
    assert "req_rate" not in o3 and "tok_total_rate" not in o3      # cur<prev → suppressed


def test_toktot_series_column_and_row():
    """The total-tokens/s series must be a persisted metric column fed by _metrics_row,
    or the new /litellm 'Tokens/s' chart plots nothing."""
    import app as appmod, db as dbmod
    assert "toktot" in dbmod._METRIC_COLS
    snap = {"ts": 0, "collectors": {
        "host": {"available": True, "cpu_pct": 1, "mem_pct": 1, "disk": {"pct": 1}, "load": [0, 0, 0]},
        "gpu": {"available": False}, "ollama": {"available": False},
        "litellm": {"available": True, "tok_total_rate": 42.5}}}
    assert appmod._metrics_row(snap)["toktot"] == 42.5
    snap["collectors"]["litellm"] = {"available": False}
    assert appmod._metrics_row(snap)["toktot"] is None


def test_spend_capture_decoupled_from_sampling_loop():
    """§6 observer-effect: the hourly spend_daily capture must NOT run inline in the main
    sampling loop (its bounded LiteLLM calls stalled the tick — snapshot age spiked to
    ~60s on a busy proxy). It runs in its own task (_spend_capture_loop), registered at
    startup and cancelled on cleanup, so it can never wedge sampling."""
    import inspect
    import app as a
    samp = inspect.getsource(a._sampling_loop)
    assert "_capture_spend_daily" not in samp, "capture must not be inline in _sampling_loop"
    loop = inspect.getsource(a._spend_capture_loop)
    assert "_capture_spend_daily" in loop and "3600" in loop, "capture loop must run it hourly"
    assert "wait_for" in loop, "each capture must stay bounded"
    startup = inspect.getsource(a._on_startup)
    cleanup = inspect.getsource(a._on_cleanup)
    assert "_spend_capture_loop" in startup and "_SPEND_CAP" in startup
    assert "_SPEND_CAP" in cleanup, "capture task must be cancelled on cleanup"


def test_sampling_loop_feeds_vllm_realtime_into_model_conc_series():
    """The sampling loop must call insert_model_conc_series with vLLM's OWN running/waiting
    gauges, gated on availability + a single resolvable model + at least one gauge present —
    and skip a multi_model reading (summed across models; attributing it to just the first
    model name would be wrong, not merely imprecise)."""
    import inspect
    import app as a
    # The per-tick DB writes (incl. the vLLM real-time feed) were extracted into
    # _persist_tick so the sampling loop can run them off-loop via asyncio.to_thread;
    # the loop must still call it, and the feed must still live in that path.
    samp = inspect.getsource(a._sampling_loop)
    assert "_persist_tick" in samp, "sampling loop must delegate per-tick writes to _persist_tick"
    persist = inspect.getsource(a._persist_tick)
    assert "insert_model_conc_series" in persist
    assert '.get("vllm"' in persist and 'coll = snap["collectors"]' in persist
    assert 'get("running")' in persist and 'get("waiting")' in persist, "must feed vLLM's own gauges"
    assert "multi_model" in persist, "must skip when the reading is summed across models"


async def test_service_toggle_disables_backend_everywhere(monkeypatch):
    """Settings → Services can turn a backend OFF. When off: its collector reports the
    'unconfigured' sentinel (so it is not polled and, per alerts.py, fires NO down-alert),
    and _configured() hides it (nav link + page gate). Covers litellm/ollama/llamacpp/vllm."""
    import app as a
    from collectors import ollama, llamacpp, vllm, litellm as llm
    cases = [("OLLAMA_ENABLED", ollama, "ollama"),
             ("LLAMACPP_ENABLED", llamacpp, "llamacpp"),
             ("VLLM_ENABLED", vllm, "vllm"),
             ("LITELLM_ENABLED", llm, "litellm")]
    for flag, mod, name in cases:
        monkeypatch.setattr(config, flag, False)
        r = await mod.sample(None)                       # gate returns before any I/O
        assert r == {"available": False, "error": "unconfigured"}, f"{name} not gated"
        monkeypatch.setattr(a, "_latest", {"ts": 0, "collectors": {name: r}})
        assert a._configured(name, True) is False, f"{name} still shown in nav when off"
        monkeypatch.setattr(config, flag, True)          # re-enable → flag no longer gates
        monkeypatch.setattr(a, "_latest", {"ts": 0, "collectors": {}})   # no sample yet
        assert a._configured(name, True) is True         # falls back to env_ok, not gated


async def test_service_toggle_off_fires_no_down_alert(monkeypatch):
    """The whole point for the operator: a disabled backend must not show in alarms.
    A backend reporting 'unconfigured' (what the toggle produces) yields no down: breach."""
    import alerts
    snap = {"collectors": {
        "ollama": {"available": False, "error": "unconfigured"},        # toggled OFF
        "llamacpp": {"available": False, "error": "conn refused"},      # genuinely down
    }}
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_AFTER", 1)  # this test is about WHICH
    alerts.reset_down_streaks()                                # backends alarm, not the streak
    keys = [k for k, _ in alerts.evaluate(snap)]
    assert "down:ollama" not in keys, "disabled backend must not alarm"
    assert "down:llamacpp" in keys, "a genuinely-down backend still alarms"


async def test_litellm_disabled_hides_spend(monkeypatch):
    """LITELLM_ENABLED off hides the Spend surface even with a URL configured."""
    import app as a
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_ENABLED", False)
    assert a._litellm_configured() is False
    monkeypatch.setattr(config, "LITELLM_ENABLED", True)
    assert a._litellm_configured() is True


def test_concurrency_by_key_ignores_idle_keys_in_lite_mode():
    """The 'Concurrent LLM work — by key' chart showed bands for keys that aren't being
    used: in lite mode key_series holds CUMULATIVE per-key spend, and the old split
    weighted the instantaneous concurrency by that lifetime total, so a key that only
    spent in the PAST got a phantom band. With cumulative=True the weight is the per-bucket
    spend DELTA (recent activity), so an idle-but-once-active key gets ZERO."""
    import time
    import db as dbmod
    dbmod.init()
    now = time.time()
    with dbmod._connect() as c:
        c.execute("DELETE FROM metrics")
        c.execute("DELETE FROM key_series")
        for i, t in enumerate([now - 90, now - 65, now - 40, now - 15]):
            c.execute("INSERT INTO metrics(ts,conc) VALUES(?,?)", (t, 2.0))
            c.execute("INSERT INTO key_series(ts,label,reqs) VALUES(?,?,?)", (t, "idle", 100.0))
            c.execute("INSERT INTO key_series(ts,label,reqs) VALUES(?,?,?)", (t, "active", float(i + 1)))
    try:
        # buggy path: lifetime total → idle key soaks up the concurrency
        old = {s["label"]: sum(s["data"])
               for s in dbmod.concurrency_by_key("1h", "conc", end=now)["series"]}
        assert old.get("idle", 0) > old.get("active", 0), "precondition: old logic favours idle key"
        # fixed path: per-bucket delta → idle key contributes nothing
        fix = {s["label"]: sum(s["data"])
               for s in dbmod.concurrency_by_key("1h", "conc", end=now, cumulative=True)["series"]}
        assert fix.get("idle", 0) == 0.0, f"idle key must get no band, got {fix.get('idle')}"
        assert fix.get("active", 0) > 0, "actively-spending key should be attributed the work"
    finally:
        with dbmod._connect() as c:
            c.execute("DELETE FROM metrics")
            c.execute("DELETE FROM key_series")


def test_concurrency_by_key_hides_when_no_activity_despite_baseline_backlog():
    """The live symptom: an idle hour (zero requests) still showed bands because the
    backlog aggregate sits at a constant 1 (LiteLLM counting the monitor's own probe).
    With no per-key activity to attribute, the by-key result must be EMPTY (so the chart
    auto-hides) rather than dumping that baseline into 'Other'."""
    import time
    import db as dbmod
    dbmod.init()
    now = time.time()
    with dbmod._connect() as c:
        c.execute("DELETE FROM metrics")
        c.execute("DELETE FROM key_series")
        for t in (now - 90, now - 65, now - 40, now - 15):
            c.execute("INSERT INTO metrics(ts,conc,backlog) VALUES(?,?,?)", (t, 1.0, 1.0))
            # keys with lifetime spend but NO change across the window = idle
            c.execute("INSERT INTO key_series(ts,label,reqs) VALUES(?,?,?)", (t, "key-r", 9.2))
            c.execute("INSERT INTO key_series(ts,label,reqs) VALUES(?,?,?)", (t, "leonor", 8.8))
    try:
        for metric in ("conc", "backlog"):
            out = dbmod.concurrency_by_key(metric=metric, window="1h", cumulative=True, end=now)
            assert out["series"] == [], f"{metric}: idle window must yield empty (hidden) chart"
    finally:
        with dbmod._connect() as c:
            c.execute("DELETE FROM metrics")
            c.execute("DELETE FROM key_series")


async def test_backlog_subtracts_own_probe(monkeypatch):
    """LiteLLM counts the monitor's own /health/backlog request as in-flight, so an idle
    proxy reports a constant 1 — which floods the by-key attribution's 'Other' band every
    idle bucket. _fetch_backlog subtracts that self-probe so idle reads 0 and real backlog
    is preserved; the toggle disables it for a build that doesn't self-count."""
    from collectors import litellm as L

    async def _fj(n):
        async def f(session, url, headers=None, timeout_s=None):
            return ({"in_flight_requests": n}, None)
        return f
    monkeypatch.setattr(config, "LITELLM_BACKLOG_PROBE_SELFCOUNT", True)
    monkeypatch.setattr(L, "fetch_json", await _fj(1))
    assert await L._fetch_backlog(None, "x", {}) == 0        # idle: just the probe → 0
    monkeypatch.setattr(L, "fetch_json", await _fj(3))
    assert await L._fetch_backlog(None, "x", {}) == 2        # 3 in-flight − our probe = 2
    monkeypatch.setattr(config, "LITELLM_BACKLOG_PROBE_SELFCOUNT", False)
    assert await L._fetch_backlog(None, "x", {}) == 3        # toggle off → raw count


def test_zooming_into_a_spike_keeps_its_key_attribution():
    """FIELD BUG: on the 24h view "Concurrent LLM work — by key" attributed a spike to a
    key (blue band), but zooming into that same spike showed 100% "Other".

    Cause: the per-key weight is the STEP of a cumulative counter, and the baseline was the
    FIRST sample INSIDE the window. A zoomed window holds only one per-key sample, so that
    sample WAS the baseline, scored 0, and the whole aggregate fell into "Other". The
    baseline now comes from the sample BEFORE the window, so the attribution is identical
    at any zoom level."""
    import time
    import db as dbmod
    dbmod.init()
    now = time.time()
    spike = now - 300                      # the moment the key spent (and conc rose)
    with dbmod._connect() as c:
        c.execute("DELETE FROM metrics")
        c.execute("DELETE FROM key_series")
        for t in [now - 1800 + 60 * i for i in range(30)]:
            conc = 5.0 if abs(t - spike) < 1e-6 else 0.0
            c.execute("INSERT INTO metrics(ts,conc) VALUES(?,?)", (t, conc))
            # cumulative spend: flat 1.0, steps to 1.143 at the spike and stays there
            c.execute("INSERT INTO key_series(ts,label,reqs) VALUES(?,?,?)",
                      (t, "pedro", 1.0 if t < spike else 1.143))
    try:
        wide = {s["label"]: sum(s["data"]) for s in dbmod.concurrency_by_key(
            "1h", "conc", end=now, cumulative=True)["series"]}
        assert wide.get("pedro", 0) > 0, "precondition: wide view attributes the spike"

        # zoom onto the spike: a 60s window whose ONLY per-key sample is the spike itself
        zoom = {s["label"]: sum(s["data"]) for s in dbmod.concurrency_by_key(
            "custom:60", "conc", end=spike + 30, cumulative=True)["series"]}
        assert zoom.get("pedro", 0) > 0, \
            f"zoomed view lost the key attribution (all 'Other'): {zoom}"
        assert zoom.get("Other", 0) == 0, f"zoomed spike must not fall into Other: {zoom}"
    finally:
        with dbmod._connect() as c:
            c.execute("DELETE FROM metrics")
            c.execute("DELETE FROM key_series")


def test_prewindow_baseline_does_not_invent_activity_on_a_flat_counter():
    """The pre-window baseline must not manufacture a band: a key whose cumulative value is
    unchanged across the window (and across the boundary) still scores 0, and a counter that
    went BACKWARDS before the window (re-based key) contributes 0, not a negative/huge step."""
    import time
    import db as dbmod
    dbmod.init()
    now = time.time()
    with dbmod._connect() as c:
        c.execute("DELETE FROM metrics")
        c.execute("DELETE FROM key_series")
        for t in [now - 600 + 60 * i for i in range(10)]:
            c.execute("INSERT INTO metrics(ts,conc) VALUES(?,?)", (t, 2.0))
            c.execute("INSERT INTO key_series(ts,label,reqs) VALUES(?,?,?)", (t, "flat", 7.0))
            # 'rebased' drops from 9 to 3 halfway: a backwards step is unknowable → 0
            c.execute("INSERT INTO key_series(ts,label,reqs) VALUES(?,?,?)",
                      (t, "rebased", 9.0 if t < now - 300 else 3.0))
    try:
        out = {s["label"]: sum(s["data"]) for s in dbmod.concurrency_by_key(
            "custom:120", "conc", end=now, cumulative=True)["series"]}
        assert out.get("flat", 0) == 0, f"flat counter must not get a band: {out}"
        assert out.get("rebased", 0) == 0, f"backwards step must score 0, got {out}"
    finally:
        with dbmod._connect() as c:
            c.execute("DELETE FROM metrics")
            c.execute("DELETE FROM key_series")


def test_custom_window_secs_parsed_and_clamped():
    """Drag-to-zoom encodes a range as WIN='custom:<secs>'. window_secs must return those
    seconds, clamped to [CUSTOM_WIN_MIN, CUSTOM_WIN_MAX] so a bogus/huge drag can't blow up
    the query, and named windows still resolve normally."""
    assert db.window_secs("custom:3600") == 3600.0
    assert db.window_secs("custom:5") == float(db.CUSTOM_WIN_MIN)          # sub-minimum → floor
    assert db.window_secs("custom:99999999999") == float(db.CUSTOM_WIN_MAX)  # over-max → ceiling
    assert db.window_secs("custom:abc") == db.window_secs("1h")            # unparseable → named path
    assert db.window_secs("1h") == 3600.0                                  # named still works


def test_custom_window_rejects_non_finite_without_raising():
    """SECURITY/robustness: the 'custom:<secs>' token is caller-supplied (a query param).
    `int(float("inf"))` / `int(float("1e400"))` raise OverflowError — which, if uncaught,
    500s the request and logs a traceback on a crafted `?window=custom:inf`. Every non-finite
    / unparseable form must degrade to the page default, never raise."""
    for tok in ("custom:inf", "custom:1e400", "custom:-inf", "custom:nan", "custom:1e309"):
        assert db._custom_secs(tok) is None, f"{tok} must not parse to a number"
        assert db.norm_window(tok, "1h") == "1h", f"{tok} must fall back to the default"
        assert db.window_secs(tok) == db.window_secs("1h"), f"{tok} must span the default window"


def test_norm_window_accepts_custom_or_falls_back():
    """norm_window is the endpoint gate: it must pass a valid custom token through, canonicalise
    it (clamped int), keep named windows, and reject junk to the page default."""
    assert db.norm_window("custom:3600", "1h") == "custom:3600"
    assert db.norm_window("custom:5", "1h") == "custom:%d" % db.CUSTOM_WIN_MIN
    assert db.norm_window("24h", "1h") == "24h"
    assert db.norm_window("bogus", "1h") == "1h"
    assert db.norm_window("custom:", "24h") == "24h"


def test_key_delta_series_monotonic_under_repeated_rebases():
    """key_delta_series backs the 'only rises' all-time chart's lite fallback, so its
    monotonicity must hold for MULTIPLE keys and repeated re-bases in one series — not
    just the single climb-then-reset the timeline test covers."""
    _clear_key_series()
    now = time.time()
    # two keys, each re-basing at different points; alice also plateaus (idle stretch)
    a = [10.0, 40.0, 40.0, 5.0, 25.0, 25.0, 2.0, 12.0]     # up, flat, reset, up, flat, reset, up
    b = [3.0, 3.0, 9.0, 9.0, 1.0, 1.0, 6.0, 20.0]          # flat, up, flat, reset, flat, up
    for i in range(len(a)):
        db.insert_key_series(now - len(a) * 300 + i * 300,
                             [{"key": "ka", "alias": "alice", "reqs": a[i]},
                              {"key": "kb", "alias": "bob", "reqs": b[i]}])
    res = db.key_delta_series("1h")
    for lab in ("alice", "bob"):
        s = [p.get(lab) for p in res["points"] if p.get(lab) is not None]
        assert s == sorted(s), f"{lab} not monotonic: {s}"
        assert s[0] == 0.0, f"{lab} must start at 0 (window start): {s[0]}"
    # sums only the UPWARD movement: alice 30+20+10 = 60, never crediting the resets
    sa = [p.get("alice") for p in res["points"] if p.get("alice") is not None]
    assert sa[-1] == 60.0, f"alice upward total wrong: {sa[-1]}"


def test_key_delta_series_empty_when_no_keys():
    """The fallback guards on `points` being non-empty; an empty window must return a
    clean empty shape, not raise, so keyrequests_handler falls through safely."""
    _clear_key_series()
    out = db.key_delta_series("1h", 200, top_n=10, end=time.time())
    assert out == {"labels": [], "points": []}


def test_key_cumulative_full_mode_path_unchanged_and_monotonic(tmp_path, monkeypatch):
    """The full-mode primary path (per-key REQUESTS from the daily rollup) was already
    monotonic by construction and this fix must not touch it — a regression guard so the
    lite-fallback change can't be blamed for the full-mode chart later."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "kc.db"))
    db.init()
    now = 1_800_000_000.0
    # daily rollup rows: per-day request counts (already deltas) → cumulative only rises
    with db._connect() as conn:
        for i, day in enumerate(range(5)):
            conn.execute(
                "INSERT INTO spend_model_user_daily(day,model,key,alias,cost,tokens,reqs) "
                "VALUES (?,?,?,?,?,?,?)",
                (f"2026-07-0{day+1}", "m", "hA", "alice", 1.0, 100, 3 + i))
    out = db.key_cumulative(metric="reqs", days_back=3650, top_n=10, end=now)
    s = [p.get("alice") for p in out["points"] if p.get("alice") is not None]
    assert s == sorted(s) and s[-1] == 3 + 4 + 5 + 6 + 7, f"full-mode cumulative wrong: {s}"


async def test_scan_heavy_reads_run_off_the_event_loop(monkeypatch):
    """PHASE-1 observer-effect (§6 covers SERVES, not just pulls): a scan-heavy DB read must
    not run on the event loop — a large/custom-window query would otherwise stall the sampler.
    Proven by capturing the thread `db.series` executes on: off-loop (asyncio.to_thread) runs
    it in a worker thread, never the loop's main thread. A regression to a blocking inline
    call would run it on the main thread and fail this."""
    import threading
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "supersecrettoken1234")
    main = threading.main_thread()
    seen = {}
    orig = db.series

    def spy(*a, **k):
        seen["on_main"] = threading.current_thread() is main
        return orig(*a, **k)

    monkeypatch.setattr(db, "series", spy)
    c = await _client()
    try:
        r = await c.get("/api/series?window=1h&token=supersecrettoken1234")
        assert r.status == 200
        assert seen.get("on_main") is False, \
            "db.series ran on the event loop — a scan-heavy read must go through to_thread"
    finally:
        await c.close()


def test_pos_step_kernel_is_reset_safe():
    """PHASE-2 (#5): the reset-safe positive-step kernel every per-key delta chart shares.
    0 on the first reading and on any backwards move (re-based counter); the plain increase
    otherwise."""
    assert db._pos_step(5.0, None) == 0.0          # first reading — no baseline
    assert db._pos_step(5.0, 3.0) == 2.0           # normal increase
    assert db._pos_step(3.0, 5.0) == 0.0           # counter re-based DOWN → 0, not -2
    assert db._pos_step(5.0, 5.0) == 0.0           # unchanged → 0


def test_three_per_key_read_paths_agree_on_a_reset(tmp_path, monkeypatch):
    """The three delta read paths (`key_series_window_delta`, `key_delta_series`,
    `concurrency_by_key`) now derive their step from the ONE `_pos_step` kernel, so they must
    treat a re-based counter identically: a key that climbs, drops (reset), then climbs again
    counts only the two positive climbs — never the drop — in all three."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    now = 1_800_000_000.0
    # one key 'k', cumulative spend: 2 → 6 (climb +4), 6 → 1 (reset), 1 → 4 (climb +3)
    seq = [2.0, 6.0, 1.0, 4.0]
    with db._connect() as c:
        c.execute("DELETE FROM metrics"); c.execute("DELETE FROM key_series")
        for i, v in enumerate(seq):
            t = now - 1800 + i * 300
            c.execute("INSERT INTO metrics(ts,conc) VALUES(?,?)", (t, 3.0))
            c.execute("INSERT INTO key_series(ts,label,reqs) VALUES(?,?,?)", (t, "k", v))
    end = now
    # (1) window_delta: sum of positive steps = 4 + 3 = 7 (the drop contributes 0)
    wd = db.key_series_window_delta("1h", 10, end=end)
    assert wd["labels"] == ["k"] and abs(wd["deltas"][0] - 7.0) < 1e-6, wd
    # (2) delta_series: the running total ends at 7, never dips below its running max
    ds = db.key_delta_series("1h", 300, top_n=10, end=end)
    vals = [p.get("k") for p in ds["points"] if p.get("k") is not None]
    assert vals == sorted(vals), f"cumulative line must never fall (reset-safe): {vals}"
    assert abs(vals[-1] - 7.0) < 1e-6, vals
    # (3) concurrency_by_key (cumulative basis): the reset bucket contributes no weight, so
    #     the key is attributed only where it actually climbed — total weight > 0, never NaN
    ck = db.concurrency_by_key("1h", "conc", end=end, cumulative=True)
    kseries = [s for s in ck["series"] if s["label"] == "k"]
    assert kseries and sum(kseries[0]["data"]) > 0, ck
    with db._connect() as c:
        c.execute("DELETE FROM metrics"); c.execute("DELETE FROM key_series")


def _seed_spend_mu(tmp_path, monkeypatch, rows, owners):
    """Seed the spend_model_user_daily rollup + known_keys for the rollup-backed by-key
    charts (key_cumulative / key_cost_window). rows: [(label, cost, reqs)]."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "mu.db"))
    db.init()
    now = 1_800_000_000.0
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    db.known_keys_upsert(owners, now)
    with db._connect() as conn:
        for lab, cost, reqs in rows:
            conn.execute("INSERT INTO spend_model_user_daily(day,model,key,alias,cost,tokens,reqs) "
                         "VALUES(?,?,?,?,?,?,?)", (day, "m", lab, lab, cost, 1000, reqs))
    return now


def test_key_cost_window_folds_hidden_keys_into_other(tmp_path, monkeypatch):
    """PHASE-2 gap fix: the Spend 'Cost by key' chart (`key_cost_window`) reads the
    spend_model_user_daily rollup and used to skip EVERY label filter — showing the operator's
    excluded key AND ownerless keys as their own bands. Excluded/hidden keys now fold into
    'Other', so the window's total spend is preserved while they lose their named band.

    F2: a label PRESENT in the spend rollup is self-evidence of a real key (it billed a
    completed request), so an unconfirmed-by-/key/list label ('garbage' here) is now ATTRIBUTED,
    not folded — only operator-excluded and hidden-unassigned keys fold."""
    monkeypatch.setattr(config, "EXCLUDE_KEYS", ["selfkey"])
    monkeypatch.setattr(config, "HIDE_UNASSIGNED_KEYS", True)
    now = _seed_spend_mu(
        tmp_path, monkeypatch,
        rows=[("alice", 5.0, 50), ("bob", 3.0, 30), ("orphan", 1.0, 10),
              ("selfkey", 9.0, 90), ("garbage", 4.0, 40)],
        owners={"alice": "u1", "bob": "u2", "orphan": ""})   # orphan = owner empty; garbage unknown
    cw = db.key_cost_window(30, end=now + 86400)
    assert set(cw) == {"alice", "bob", "garbage", "Other"}, f"billed keys keep a band: {cw}"
    assert round(cw["garbage"], 2) == 4.0, "unconfirmed but BILLED key keeps its band (F2 self-evidence)"
    assert round(cw["Other"], 2) == 10.0, f"only orphan(hidden)+selfkey(excluded) fold: {cw}"
    assert round(sum(cw.values()), 2) == 22.0, f"total spend must be preserved: {cw}"


def test_key_cumulative_drops_hidden_keys_from_topn(tmp_path, monkeypatch):
    """Same rollup, the 'Top 10 API keys over time' chart in FULL spend mode (`key_cumulative`):
    excluded and hidden-unassigned labels are dropped from top-N candidacy. F2: an unconfirmed-
    by-/key/list label that nonetheless BILLED spend (present in the rollup = self-evidence of a
    real key) is KEPT, not dropped — only operator-excluded (selfkey) and hidden (orphan) fold."""
    monkeypatch.setattr(config, "EXCLUDE_KEYS", ["selfkey"])
    monkeypatch.setattr(config, "HIDE_UNASSIGNED_KEYS", True)
    now = _seed_spend_mu(
        tmp_path, monkeypatch,
        rows=[("alice", 5.0, 50), ("bob", 3.0, 30), ("orphan", 1.0, 99),
              ("selfkey", 9.0, 90), ("garbage", 4.0, 40)],
        owners={"alice": "u1", "bob": "u2", "orphan": ""})
    kc = db.key_cumulative(metric="reqs", top_n=10, end=now + 86400)
    assert set(kc["labels"]) == {"alice", "bob", "garbage"}, \
        f"orphan(hidden)/selfkey(excluded) dropped; billed-but-unconfirmed garbage kept (F2): {kc['labels']}"


def test_label_hidden_predicate_covers_all_three_classes(tmp_path, monkeypatch):
    """The one shared predicate every per-key chart applies: excluded, unconfirmed, hidden."""
    monkeypatch.setattr(config, "EXCLUDE_KEYS", ["selfkey"])
    known = {"alice", "selfkey"}          # /key/list-confirmed labels
    hidden = {"orphan"}                    # the hidden Unassigned set
    assert db._label_hidden("alice", known, hidden) is False       # real, known, shown
    assert db._label_hidden("selfkey", known, hidden) is True      # operator-excluded
    assert db._label_hidden("garbage", known, hidden) is True      # never confirmed by /key/list
    assert db._label_hidden("orphan", known, hidden) is True       # hidden Unassigned


async def test_spend_keycost_falls_back_to_key_series_delta_in_lite_mode(monkeypatch, tmp_path):
    """The LiteLLM page's 'Top 10 API keys/users — spend in window' cards read
    /api/spend/keycost, backed by the day-granular spend_model_user_daily rollup — which
    is fed ONLY from full-mode /spend/logs parsing (mu_rows). On a lite-mode deployment
    that rollup never gets a single row, so these cards were permanently empty even with
    real, active spend (observed live: a key's cumulative cost climbing while the window
    cards showed nothing). Confirm the endpoint falls back to key_series_window_delta
    (the same lite-compatible per-bucket delta the sibling 'requests/spend in window' bar
    chart already uses) when the day rollup is empty and spend_mode isn't full."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "kc_lite.db"))
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "supersecrettoken1234")
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://x")   # gate open
    db.init()
    now = time.time()
    db.known_keys_upsert(["pedro"], now)
    # lite-mode key_series holds CUMULATIVE spend; two samples establish a positive delta
    db.insert_key_series(now - 300, [{"key": "h1", "alias": "pedro", "reqs": 1.0}])
    db.insert_key_series(now, [{"key": "h1", "alias": "pedro", "reqs": 1.5}])
    # spend_model_user_daily deliberately left EMPTY — the exact lite-mode gap
    c = await _client()
    try:
        import app as appmod
        monkeypatch.setitem(appmod._backend_latest, "litellm", {"spend_mode": "lite"})
        r = await c.get("/api/spend/keycost?window=1h&token=supersecrettoken1234")
        assert r.status == 200
        body = await r.json()
        assert body["cost"].get("pedro") == 0.5, f"expected the fallback delta, got {body['cost']}"
        # full mode must NOT take this fallback — key_series_window_delta's numbers are
        # REQUEST COUNTS there, not dollars, and plotting them here would mislabel units
        monkeypatch.setitem(appmod._backend_latest, "litellm", {"spend_mode": "full"})
        r2 = await c.get("/api/spend/keycost?window=1h&token=supersecrettoken1234")
        body2 = await r2.json()
        assert body2["cost"] == {}, f"full mode must not fall back to request-count deltas: {body2['cost']}"
    finally:
        await c.close()


async def test_spend_keycost_accepts_litellm_page_windows(monkeypatch):
    """The LiteLLM 'spend in window' cards pass the page window (15m/1h/24h/custom) to
    /api/spend/keycost, which used to hard-restrict to 30d/12mo/month and silently coerce
    everything else to 30d. It now accepts any windowed token via norm_window."""
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "supersecrettoken1234")
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://x")   # gate open
    c = await _client()
    try:
        for w in ("1h", "24h", "30d", "custom:3600"):
            r = await c.get(f"/api/spend/keycost?window={w}&token=supersecrettoken1234")
            assert r.status == 200, f"{w}: {r.status}"
            body = await r.json()
            assert body["window"] == w, f"{w} was coerced to {body['window']}"
            assert "cost" in body
    finally:
        await c.close()


async def test_containers_admin_only_redacts_names_for_non_admin_pentest_f2(monkeypatch):
    """PENTEST F-2 (host container-inventory disclosure): with MONITOR_CONTAINERS_ADMIN_ONLY
    on, a non-admin session sees container health (count + running/status) but NOT the host's
    container NAMES; admins (and the default-off config) see everything."""
    import app as a
    snap = {"collectors": {"containers": {"available": True, "containers": [
        {"name": "aimon-litellm-db", "running": True, "status": "Up"},
        {"name": "customer-secrets", "running": False, "status": "Exited"}]}}}
    # default OFF → names shown to everyone (unchanged behaviour)
    monkeypatch.setattr(config, "CONTAINERS_ADMIN_ONLY", False)
    names = [c["name"] for c in a._redact_containers(snap, "viewer")["collectors"]["containers"]["containers"]]
    assert names == ["aimon-litellm-db", "customer-secrets"]
    # ON + admin → still full
    monkeypatch.setattr(config, "CONTAINERS_ADMIN_ONLY", True)
    names = [c["name"] for c in a._redact_containers(snap, "admin")["collectors"]["containers"]["containers"]]
    assert names == ["aimon-litellm-db", "customer-secrets"]
    # ON + non-admin (or token-auth role=None) → names redacted, health preserved
    for r in ("viewer", None):
        red = a._redact_containers(snap, r)["collectors"]["containers"]["containers"]
        assert [c["name"] for c in red] == ["container-1", "container-2"], f"role={r}"
        assert [c["status"] for c in red] == ["Up", "Exited"], "health must be preserved"
    # the original snapshot is not mutated
    assert snap["collectors"]["containers"]["containers"][0]["name"] == "aimon-litellm-db"


async def test_hide_unassigned_saves_through_the_real_settings_endpoint(monkeypatch):
    """FIELD BUG: the Unassigned Show/Hide button posted `{HIDE_UNASSIGNED_KEYS: "1"}`,
    but /api/admin/settings wants `action=set&name=&value=` — so the server answered
    400 "unknown setting", the button clicked and nothing changed. This drives the REAL
    handler with the shape the (fixed) button sends and asserts the tunable actually flips
    live + persists — even though HIDE_UNASSIGNED_KEYS is card:False (not a rendered card,
    but still settable)."""
    c, csrf = await _admin_client(monkeypatch)
    try:
        r = await c.post("/api/admin/settings",
                         data={"action": "set", "name": "HIDE_UNASSIGNED_KEYS", "value": "1"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200, f"save must be accepted, got {r.status}: {await r.text()}"
        assert (await r.json())["overridden"] is True
        assert config.HIDE_UNASSIGNED_KEYS is True, "must apply live (module constant)"
        assert db.settings_all().get("HIDE_UNASSIGNED_KEYS") in ("1", "1.0", "True", "true")
        # and back off
        r = await c.post("/api/admin/settings",
                         data={"action": "set", "name": "HIDE_UNASSIGNED_KEYS", "value": "0"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200 and config.HIDE_UNASSIGNED_KEYS is False
        # the bare-name shape the old button used must still be REJECTED (proves the
        # handler contract the button has to satisfy)
        r = await c.post("/api/admin/settings",
                         data={"HIDE_UNASSIGNED_KEYS": "1"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 400, "bare {NAME:value} must be rejected — that was the bug"
    finally:
        config.clear_override("HIDE_UNASSIGNED_KEYS")
        await c.close()


def test_db_swallowed_errors_are_logged_not_silent_d2(monkeypatch, caplog):
    """REVIEW D-2: a monitoring tool must not fail its own storage silently. Every
    `except Exception` in db.py logs (aimon.db, WARNING) the failing function + exception type
    while still returning its empty default — so a query bug / schema drift / locked DB is
    diagnosable instead of an indistinguishable empty result."""
    import logging
    # parent "/etc/hostname" is a FILE → os.makedirs in _connect raises → every read fails
    monkeypatch.setattr(config, "DB_PATH", "/etc/hostname/nope.db")
    with caplog.at_level(logging.WARNING, logger="aimon.db"):
        assert db.series("1h", 100) == []             # behaviour unchanged: empty default
        assert db.key_series_window_delta("1h") == {"labels": [], "deltas": []}
    msgs = [r.getMessage() for r in caplog.records if r.name == "aimon.db"]
    assert any(m.startswith("series:") for m in msgs), \
        f"the failing function must be logged, not silent: {msgs!r}"
    # a different read logs under ITS own function name (frame-accurate)
    assert any(m.startswith("key_series_window_delta:") for m in msgs)


def test_key_label_is_the_canonical_join_resolver_d1():
    """REVIEW D-1: ONE resolver for a key's join label across every LiteLLM shape
    (key_alias/key_name on /spend/keys, alias/key on top_keys, token on /key/list, api_key on
    the raw list). A key STORED under one label but LOOKED UP by another silently misses the
    join — the root of the recurring by-key / by-user attribution bugs."""
    from collectors import litellm as L
    # the human alias wins, whatever field name it arrives under
    assert L.key_label({"alias": "team-a"}) == "team-a"
    assert L.key_label({"key_alias": "team-a"}) == "team-a"
    assert L.key_label({"key_name": "team-a"}) == "team-a"
    # falls back to the raw key hash, never empty; "?" only when a row has no identity at all
    for f in ("key", "api_key", "token"):
        assert L.key_label({f: "sk-abc"}) == "sk-abc"
    assert L.key_label({}) == "?"
    assert L.key_label(None) == "?"          # defensive: non-dict input
    assert L.key_label({"key_alias": "  spaced  "}) == "spaced"
    # THE invariant: every join-key site yields the SAME label for the same key dict
    import app as a
    k = {"key_alias": "alice", "key": "sk-hash", "key_name": "ignored"}
    assert a._team_key_id(k) == L.key_label(k) == "alice"


def test_no_divergent_key_label_chains_remain_d1():
    """Guard: the join-key sites delegate to litellm.key_label, not their own inline
    `k.get('alias') or k.get('key_alias') or …` chains (which is exactly how they drifted)."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    app_src = (root / "app.py").read_text(encoding="utf-8")
    ll_src = (root / "collectors" / "litellm.py").read_text(encoding="utf-8")
    # the specific divergent chains that caused the drift are gone
    assert 'k.get("key_alias") or k.get("key_name") or k.get("token")' not in ll_src
    assert 'k.get("alias") or k.get("key_alias") or k.get("key_name")\n                 or k.get("key")' not in ll_src
    # _team_key_id + _alias delegate to the canonical resolver
    assert "return litellm.key_label(k)" in app_src
    # the canonical resolver + its field list exist
    assert "def key_label(" in ll_src and "_KEY_ID_FIELDS" in ll_src


def _seed_conc_model(tmp_path, monkeypatch, models, conc=9.0, n=20):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "cm.db"))
    db.init()
    now = 1_800_000_000.0
    with db._connect() as c:
        for i in range(n):
            c.execute("INSERT INTO metrics(ts,conc) VALUES (?,?)", (now - 1200 + i * 60, conc))
    for i in range(n):
        db.insert_model_series(now - 1200 + i * 60,
                               [{"model": m, "reqs": i * w} for m, w in models.items()])
    return now


def test_concurrency_by_model_splits_by_model_and_sums_to_aggregate(tmp_path, monkeypatch):
    """The new 'Concurrent LLM work — by model' card: the SAME proxy-wide aggregate as the
    by-key card, split across models by each model's activity share. Bands must sum to the
    measured aggregate in every bucket (only the split is inferred)."""
    now = _seed_conc_model(tmp_path, monkeypatch,
                           {"vllm/qwen": 6, "gpt-4o": 3, "ollama/llama": 1})
    out = db.concurrency_by_key("1h", "conc", end=now, cumulative=True, source="model")
    labels = [s["label"] for s in out["series"]]
    assert labels[:3] == ["vllm/qwen", "gpt-4o", "ollama/llama"], labels
    # proportional 6:3:1
    tot = {s["label"]: round(sum(v for v in s["data"] if v), 2) for s in out["series"]}
    assert tot["vllm/qwen"] == 2 * tot["gpt-4o"] == 6 * tot["ollama/llama"]
    # bands sum to the aggregate per bucket
    n = len(out["series"][0]["data"])
    for j in range(n):
        assert abs(sum(s["data"][j] for s in out["series"]) - 9.0) < 1e-6


def test_concurrency_by_model_ignores_key_only_filters(tmp_path, monkeypatch):
    """Model labels are not keys, so the by-KEY candidacy filters must NOT apply: a model
    whose name collides with an excluded key, or that /key/list never confirmed, still gets
    its own band (unlike the by-key split, which would fold those into 'Other')."""
    monkeypatch.setattr(config, "EXCLUDE_KEYS", {"gpt-4o"})       # would hide a KEY named gpt-4o
    now = _seed_conc_model(tmp_path, monkeypatch, {"gpt-4o": 5, "vllm/qwen": 5})
    out = db.concurrency_by_key("1h", "conc", end=now, cumulative=True, source="model")
    assert "gpt-4o" in [s["label"] for s in out["series"]], "model must not be key-excluded"
    # and by-KEY on the same excluded label WOULD fold it away (sanity that the gate exists)
    ck = db.concurrency_by_key("1h", "conc", end=now, cumulative=True, source="key")
    assert "gpt-4o" not in [s["label"] for s in ck["series"] if s["label"] != "Other"]


def test_insert_model_series_stores_reqs_with_token_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "m.db"))
    db.init()
    db.insert_model_series(1000.0, [{"model": "a", "reqs": 7},
                                    {"model": "b", "tokens": 50},     # no reqs → tokens
                                    {"model": "", "reqs": 9}])         # blank model dropped
    with db._connect() as c:
        rows = dict(c.execute("SELECT label, reqs FROM model_series WHERE ts=1000.0").fetchall())
    assert rows == {"a": 7.0, "b": 50.0}, rows


def test_model_series_rolls_up_and_prunes_like_key_series(tmp_path, monkeypatch):
    """model_series must ride the same rollup + retention plumbing as key_series, or its
    history would never reach the 1m/1h tiers the windowed reads use."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "r.db"))
    db.init()
    now = 1_800_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    for i in range(30):
        db.insert_model_series(now - 30 * 120 + i * 120, [{"model": "m", "reqs": i}])
    db.rollup()
    with db._connect() as c:
        assert c.execute("SELECT COUNT(*) FROM model_series_1m").fetchone()[0] > 0
        assert c.execute("SELECT COUNT(*) FROM model_series_1h").fetchone()[0] > 0
    db.prune_key_series()   # shared prune — must not error and must know model_series
    src = (__import__("pathlib").Path(__file__).resolve().parent.parent / "db.py").read_text()
    assert "DELETE FROM model_series WHERE ts" in src, "prune must cover model_series"


def test_insert_model_conc_series_stores_and_skips_when_nothing_to_attribute(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "mcs.db"))
    db.init()
    db.insert_model_conc_series(1000.0, "vllm/mini", 3.0, 1.0)
    db.insert_model_conc_series(1000.0, "vllm/waiting-only", None, 2.0)
    db.insert_model_conc_series(1000.0, "", 5.0, 5.0)          # no label → dropped
    db.insert_model_conc_series(1000.0, "vllm/both-none", None, None)  # nothing to store
    with db._connect() as c:
        rows = dict((lbl, (run, wait)) for lbl, run, wait in
                    c.execute("SELECT label, running, waiting FROM model_conc_series").fetchall())
    assert rows == {"vllm/mini": (3.0, 1.0), "vllm/waiting-only": (None, 2.0)}, rows


def test_concurrency_by_model_overrides_with_realtime_running_for_a_slow_model(tmp_path, monkeypatch):
    """Live bug: vllm/MiniMax showed 'Other' on 'Concurrent LLM work — by model' despite
    real backlog=3, while a fast API model (azure_ai/gpt-5.4-mini) attributed correctly.
    Root cause: model_series infers activity from the CHANGE in completed-request count —
    a slow, self-hosted model's request can still be GENERATING when the bucket closes, so
    its completion count (and delta) reads zero the whole time it's in flight. vLLM's own
    real-time running/waiting gauge (model_conc_series) has no such lag and must override
    the misleadingly-zero completion-delta weight for that label."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "cm_rt.db"))
    db.init()
    now = 1_800_000_000.0
    with db._connect() as c:
        for i in range(5):
            c.execute("INSERT INTO metrics(ts,conc) VALUES (?,?)", (now - 240 + i * 60, 4.0))
    # gpt-5.4-mini completes quickly -> a real completion-delta every bucket
    for i in range(5):
        db.insert_model_series(now - 240 + i * 60,
                               [{"model": "azure_ai/gpt-5.4-mini", "reqs": i}])
    # MiniMax: reqs count never moves all window (still generating) -> zero completion-delta,
    # but vLLM reports real in-flight work throughout
    for i in range(5):
        db.insert_model_series(now - 240 + i * 60,
                               [{"model": "vllm/MiniMax-M2.5-REAP-139B-A10B-NVFP4-GB10", "reqs": 0}])
        db.insert_model_conc_series(now - 240 + i * 60,
                                    "vllm/MiniMax-M2.5-REAP-139B-A10B-NVFP4-GB10", 3.0, None)
    out = db.concurrency_by_key("1h", "conc", end=now, cumulative=True, source="model")
    data = {s["label"]: s["data"] for s in out["series"]}
    assert sum(data.get("vllm/MiniMax-M2.5-REAP-139B-A10B-NVFP4-GB10", [])) > 0, (
        f"MiniMax's real-time backlog must not fold into Other: {data}")
    assert sum(data.get("Other", [0])) == 0, f"nothing should be left unattributed: {data}"
    # the fast model's own attribution is unaffected by the override existing
    assert sum(data.get("azure_ai/gpt-5.4-mini", [])) > 0


def test_concurrency_by_model_realtime_override_is_scoped_to_the_short_window(tmp_path, monkeypatch):
    """The override reads model_conc_series's RAW tier only (no _1m/_1h rollup exists for
    it) — a 24h+ window must ignore it entirely rather than erroring, so a genuinely
    completion-delta-attributed model's result is UNCHANGED whether or not a (wrongly
    scoped) real-time row happens to also exist for the same time range."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "cm_rt_scope.db"))
    db.init()
    now = 1_800_000_000.0
    with db._connect() as c:
        for i in range(5):
            bkt = now - 3600 * 20 + i * 3600
            c.execute("INSERT INTO metrics_1m(bucket,conc) VALUES (?,?)", (bkt, 4.0))
            # real completion-delta activity (increasing cumulative reqs), rolled up directly
            c.execute("INSERT INTO model_series_1m(bucket,label,reqs) VALUES (?,?,?)",
                     (bkt, "vllm/slow-model", float(i)))
            # a real-time row exists for the SAME window — must be ignored beyond 1h
            c.execute("INSERT INTO model_conc_series(ts,label,running,waiting) VALUES (?,?,?,?)",
                     (bkt, "vllm/slow-model", 999.0, None))
    baseline = db.concurrency_by_key("24h", "conc", end=now, cumulative=True, source="model")
    with db._connect() as c:
        c.execute("DELETE FROM model_conc_series")
    without_rt = db.concurrency_by_key("24h", "conc", end=now, cumulative=True, source="model")
    assert baseline["series"] == without_rt["series"], (
        "a >1h window must ignore model_conc_series entirely — the out-of-scope "
        "real-time row changed the result")


async def test_concurrency_by_model_endpoint(monkeypatch):
    """/api/litellm/concurrency-by-key?by=model routes to the model split."""
    monkeypatch.setattr(config, "ALLOW_OPEN", True)
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "")
    import app as appmod
    monkeypatch.setattr(appmod.db, "concurrency_by_key",
                        lambda *a, **k: {"labels": [1], "metric": "conc",
                                         "series": [{"label": "gpt-4o", "data": [5]}],
                                         "_src": k.get("source")})
    c = await _client()
    try:
        r = await c.get("/api/litellm/concurrency-by-key?by=model&metric=conc")
        assert r.status == 200
        j = await r.json()
        assert j["_src"] == "model", "by=model must pass source='model'"
    finally:
        await c.close()


def test_key_series_monotonic_never_decreases_on_a_rebase(tmp_path, monkeypatch):
    """The windowed 'Top 10 API keys over time' card (/api/keyseries) is an "only rises"
    cumulative view, but the raw stored value RE-BASES DOWN when a key is re-issued / a
    budget rolls (observed live: RodolfoSantos 699 -> 1, 19 drops on the 30d window).
    monotonic=True must plot a non-decreasing running total (positive steps only), while
    the raw read still shows the drop."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "ks.db"))
    db.init()
    now = 1_800_000_000.0
    seq = [100.0, 130.0, 160.0, 20.0, 45.0, 70.0, 5.0, 25.0, 40.0]   # climbs, re-bases twice
    with db._connect() as c:
        c.executemany("INSERT INTO key_series_1h(bucket,label,reqs) VALUES (?,?,?)",
                      [(now - 86400 * 30 + i * 86400 * 3, "k", v) for i, v in enumerate(seq)])
    db.known_keys_upsert({"k": "u-1"}, now)

    raw = [p["k"] for p in db.key_series("12mo", 400, end=now)["points"] if "k" in p]
    mono = [p["k"] for p in db.key_series("12mo", 400, end=now, monotonic=True)["points"]
            if "k" in p]
    assert any(b < a for a, b in zip(raw, raw[1:])), "raw must still show the re-base drop"
    assert all(b >= a for a, b in zip(mono, mono[1:])), f"monotonic must never fall: {mono}"
    assert mono[0] == raw[0], "seeds at the first in-window value"
    # captures activity AFTER a re-base (not frozen like a running-max would be)
    assert mono[-1] > mono[0], "post-rebase positive steps still accrue"


async def test_keyseries_endpoint_is_monotonic(monkeypatch):
    """The /api/keyseries handler (windowed keytime card) must request the monotonic
    series, so the served line for a re-basing key only rises."""
    monkeypatch.setattr(config, "ALLOW_OPEN", True)
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "")
    captured = {}
    import app as appmod
    real = appmod.db.key_series
    def _spy(*a, **k):
        captured.update(k)
        return real(*a, **k)
    monkeypatch.setattr(appmod.db, "key_series", _spy)
    c = await _client()
    try:
        r = await c.get("/api/keyseries?window=24h")
        assert r.status == 200
        assert captured.get("monotonic") is True, "handler must pass monotonic=True"
    finally:
        await c.close()


def test_concurrency_reports_attribution_for_the_why_other_popover(tmp_path, monkeypatch):
    """The 'why Other?' popover needs to state how much of the aggregate was attributed vs
    not, and whether Other hides labels beyond the top-N. concurrency_by_key must return an
    `attribution` summary: aggregate, attributed, other (=aggregate-attributed), labels_total,
    shown."""
    now = _seed_conc_model(tmp_path, monkeypatch,
                           {"a": 5, "b": 3, "c": 2, "d": 1, "e": 1, "f": 1,
                            "g": 1, "h": 1, "i": 1, "j": 1}, conc=9.0)  # 10 models
    out = db.concurrency_by_key("1h", "conc", end=now, cumulative=True, source="model", top_n=8)
    at = out.get("attribution")
    assert at, "must return an attribution summary"
    assert at["aggregate"] >= at["attributed"] >= 0
    assert abs(at["other"] - max(0.0, at["aggregate"] - at["attributed"])) < 1e-6
    assert at["labels_total"] == 10 and at["shown"] == 8, at
    # with 10 models but only 8 shown, Other legitimately hides 2 beyond top-N
    assert at["labels_total"] > at["shown"]
    # and the popover can NAME them (not just count) — the "models being used there"
    assert isinstance(at.get("other_labels"), list) and len(at["other_labels"]) == 2, at
    assert set(at["other_labels"]).isdisjoint({s["label"] for s in out["series"]})


def test_concurrency_by_key_default_top_n_shows_more_before_folding_to_other(tmp_path, monkeypatch):
    """Live report: with 43 total keys but only ~6 shown, most windows drew a large 'Other'
    band even during ordinary, non-degenerate traffic. Bumped the default top_n 8 -> 12 so
    more genuinely-active keys/models get their own band before anything folds into Other."""
    now = _seed_conc_model(tmp_path, monkeypatch,
                           {chr(ord("a") + i): 12 - i for i in range(12)}, conc=9.0)  # 12 models
    out = db.concurrency_by_key("1h", "conc", end=now, cumulative=True, source="model")
    shown = {s["label"] for s in out["series"] if s["label"] != "Other"}
    assert len(shown) == 12, f"default top_n must show all 12, not just the old default of 8: {shown}"
    assert "Other" not in [s["label"] for s in out["series"]], "nothing left to fold into Other"


def test_why_other_never_names_excluded_or_garbage_keys(tmp_path, monkeypatch):
    """CODE-REVIEW REGRESSION: the 'why Other?' popover's `other_labels` / `labels_total`
    must be drawn from ELIGIBLE labels only — never the MONITOR_EXCLUDE_KEYS key, a hidden
    key, or a label /key/list never confirmed (garbage like '${ENV}'). Naming them would
    re-expose exactly what exclude/hide/known were meant to keep out of the UI and inflate
    the 'N beyond the top-N' count."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "wo.db"))
    monkeypatch.setattr(config, "EXCLUDE_KEYS", {"svc-monitor"})
    db.init()
    now = 1_800_000_000.0
    with db._connect() as c:
        for i in range(20):
            c.execute("INSERT INTO metrics(ts,conc) VALUES (?,?)", (now - 1200 + i * 60, 9.0))
    db.known_keys_upsert({"realkey": "u-1", "realkey2": "u-2"}, now)   # only these confirmed
    for i in range(20):
        db.insert_key_series(now - 1200 + i * 60, [
            {"key": "realkey", "alias": "realkey", "reqs": i * 5},
            {"key": "realkey2", "alias": "realkey2", "reqs": i * 4},
            {"key": "svc-monitor", "alias": "svc-monitor", "reqs": i * 3},   # excluded
            {"key": "${LITELLM_API_KEY}", "alias": "", "reqs": i * 2}])       # garbage/unknown
    at = db.concurrency_by_key("1h", "conc", end=now, cumulative=True,
                               source="key", top_n=1)["attribution"]
    assert "svc-monitor" not in at["other_labels"], "excluded key leaked into other_labels"
    assert "${LITELLM_API_KEY}" not in at["other_labels"], "garbage label leaked"
    assert at["other_labels"] == ["realkey2"], at["other_labels"]
    assert at["labels_total"] == 2, "labels_total must count only eligible keys, got %s" % at


def test_model_cost_price_per_type_derives_blend_and_reads_back(tmp_path, monkeypatch):
    """The editable in/out/cch cells persist per-type overrides; usd_1m (what the whole cost
    pipeline reads) is DERIVED from input+output so a mistaken per-type edit can't desync the
    charts, and model_cost_details() reads the per-type values back for the card to show."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "mc.db"))
    db.init()
    assert db.model_cost_price_set("gpt-4o", 0.0, 1.0, in_1m="5", out_1m="15", cache_1m="1")
    assert db.model_cost_prices()["gpt-4o"] == 10.0            # (5+15)/2 blend
    assert db.model_cost_details()["gpt-4o"] == {"in": 5.0, "out": 15.0, "cache": 1.0}
    # a single-sided rate uses that side (not halved)
    db.model_cost_price_set("m2", 0.0, 1.0, in_1m="8")
    assert db.model_cost_prices()["m2"] == 8.0
    # blended-only override still works and stores no per-type detail
    db.model_cost_price_set("claude", 7.5, 1.0)
    assert db.model_cost_prices()["claude"] == 7.5 and "claude" not in db.model_cost_details()
    # a bad per-type value is rejected (no partial write)
    assert not db.model_cost_price_set("bad", 0.0, 1.0, in_1m="-3")
    assert not db.model_cost_price_set("bad", 0.0, 1.0, out_1m="NaNish")
    assert "bad" not in db.model_cost_prices()
    # reset drops everything
    db.model_cost_price_delete("gpt-4o")
    assert "gpt-4o" not in db.model_cost_prices() and "gpt-4o" not in db.model_cost_details()


def test_model_cost_partial_override_fills_blank_types_from_litellm_rate(tmp_path, monkeypatch):
    """Review #13: a partial per-type override (only one type pinned) must NOT count the blank
    types as $0 and zero-deflate the derived blend. The blanks fill from LiteLLM's live rate
    (fill_*), while the stored per-type detail still holds only the operator's explicit override."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "mcfill.db"))
    db.init()
    # only OUTPUT overridden (20); input/cache blank → fill from LiteLLM live (in=5, cache=1).
    db.model_cost_price_set("m", 0.0, 1.0, out_1m="20",
                            vol_in="100", vol_out="10", vol_cache="0",
                            fill_in="5", fill_cache="1")
    assert db.model_cost_prices()["m"] == pytest.approx((5*100 + 20*10 + 1*0) / 110)
    assert db.model_cost_details()["m"] == {"out": 20.0}      # only the explicit override is stored
    # WITHOUT the fill the same partial override zero-deflates input to $0 (the bug this fixes).
    db.model_cost_price_set("m2", 0.0, 1.0, out_1m="20",
                            vol_in="100", vol_out="10", vol_cache="0")
    assert db.model_cost_prices()["m2"] == pytest.approx((0*100 + 20*10) / 110)


async def test_model_kinds_post_accepts_per_type_cost(monkeypatch):
    """The /api/admin/model-kinds handler accepts action=cost with in/out/cache and persists
    a per-type override (deriving usd_1m); the blended usd_1m path still works too."""
    c, csrf = await _admin_client(monkeypatch)
    try:
        r = await c.post("/api/admin/model-kinds",
                         data={"action": "cost", "model": "gpt-4o",
                               "in_1m": "4", "out_1m": "12", "cache_1m": "0.5"},
                         headers={"X-CSRF-Token": csrf})
        assert r.status == 200 and (await r.json())["cost_overridden"] is True
        assert db.model_cost_prices().get("gpt-4o") == 8.0      # (4+12)/2
        assert db.model_cost_details().get("gpt-4o", {}).get("cache") == 0.5
    finally:
        db.model_cost_price_delete("gpt-4o")
        await c.close()


# --- Service status timeline (Alerts page) -----------------------------------
# Backend for the "Service status over time" stepped-line graph: per-service
# up/down segments from the events table, the monitoring site derived from
# metrics-row cadence, and the endpoint that omits Settings-disabled services.

def test_status_segments_reconstructs_up_down_runs(tmp_path, monkeypatch):
    """A backend up before the window with a mid-window outage yields three
    ordered segments (up / down / up) and the matching uptime%."""
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "seg.db"))
    db.init()
    now = _t.time()
    db.record_event(now - 2 * 86400, "ollama", True)     # up long before window
    db.record_event(now - 12 * 3600, "ollama", False)    # down at -12h
    db.record_event(now - 11 * 3600, "ollama", True)     # back up at -11h
    out = db.status_segments("24h", ["ollama"], end=now)["ollama"]
    segs = out["segments"]
    assert [s["up"] for s in segs] == [True, False, True]
    assert out["no_data"] is False
    # exactly one hour of downtime in a 24h window
    assert abs(out["uptime_pct"] - (23 / 24 * 100)) < 0.1
    # segments are contiguous and cover the whole window
    assert abs(segs[0]["from"] - (now - 86400)) < 1
    assert abs(segs[-1]["to"] - now) < 1
    for a, b in zip(segs, segs[1:]):
        assert abs(a["to"] - b["from"]) < 1e-6


def test_status_segments_no_data_for_backend_without_events(tmp_path, monkeypatch):
    """An enabled backend that has never produced a state event is flagged
    no_data (frontend draws a dashed 'no data yet' lane, never a fake green)."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "nd.db"))
    db.init()
    out = db.status_segments("24h", ["vllm"], end=1_000_000.0)["vllm"]
    assert out["no_data"] is True


def test_self_uptime_segments_flags_a_metrics_gap(tmp_path, monkeypatch):
    """The monitoring-site lane is inferred from metrics cadence: a gap larger
    than 3x the sample interval becomes a 'down' segment."""
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "site.db"))
    monkeypatch.setattr(config, "ROLLUP_RAW_HOURS", 24)   # pin so a 24h window tiers to raw regardless of env
    monkeypatch.setattr(config, "SAMPLE_INTERVAL", 5.0)
    db.init()
    now = _t.time()
    gap_lo, gap_hi = now - 6 * 3600 - 600, now - 6 * 3600   # a 10-min blackout at -6h
    with db._connect() as c:
        t = now - 86400
        while t < now:
            if not (gap_lo < t < gap_hi):
                c.execute("INSERT INTO metrics(ts,cpu) VALUES(?,?)", (t, 10.0))
            t += 5
    out = db.self_uptime_segments("24h", end=now)
    assert out["no_data"] is False
    downs = [s for s in out["segments"] if not s["up"]]
    assert len(downs) == 1
    # the down segment matches the injected blackout (~10 min), not the whole window
    assert 540 < (downs[0]["to"] - downs[0]["from"]) < 660
    assert out["uptime_pct"] < 100 and out["uptime_pct"] > 99


async def test_status_timeline_endpoint_omits_services_disabled_in_settings(tmp_path, monkeypatch):
    """A service switched OFF in Settings -> Services is absent from the graph
    entirely (same gate as the sidebar link); the monitoring site is always
    present and always last."""
    from aiohttp.test_utils import make_mocked_request
    import json
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "ep.db"))
    db.init()
    monkeypatch.setattr(appmod, "_latest", {"ts": 0, "collectors": {}})
    # ollama enabled + configured; vllm/litellm/llamacpp disabled; gpu unconfigured
    monkeypatch.setattr(config, "OLLAMA_ENABLED", True)
    monkeypatch.setattr(config, "OLLAMA_BASE_URL", "http://ollama:11434")
    monkeypatch.setattr(config, "VLLM_ENABLED", False)
    monkeypatch.setattr(config, "VLLM_BASE_URL", "http://vllm:8000")
    monkeypatch.setattr(config, "LITELLM_ENABLED", False)
    monkeypatch.setattr(config, "LLAMACPP_ENABLED", False)
    for attr in ("GPU_SSH", "GPU_METRICS_URL", "GPU_METRICS_FILE"):
        monkeypatch.setattr(config, attr, "", raising=False)
    now = _t.time()
    with db._connect() as c:
        for k in range(30):
            c.execute("INSERT INTO metrics(ts,cpu) VALUES(?,?)", (now - 150 + k * 5, 10.0))
    req = make_mocked_request("GET", "/api/status-timeline?window=24h")
    resp = await appmod.status_timeline_handler(req)
    data = json.loads(resp.text)
    keys = [s["key"] for s in data["services"]]
    assert "ollama" in keys                     # enabled -> present
    assert "vllm" not in keys                    # disabled in Settings -> omitted
    assert "litellm" not in keys and "llamacpp" not in keys
    assert "gpu" not in keys                      # unconfigured -> omitted
    assert keys[-1] == "site"                     # site always last, always present
    site = data["services"][-1]
    assert site["configured"] is True and site["no_data"] is False


def test_status_segments_full_uptime_when_up_since_before_window(tmp_path, monkeypatch):
    """A backend that came up before the window and never fell over shows a single
    up segment spanning the whole window at 100% (no events inside the window)."""
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "up.db"))
    db.init()
    now = _t.time()
    db.record_event(now - 3 * 86400, "llamacpp", True)     # up well before the window
    out = db.status_segments("24h", ["llamacpp"], end=now)["llamacpp"]
    assert out["no_data"] is False
    assert [s["up"] for s in out["segments"]] == [True]
    assert out["uptime_pct"] == 100.0


async def test_status_timeline_honours_end_pan_cursor(tmp_path, monkeypatch):
    """Alerts pan: /api/status-timeline?end=<past> anchors the window END at that cursor
    (now==end, start==end-secs) instead of 'now' — this is what the ◀▶ arrows send."""
    import time as _t
    import json
    from aiohttp.test_utils import make_mocked_request
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "pan.db"))
    db.init()
    end = _t.time() - 3 * 86400            # three days back
    req = make_mocked_request("GET", f"/api/status-timeline?window=24h&end={end:.0f}")
    resp = await appmod.status_timeline_handler(req)
    data = json.loads(resp.text)
    assert data["window"] == "24h"
    assert abs(data["now"] - end) < 1.0                 # window END pinned to the cursor
    assert abs(data["start"] - (end - 86400)) < 1.0     # start = end - 24h, not now - 24h


async def test_spend_series_forwards_end_pan_to_anchor(monkeypatch):
    """Spend pan: /api/spend/series?end=<past> forwards that cursor as the window anchor
    (the day-granular charts then end there); a param-less call anchors at ~now."""
    from aiohttp.test_utils import make_mocked_request
    seen = {}

    def _src(anchor, window):
        seen["anchor"] = anchor
        seen["window"] = window
        return {"window": window, "available": True, "points": [], "years": []}

    monkeypatch.setattr(appmod, "_spend_series_source", _src)
    end = 1_700_000_000.0
    req = make_mocked_request("GET", f"/api/spend/series?window=30d&end={end:.0f}")
    resp = await appmod.spend_series_handler(req)
    assert resp.status == 200
    assert seen["anchor"] == end and seen["window"] == "30d"   # pan cursor → anchor
    req2 = make_mocked_request("GET", "/api/spend/series?window=30d")
    await appmod.spend_series_handler(req2)
    assert seen["anchor"] > end                                # live: anchor ~= now (future of cursor)


async def test_spend_model_series_forwards_end_pan(monkeypatch):
    """/api/spend/model-series honours the ?end= pan cursor: the per-model bucketing anchors
    at the cursor, not 'now'. A param-less call anchors at ~now."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")

    async def fake_prices(session):
        return {"m": 2.25e-06}

    async def fake_series(session, start, end, prices, ov):
        return {"dates": ["2026-07-15"], "models": [
            {"model": "m", "kind": "real", "total": 1.0, "daily": {"2026-07-15": 1.0}}]}

    monkeypatch.setattr(litellm, "model_prices", fake_prices)
    monkeypatch.setattr(litellm, "per_model_daily_series", fake_series)
    seen = {}

    def cap(series, window, anchor, **kw):
        seen["anchor"] = anchor
        return {"window": window, "available": True, "labels": ["x"], "models": []}

    monkeypatch.setattr(appmod, "bucket_model_series", cap)
    end = 1_700_000_000.0
    c = await _client()
    try:
        await (await c.get(f"/api/spend/model-series?window=30d&end={end:.0f}")).json()
        assert seen["anchor"] == end                # pan cursor → bucket anchor
        seen.clear()
        await (await c.get("/api/spend/model-series?window=30d")).json()
        assert seen["anchor"] > end                 # live ~ now
    finally:
        await c.close()


async def test_spend_model_user_series_forwards_end_and_serves_fresh(monkeypatch):
    """/api/spend/model-user-series forwards ?end= to BOTH the rollup read (day span anchored
    at the cursor) and the bucketing; a panned view is served fresh (never from the window-keyed
    cache), so a following live call still anchors at ~now."""
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    rows_seen = {}

    def fake_rows(days_back, end=None):
        rows_seen["days"] = days_back
        rows_seen["end"] = end
        return [{"date": "2026-07-15", "model": "m", "key": "k", "cost": 1.0}]

    async def fake_owner(session):
        return {"ovr": {}, "live": {}}

    async def fake_prices(session):
        return {}

    monkeypatch.setattr(db, "spend_model_user_rows", fake_rows)
    monkeypatch.setattr(appmod, "_key_owner_map", fake_owner)
    monkeypatch.setattr(litellm, "model_prices", fake_prices)
    bseen = {}

    def cap(rows, omap, prices, kind_ov, window, anchor):
        bseen["anchor"] = anchor
        return {"window": window, "available": True, "labels": [], "series": []}

    monkeypatch.setattr(appmod, "bucket_model_user_series", cap)
    end = 1_700_000_000.0
    c = await _client()
    try:
        await (await c.get(f"/api/spend/model-user-series?window=30d&end={end:.0f}")).json()
        assert rows_seen["end"] == end and bseen["anchor"] == end   # cursor → rollup read + bucket
        rows_seen.clear()
        bseen.clear()
        await (await c.get("/api/spend/model-user-series?window=30d")).json()
        assert bseen["anchor"] > end        # live served fresh (panned view was not cached)
    finally:
        await c.close()


async def test_userreqs_follows_window_and_end(monkeypatch):
    """The /litellm 'Usage by user over time' card follows the window (→ day span) AND the
    ?end= pan cursor: the handler maps window→days_back and forwards end to key_cumulative."""
    import json as _j
    from aiohttp.test_utils import make_mocked_request
    seen = {}

    def fake_cum(metric="reqs", days_back=366, top_n=10, end=None):
        seen["days_back"] = days_back
        seen["end"] = end
        return {"labels": ["k1"], "points": [{"t": 1, "k1": 5}]}

    monkeypatch.setattr(db, "key_cumulative", fake_cum)
    monkeypatch.setattr(db, "known_owner_names", lambda: {})
    monkeypatch.setattr(db, "key_user_overrides", lambda: {})
    end = 1_700_000_000.0
    req = make_mocked_request("GET", f"/api/userreqs?window=24h&end={end:.0f}")
    d = _j.loads((await appmod.userreqs_handler(req)).text)
    assert seen["end"] == end and seen["days_back"] == 1    # 24h → 1 day (day-granular)
    assert d["metric"] == "requests"
    seen.clear()
    req2 = make_mocked_request("GET", "/api/userreqs?window=30d")
    await appmod.userreqs_handler(req2)
    assert seen["days_back"] == 30 and seen["end"] is None  # window widens the span; live = no cursor


def test_window_and_years_clamps_both_edges_to_anchor():
    """Pan correctness: window_and_years must bound the chart points to [anchor-span, anchor]
    for 30d/month/12mo — a past pan cursor SHIFTS the window, never widening it to today and
    never (for 12mo) ignoring the cursor. Guards the review's B1/B3."""
    import time as _t
    now = _t.time()

    def day(d):
        return _t.strftime("%Y-%m-%d", _t.gmtime(now - d * 86400))
    # rows every 5 days from 400d ago to today
    daily = [{"date": day(d), "spend": 1.0, "real": 1.0, "reference": 0.0,
              "requests": 1, "tokens": 10} for d in range(0, 400, 5)]
    anchor = now - 90 * 86400                     # pan back ~3 months
    anchor_day = _t.strftime("%Y-%m-%d", _t.gmtime(anchor))
    for win, span_days in (("30d", 30), ("12mo", 365)):
        out = appmod.window_and_years(daily, win, anchor)
        dates = [_t.strftime("%Y-%m-%d", _t.gmtime(p["t"])) for p in out["points"]]
        assert dates, f"{win}: no points"
        assert max(dates) <= anchor_day, f"{win}: point past the anchor (window widened to today)"
        lo = _t.strftime("%Y-%m-%d", _t.gmtime(anchor - span_days * 86400))
        assert min(dates) >= lo, f"{win}: point before the window start"
    # 12mo pan is NOT a no-op: anchored payload differs from the live one
    live = appmod.window_and_years(daily, "12mo", now)
    panned = appmod.window_and_years(daily, "12mo", anchor)
    assert [p["t"] for p in live["points"]] != [p["t"] for p in panned["points"]]


def test_bucket_model_series_clamps_right_edge_to_anchor():
    """Pan correctness: bucket_model_series (30d/month) must not emit labels past the anchor —
    the full-year series it receives contains dates after a past cursor. Guards review B2."""
    import time as _t
    now = _t.time()
    anchor = now - 60 * 86400
    anchor_day = _t.strftime("%Y-%m-%d", _t.gmtime(anchor))
    dates = [_t.strftime("%Y-%m-%d", _t.gmtime(now - d * 86400)) for d in range(0, 200, 3)]
    series = {"dates": dates, "models": [
        {"model": "m", "kind": "real", "total": 1.0, "daily": {d: 1.0 for d in dates}}]}
    out = appmod.bucket_model_series(series, "30d", anchor)
    assert out["labels"], "no labels"
    assert max(out["labels"]) <= anchor_day, "label past the anchor (right edge not clamped)"
    lo = _t.strftime("%Y-%m-%d", _t.gmtime(anchor - 30 * 86400))
    assert min(out["labels"]) >= lo, "label before the window start"


async def test_q_end_rejects_non_finite():
    """_q_end must reject inf/-inf/nan/overflow (they slip past float() and 500 the pan
    handlers via gmtime/json). Guards review B4."""
    from aiohttp.test_utils import make_mocked_request
    for bad in ("nan", "inf", "-inf", "1e999", "Infinity", "NaN"):
        req = make_mocked_request("GET", f"/api/x?end={bad}")
        assert appmod._q_end(req) is None, f"{bad!r} not rejected"
    for good, exp in (("1700000000", 1700000000.0), ("0", 0.0), ("-5", -5.0)):
        req = make_mocked_request("GET", f"/api/x?end={good}")
        assert appmod._q_end(req) == exp
    assert appmod._q_end(make_mocked_request("GET", "/api/x")) is None   # absent → live


def test_webhook_private_target_requires_allowlist(monkeypatch):
    """Threat-model T-9: a per-user webhook may resolve to a private/reserved address ONLY when
    the operator ALSO pins it with WEBHOOK_ALLOW_HOSTS. WEBHOOK_ALLOW_PRIVATE on its own no
    longer opens an unconstrained SSRF pivot. Public + allow-listed-private targets still
    validate (IP literal → getaddrinfo echoes it, offline-safe)."""
    import alerts
    priv = "http://169.254.169.254/hook"     # link-local (cloud-metadata) — always _ip_blocked
    monkeypatch.setattr(alerts.socket, "getaddrinfo",
                        lambda host, port, **k: [(2, 1, 6, "", (host, port))])
    monkeypatch.setattr(config, "WEBHOOK_HTTPS_ONLY", False)
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_PRIVATE", False)
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_HOSTS", "")
    assert alerts._validate_sync(priv) is not None            # default: blocked
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_PRIVATE", True)
    assert alerts._priv_allowed() is False                    # ALLOW_PRIVATE alone is NOT enough
    assert alerts._validate_sync(priv) is not None            # still blocked (the fix)
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_HOSTS", "169.254.169.254")
    assert alerts._priv_allowed() is True                     # + allow-list → LAN opt-in preserved
    assert alerts._validate_sync(priv) is None
    # a public IP is always fine — no allow-list, no ALLOW_PRIVATE needed (zero impact)
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_PRIVATE", False)
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_HOSTS", "")
    assert alerts._validate_sync("http://1.1.1.1/hook") is None


def test_startup_selfcheck_flags_open_mode_on_nonloopback(monkeypatch, tmp_path):
    """Threat-model T-1: open mode (no dashboard token AND no users) bound to a non-loopback
    interface is surfaced as a startup problem (world-readable spend/attribution). Informational
    — never blocks boot; a loopback bind or any auth suppresses it."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "sc.db"))
    db.init()                                    # fresh db → 0 users
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "")
    monkeypatch.setattr(config, "MONITOR_HOST", "0.0.0.0")
    assert any("OPEN MODE" in p for p in appmod.startup_selfcheck())
    monkeypatch.setattr(config, "MONITOR_HOST", "127.0.0.1")   # loopback → suppressed
    assert not any("OPEN MODE" in p for p in appmod.startup_selfcheck())
    monkeypatch.setattr(config, "MONITOR_HOST", "0.0.0.0")
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "x" * 20)   # a token → not open mode
    assert not any("OPEN MODE" in p for p in appmod.startup_selfcheck())


async def test_spend_series_cache_bypassed_and_not_poisoned_by_pan(monkeypatch):
    """The short-TTL spend/series cache must (a) serve a live repeat from cache, (b) be BYPASSED
    on a panned request (recompute, not the stale live payload), and (c) NOT be poisoned by the
    panned response (a following live call still gets the live data). Guards review T2 — the
    only behavioral coverage of the end_q-is-None cache guards (the source-hook test skips them)."""
    import time as _t
    monkeypatch.setattr(appmod, "_spend_series_source", None)   # force the real cache path
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    appmod._SPEND_SERIES_CACHE.clear()
    calls = {"n": 0}
    today = _t.strftime("%Y-%m-%d", _t.gmtime(_t.time()))

    async def fake_activity(session, start, end):
        calls["n"] += 1
        return [{"date": today, "spend": 1.0, "requests": 5, "tokens": 100}]

    async def _empty(*a, **k):
        return {}

    async def _emptylist(*a, **k):
        return []

    monkeypatch.setattr(appmod.litellm, "spend_activity", fake_activity)
    monkeypatch.setattr(appmod.litellm, "model_prices", _empty)
    monkeypatch.setattr(appmod.litellm, "per_model_range", _emptylist)
    monkeypatch.setattr(appmod.litellm, "per_model_daily_cost", _empty)
    monkeypatch.setattr(appmod.litellm, "per_model_daily_tokens", _empty)
    monkeypatch.setattr(db, "spend_daily_range", lambda *a, **k: [])
    monkeypatch.setattr(db, "spend_daily_upsert", lambda *a, **k: None)
    monkeypatch.setattr(db, "model_kind_overrides", lambda *a, **k: {})
    c = await _client()
    try:
        live1 = await (await c.get("/api/spend/series?window=30d")).json()
        assert calls["n"] == 1 and live1.get("points")          # computed + cached
        await (await c.get("/api/spend/series?window=30d")).json()
        assert calls["n"] == 1                                   # live repeat served FROM cache
        past = _t.time() - 100 * 86400
        await (await c.get(f"/api/spend/series?window=30d&end={past:.0f}")).json()
        assert calls["n"] == 2                                   # panned BYPASSED the cache read
        live2 = await (await c.get("/api/spend/series?window=30d")).json()
        assert calls["n"] == 2                                   # live still cached...
        assert live2.get("points") == live1.get("points")       # ...and NOT poisoned by the pan
    finally:
        await c.close()
        appmod._SPEND_SERIES_CACHE.clear()


def test_status_segments_currently_down(tmp_path, monkeypatch):
    """A backend whose last state before the window was DOWN (and never recovered)
    reads down for the whole window: 0% uptime, one down segment, not no_data."""
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "down.db"))
    db.init()
    now = _t.time()
    db.record_event(now - 2 * 86400, "vllm", False)
    out = db.status_segments("24h", ["vllm"], end=now)["vllm"]
    assert out["no_data"] is False
    assert [s["up"] for s in out["segments"]] == [False]
    assert out["uptime_pct"] == 0.0


def test_status_segments_ignores_model_kind_events(tmp_path, monkeypatch):
    """Only kind='state' events drive the timeline. A backend with ONLY model
    load/unload events (kind='model') has no state history → no_data, never a
    phantom up/down flip from a model swap."""
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "mk.db"))
    db.init()
    now = _t.time()
    db.record_event(now - 3600, "ollama", True, "loaded m", kind="model")
    db.record_event(now - 1800, "ollama", False, "unloaded m", kind="model")
    out = db.status_segments("24h", ["ollama"], end=now)["ollama"]
    assert out["no_data"] is True


def test_status_segments_honours_end_cursor(tmp_path, monkeypatch):
    """Passing `end` pans the window: an outage sits at the right offset from the
    cursor, and events after the cursor are excluded."""
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "pan.db"))
    db.init()
    now = _t.time()
    cursor = now - 48 * 3600                       # view a window ending 2 days ago
    db.record_event(cursor - 5 * 86400, "ollama", True)
    db.record_event(cursor - 3 * 3600, "ollama", False)   # down 3h before the cursor
    db.record_event(cursor - 2 * 3600, "ollama", True)    # back up 2h before
    db.record_event(now - 60, "ollama", False)            # AFTER the cursor → ignored
    out = db.status_segments("24h", ["ollama"], end=cursor)["ollama"]
    assert [s["up"] for s in out["segments"]] == [True, False, True]
    assert abs(out["segments"][-1]["to"] - cursor) < 1     # window ends AT the cursor
    assert abs(out["uptime_pct"] - (23 / 24 * 100)) < 0.1  # exactly 1h down


def test_status_segments_handles_multiple_backends_in_one_call(tmp_path, monkeypatch):
    """One query returns an independent entry per requested backend."""
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "multi.db"))
    db.init()
    now = _t.time()
    db.record_event(now - 2 * 86400, "ollama", True)
    db.record_event(now - 2 * 86400, "vllm", False)
    out = db.status_segments("24h", ["ollama", "vllm"], end=now)
    assert out["ollama"]["uptime_pct"] == 100.0
    assert out["vllm"]["uptime_pct"] == 0.0


def test_self_uptime_segments_no_metrics_is_no_data(tmp_path, monkeypatch):
    """No metrics rows at all → no_data (the site lane draws 'no data yet', never
    a fabricated up)."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "nosite.db"))
    monkeypatch.setattr(config, "ROLLUP_RAW_HOURS", 24)   # pin so a 24h window tiers to raw regardless of env
    db.init()
    out = db.self_uptime_segments("24h", end=1_000_000.0)
    assert out["no_data"] is True and out["segments"] == []


def test_self_uptime_segments_continuous_is_fully_up(tmp_path, monkeypatch):
    """Unbroken sample cadence across the window → 100% up, no down segment."""
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "cont.db"))
    monkeypatch.setattr(config, "ROLLUP_RAW_HOURS", 24)   # pin so a 24h window tiers to raw regardless of env
    monkeypatch.setattr(config, "SAMPLE_INTERVAL", 5.0)
    db.init()
    now = _t.time()
    with db._connect() as c:
        t = now - 86400
        while t <= now:
            c.execute("INSERT INTO metrics(ts,cpu) VALUES(?,?)", (t, 10.0))
            t += 5
    out = db.self_uptime_segments("24h", end=now)
    assert out["no_data"] is False
    assert all(s["up"] for s in out["segments"])
    assert out["uptime_pct"] == 100.0


def test_self_uptime_segments_current_down_when_no_recent_sample(tmp_path, monkeypatch):
    """Samples stop an hour before now (site currently down/host off) → the lane
    ends in a down segment and uptime is below 100%."""
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "tail.db"))
    monkeypatch.setattr(config, "ROLLUP_RAW_HOURS", 24)   # pin so a 24h window tiers to raw regardless of env
    monkeypatch.setattr(config, "SAMPLE_INTERVAL", 5.0)
    db.init()
    now = _t.time()
    with db._connect() as c:
        t = now - 86400
        while t <= now - 3600:                      # nothing in the last hour
            c.execute("INSERT INTO metrics(ts,cpu) VALUES(?,?)", (t, 10.0))
            t += 5
    out = db.self_uptime_segments("24h", end=now)
    assert out["segments"][-1]["up"] is False
    assert 95 < out["uptime_pct"] < 96              # ~23/24


async def test_status_timeline_endpoint_shape_and_lane_order(tmp_path, monkeypatch):
    """The endpoint returns window/start/now plus one service object per enabled
    lane in fixed order (litellm, ollama, llamacpp, vllm, then site), each with
    segments/uptime_pct/no_data/configured. A bogus window normalises to 24h."""
    from aiohttp.test_utils import make_mocked_request
    import json
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "shape.db"))
    db.init()
    monkeypatch.setattr(appmod, "_latest", {"ts": 0, "collectors": {}})
    for name, url in (("LITELLM", "http://litellm:4000"), ("OLLAMA", "http://ollama:11434"),
                      ("LLAMACPP", "http://llamacpp:8080"), ("VLLM", "http://vllm:8000")):
        monkeypatch.setattr(config, f"{name}_ENABLED", True)
        monkeypatch.setattr(config, f"{name}_BASE_URL", url)
    for attr in ("GPU_SSH", "GPU_METRICS_URL", "GPU_METRICS_FILE"):
        monkeypatch.setattr(config, attr, "", raising=False)
    now = _t.time()
    db.record_event(now - 2 * 86400, "ollama", True)
    with db._connect() as c:
        for k in range(40):
            c.execute("INSERT INTO metrics(ts,cpu) VALUES(?,?)", (now - 200 + k * 5, 10.0))
    req = make_mocked_request("GET", "/api/status-timeline?window=bogus")
    resp = await appmod.status_timeline_handler(req)
    data = json.loads(resp.text)
    assert data["window"] == "24h"                       # bogus normalised
    assert data["now"] >= data["start"]
    assert abs((data["now"] - data["start"]) - 86400) < 2
    keys = [s["key"] for s in data["services"]]
    assert keys == ["litellm", "ollama", "llamacpp", "vllm", "site"]
    for s in data["services"]:
        assert set(("key", "label", "configured", "segments", "uptime_pct", "no_data")) <= set(s)
    ol = next(s for s in data["services"] if s["key"] == "ollama")
    assert ol["uptime_pct"] == 100.0 and ol["no_data"] is False


async def test_userreqs_resolves_owners_from_persisted_store_not_live(tmp_path, monkeypatch):
    """/api/userreqs must attach an owner map resolved from the PERSISTED store
    (known_keys.owner_name), so the by-user chart names keys immediately — without
    waiting for LiteLLM's ~60s live /user/list poll — and covers historical keys
    that are no longer in the current budgets list. No live LiteLLM call is made."""
    from aiohttp.test_utils import make_mocked_request
    import json
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "ur.db"))
    db.init()
    now = _t.time()
    day = _t.strftime("%Y-%m-%d", _t.gmtime(now))
    with db._connect() as c:
        c.execute("INSERT INTO spend_model_user_daily(day,model,key,alias,cost,tokens,reqs) "
                  "VALUES(?,?,?,?,?,?,?)", (day, "m", "k_alice", "alice-key", 0.0, 100.0, 50.0))
        # persisted owner for that key — the store, NOT a live poll
        c.execute("INSERT INTO known_keys(label,first_seen,last_seen,owner,owner_name) "
                  "VALUES(?,?,?,?,?)", ("alice-key", now, now, "u_alice", "alice@example.com"))
    req = make_mocked_request("GET", "/api/userreqs")
    resp = await appmod.userreqs_handler(req)
    d = json.loads(resp.text)
    assert "alice-key" in d.get("labels", [])
    assert "owners" in d, "userreqs must return an owners map"
    assert d["owners"].get("alice-key") == "alice@example.com"


async def test_userreqs_owner_override_beats_stored_name(tmp_path, monkeypatch):
    """An admin per-key user reassignment (key_user_overrides) wins over the stored
    last-known name in the userreqs owner map — same precedence as the budgets path."""
    from aiohttp.test_utils import make_mocked_request
    import json
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "urov.db"))
    db.init()
    now = _t.time()
    day = _t.strftime("%Y-%m-%d", _t.gmtime(now))
    with db._connect() as c:
        c.execute("INSERT INTO spend_model_user_daily(day,model,key,alias,cost,tokens,reqs) "
                  "VALUES(?,?,?,?,?,?,?)", (day, "m", "k_bob", "bob-key", 0.0, 100.0, 40.0))
        c.execute("INSERT INTO known_keys(label,first_seen,last_seen,owner,owner_name) "
                  "VALUES(?,?,?,?,?)", ("bob-key", now, now, "u_bob", "stored@example.com"))
    db.key_user_set("bob-key", "reassigned@example.com", now)
    req = make_mocked_request("GET", "/api/userreqs")
    resp = await appmod.userreqs_handler(req)
    d = json.loads(resp.text)
    assert d["owners"].get("bob-key") == "reassigned@example.com"


async def test_conc_by_key_and_keydelta_ship_server_owner_map(tmp_path, monkeypatch):
    """The 'by user' concurrency/backlog/user-delta charts fold keys → owners CLIENT-side; if the
    handler ships no owner map, every owned key stacks into one oversized 'Unassigned' band until
    /api/budgets warms up. Both concurrency-by-key and keydelta must attach the same server-
    resolved owner map userreqs does (persisted store + admin override), keyed by the series
    label, so owned keys attribute on the first paint."""
    from aiohttp.test_utils import make_mocked_request
    import json
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "own.db"))
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    monkeypatch.setattr(appmod, "_backend_latest", {"litellm": {"top_keys": [{"reqs": 1}]}})
    for i in range(8):
        t = now - 420 + i * 60
        with db._connect() as c:
            c.execute("INSERT INTO metrics(ts,conc,backlog) VALUES (?,?,?)", (t, 4.0, 3.0))
        db.insert_key_series(t, [{"key": "hA", "alias": "alice-key", "reqs": 5 + i}])
    with db._connect() as c:
        c.execute("INSERT INTO known_keys(label,first_seen,last_seen,owner,owner_name) "
                  "VALUES(?,?,?,?,?)", ("alice-key", now, now, "u_alice", "alice@example.com"))

    async def _cbk(path):
        r = await appmod.concurrency_by_key_handler(make_mocked_request("GET", path))
        return json.loads(r.text)

    async def _kd(path):
        r = await appmod.keydelta_handler(make_mocked_request("GET", path))
        return json.loads(r.text)

    ck = await _cbk("/api/litellm/concurrency-by-key?window=1h")
    assert ck.get("owners", {}).get("alice-key") == "alice@example.com", ck.get("owners")
    kd = await _kd("/api/keydelta?window=1h")
    assert kd.get("owners", {}).get("alice-key") == "alice@example.com", kd.get("owners")
    # an admin per-key reassignment must win here too (same precedence as userreqs)
    db.key_user_set("alice-key", "reassigned@example.com", now)
    ck2 = await _cbk("/api/litellm/concurrency-by-key?window=1h")
    assert ck2.get("owners", {}).get("alice-key") == "reassigned@example.com"


async def test_userreqs_follows_the_page_time_window(tmp_path, monkeypatch):
    """The 'Usage by user over time' chart must honour the page window (?window=):
    a 24h window excludes a key whose usage was 60 days ago, while 12mo (all-time)
    includes it. Day-granular, so the window maps to a day span."""
    from aiohttp.test_utils import make_mocked_request
    import json
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "urw.db"))
    db.init()
    now = _t.time()
    for off, alias in ((60, "old-key"), (0, "new-key")):
        day = _t.strftime("%Y-%m-%d", _t.gmtime(now - off * 86400))
        with db._connect() as c:
            c.execute("INSERT INTO spend_model_user_daily(day,model,key,alias,cost,tokens,reqs) "
                      "VALUES(?,?,?,?,?,?,?)", (day, "m", "k_" + alias, alias, 0.0, 10.0, 5.0))
            c.execute("INSERT INTO known_keys(label,first_seen,last_seen,owner,owner_name) "
                      "VALUES(?,?,?,?,?)", (alias, now, now, "u", alias + "@x.io"))

    async def labels_for(win):
        r = await appmod.userreqs_handler(make_mocked_request("GET", "/api/userreqs?window=" + win))
        return set(json.loads(r.text).get("labels", []))

    day_labels = await labels_for("24h")
    all_labels = await labels_for("12mo")
    assert "old-key" not in day_labels, "24h window must exclude 60-day-old usage"
    assert "new-key" in day_labels
    assert {"old-key", "new-key"} <= all_labels, "12mo must include all-time"


async def test_userreqs_default_window_is_all_time(tmp_path, monkeypatch):
    """Back-compat guard: with NO ?window= the endpoint defaults to all-time (12mo),
    so an older caller / the first paint still sees the full history."""
    from aiohttp.test_utils import make_mocked_request
    import json
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "urdef.db"))
    db.init()
    now = _t.time()
    day_old = _t.strftime("%Y-%m-%d", _t.gmtime(now - 60 * 86400))
    with db._connect() as c:
        c.execute("INSERT INTO spend_model_user_daily(day,model,key,alias,cost,tokens,reqs) "
                  "VALUES(?,?,?,?,?,?,?)", (day_old, "m", "k_old", "old-key", 0.0, 10.0, 5.0))
    resp = await appmod.userreqs_handler(make_mocked_request("GET", "/api/userreqs"))
    d = json.loads(resp.text)
    assert "old-key" in d.get("labels", []), "no window param must default to all-time"


async def test_userreqs_end_cursor_pans_the_window(tmp_path, monkeypatch):
    """?end= pans the window back in time: a 24h window anchored 40 days ago shows the
    usage from THEN, not today's."""
    from aiohttp.test_utils import make_mocked_request
    import json
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "urpan.db"))
    db.init()
    now = _t.time()
    past = now - 40 * 86400
    with db._connect() as c:
        c.execute("INSERT INTO spend_model_user_daily(day,model,key,alias,cost,tokens,reqs) "
                  "VALUES(?,?,?,?,?,?,?)",
                  (_t.strftime("%Y-%m-%d", _t.gmtime(past)), "m", "k_then", "then-key", 0.0, 10.0, 5.0))
        c.execute("INSERT INTO spend_model_user_daily(day,model,key,alias,cost,tokens,reqs) "
                  "VALUES(?,?,?,?,?,?,?)",
                  (_t.strftime("%Y-%m-%d", _t.gmtime(now)), "m", "k_now", "now-key", 0.0, 10.0, 5.0))
    url = "/api/userreqs?window=24h&end=" + str(int(past))
    d = json.loads((await appmod.userreqs_handler(make_mocked_request("GET", url))).text)
    labels = set(d.get("labels", []))
    assert "then-key" in labels, "panned window must show the past usage"
    assert "now-key" not in labels, "panned 24h window must exclude today"


async def test_userreqs_owners_map_only_covers_returned_labels(tmp_path, monkeypatch):
    """The owners map is scoped to the labels actually returned — no stray owners for
    keys that fell outside the window / top-N."""
    from aiohttp.test_utils import make_mocked_request
    import json
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "urscope.db"))
    db.init()
    now = _t.time()
    today = _t.strftime("%Y-%m-%d", _t.gmtime(now))
    with db._connect() as c:
        c.execute("INSERT INTO spend_model_user_daily(day,model,key,alias,cost,tokens,reqs) "
                  "VALUES(?,?,?,?,?,?,?)", (today, "m", "k_in", "in-key", 0.0, 10.0, 5.0))
        # owner stored for a key that has NO usage in the window → must NOT leak into owners
        c.execute("INSERT INTO known_keys(label,first_seen,last_seen,owner,owner_name) "
                  "VALUES(?,?,?,?,?)", ("in-key", now, now, "u", "in@x.io"))
        c.execute("INSERT INTO known_keys(label,first_seen,last_seen,owner,owner_name) "
                  "VALUES(?,?,?,?,?)", ("absent-key", now, now, "u", "absent@x.io"))
    d = json.loads((await appmod.userreqs_handler(make_mocked_request("GET", "/api/userreqs?window=24h"))).text)
    assert set(d.get("owners", {}).keys()) <= set(d.get("labels", [])), "owners must not exceed labels"
    assert "absent-key" not in d.get("owners", {})


async def test_budgets_ships_persisted_owner_map_for_by_user_charts(tmp_path, monkeypatch):
    """/api/budgets includes the persisted owner map (owner_names) so the client can seed its
    key->user map warm — fixing 'Unassigned' on ALL by-user charts, including historical keys
    that are no longer in the live budgets list."""
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "budown.db"))
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "budtok-123456")
    monkeypatch.setattr(config, "KEY_BUDGETS_JSON", "")
    db.init()
    with db._connect() as conn:
        conn.execute("INSERT INTO known_keys(label,first_seen,last_seen,owner,owner_name) "
                     "VALUES(?,?,?,?,?)", ("hist-key", _t.time(), _t.time(), "u", "hist@x.io"))
    hdr = {"Authorization": "Bearer budtok-123456"}
    c = await _client()
    try:
        d = await (await c.get("/api/budgets", headers=hdr)).json()
        assert "owner_names" in d, "budgets must ship the persisted owner map"
        assert d["owner_names"].get("hist-key") == "hist@x.io"
    finally:
        await c.close()


def test_self_uptime_segments_long_window_uses_rollup_not_fabricated_down(tmp_path, monkeypatch):
    """Regression (code review, Critical): a 30d/12mo site-uptime read must tier to the
    metrics_1h rollup (365d+ retention), NOT the raw `metrics` table (pruned to ~24h). Reading
    raw for a long window fabricated weeks of false 'down'. With hourly buckets present, a 6h
    outage shows as one ~6h down segment (not a 29-day one); with only 24h of raw and no rollup,
    the lane is `no_data`, never a giant fabricated outage."""
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "site30d.db"))
    monkeypatch.setattr(config, "ROLLUP_RAW_HOURS", 24)
    monkeypatch.setattr(config, "ROLLUP_MIN_DAYS", 1)   # so 30d tiers to metrics_1h deterministically
    db.init()
    now = _t.time()
    # metrics_1h = the 30d tier's heartbeat: seed hourly buckets across 30 days...
    with db._connect() as c:
        t = now - 30 * 86400
        while t < now:
            c.execute("INSERT OR IGNORE INTO metrics_1h(bucket,cpu) VALUES(?,?)", (t, 10.0))
            t += 3600
        # ...with a 6h hole 10 days ago (missing buckets = monitor was down)
        lo, hi = now - 10 * 86400, now - 10 * 86400 + 6 * 3600
        c.execute("DELETE FROM metrics_1h WHERE bucket>? AND bucket<?", (lo, hi))
    out = db.self_uptime_segments("30d", end=now)
    downs = [s for s in out["segments"] if not s["up"]]
    assert out["no_data"] is False
    assert len(downs) == 1, "the 6h outage must be one down segment, not a fabricated month"
    assert 5 * 3600 < (downs[0]["to"] - downs[0]["from"]) < 7 * 3600  # ~6h, not ~29 days
    assert out["uptime_pct"] > 99, "≈6h down out of 30d ≈ 99.2% up"


def test_self_uptime_segments_long_window_without_rollup_is_no_data(tmp_path, monkeypatch):
    """The other half: 30d window with ONLY the last 24h of raw metrics and no rollup buckets
    must return no_data (dashed 'no data yet') — NEVER ~29 days of fabricated down."""
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "site30d_raw.db"))
    monkeypatch.setattr(config, "SAMPLE_INTERVAL", 5.0)
    monkeypatch.setattr(config, "ROLLUP_RAW_HOURS", 24)
    monkeypatch.setattr(config, "ROLLUP_MIN_DAYS", 1)
    db.init()
    now = _t.time()
    with db._connect() as c:
        t = now - 24 * 3600
        while t < now:
            c.execute("INSERT INTO metrics(ts,cpu) VALUES(?,?)", (t, 10.0))
            t += 5
    out = db.self_uptime_segments("30d", end=now)
    assert out["no_data"] is True and out["uptime_pct"] == 0.0
    assert not any(not s["up"] and (s["to"] - s["from"]) > 2 * 86400 for s in out["segments"])


def test_self_uptime_segments_uses_1m_tier_for_mid_range_window(tmp_path, monkeypatch):
    """The MIDDLE tier: a window past raw retention but within ROLLUP_MIN_DAYS reads metrics_1m
    (per-minute) with a ~3min gap threshold. A 30-min hole in per-minute buckets = one ~30min
    down segment; a sub-threshold blip does not."""
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "site1m.db"))
    monkeypatch.setattr(config, "ROLLUP_RAW_HOURS", 24)
    monkeypatch.setattr(config, "ROLLUP_MIN_DAYS", 60)   # 30d window (< 60d) tiers to metrics_1m
    db.init()
    now = _t.time()
    with db._connect() as c:
        t = now - 30 * 86400
        while t < now:
            c.execute("INSERT OR IGNORE INTO metrics_1m(bucket,cpu) VALUES(?,?)", (t, 10.0))
            t += 60
        # a 30-min outage 5 days ago (missing per-minute buckets)
        lo, hi = now - 5 * 86400, now - 5 * 86400 + 30 * 60
        c.execute("DELETE FROM metrics_1m WHERE bucket>? AND bucket<?", (lo, hi))
    out = db.self_uptime_segments("30d", end=now)
    downs = [s for s in out["segments"] if not s["up"]]
    assert out["no_data"] is False
    assert len(downs) == 1 and 25 * 60 < (downs[0]["to"] - downs[0]["from"]) < 35 * 60  # ~30 min
    assert out["uptime_pct"] > 99.9


def test_self_uptime_segments_panned_short_window_reads_rollup_not_empty_raw(tmp_path, monkeypatch):
    """Pan-awareness (the whole reason for tiering): a SHORT window dragged deep into history
    (oldest point older than raw retention) must read the rollup, not the pruned raw table — else
    the site lane reads empty/no_data even though the monitor was up. A 1h window anchored 10 days
    ago finds its per-minute buckets and shows up, not no_data."""
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "sitepan.db"))
    monkeypatch.setattr(config, "ROLLUP_RAW_HOURS", 24)
    monkeypatch.setattr(config, "ROLLUP_MIN_DAYS", 60)
    db.init()
    now = _t.time()
    cursor = now - 10 * 86400            # view a 1h window ending 10 days ago
    with db._connect() as c:
        # per-minute buckets across that historical hour (+ a margin before it)
        t = cursor - 2 * 3600
        while t <= cursor:
            c.execute("INSERT OR IGNORE INTO metrics_1m(bucket,cpu) VALUES(?,?)", (t, 10.0))
            t += 60
    out = db.self_uptime_segments("1h", end=cursor)
    assert out["no_data"] is False, "panned window must read the rollup, not the empty pruned raw table"
    assert out["uptime_pct"] > 99 and all(s["up"] for s in out["segments"])


def test_self_uptime_segments_panned_24h_window_no_leading_fabricated_down(tmp_path, monkeypatch):
    """Regression (code review #2, Important): a 24h window PANNED back ~30 min must not reopen
    the fabricated-down bug. Its oldest point is ~24h30m old — past raw retention — so it must
    tier to metrics_1m and show the real (up) history, NOT a false 'down' band at the leading edge
    from the pruned raw table. The old `3600s live grace` incorrectly kept it on raw."""
    import time as _t
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "pan24.db"))
    monkeypatch.setattr(config, "ROLLUP_RAW_HOURS", 24)
    monkeypatch.setattr(config, "ROLLUP_MIN_DAYS", 60)   # 1m retention covers the panned span
    db.init()
    now = _t.time()
    end = now - 1800                                     # pan the 24h window back 30 min
    with db._connect() as c:
        # raw only for the last 24h (irrelevant to the panned window) — the old-bug bait
        t = now - 24 * 3600
        while t < now:
            c.execute("INSERT INTO metrics(ts,cpu) VALUES(?,?)", (t, 10.0))
            t += 5
        # per-minute 1m buckets across the panned window (+margin) = the real heartbeat there
        t = end - 24 * 3600 - 3600
        while t <= end:
            c.execute("INSERT OR IGNORE INTO metrics_1m(bucket,cpu) VALUES(?,?)", (t, 10.0))
            t += 60
    out = db.self_uptime_segments("24h", end=end)
    assert out["no_data"] is False
    assert out["uptime_pct"] > 99, "panned 24h with continuous 1m buckets ≈ fully up"
    # the key regression: no big fabricated 'down' band anywhere in the window
    assert not any(not s["up"] and (s["to"] - s["from"]) > 3600 for s in out["segments"]), \
        "no leading (or any) >1h fabricated-down band on a panned 24h window"


def test_webhook_log_records_and_reads_recent_deliveries(tmp_path, monkeypatch):
    """Webhook DELIVERY outcomes are persisted (they used to exist only in logs, so the UI could
    never answer 'did my alert actually reach Teams/Slack?' — the 202-accepted-but-nothing-rendered
    class of problem). Newest-first, capped, and every field the Channels card renders."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "wl.db"))
    db.init()
    now = 9_000_000.0
    db.record_webhook_send(now - 30, "webhook", "cpu_pct", 204, True, 41.5)
    db.record_webhook_send(now - 20, "webhook", "gpu_pct", 500, False, 12.0)
    db.record_webhook_send(now - 10, "webhook", "test", None, False, None)   # transport failure
    rows = db.recent_webhook_sends(10)
    assert len(rows) == 3
    assert [r["akey"] for r in rows] == ["test", "gpu_pct", "cpu_pct"], "newest first"
    assert rows[2]["status"] == 204 and rows[2]["ok"] is True and rows[2]["ms"] == 41.5
    assert rows[1]["ok"] is False and rows[1]["status"] == 500
    assert rows[0]["status"] is None and rows[0]["ok"] is False, "transport failure keeps a row"
    assert len(db.recent_webhook_sends(2)) == 2, "limit honoured"


def test_webhook_log_never_raises_on_bad_input(tmp_path, monkeypatch):
    """Recording a delivery must never propagate into the notifier — a logging concern must not
    break alert delivery itself (same best-effort contract as record_alert)."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "wl2.db"))
    db.init()
    db.record_webhook_send(9_000_000.0, "webhook", "x" * 500, "not-an-int", True, "nope")
    assert isinstance(db.recent_webhook_sends(5), list)


async def test_post_json_returns_outcome_and_fanout_batches_it(tmp_path, monkeypatch):
    """_post_json RETURNS (akey, status, ok, ms) and does NOT write — the write happens once,
    after the whole fan-out (a fan-out is 1+WEBHOOK_MAX_RECIPIENTS posts, and recording each
    inline put sqlite work inside the notifier's time budget, where a cancellation would sail
    past the recorder's `except Exception` and delay real alerts). 2xx -> ok+status,
    5xx -> not ok, transport failure -> ok False with NULL status/ms ('never arrived')."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "wl3.db"))
    db.init()

    class _Resp:
        def __init__(self, st): self.status = st
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

    class _Sess:
        def __init__(self, st=None, boom=False): self._st, self._boom = st, boom
        def post(self, *a, **k):
            if self._boom:
                raise OSError("connection refused")
            return _Resp(self._st)

    n = alerts.Notifier()
    ok_out = await n._post_json(_Sess(204), "https://hook.example.com/x", {"text": "t"}, "cpu")
    # (ts, akey, status, ok, ms) — ts is per-row so each delivery carries its own completion time
    assert len(ok_out) == 5 and ok_out[0] > 0
    assert ok_out[1] == "cpu" and ok_out[2] == 204 and ok_out[3] is True and ok_out[4] is not None
    bad_out = await n._post_json(_Sess(500), "https://hook.example.com/x", {"text": "t"}, "gpu")
    assert bad_out[2] == 500 and bad_out[3] is False
    dead_out = await n._post_json(_Sess(boom=True), "https://hook.example.com/x", {"t": 1}, "disk")
    assert dead_out[2] is None and dead_out[3] is False and dead_out[4] is None
    assert db.recent_webhook_sends(10) == [], "_post_json must not write; the fan-out batches"

    # the fan-out performs the single batched write
    monkeypatch.setattr(config, "ALERT_WEBHOOK_URL", "https://hook.example.com/global")
    await n._fanout(_Sess(204), "hello", [], "cpu_pct")
    rows = db.recent_webhook_sends(10)
    assert len(rows) == 1 and rows[0]["akey"] == "cpu_pct" and rows[0]["channel"] == "webhook"
    assert rows[0]["ok"] is True and rows[0]["status"] == 204


def test_record_webhook_sends_batches_in_one_call(tmp_path, monkeypatch):
    """The batch writer takes (ts,channel,akey,status,ok,ms) tuples, coerces defensively, and
    never raises — one connection for a whole fan-out instead of one per recipient."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "wlb.db"))
    db.init()
    now = 9_000_000.0
    db.record_webhook_sends([(now, "webhook", "a", 204, True, 5.0),
                             (now, "user", "a", None, False, None),
                             (now, "user", "a", "bogus", True, "bogus")])
    rows = db.recent_webhook_sends(10)
    assert len(rows) == 3
    assert {r["channel"] for r in rows} == {"webhook", "user"}
    db.record_webhook_sends([])          # no-op, must not raise


async def test_deliveries_hide_per_user_rows_from_non_admins(tmp_path, monkeypatch):
    """A fan-out writes one 'user' row per per-user recipient. Returning those to a viewer would
    leak how many colleagues have a webhook configured and whether each is failing, so a non-admin
    sees the operator-global scope only ('webhook'/'test')."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "wlscope.db"))
    db.init()
    now = 9_000_000.0
    db.record_webhook_sends([(now, "webhook", "cpu", 204, True, 5.0),
                            (now + 1, "user", "cpu", 204, True, 6.0),
                            (now + 2, "user", "cpu", 500, False, 7.0),
                            (now + 3, "test", "test", 200, True, 8.0)])
    assert {r["channel"] for r in db.recent_webhook_sends(10)} == {"webhook", "user", "test"}
    scoped = db.recent_webhook_sends(10, ("webhook", "test"))
    assert {r["channel"] for r in scoped} == {"webhook", "test"}, "per-user rows must be excluded"
    assert len(scoped) == 2


async def test_alerts_endpoint_exposes_recent_deliveries(tmp_path, monkeypatch):
    """/api/alerts ships the last-10 delivery list the Channels card reads, separate from
    `history` (which is what was EVALUATED, not what was delivered)."""
    from aiohttp.test_utils import make_mocked_request
    import json as _json
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "wl4.db"))
    db.init()
    now = 9_000_000.0
    for i in range(12):                       # more than the cap, to prove the limit
        db.record_webhook_send(now + i, "webhook", f"k{i}", 204, True, 10.0)
    d = _json.loads((await appmod.alerts_handler(make_mocked_request("GET", "/api/alerts"))).text)
    assert "deliveries" in d, "the endpoint must expose the delivery list"
    assert len(d["deliveries"]) == 10, "capped at 10"
    assert d["deliveries"][0]["akey"] == "k11", "newest first"
    assert "history" in d and isinstance(d["history"], list), "history must remain"


def test_backend_down_never_alerts_on_the_startup_seed(monkeypatch):
    """FIELD BUG: every monitor restart paged 'vLLM is DOWN — starting' + a recovery moments
    later. `_backend_latest` is seeded {"available": False, "error": "starting"} at import, and
    the main loop's first tick (pure /proc, sub-ms) beats the HTTP backends' first round-trip, so
    evaluate() read the SEED. 'starting' means NOT YET CHECKED — absence of a measurement is not
    evidence of an outage, and the monitor's own restart says nothing about the backend."""
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    snap = {"collectors": {
        "vllm": {"available": False, "error": "starting"},
        "litellm": {"available": False, "error": "starting"},
        "ollama": {"available": False, "error": "unconfigured"},
    }}
    keys = [k for k, _ in alerts.evaluate(snap)]
    assert keys == [], f"the startup seed must never alert; got {keys}"
    # a REAL transport failure still alerts (once it has crossed the strike threshold)
    real = {"collectors": {"vllm": {"available": False, "error": "ClientConnectorError"}}}
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_AFTER", 1)
    assert [k for k, _ in alerts.evaluate(real)] == ["down:vllm"]


def test_backend_down_requires_consecutive_failures(monkeypatch):
    """One failed poll is not an outage — a TLS-handshake blip or a proxy reload produces it.
    A backend must fail ALERT_BACKEND_DOWN_AFTER consecutive samples before it is called DOWN,
    and one success resets the streak."""
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_AFTER", 3)
    monkeypatch.setattr(config, "ALERT_BACKEND_UP_AFTER", 1)   # isolate the DOWN streak (instant recovery)
    alerts.reset_down_streaks()
    bad = {"collectors": {"vllm": {"available": False, "error": "TimeoutError"}}}
    good = {"collectors": {"vllm": {"available": True}}}
    assert [k for k, _ in alerts.evaluate(bad)] == [], "1st failure must stay quiet"
    assert [k for k, _ in alerts.evaluate(bad)] == [], "2nd failure must stay quiet"
    assert [k for k, _ in alerts.evaluate(bad)] == ["down:vllm"], "3rd consecutive failure alerts"
    assert [k for k, _ in alerts.evaluate(bad)] == ["down:vllm"], "stays down while failing"
    assert [k for k, _ in alerts.evaluate(good)] == [], "recovery clears"
    assert [k for k, _ in alerts.evaluate(bad)] == [], "streak reset by the success"


def test_backend_down_streak_is_per_backend(monkeypatch):
    """Each backend keeps its own streak — a flapping LiteLLM must not push vLLM toward DOWN."""
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_AFTER", 2)
    alerts.reset_down_streaks()
    both_bad = {"collectors": {"vllm": {"available": False, "error": "E"},
                               "litellm": {"available": False, "error": "E"}}}
    only_ll = {"collectors": {"vllm": {"available": True},
                              "litellm": {"available": False, "error": "E"}}}
    assert alerts.evaluate(both_bad) == []
    keys = [k for k, _ in alerts.evaluate(only_ll)]
    assert keys == ["down:litellm"], f"only litellm reached the threshold: {keys}"


def test_maintenance_window_suppresses_down_alert(monkeypatch):
    """A backend down INSIDE its configured maintenance window (a known, expected
    outage — e.g. a daily vLLM model-reload restart) must never alert, no matter how
    many consecutive failures accumulate. Once the window closes, it's a normal
    backend again — a real outage past that point still pages, after the usual
    N-consecutive-failures arm delay (the window boundary must not itself count)."""
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_AFTER", 2)
    alerts.reset_down_streaks()
    bad = {"collectors": {"vllm": {"available": False, "error": "connection refused"}}}

    monkeypatch.setattr(config, "in_maintenance_window", lambda name, now_ts=None: name == "vllm")
    assert alerts.evaluate(bad) == [], "1st failure inside the window: quiet"
    assert alerts.evaluate(bad) == [], "2nd failure inside the window: still quiet (would have armed)"
    assert alerts.evaluate(bad) == [], "stays quiet the whole window, however long it runs"

    monkeypatch.setattr(config, "in_maintenance_window", lambda name, now_ts=None: False)
    assert alerts.evaluate(bad) == [], "window just closed: 1st failure after, still not armed"
    keys = [k for k, _ in alerts.evaluate(bad)]
    assert keys == ["down:vllm"], f"2nd consecutive failure after the window must page: {keys}"


def test_maintenance_window_does_not_suppress_other_backends(monkeypatch):
    """A window scoped to vllm must not silence a genuine litellm outage."""
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_AFTER", 1)
    monkeypatch.setattr(config, "in_maintenance_window", lambda name, now_ts=None: name == "vllm")
    alerts.reset_down_streaks()
    both_bad = {"collectors": {"vllm": {"available": False, "error": "reload"},
                               "litellm": {"available": False, "error": "ClientConnectorError"}}}
    keys = [k for k, _ in alerts.evaluate(both_bad)]
    assert keys == ["down:litellm"], f"vllm suppressed, litellm still pages: {keys}"


def test_machine_name_reads_the_real_collector_shape(monkeypatch):
    """FIELD BUG: every webhook line read '[unknown-host]'. _machine() looked up
    host['hostname'], but the host collector puts it at host['info']['hostname'] — one level
    down — so the lookup ALWAYS missed and the fallback always won. The old unit test used a
    hand-made top-level shape that production never emits, which is why it stayed green."""
    monkeypatch.setattr(config, "INSTANCE_NAME", "")
    real = {"collectors": {"host": {"available": True, "info": {"hostname": "gpu-box-01"}}}}
    assert alerts._machine(real) == "gpu-box-01", "must read the REAL collector shape"
    legacy = {"collectors": {"host": {"available": True, "hostname": "gpu-box-01"}}}
    assert alerts._machine(legacy) == "gpu-box-01", "top-level shape still supported"
    monkeypatch.setattr(config, "INSTANCE_NAME", "prod-eu-1")
    assert alerts._machine(real) == "prod-eu-1", "operator override still wins"


def test_alert_text_falls_back_to_the_tool_name_not_unknown_host(monkeypatch):
    """When the hostname genuinely can't be resolved, the line must NOT say 'unknown-host' —
    it names the tool instead. No empty '[]' and no '[AI Monitoring] AI-Monitoring' stutter."""
    monkeypatch.setattr(config, "INSTANCE_NAME", "")
    blind = {"collectors": {"host": {"available": False}}}
    txt = alerts._alert_text(blind, "vLLM is DOWN — conn refused", fired=True)
    assert "unknown-host" not in txt and "unknown host" not in txt, txt
    assert "[]" not in txt, f"no empty bracket: {txt}"
    assert txt.count("AI-Monitoring") == 1, f"tool name must not stutter: {txt}"
    assert txt.startswith("🔴 AI-Monitoring — "), txt
    assert "vLLM is DOWN — conn refused" in txt
    # with a hostname the prefix is still there
    named = {"collectors": {"host": {"info": {"hostname": "gpu-box-01"}}}}
    assert alerts._alert_text(named, "x", fired=True).startswith("🔴 [gpu-box-01] AI-Monitoring — ")


class _RecSess:
    """Notifier fan-out stub: captures the messages that would be sent."""
    def __init__(self): self.msgs = []


async def _drive(n, snaps, monkeypatch, now0=1000.0, step=10.0):
    """Drive Notifier.process over a tick sequence, returning the emitted texts per tick."""
    out = []
    sess = _RecSess()

    async def _fanout(self, session, text, recipients, akey=""):
        sess.msgs.append(text)
    monkeypatch.setattr(alerts.Notifier, "_fanout", _fanout)
    monkeypatch.setattr(alerts.Notifier, "_recipients", lambda self: _noop_recipients())
    for i, s in enumerate(snaps):
        sess.msgs.clear()
        await n.process(None, s, now0 + i * step)
        out.append(list(sess.msgs))
    return out


async def _noop_recipients():
    return []


def _snap_backend(name, state, err="connection refused"):
    if state == "down":
        return {"ts": 0, "collectors": {name: {"available": False, "error": err}}}
    if state == "up":
        return {"ts": 0, "collectors": {name: {"available": True}}}
    if state == "unconfigured":
        return {"ts": 0, "collectors": {name: {"available": False, "error": "unconfigured"}}}
    return {"ts": 0, "collectors": {}}                      # missing


async def test_maintenance_window_never_sends_a_false_recovery(monkeypatch, tmp_path):
    """CRITICAL: a maintenance window opening MID-OUTAGE used to emit '🟢 vLLM is back UP' for a
    backend that never came up. evaluate() dropped the key to suppress it, but Notifier reads
    `_active - firing` as RECOVERED — absence meant recovery. Suppression must be silent."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "mw.db")); db.init()
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_AFTER", 3)
    monkeypatch.setattr(config, "ALERT_BACKEND_UP_AFTER", 3)
    monkeypatch.setattr(config, "ALERT_WEBHOOK_URL", "")
    alerts.reset_down_streaks()
    win = {"vllm": False}
    monkeypatch.setattr(config, "in_maintenance_window", lambda n: win.get(n, False))
    n = alerts.Notifier()
    down = _snap_backend("vllm", "down")
    # t1..t3 arm and fire
    msgs = await _drive(n, [down, down, down], monkeypatch)
    assert msgs[0] == [] and msgs[1] == []
    assert any("is DOWN" in m for m in msgs[2]), msgs[2]
    # t4: window opens while STILL down — must be silent, never a recovery
    win["vllm"] = True
    m4 = (await _drive(n, [down], monkeypatch, now0=2000.0))[0]
    assert not any("back UP" in m for m in m4), f"false recovery during maintenance: {m4}"
    assert m4 == [], f"maintenance must be silent, got {m4}"
    # t5-t6 inside the window: still silent
    inside = await _drive(n, [down, down], monkeypatch, now0=3000.0)
    assert inside == [[], []], inside
    # window closes, still down: no NEW page (nothing changed) and no recovery
    win["vllm"] = False
    after = await _drive(n, [down, down], monkeypatch, now0=4000.0)
    assert not any("back UP" in m for tick in after for m in tick), after


async def test_disabling_a_backend_closes_the_alert_silently(monkeypatch, tmp_path):
    """Toggling a backend OFF (collector -> 'unconfigured'), or it vanishing from the snapshot,
    must CANCEL a latched DOWN silently — 'no longer monitored' is not 'recovered'."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "mw2.db")); db.init()
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_AFTER", 2)
    monkeypatch.setattr(config, "ALERT_WEBHOOK_URL", "")
    monkeypatch.setattr(config, "in_maintenance_window", lambda n: False)
    for state in ("unconfigured", "missing"):
        alerts.reset_down_streaks()
        n = alerts.Notifier()
        down = _snap_backend("vllm", "down")
        msgs = await _drive(n, [down, down], monkeypatch)
        assert any("is DOWN" in m for m in msgs[1]), (state, msgs)
        off = (await _drive(n, [_snap_backend("vllm", state)], monkeypatch, now0=9000.0))[0]
        assert off == [], f"{state}: must close silently, got {off}"
        assert n.active_keys() == [], f"{state}: alert must be cleared, got {n.active_keys()}"


def test_up_streak_decays_so_a_mostly_healthy_backend_recovers(monkeypatch):
    """A hard up-streak reset meant that if the blip period was shorter than UP_AFTER ticks, the
    up-streak could never reach the threshold — an 85%-healthy backend stayed latched DOWN
    forever and re-paged every ALERT_REPEAT_MIN, inverting the flap-damping it was added for.
    The streak now DECAYS by one per bad poll, so a mostly-good backend still recovers."""
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_AFTER", 3)
    monkeypatch.setattr(config, "ALERT_BACKEND_UP_AFTER", 10)
    monkeypatch.setattr(config, "in_maintenance_window", lambda n: False)
    alerts.reset_down_streaks()
    down = {"collectors": {"vllm": {"available": False, "error": "conn refused"}}}
    up = {"collectors": {"vllm": {"available": True}}}
    for _ in range(3):
        alerts.evaluate(down)
    assert [k for k, _ in alerts.evaluate(down)] == ["down:vllm"], "must be latched"
    # 7 good : 1 bad, repeated — 85% healthy. With a hard reset this NEVER clears.
    fired = True
    for _ in range(12):
        for _ in range(7):
            fired = bool([k for k, _ in alerts.evaluate(up)])
        alerts.evaluate(down)
    assert not fired, "a mostly-healthy backend must eventually clear, not latch forever"


async def test_backend_timeout_is_recorded_as_a_failure_not_a_stale_good_sample(monkeypatch):
    """A wedged backend used to keep its LAST sample on timeout, so it presented available:True
    forever — the panel showed it healthy, the up-streak could emit 'back UP' for something hung,
    and no down: alert could ever arm. A timeout is itself the failure signal."""
    monkeypatch.setattr(appmod, "_backend_latest", dict(appmod._backend_latest))
    appmod._backend_latest["vllm"] = {"available": True, "models": ["m"]}

    async def _hang(session):
        await asyncio.sleep(9999)

    async def _one_tick():
        task = asyncio.create_task(appmod._backend_loop("vllm", _hang, None, 0.05))
        await asyncio.sleep(0.35)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    await _one_tick()
    got = appmod._backend_latest["vllm"]
    assert got.get("available") is False, f"timeout must mark the backend down: {got}"
    assert "timeout" in str(got.get("error", "")), got
    assert got.get("error") not in alerts._NOT_AN_OUTAGE, "a timeout must be able to arm an alert"


def test_majority_failing_backend_arms_without_consecutive_failures(monkeypatch):
    """Consecutive-only arming can never page a backend that fails MOST polls without ever
    failing N in a row (2-in-3 error rate resets the streak forever). More-than-half of the last
    window arms it. A strict 50/50 alternation must STAY quiet — that is the flap the hysteresis
    exists to damp, and paging on it would undo the anti-flap work."""
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_AFTER", 3)
    monkeypatch.setattr(config, "ALERT_BACKEND_UP_AFTER", 3)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_WINDOW", 10)
    monkeypatch.setattr(config, "in_maintenance_window", lambda n: False)
    D = {"collectors": {"vllm": {"available": False, "error": "e"}}}
    U = {"collectors": {"vllm": {"available": True}}}

    alerts.reset_down_streaks()
    fired = []
    for _ in range(12):                       # 66% failing, never 3 consecutive
        for s in (D, D, U):
            fired = [k for k, _ in alerts.evaluate(s)]
    assert fired == ["down:vllm"], "a mostly-failing backend must page"

    alerts.reset_down_streaks()
    for _ in range(12):                       # exact 50/50 = flap
        for s in (D, U):
            fired = [k for k, _ in alerts.evaluate(s)]
    assert fired == [], "a 50/50 flap must stay damped, not page"

    # disabled by config → consecutive-only behaviour restored
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_WINDOW", 0)
    alerts.reset_down_streaks()
    for _ in range(12):
        for s in (D, D, U):
            fired = [k for k, _ in alerts.evaluate(s)]
    assert fired == [], "window=0 disables the majority arm"


def test_merge_key_budgets_dedups_a_key_seen_under_two_identities():
    """One physical key described differently by the two sources (live /key/list knows it by the
    masked key_name, the spend snapshot only by the full hash) used to be appended TWICE, double
    counting its spend across the totals, the key count and the table."""
    live = {"sk-...9f3c": {"spend": 100.0, "team": "", "budget": 0.0, "user": "", "user_name": "",
                           "ids": ["sk-...9f3c", "FULLHASH123"],
                           "ids_strong": ["FULLHASH123"]}}   # hash-class subset (production shape)
    snapshot = [{"key": "FULLHASH123", "alias": "", "cost": 12.34}]
    rows = appmod.merge_key_budgets(live, snapshot, {})
    assert len(rows) == 1, f"same key under two identities must not duplicate: {rows}"
    assert rows[0]["cost"] == 100.0
    # a genuinely different key is still unioned in
    rows2 = appmod.merge_key_budgets(live, [{"key": "OTHERHASH", "alias": "", "cost": 5.0}], {})
    assert len(rows2) == 2, rows2


def test_budget_rows_expose_every_identity_for_the_cost_join():
    """The windowed cost map is keyed by whatever label the rollup stored (the full hash for an
    alias-less key) while the budget row's `key` may be the masked name — so the row must carry
    ALL its identities or the client's winSpent() lookup misses and the user vanishes from the
    Cost chart while the table still lists their spend."""
    from collectors import litellm as L
    rows = L.budget_rows([{"key_name": "sk-...9f3c", "token": "FULLHASH123", "spend": 5.0}],
                         {}, 15, 30)
    assert rows, "expected a budget row"
    ids = rows[0].get("ids") or []
    assert "sk-...9f3c" in ids and "FULLHASH123" in ids, f"both identities must ship: {ids}"


async def test_flapping_backend_cannot_storm_past_repeat_min(monkeypatch, tmp_path):
    """ALERT_REPEAT_MIN rate-limits STATE CHANGES. A recovery used to send immediately AND clear
    the debounce, so the next failure counted as first-seen: fire→recover→fire→recover forever
    (measured 15 webhook posts in ~5 min on defaults). A not-yet-due recovery is DEFERRED, never
    dropped — the all-clear still arrives once the cooldown passes."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "storm.db")); db.init()
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_AFTER", 3)
    monkeypatch.setattr(config, "ALERT_BACKEND_UP_AFTER", 3)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_WINDOW", 0)
    monkeypatch.setattr(config, "ALERT_REPEAT_MIN", 30.0)
    monkeypatch.setattr(config, "ALERT_WEBHOOK_URL", "")
    monkeypatch.setattr(config, "in_maintenance_window", lambda n: False)
    alerts.reset_down_streaks()
    D = {"ts": 0, "collectors": {"vllm": {"available": False, "error": "e"}}}
    U = {"ts": 0, "collectors": {"vllm": {"available": True}}}
    posts = []

    async def _fanout(self, session, text, recipients, akey=""):
        posts.append(text)
    monkeypatch.setattr(alerts.Notifier, "_fanout", _fanout)
    monkeypatch.setattr(alerts.Notifier, "_recipients", lambda self: _noop_recipients())
    n = alerts.Notifier()
    pattern = [U, U, D, U, U, D, D, D]
    t = 1000.0
    for _ in range(8):                      # 64 ticks at 5s ≈ 5.3 minutes
        for s in pattern:
            await n.process(None, s, t)
            t += 5.0
    assert len(posts) <= 2, f"flap storm: {len(posts)} posts in 5 min with REPEAT_MIN=30: {posts}"


async def test_backend_recovering_inside_a_maintenance_window_does_not_false_page(monkeypatch, tmp_path):
    """The normal maintenance case: an outage arms, the window opens, the restart FIXES it. The
    window branch used to skip poll data entirely, so the latch survived and the first tick after
    the window emitted '🔴 is DOWN' with the stale pre-window reason for a healthy backend."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "mwrec.db")); db.init()
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_AFTER", 3)
    monkeypatch.setattr(config, "ALERT_BACKEND_UP_AFTER", 3)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_WINDOW", 0)
    monkeypatch.setattr(config, "ALERT_WEBHOOK_URL", "")
    alerts.reset_down_streaks()
    win = {"on": False}
    monkeypatch.setattr(config, "in_maintenance_window", lambda n: win["on"])
    posts = []

    async def _fanout(self, session, text, recipients, akey=""):
        posts.append(text)
    monkeypatch.setattr(alerts.Notifier, "_fanout", _fanout)
    monkeypatch.setattr(alerts.Notifier, "_recipients", lambda self: _noop_recipients())
    n = alerts.Notifier()
    D = {"ts": 0, "collectors": {"vllm": {"available": False, "error": "conn refused"}}}
    U = {"ts": 0, "collectors": {"vllm": {"available": True}}}
    t = 1000.0
    for _ in range(3):                      # arm + fire
        await n.process(None, D, t); t += 5
    assert any("is DOWN" in p for p in posts)
    win["on"] = True
    posts.clear()
    for _ in range(8):                      # recovers INSIDE the window
        await n.process(None, U, t); t += 5
    win["on"] = False
    for _ in range(3):                      # window closes, still healthy
        await n.process(None, U, t); t += 5
    assert not any("is DOWN" in p for p in posts), f"false page after window: {posts}"
    # The genuine recovery IS announced — we paged for this outage, so the all-clear is owed and
    # arrives as soon as the backend is stably up, window or not.
    assert any("back UP" in p for p in posts), f"recovery must be delivered: {posts}"
    assert n.active_keys() == [], f"alert must clear after the recovery: {n.active_keys()}"


def test_backend_down_toggle_off_cancels_silently(monkeypatch):
    """Turning ALERT_ON_BACKEND_DOWN off while a backend is latched must CANCEL the alert, not
    let the key vanish (which Notifier reads as '🟢 back UP' for a still-down backend)."""
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_AFTER", 2)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_WINDOW", 0)
    monkeypatch.setattr(config, "in_maintenance_window", lambda n: False)
    alerts.reset_down_streaks()
    D = {"collectors": {"vllm": {"available": False, "error": "e"}}}
    alerts.evaluate(D)
    assert [k for k, _ in alerts.evaluate(D)] == ["down:vllm"]
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", False)
    assert alerts.evaluate(D) == []
    assert "down:vllm" in alerts.cancelled_keys(), "toggle-off must CANCEL, not look like recovery"


def test_down_window_does_not_silently_cap_down_after(monkeypatch):
    """N consecutive failures always satisfy 'more than half of the last N', so the smaller knob
    used to win: an operator raising ALERT_BACKEND_DOWN_AFTER above the window size was paged
    after `window` failures instead. The majority arm now also requires DOWN_AFTER failures."""
    monkeypatch.setattr(config, "ALERT_ON_BACKEND_DOWN", True)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_AFTER", 10)
    monkeypatch.setattr(config, "ALERT_BACKEND_DOWN_WINDOW", 3)
    monkeypatch.setattr(config, "in_maintenance_window", lambda n: False)
    alerts.reset_down_streaks()
    D = {"collectors": {"vllm": {"available": False, "error": "e"}}}
    for i in range(9):
        assert alerts.evaluate(D) == [], f"must not page before 10 failures (tick {i+1})"
    assert [k for k, _ in alerts.evaluate(D)] == ["down:vllm"], "pages at the 10th, as configured"


def test_merge_key_budgets_does_not_lose_a_key_to_an_alias_collision():
    """The identity-set dedup must not collapse DISTINCT keys. Hash-class ids (key/api_key/token)
    are unique and match across fields; alias-class ids (key_name `sk-…4chars`, reusable aliases)
    match canonical-label to canonical-label only. Matching any-id-to-any-id made a real key's
    spend vanish from the totals, the count, the table AND the chart."""
    live = {"billing": {"spend": 10.0, "team": "", "budget": 0.0, "user": "", "user_name": "",
                        "ids": ["billing", "sk-...4f2a", "hashL"],
                        "key_name": "sk-...4f2a", "token": "hashL"}}
    # a DIFFERENT (deleted) key whose alias equals the live key's masked name
    rows = appmod.merge_key_budgets(live, [{"key": "hashD", "alias": "sk-...4f2a", "cost": 300.0}], {})
    assert len(rows) == 2, f"distinct keys must both survive: {rows}"
    assert round(sum(r.get("cost", 0) for r in rows), 2) == 310.0, "no money may vanish"
    # the SAME key under two representations must still collapse (the original double-count bug)
    live2 = {"sk-...9f3c": {"spend": 100.0, "ids": ["sk-...9f3c", "FULLHASH123"],
                            "key_name": "sk-...9f3c", "token": "FULLHASH123"}}
    rows2 = appmod.merge_key_budgets(live2, [{"key": "FULLHASH123", "alias": "", "cost": 12.34}], {})
    assert len(rows2) == 1 and round(sum(r.get("cost", 0) for r in rows2), 2) == 100.0


def test_status_segments_never_draws_unobserved_time_as_up(tmp_path, monkeypatch):
    """FIELD BUG: the status timeline drew confident GREEN for time the monitor never observed.
    State before the first event defaulted to UP, so a backend whose first-ever event was a DOWN
    3h ago rendered 21h of green and claimed 87.5% uptime. Unknown is its own state: it must be
    reported as up=None (dashed 'no data' styling) and excluded from the uptime denominator."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "unk.db"))
    db.init()
    now = 1_000_000.0
    db.record_event(now - 3 * 3600, "vllm", False, "conn refused")   # first-ever event, DOWN
    out = db.status_segments("24h", ["vllm"], end=now)["vllm"]
    kinds = [s["up"] for s in out["segments"]]
    assert kinds[0] is None, f"time before the first observation must be UNKNOWN, got {kinds}"
    assert kinds[-1] is False, f"the observed span is down, got {kinds}"
    assert not any(s["up"] is True for s in out["segments"]), \
        f"no fabricated UP run: {out['segments']}"
    # uptime is over OBSERVED time only — 0 of the 3 known hours were up
    assert out["uptime_pct"] == 0.0, f"unobserved time must not inflate uptime: {out}"


def test_status_segments_uptime_is_over_observed_time_only(tmp_path, monkeypatch):
    """A backend never sampled at all reported uptime_pct 100.0 — a perfect score for something
    that was never observed. With nothing known, the percentage is 0 and no_data flags the lane."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "unk2.db"))
    db.init()
    out = db.status_segments("24h", ["ollama"], end=1_000_000.0)["ollama"]
    assert out["no_data"] is True
    assert out["uptime_pct"] == 0.0, f"never-sampled must not claim 100%: {out}"
    assert all(s["up"] is None for s in out["segments"]), out["segments"]
