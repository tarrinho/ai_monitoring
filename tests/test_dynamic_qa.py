# Dynamic QA — runs the real aiohttp app + real collectors against a stub
# backend server. Proves: endpoints serve, auth gate works, host metrics are
# live, unconfigured backends degrade gracefully, and each collector parses
# real JSON responses correctly.
import asyncio
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
from collectors import host, litellm, ollama, llamacpp, gpu, procs


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
    _s = app.get(appmod._SAMPLER)
    if _s is not None:
        _s.cancel()
    return c


async def test_healthz_open_and_ok():
    c = await _client()
    try:
        r = await c.get("/healthz")
        assert r.status == 200
        body = await r.json()
        assert body["version"] == config.VERSION
        assert body["status"] in ("ok", "starting")
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
        # a CORRECT token is still refused while the IP is locked out
        assert (await c.get("/api/data?token=supersecrettoken1234")).status == 429
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
    """A backend whose sample never returns (wedged nvidia-smi / dead proxy) must
    be timed out by the loop's wait_for bound — the loop survives and keeps its
    last good value instead of freezing forever (the wedged-loop bug)."""
    import app as appmod
    appmod._backend_latest["ollama"] = {"available": True, "_pre": 1}

    async def _hang(_s):
        await asyncio.sleep(100)      # simulate a wedged backend

    task = asyncio.create_task(appmod._backend_loop("ollama", _hang, None, 0.3))
    await asyncio.sleep(0.8)          # > bound, so at least one tick timed out
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    # timed out -> prior value preserved, loop never wedged or crashed
    assert appmod._backend_latest["ollama"] == {"available": True, "_pre": 1}


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


def test_collector_status_logging(monkeypatch, capsys):
    """MONITOR_DEBUG logs each collector's availability + error on change, incl. a
    GPU hint — so 'why is the GPU panel missing?' is visible in docker logs."""
    import app as appmod
    monkeypatch.setattr(config, "MONITOR_DEBUG", True)
    appmod._status_prev.clear()
    snap = {"collectors": {
        "host": {"available": True},
        "gpu": {"available": False, "error": "unconfigured"},
        "litellm": {"available": False, "error": "conn: ClientConnectorError"},
    }}
    appmod._log_collector_status(snap)
    err = capsys.readouterr().err
    assert "[collector] host: OK" in err
    assert "gpu: unavailable — unconfigured" in err and "GPU_SSH" in err
    assert "litellm: unavailable — conn: ClientConnectorError" in err
    # unchanged status is NOT re-logged (only on change)
    appmod._log_collector_status(snap)
    assert capsys.readouterr().err == ""
    # disabled => silent
    monkeypatch.setattr(config, "MONITOR_DEBUG", False)
    appmod._status_prev.clear()
    appmod._log_collector_status(snap)
    assert capsys.readouterr().err == ""


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


# --------------------------------------------------------------- host live ----
def test_host_sample_live():
    h = host.sample("/")
    assert h["available"] is True
    assert isinstance(h["cpu_pct"], (int, float))
    assert h["mem_total"] > 0
    assert 0 <= h["mem_pct"] <= 100
    assert h["ncpu"] >= 1


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

    async def fake_fanout(self, session, text, recipients=None):
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
    assert any("recovered" in m for m in sent_log)


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
        assert set(d) == {"litellm", "spend", "ollama", "llamacpp", "gpu", "admin"}
        assert all(isinstance(v, bool) for v in d.values())
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
    now = _t.mktime(_t.strptime("2026-07-16", "%Y-%m-%d"))
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


async def test_spend_series_uses_per_day_cost_when_available(monkeypatch):
    """When LiteLLM gives a per-day per-model breakdown, the series uses it (cost_basis
    'per-day') so an external model's cost lands ONLY on days it ran — Jul 07 (self-hosted
    only) shows real_cost 0, which the old blended estimate wrongly smeared > 0."""
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "sp-tok-pd1")
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")

    async def _daily(session, s, e):
        return [{"date": "2026-07-07", "requests": 5, "tokens": 2000, "spend": 0.0},
                {"date": "2026-07-08", "requests": 9, "tokens": 4000, "spend": 0.0}]

    async def _prices(session):
        return {"gpt-4o": 0.001, "ollama/qwen": 0.0001}

    async def _pm(session, s, e, ov=None):
        return [{"model": "gpt-4o", "tokens": 1000, "reqs": 4,
                 "internal": False, "cost_kind": "real"},
                {"model": "ollama/qwen", "tokens": 5000, "reqs": 10,
                 "internal": True, "cost_kind": "reference"}]

    async def _pmd(session, s, e, prices, ov=None):
        return {"2026-07-07": {"real": 0.0, "est": 0.20},
                "2026-07-08": {"real": 1.00, "est": 0.30}}
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
        assert pts["2026-07-07"]["real_cost"] == 0.0      # external model didn't run → 0
        assert pts["2026-07-08"]["real_cost"] == 1.00
        assert d["real_cost_total"] == 1.00
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
    assert rows[0]["pct"] == 95.0 and rows[0]["projected"] > 0
    assert rows[0]["days_to_cap"] >= 0


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
    """A key with no budget defined is NEVER dropped — its spend/burn are shown,
    with no cap maths (budget/pct/days_to_cap are None, status 'none')."""
    rows = litellm.budget_rows([{"alias": "nobudget", "cost": 500}], {}, 10, 30)
    assert len(rows) == 1
    r = rows[0]
    assert r["key"] == "nobudget" and r["status"] == "none"
    assert r["budget"] is None and r["pct"] is None and r["days_to_cap"] is None
    assert r["spent"] == 500 and r["burn"] == 50.0      # spend + burn still reported
    # summary counts the gap so it can be surfaced, not hidden
    s = appmod._budget_summary(rows)
    assert s["unbudgeted"] == 1 and s["unbudgeted_spend"] == 500
    assert s["budgeted"] == 0 and s["budget"] == 0 and s["pct"] == 0


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

    class _FakeSess:
        def get(self, url, **kw):
            if "containers/json?all=1" in url:
                class _L(_FakeResp):
                    async def json(self):
                        return [{"Names": [f"/c{i}"]} for i in range(N)]
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
    """Unconfigured-backend sidebar links (LiteLLM/Spend/Ollama/llama.cpp/GPU) are
    dropped SERVER-side, not only by the client /api/nav fetch — so a slow/failed
    fetch can't leave a dead link visible (the reported token-session symptom). The
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
        assert "🦙 Ollama" not in h and "🐫 llama.cpp" not in h
        assert "🖥️ GPU" not in h
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
        assert "🔀 LiteLLM" in h2 and "🦙 Ollama" in h2 and "🖥️ GPU" in h2
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


async def test_litellm_auth_failure_reported_clearly(monkeypatch, capsys):
    # A rejected master key (401/403) must be reported CLEARLY in the log ("the
    # token is invalid/expired") and set an auth_error on the collector — not just a
    # bare "HTTP 401", and it must short-circuit the key-gated /spend calls.
    litellm._AUTH_BAD = False

    async def fake_fetch(session, url, headers=None, timeout_s=None):
        if "liveliness" in url:
            return ("I'm alive!", None)
        return (None, "HTTP 401")             # models / spend / everything → 401
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-wrong")
    out = await litellm.sample(None)
    assert out.get("auth_error") is True
    assert "master key rejected" in (out.get("error") or "")
    log = capsys.readouterr().err
    assert "AUTH FAILED" in log and ("invalid" in log and "expired" in log)
    litellm._AUTH_BAD = False                  # reset shared state for other tests


def test_note_auth_one_shot_and_recovery(capsys):
    """_note_auth logs the failure ONCE (not every poll), stays quiet while still bad,
    then logs a single AUTH OK on recovery and clears the flag."""
    litellm._AUTH_BAD = False
    assert litellm._note_auth("http://litellm:4000", "HTTP 401") is True   # bad → log
    assert litellm._AUTH_BAD is True
    assert litellm._note_auth("http://litellm:4000", "HTTP 403") is True   # still bad → quiet
    err1 = capsys.readouterr().err
    assert err1.count("AUTH FAILED") == 1 and "AUTH OK" not in err1
    assert litellm._note_auth("http://litellm:4000", None) is False        # recovered
    assert litellm._AUTH_BAD is False
    err2 = capsys.readouterr().err
    assert err2.count("AUTH OK") == 1
    # a clean tick while already-good logs nothing
    assert litellm._note_auth("http://litellm:4000", None) is False
    assert capsys.readouterr().err == ""
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
    """litellm.model_prices reads input+output cost per token from /model/info and only
    keeps models with a non-zero price."""
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
    assert round(pr["azure_ai/gpt-5-mini"], 12) == 2.25e-06   # in + out
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
    # cases use ALLOW_PRIVATE=True which skips the resolve step.
    monkeypatch.setattr(config, "WEBHOOK_HTTPS_ONLY", False)
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_HOSTS", "")
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_PRIVATE", False)
    for bad in ("http://169.254.169.254/latest/meta", "http://127.0.0.1:9000/x",
                "http://10.1.2.3/hook", "http://[::1]/x", "ftp://host/x", "notaurl"):
        assert await alerts.validate_webhook_url(bad) is not None, bad
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_PRIVATE", True)   # skip DNS/IP check
    assert await alerts.validate_webhook_url("https://hooks.slack.com/services/x") is None
    monkeypatch.setattr(config, "WEBHOOK_HTTPS_ONLY", True)      # rejects http
    assert await alerts.validate_webhook_url("http://hooks.slack.com/x") is not None
    monkeypatch.setattr(config, "WEBHOOK_HTTPS_ONLY", False)
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_HOSTS", "hooks.slack.com,discord.com")
    assert await alerts.validate_webhook_url("https://evil.example.com/x") is not None
    assert await alerts.validate_webhook_url("https://team.discord.com/x") is None   # subdomain ok


async def test_account_webhook_get_set(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_PRIVATE", True)      # allow test host
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
    monkeypatch.setattr(config, "WEBHOOK_ALLOW_PRIVATE", True)
    monkeypatch.setattr(config, "ALERT_CPU_PCT", 50.0)
    monkeypatch.setattr(config, "ALERT_REPEAT_MIN", 9999)
    db.user_create("wf", "f@x.io", auth.hash_password("wfpw1234"), "viewer", time.time())
    db.user_set_webhook("wf", "https://hooks.example.test/mine", True)
    posted = []

    async def fake_post(self, session, url, payload):
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


async def test_webhook_set_is_audited(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
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
    # the operator opt-in must still reach a LAN host (resolver mustn't over-block)
    import alerts
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


# ── server error logging (1.3.2) ──────────────────────────────────────────────
async def test_server_logs_failed_login(monkeypatch):
    logs = []
    monkeypatch.setattr(appmod, "_log", lambda m: logs.append(m))
    db.user_create("le", "l@x.io", auth.hash_password("lepw1234"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "le", "password": "WRONG"})
    finally:
        await c.close()
    assert any("login FAILED" in m and "le" in m for m in logs)


async def test_server_logs_denied_admin_action(monkeypatch):
    monkeypatch.setattr(config, "COOKIE_ALLOW_INSECURE", True)
    logs = []
    monkeypatch.setattr(appmod, "_log", lambda m: logs.append(m))
    db.user_create("vw", "v@x.io", auth.hash_password("vwpw1234"), "viewer", time.time())
    c = await _client()
    try:
        await c.post("/login", data={"username": "vw", "password": "vwpw1234"})
        await c.get("/api/admin/users")           # viewer -> 403
    finally:
        await c.close()
    assert any("[deny]" in m and "403" in m for m in logs)


async def test_server_does_not_log_normal_200(monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "")
    monkeypatch.setattr(config, "ALLOW_OPEN", True)
    logs = []
    monkeypatch.setattr(appmod, "_log", lambda m: logs.append(m))
    c = await _client()
    try:
        assert (await c.get("/healthz")).status == 200
        assert (await c.get("/gpu")).status == 200
    finally:
        await c.close()
    assert not any("healthz" in m or "/gpu" in m for m in logs)   # no 200 noise


async def test_log_mw_logs_unhandled_exception_with_traceback(monkeypatch):
    logs = []
    monkeypatch.setattr(appmod, "_log", lambda m: logs.append(m))

    class _Req:
        method = "GET"
        path = "/api/boom"

    async def boom(_r):
        raise ValueError("kaboom")
    with pytest.raises(ValueError):
        await appmod._log_mw(_Req(), boom)
    assert any("500" in m and "Traceback" in m and "kaboom" in m for m in logs)


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


# ── Top-10 keys "requests in window" delta chart (1.3.2) ──────────────────────
def _clear_key_series():
    """Isolate per-key delta tests from cross-run pollution (the shared test DB is
    not reset for key_series between runs)."""
    db.init()
    with db._connect() as conn:
        conn.execute("DELETE FROM key_series")
        conn.execute("DELETE FROM key_series_1m")
        conn.execute("DELETE FROM key_series_1h")


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
    _clear_key_series()
    now = time.time()
    db.insert_key_series(now - 1800, [{"key": "kr", "alias": "RST_delta", "reqs": 900}])
    db.insert_key_series(now - 60,   [{"key": "kr", "alias": "RST_delta", "reqs": 50}])  # daily reset
    res = db.key_series_window_delta("1h")
    m = dict(zip(res["labels"], res["deltas"]))
    assert m.get("RST_delta") == 50                        # end value, never negative


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
