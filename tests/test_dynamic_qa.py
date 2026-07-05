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
        assert set(d["windows"]) >= {"15m", "1h", "24h", "30d"}
        assert isinstance(d["points"], list)
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
        assert set(d) == {"litellm", "ollama", "llamacpp", "gpu"}
        assert all(isinstance(v, bool) for v in d.values())
    finally:
        await c.close()


async def test_alerts_endpoint_shape():
    c = await _client()
    try:
        r = await c.get("/api/alerts")
        assert r.status == 200
        d = await r.json()
        assert "channels" in d and "thresholds" in d
        assert "active" in d and "history" in d
        ids = {ch["id"] for ch in d["channels"]}
        assert ids == {"webhook"}          # webhook-only
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
    c = await _client()
    try:
        r = await c.get("/alerts")
        assert r.status == 200
        html = await r.text()
        assert "Alerts" in html and "Send test alert" in html
    finally:
        await c.close()
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "tok-al-1")
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


async def test_legacy_token_reaches_admin(monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "master-tok-123")
    c = await _client()
    try:
        # the master token counts as admin and is CSRF-exempt (not a browser cookie)
        assert (await c.get("/api/admin/users?token=master-tok-123")).status == 200
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


async def test_token_auth_admin_write_is_csrf_exempt(monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_TOKEN", "mtok-abc-123")
    c = await _client()
    try:
        # bearer/token auth is not a browser cookie -> no CSRF token needed
        r = await c.post("/api/admin/users?token=mtok-abc-123",
                         data={"username": "viaTok", "email": "t@x.io",
                               "password": "tokpw1234", "role": "viewer"})
        assert r.status == 200 and db.user_get("viaTok") is not None
    finally:
        await c.close()


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
