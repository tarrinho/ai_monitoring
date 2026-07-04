#!/usr/bin/env python3
# app.py — AI-Monitoring page service (aiohttp).
#
# Reuses the GW page-service design: an aiohttp app serving a dashboard HTML
# page + static assets + a JSON data endpoint, fed by a background sampling
# loop with sqlite retention. Collectors poll LiteLLM / Ollama / llama.cpp
# native JSON endpoints (no prometheus) plus host /proc.
from __future__ import annotations

import asyncio
import collections
import hmac
import json
import re
import sys
import time
from pathlib import Path

import aiohttp
from aiohttp import web

import config
import db
import alerts
import anomaly
from collectors import host, litellm, ollama, llamacpp, gpu, procs, containers

_notifier = alerts.Notifier()
# last-known up/down state per backend, for transition (event) detection
_backend_state: dict = {}
# model load/unload tracking (None/False = baseline not yet established, so the
# models already resident at startup don't spam the timeline as "loaded")
_ollama_models: set | None = None
_llamacpp_model: str | None = None
_llamacpp_model_seen: bool = False
# latest active per-key anomalies (for /api/anomalies + dashboard)
_latest_anomalies: list = []

_WEB = Path(__file__).parent / "web"
_INDEX = _WEB / "index.html"

# Typed app-state keys (aiohttp recommends web.AppKey over string keys).
_SESSION: web.AppKey = web.AppKey("session", aiohttp.ClientSession)
_SAMPLER: web.AppKey = web.AppKey("sampler", asyncio.Task)
_BACKENDS: web.AppKey = web.AppKey("backends", list)

# In-memory ring of recent merged snapshots (newest last).
_ring: collections.deque = collections.deque(maxlen=config.RETENTION_SAMPLES)
_latest: dict = {"ts": 0, "collectors": {}}


# ---------------------------------------------------------------- sampling ----
# Latest result from each HTTP backend, refreshed by its own decoupled loop. The
# main sampler reads these instead of awaiting the backends inline, so a slow
# backend (e.g. LiteLLM's whole-day /spend/logs, which can take tens of seconds)
# can NEVER stall host/GPU/procs sampling — those stay fresh at SAMPLE_INTERVAL.
_backend_latest: dict = {
    "gpu": {"available": False, "error": "starting"},
    "litellm": {"available": False, "error": "starting"},
    "ollama": {"available": False, "error": "starting"},
    "llamacpp": {"available": False, "error": "starting"},
    "containers": {"available": False, "error": "starting"},
}


async def _gpu_sample(_session) -> dict:
    # gpu.sample runs a subprocess (nvidia-smi/rocm-smi). Under GPU overload that
    # can wedge in uninterruptible-sleep and hang past its own timeout — so it
    # lives in its OWN bounded loop, never in the main sampler's critical path.
    return await asyncio.to_thread(gpu.sample)


async def _backend_loop(name: str, sample_fn, session, bound: float) -> None:
    """Sample one backend on its own cadence into _backend_latest, HARD-bounded by
    `bound` seconds via wait_for. A hung backend (slow HTTP, wedged subprocess) can
    only delay its OWN loop for `bound` — it can never freeze the main sampler or
    another backend. This is the anti-wedge guarantee."""
    while True:
        try:
            _backend_latest[name] = await asyncio.wait_for(sample_fn(session), bound)
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            print(f"[sample] backend '{name}' exceeded {bound:.0f}s — skipped this tick",
                  file=sys.stderr)
        except Exception as e:
            _backend_latest[name] = {"available": False, "error": f"{type(e).__name__}"}
        await asyncio.sleep(config.SAMPLE_INTERVAL)


async def _sample_once(session: aiohttp.ClientSession) -> dict:
    # ONLY host + procs are sampled inline — both are pure /proc reads that never
    # block on a subprocess or the network. GPU (subprocess) and the HTTP backends
    # run in their own bounded loops, so nothing here can wedge the main sampler.
    h, pr = await asyncio.gather(
        asyncio.to_thread(host.sample, "/"),
        asyncio.to_thread(procs.sample, 10),
    )
    return {
        "ts": time.time(),
        "collectors": {"host": h, "procs": pr,
                       "gpu": _backend_latest["gpu"],
                       "litellm": _backend_latest["litellm"],
                       "ollama": _backend_latest["ollama"],
                       "llamacpp": _backend_latest["llamacpp"],
                       "containers": _backend_latest["containers"]},
    }


def _metrics_row(snap: dict) -> dict:
    """Flatten a snapshot into the numeric columns charted over time.

    VRAM falls back to Ollama's per-model size_vram when no GPU CLI is present,
    so a remote GPU host still yields a VRAM signal via the Ollama API.
    """
    c = snap["collectors"]
    h, g = c.get("host", {}), c.get("gpu", {})
    ol, ll, lc = c.get("ollama", {}), c.get("litellm", {}), c.get("llamacpp", {})
    host_ok = h.get("available")
    gpu_ok = g.get("available")
    vram_used = g.get("vram_used") if gpu_ok else (
        ol.get("vram_used") if ol.get("available") else None)
    load = h.get("load") or []
    return {
        "cpu": h.get("cpu_pct") if host_ok else None,
        "mem": h.get("mem_pct") if host_ok else None,
        "gpu": g.get("util") if gpu_ok else None,
        "vram_used": vram_used,
        "vram_total": g.get("vram_total") if gpu_ok else None,
        "wait": ll.get("wait_avg_ms") if ll.get("available") else None,
        "disk": (h.get("disk") or {}).get("pct") if host_ok else None,
        "load1": load[0] if load else None,
        "tok": lc.get("predicted_per_second") if lc.get("available") else None,
        "power": g.get("power") if gpu_ok else None,
        "gtemp": g.get("temp_max") if gpu_ok else None,
        "slots": lc.get("slots_active") if lc.get("available") else None,
        # Tier A + efficiency (derived / rate metrics)
        "reqrate": ll.get("req_rate") if ll.get("available") else None,
        "tok_in": ll.get("tok_in_rate") if ll.get("available") else None,
        "tok_out": ll.get("tok_out_rate") if ll.get("available") else None,
        "errrate": ll.get("error_pct") if ll.get("available") else None,
        "costrate": ll.get("cost_rate_hr") if ll.get("available") else None,
        "kvcache": lc.get("kv_cache_pct") if lc.get("available") else None,
        "vram_pct": _pct(vram_used, g.get("vram_total")) if gpu_ok else None,
        "tokwatt": _tokwatt(lc, g) if (gpu_ok and lc.get("available")) else None,
        "backlog": ll.get("backlog") if ll.get("available") else None,
        "ttft": ll.get("ttft_avg_ms") if ll.get("available") else None,
        "cachehit": ll.get("cache_hit_pct") if ll.get("available") else None,
        "p50": ll.get("p50_ms") if ll.get("available") else None,
        "p95": ll.get("p95_ms") if ll.get("available") else None,
        "p99": ll.get("p99_ms") if ll.get("available") else None,
        "orun": ol.get("models_running") if ol.get("available") else None,
        "oram": ol.get("ram_used") if ol.get("available") else None,
        "ovram": ol.get("vram_used") if ol.get("available") else None,
        "conc": _concurrency(ll, lc),
    }


def _load_per_core(snap: dict) -> float:
    """Host 1-min load average divided by core count — the saturation signal that
    drives LiteLLM load-shedding. 0 when host data is unavailable."""
    h = snap.get("collectors", {}).get("host", {})
    load = h.get("load") or []
    ncpu = h.get("ncpu") or 0
    if not load or not ncpu:
        return 0.0
    return load[0] / ncpu


def _concurrency(ll: dict, lc: dict):
    """Stack-wide concurrent LLM work = LiteLLM in-flight requests + llama.cpp
    active slots. None when no LLM backend is available."""
    parts = []
    if ll.get("available") and ll.get("backlog") is not None:
        parts.append(ll["backlog"])
    if lc.get("available") and lc.get("slots_active") is not None:
        parts.append(lc["slots_active"])
    return sum(parts) if parts else None


def _pct(used, total):
    try:
        return round(used / total * 100, 1) if used is not None and total else None
    except Exception:
        return None


def _tokwatt(lc: dict, g: dict):
    """Tokens per watt = throughput ÷ GPU power draw (LLM-box efficiency)."""
    tok = lc.get("predicted_per_second")
    power = g.get("power")
    try:
        return round(tok / power, 2) if tok and power and power > 0 else None
    except Exception:
        return None


def _detect_anomalies(snap: dict) -> list:
    """Run per-key anomaly detection; record new ones + keep latest for the API.
    Returns (key, message) breaches for the notifier."""
    global _latest_anomalies
    ll = snap["collectors"].get("litellm", {})
    if not ll.get("available"):
        _latest_anomalies = []
        return []
    baselines = db.key_rate_baselines()
    breaches = anomaly.detect(ll, baselines)
    _latest_anomalies = [{"key": k, "message": m} for k, m in breaches]
    # record newly-active anomalies (not already firing) for history
    prev = set(_notifier._active)
    for key, msg in breaches:
        if key not in prev:
            kind = key.split(":", 1)[0]
            db.record_anomaly(snap["ts"], key.split(":", 1)[-1], kind, msg)
    return breaches


_status_prev: dict = {}


def _log_collector_status(snap: dict) -> None:
    """When MONITOR_DEBUG is on, log each collector's availability + error to
    stderr on startup and whenever it changes — makes 'why is panel X missing?'
    (e.g. GPU) obvious in `docker logs`."""
    if not config.MONITOR_DEBUG:
        return
    for name, c in snap.get("collectors", {}).items():
        avail = bool(c.get("available"))
        err = c.get("error")
        cur = (avail, err)
        if _status_prev.get(name) == cur:
            continue
        _status_prev[name] = cur
        if avail:
            print(f"[collector] {name}: OK", file=sys.stderr, flush=True)
        else:
            hint = ""
            if name == "gpu" and err == "unconfigured":
                hint = " — no local nvidia-smi/rocm-smi; set GPU_SSH or GPU_METRICS_URL for a remote GPU"
            print(f"[collector] {name}: unavailable — {err or '?'}{hint}",
                  file=sys.stderr, flush=True)


def _track_events(snap: dict) -> None:
    """Record up/down transitions for configured backends (uptime history)."""
    c = snap["collectors"]
    ts = snap["ts"]
    for name in ("litellm", "ollama", "llamacpp", "gpu"):
        b = c.get(name, {})
        # only track backends that are actually configured (not the "unconfigured"
        # note); a configured backend is either up or down-with-a-real-error.
        configured = b and not (b.get("available") is False
                                and b.get("error") in (None, "unconfigured"))
        if not configured:
            continue
        up = bool(b.get("available"))
        prev = _backend_state.get(name)
        if prev is None:
            _backend_state[name] = up
            db.record_event(ts, name, up, b.get("error") or "")
        elif prev != up:
            _backend_state[name] = up
            db.record_event(ts, name, up, b.get("error") or "")


def _track_model_events(snap: dict) -> None:
    """Record model load/unload events (kind='model') for the model timeline.
    Ollama: diff the set of running models. llama.cpp: watch the loaded path."""
    global _ollama_models, _llamacpp_model, _llamacpp_model_seen
    c = snap["collectors"]
    ts = snap["ts"]
    ol = c.get("ollama", {})
    if ol.get("available"):
        cur = {m.get("name") for m in (ol.get("models") or []) if m.get("name")}
        if _ollama_models is not None:            # baseline established → diff it
            for name in cur - _ollama_models:
                db.record_event(ts, "ollama", True, f"loaded {name}", kind="model")
            for name in _ollama_models - cur:
                db.record_event(ts, "ollama", False, f"unloaded {name}", kind="model")
        _ollama_models = cur
    lc = c.get("llamacpp", {})
    if lc.get("available"):
        model = lc.get("model")
        if model and model != _llamacpp_model:
            if _llamacpp_model_seen:              # skip the first-seen baseline
                db.record_event(ts, "llamacpp", True,
                                f"loaded {model.rsplit('/', 1)[-1]}", kind="model")
            _llamacpp_model = model
            _llamacpp_model_seen = True


async def _sampling_loop(app: web.Application) -> None:
    global _latest
    session: aiohttp.ClientSession = app[_SESSION]
    last_prune = 0.0
    last_rollup = 0.0
    while True:
        try:
            # Watchdog: host+procs are pure /proc reads (<1s), but if a /proc read
            # ever wedges, wait_for keeps the loop alive instead of freezing it.
            snap = await asyncio.wait_for(_sample_once(session), 15)
            _latest = snap
            _log_collector_status(snap)
            # feed host load-per-core to LiteLLM so it can auto-shed heavy calls
            litellm.note_load(_load_per_core(snap))
            _ring.append(snap)
            db.insert(snap["ts"], snap["collectors"])
            db.insert_metrics(snap["ts"], _metrics_row(snap))
            _ll = snap["collectors"].get("litellm", {})
            if _ll.get("available"):
                db.insert_key_series(snap["ts"], _ll.get("top_keys") or [])
            _pr = snap["collectors"].get("procs", {})
            if _pr.get("available"):
                db.insert_proc_series(snap["ts"], "cpu", _pr.get("top_cpu") or [], "cpu")
                db.insert_proc_series(snap["ts"], "ram", _pr.get("top_ram") or [], "ram")
            _track_events(snap)
            _track_model_events(snap)
            anoms = _detect_anomalies(snap)
            await _notifier.process(session, snap, snap["ts"],
                                    extra_breaches=anoms)
            if snap["ts"] - last_rollup > 60:
                db.rollup()
                last_rollup = snap["ts"]
            if snap["ts"] - last_prune > 3600:
                db.prune()
                db.prune_metrics()
                db.prune_key_series()
                last_prune = snap["ts"]
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[sample] error: {type(e).__name__}: {e}", file=sys.stderr)
        await asyncio.sleep(config.SAMPLE_INTERVAL)


# -------------------------------------------------------- security headers ----
# CSP keeps 'unsafe-inline' because the dashboard ships one inline <script>/
# <style>; frame-ancestors 'none' still blocks clickjacking regardless. The
# Server header is overwritten to avoid version fingerprinting.
_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'")


def _apply_sec_headers(resp) -> None:
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = _CSP
    resp.headers["Server"] = "AI-Monitoring"


@web.middleware
async def _sechdr_mw(request: web.Request, handler):
    try:
        resp = await handler(request)
    except web.HTTPException as e:
        _apply_sec_headers(e)   # headers on redirects/errors too, then re-raise
        raise
    _apply_sec_headers(resp)
    return resp


# ------------------------------------------------------------------- auth -----
_COOKIE = "aimon_session"


def _is_https(request: web.Request) -> bool:
    return request.secure or \
        request.headers.get("X-Forwarded-Proto", "") == "https"


def _token_ok(tok: str | None) -> bool:
    expected = config.DASHBOARD_TOKEN or ""
    return bool(tok) and bool(expected) and \
        hmac.compare_digest(tok or "", expected)


def _request_token(request: web.Request) -> str | None:
    """Token from Authorization header, then ?token=, then session cookie."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.query.get("token") or request.cookies.get(_COOKIE)


# HTML pages that require auth (static assets + /healthz stay open).
_PAGES = ("/", "/litellm", "/gpu", "/ollama", "/llamacpp", "/alerts")

# Brute-force protection: per-IP failed-token counters + lockouts (in-memory;
# single-instance app, resets on restart — fine for this purpose).
_auth_fails: dict[str, collections.deque] = collections.defaultdict(
    lambda: collections.deque(maxlen=128))
_auth_locked_until: dict[str, float] = {}


def _client_ip(request: web.Request) -> str:
    """Client IP for rate-limiting. Reads X-Forwarded-For ONLY when a trusted
    proxy is declared — otherwise an attacker spoofs the header to dodge lockout."""
    if config.AUTH_TRUSTED_PROXY:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
    return request.remote or "?"


def _record_auth_attack(ip: str) -> None:
    print(f"[auth] lockout: {ip} hit {config.AUTH_MAX_FAILS} bad tokens in "
          f"{config.AUTH_WINDOW_S:.0f}s — locked {config.AUTH_LOCKOUT_S:.0f}s",
          file=sys.stderr)


@web.middleware
async def _auth_mw(request: web.Request, handler):
    # Only dashboard pages and the data API are gated. Static assets
    # (/assets/*) and the container probe (/healthz) stay open, otherwise the
    # browser — which loads assets without the token — gets 401 and the page
    # renders blank.
    if config.DASHBOARD_TOKEN:
        p = request.path
        needs_auth = p in _PAGES or p.startswith("/api/")
        if needs_auth:
            ip = _client_ip(request)
            now = time.time()
            locked = _auth_locked_until.get(ip, 0.0)
            if locked > now:
                return web.json_response(
                    {"error": "too many attempts"}, status=429,
                    headers={"Retry-After": str(int(locked - now))})
            fails = _auth_fails[ip]
            while fails and now - fails[0] > config.AUTH_WINDOW_S:
                fails.popleft()
            if not _token_ok(_request_token(request)):
                fails.append(now)
                if len(fails) >= config.AUTH_MAX_FAILS:
                    _auth_locked_until[ip] = now + config.AUTH_LOCKOUT_S
                    _record_auth_attack(ip)
                    fails.clear()
                return web.json_response({"error": "unauthorized"}, status=401)
            fails.clear()
            _auth_locked_until.pop(ip, None)
    return await handler(request)


# ------------------------------------------------------------ base prefix -----
# Support being reverse-proxied under a sub-path (e.g. Apache
# `ProxyPass /ai_monitoring/ http://127.0.0.1:9925/` +
# `RequestHeader set X-Forwarded-Prefix "/ai_monitoring"`). The proxy strips the
# prefix, so the app's own routing/auth stay unprefixed; we only need to prepend
# the prefix to the *absolute* links/fetches in the HTML we send back, and to the
# cookie-redirect Location. No header → served at root, unchanged.
_PFX_RE = re.compile(r"^/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")


def _fwd_prefix(request: web.Request) -> str:
    """Validated X-Forwarded-Prefix (trailing slash trimmed). Strict because it
    is echoed into HTML — reject anything but a clean path to avoid injection.
    Returns '' (root mount) when absent or malformed."""
    raw = request.headers.get("X-Forwarded-Prefix", "").strip().rstrip("/")
    if not raw or ".." in raw or not _PFX_RE.match(raw):
        return ""
    return raw


# (marker, replacement-lead) pairs. Markers are anchored so each hits only real
# links/fetches, never bare "/" inside data. Order-independent, single pass each.
def _apply_prefix(html: str, p: str) -> str:
    for marker in (' href="/', ' src="/', 'fetch("/', 'api("/',
                   '.open("/', 'a[href="/'):
        html = html.replace(marker, marker[:-1] + p + "/")
    return html


# --------------------------------------------------------------- handlers -----
def _maybe_cookie_redirect(request: web.Request, dest: str) -> None:
    """If authed via ?token=, move it into an HttpOnly cookie and redirect to a
    clean URL — keeps the secret out of history, access logs, Referer, and the
    tunnel's request inspector after the very first hit."""
    if config.DASHBOARD_TOKEN and request.query.get("token") and \
            not request.cookies.get(_COOKIE):
        resp = web.HTTPFound((_fwd_prefix(request) + dest) or dest)
        resp.set_cookie(_COOKIE, config.DASHBOARD_TOKEN, max_age=86400 * 7,
                        httponly=True, samesite="Strict",
                        secure=_is_https(request), path="/")
        raise resp


def _serve_page(path: Path, prefix: str = "") -> web.Response:
    try:
        html = path.read_text(encoding="utf-8")
    except Exception:
        return web.Response(text="dashboard missing", status=500)
    if prefix:
        html = _apply_prefix(html, prefix)
    return web.Response(text=html, content_type="text/html")


async def index_handler(request: web.Request) -> web.Response:
    _maybe_cookie_redirect(request, "/")
    return _serve_page(_INDEX, _fwd_prefix(request))


async def litellm_page_handler(request: web.Request) -> web.Response:
    _maybe_cookie_redirect(request, "/litellm")
    return _serve_page(_WEB / "litellm.html", _fwd_prefix(request))


async def gpu_page_handler(request: web.Request) -> web.Response:
    _maybe_cookie_redirect(request, "/gpu")
    return _serve_page(_WEB / "gpu.html", _fwd_prefix(request))


async def ollama_page_handler(request: web.Request) -> web.Response:
    _maybe_cookie_redirect(request, "/ollama")
    return _serve_page(_WEB / "ollama.html", _fwd_prefix(request))


async def llamacpp_page_handler(request: web.Request) -> web.Response:
    _maybe_cookie_redirect(request, "/llamacpp")
    return _serve_page(_WEB / "llamacpp.html", _fwd_prefix(request))


async def alerts_page_handler(request: web.Request) -> web.Response:
    _maybe_cookie_redirect(request, "/alerts")
    return _serve_page(_WEB / "alerts.html", _fwd_prefix(request))


async def data_handler(request: web.Request) -> web.Response:
    try:
        n = int(request.query.get("history", "180"))
    except ValueError:
        n = 180
    n = max(1, min(n, config.RETENTION_SAMPLES))
    hist = list(_ring)[-n:]
    return web.json_response({
        "version": config.VERSION,
        "now": time.time(),
        "latest": _latest,
        "history": hist,
    })


async def series_handler(request: web.Request) -> web.Response:
    window = request.query.get("window", "1h")
    if window not in db.WINDOWS:
        window = "1h"
    try:
        pts = int(request.query.get("points", "300"))
    except ValueError:
        pts = 300
    pts = max(30, min(pts, 1000))
    return web.json_response({
        "window": window,
        "windows": list(db.WINDOWS.keys()),
        "points": db.series(window, pts, end=_q_end(request)),
    })


def _q_end(request: web.Request) -> float | None:
    """Parse the optional ?end= pan cursor (epoch seconds). None = live/now."""
    v = request.query.get("end")
    if not v:
        return None
    try:
        return float(v)
    except ValueError:
        return None


async def procseries_handler(request: web.Request) -> web.Response:
    kind = request.query.get("kind", "cpu")
    if kind not in ("cpu", "ram"):
        kind = "cpu"
    window = request.query.get("window", "1h")
    if window not in db.WINDOWS:
        window = "1h"
    return web.json_response({"kind": kind, "window": window,
                              **db.proc_series(kind, window,
                                               end=_q_end(request))})


async def keyseries_handler(request: web.Request) -> web.Response:
    window = request.query.get("window", "1h")
    if window not in db.WINDOWS:
        window = "1h"
    try:
        pts = int(request.query.get("points", "200"))
    except ValueError:
        pts = 200
    pts = max(30, min(pts, 1000))
    data = db.key_series(window, pts, end=_q_end(request))
    return web.json_response({"window": window, **data})


def _configured(name: str, env_ok: bool) -> bool:
    """A dashboard link is shown when its backend is configured. Prefer the
    latest live sample (handles local GPU auto-detect); fall back to env."""
    c = _latest.get("collectors", {}).get(name, {})
    if c:
        return not (c.get("available") is False and c.get("error") == "unconfigured")
    return env_ok


async def nav_handler(request: web.Request) -> web.Response:
    """Which backend dashboards are configured — drives nav-link visibility."""
    return web.json_response({
        "litellm": _configured("litellm", bool(config.LITELLM_BASE_URL)),
        "ollama": _configured("ollama", bool(config.OLLAMA_BASE_URL)),
        "llamacpp": _configured("llamacpp", bool(config.LLAMACPP_BASE_URL)),
        "gpu": _configured("gpu", bool(config.GPU_SSH or config.GPU_METRICS_URL)),
    })


async def alerts_handler(request: web.Request) -> web.Response:
    return web.json_response({
        "channels": alerts.channels_status(),
        "thresholds": alerts.thresholds_status(),
        "active": _notifier.active_keys(),
        "history": db.recent_alerts(50),
    })


async def alerts_test_handler(request: web.Request) -> web.Response:
    session: aiohttp.ClientSession = request.app[_SESSION]
    results = await alerts.send_test(session)
    return web.json_response({"results": results})


async def anomalies_handler(request: web.Request) -> web.Response:
    return web.json_response({
        "active": _latest_anomalies,
        "history": db.recent_anomalies(30),
    })


async def uptime_handler(request: web.Request) -> web.Response:
    window = request.query.get("window", "24h")
    if window not in db.WINDOWS:
        window = "24h"
    return web.json_response({
        "window": window,
        "uptime": db.uptime(window),
        "events": db.recent_events(30, kind="state"),
    })


async def stream_handler(request: web.Request) -> web.StreamResponse:
    """Server-Sent Events: push the latest snapshot every SAMPLE_INTERVAL so the
    dashboards get live updates over one connection instead of polling /api/data.
    Gated by the same token middleware (EventSource passes ?token=)."""
    resp = web.StreamResponse(status=200, headers={
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",     # don't let a reverse proxy buffer the stream
    })
    await resp.prepare(request)
    try:
        while True:
            data = json.dumps({"ts": _latest.get("ts"),
                               "collectors": _latest.get("collectors", {})})
            await resp.write(b"data: " + data.encode() + b"\n\n")
            await asyncio.sleep(config.SAMPLE_INTERVAL)
    except (ConnectionResetError, asyncio.CancelledError):
        pass
    except Exception:
        pass
    return resp


async def events_handler(request: web.Request) -> web.Response:
    """Recent events. ?kind=state|model filters; default = model timeline."""
    kind = request.query.get("kind", "model")
    if kind not in ("state", "model", "all"):
        kind = "model"
    try:
        limit = max(1, min(int(request.query.get("limit", "40")), 200))
    except ValueError:
        limit = 40
    return web.json_response({
        "kind": kind,
        "events": db.recent_events(limit, kind=None if kind == "all" else kind),
    })


async def export_handler(request: web.Request) -> web.Response:
    """Export a window's series as CSV or JSON for offline analysis."""
    window = request.query.get("window", "24h")
    if window not in db.WINDOWS:
        window = "24h"
    fmt = request.query.get("format", "csv").lower()
    pts = db.series(window, 1000)
    cols = ["t"] + db._METRIC_COLS
    if fmt == "json":
        return web.json_response({"window": window, "points": pts})
    lines = [",".join(cols)]
    for p in pts:
        lines.append(",".join(
            "" if p.get(c) is None else str(round(p[c], 3)) for c in cols))
    return web.Response(
        text="\n".join(lines), content_type="text/csv",
        headers={"Content-Disposition":
                 f'attachment; filename="ai-monitoring-{window}.csv"'})


async def healthz_handler(request: web.Request) -> web.Response:
    ok = _latest.get("ts", 0) > 0 or len(_ring) == 0
    return web.json_response(
        {"status": "ok" if ok else "starting", "version": config.VERSION,
         "samples": len(_ring)},
        status=200,
    )


# --------------------------------------------------------------- lifecycle ----
async def _on_startup(app: web.Application) -> None:
    session = app[_SESSION] = aiohttp.ClientSession()
    # Warm the ring from sqlite so the dashboard isn't empty on restart.
    for payload in db.recent(180):
        _ring.append({"ts": 0, "collectors": payload})
    # One decoupled loop per HTTP backend + the main (local-only) sampler.
    app[_BACKENDS] = [
        asyncio.create_task(_backend_loop("gpu", _gpu_sample, session, 8.0)),
        asyncio.create_task(_backend_loop(
            "litellm", litellm.sample, session, config.LITELLM_SPEND_TIMEOUT * 2 + 10)),
        asyncio.create_task(_backend_loop(
            "ollama", ollama.sample, session, config.HTTP_TIMEOUT + 5)),
        asyncio.create_task(_backend_loop(
            "llamacpp", llamacpp.sample, session, config.HTTP_TIMEOUT + 5)),
        asyncio.create_task(_backend_loop(
            "containers", containers.sample, session, config.HTTP_TIMEOUT + 5)),
    ]
    app[_SAMPLER] = asyncio.create_task(_sampling_loop(app))


async def _on_cleanup(app: web.Application) -> None:
    tasks = [app.get(_SAMPLER), *(app.get(_BACKENDS) or [])]
    for task in tasks:
        if task:
            task.cancel()
    for task in tasks:
        if task:
            try:
                await task
            except asyncio.CancelledError:
                pass
    sess = app.get(_SESSION)
    if sess:
        await sess.close()
    # the containers collector holds its own unix-socket session — close it too
    await containers.close()


def build_app() -> web.Application:
    app = web.Application(middlewares=[_sechdr_mw, _auth_mw])
    app.router.add_get("/", index_handler)
    app.router.add_get("/litellm", litellm_page_handler)
    app.router.add_get("/gpu", gpu_page_handler)
    app.router.add_get("/ollama", ollama_page_handler)
    app.router.add_get("/llamacpp", llamacpp_page_handler)
    app.router.add_get("/alerts", alerts_page_handler)
    app.router.add_get("/api/data", data_handler)
    app.router.add_get("/api/series", series_handler)
    app.router.add_get("/api/uptime", uptime_handler)
    app.router.add_get("/api/events", events_handler)
    app.router.add_get("/api/stream", stream_handler)
    app.router.add_get("/api/keyseries", keyseries_handler)
    app.router.add_get("/api/procseries", procseries_handler)
    app.router.add_get("/api/anomalies", anomalies_handler)
    app.router.add_get("/api/nav", nav_handler)
    app.router.add_get("/api/alerts", alerts_handler)
    app.router.add_post("/api/alerts/test", alerts_test_handler)
    app.router.add_get("/api/export", export_handler)
    app.router.add_get("/healthz", healthz_handler)
    app.router.add_static("/assets/", path=str(_WEB / "assets"), show_index=False)
    app.on_startup.append(_on_startup)
    app.on_cleanup.append(_on_cleanup)
    return app


def startup_selfcheck() -> list[str]:
    """Per-run smoke check of critical invariants. Returns a list of problems
    (empty = healthy). Logged at boot so every run surfaces breakage, even the
    ones unit tests can't see (missing files in the image, route/metric drift)."""
    problems: list[str] = []
    # dashboards present
    for page in (_INDEX, _WEB / "litellm.html", _WEB / "llamacpp.html"):
        if not page.exists():
            problems.append(f"missing dashboard: {page.name}")
    # assets present
    for a in ("chart.umd.min.js", "purify.min.js"):
        if not (_WEB / "assets" / a).exists():
            problems.append(f"missing asset: {a}")
    # every charted metric column resolves after migration
    try:
        row = _metrics_row({"ts": 0, "collectors": {}})
        missing = [c for c in db._METRIC_COLS if c not in row]
        if missing:
            problems.append(f"metric cols not emitted by _metrics_row: {missing}")
    except Exception as e:
        problems.append(f"_metrics_row failed: {type(e).__name__}: {e}")
    # routes wired
    paths = {r.resource.canonical for r in build_app().router.routes()
             if r.resource}
    for need in ("/", "/litellm", "/gpu", "/ollama", "/alerts", "/api/data",
                 "/api/series", "/api/uptime", "/api/keyseries",
                 "/api/procseries", "/api/anomalies", "/api/nav",
                 "/api/alerts", "/api/export", "/healthz"):
        if need not in paths:
            problems.append(f"route not registered: {need}")
    # weak dashboard token — brute-force risk, especially behind a public tunnel
    if config.DASHBOARD_TOKEN and len(config.DASHBOARD_TOKEN) < 16:
        problems.append(f"weak dashboard token ({len(config.DASHBOARD_TOKEN)} chars) "
                        "— use ≥16 random chars; rate-limit is on but a short token "
                        "is still guessable")
    return problems


def main() -> int:
    errs = config.validate()
    if errs:
        print("FATAL config errors:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 2
    db.init()
    sc = startup_selfcheck()
    if sc:
        print("[selfcheck] PROBLEMS DETECTED:", file=sys.stderr)
        for p in sc:
            print(f"  ⚠ {p}", file=sys.stderr)
    else:
        print("[selfcheck] OK — dashboards, assets, metrics, routes all present")
    banner = config.redacted_summary()
    print(f"[AI-Monitoring] {banner['version']} listening on {banner['listen']}")
    for k, v in banner.items():
        print(f"    {k}: {v}")
    web.run_app(build_app(), host=config.MONITOR_HOST, port=config.MONITOR_PORT,
                print=None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
