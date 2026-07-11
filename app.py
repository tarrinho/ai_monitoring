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
import hashlib
import hmac
import json
import re
import secrets
import sys
import time
import traceback
from html import escape as _html_escape
from pathlib import Path
from urllib.parse import quote

import aiohttp
from aiohttp import web

import config
import db
import auth
import alerts
import anomaly
import metrics_prom
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
            # Bound the notifier like _sample_once: a user webhook with a slow-
            # resolving/blackholed host must never wedge the sampling loop (§6).
            try:
                await asyncio.wait_for(
                    _notifier.process(session, snap, snap["ts"],
                                      extra_breaches=anoms), 15)
            except asyncio.TimeoutError:
                print("[alert] notifier exceeded 15s — skipped this tick",
                      file=sys.stderr)
            if snap["ts"] - last_rollup > 60:
                db.rollup()
                last_rollup = snap["ts"]
            if snap["ts"] - last_prune > 3600:
                db.prune()
                db.prune_metrics()
                db.prune_key_series()
                db.audit_prune(snap["ts"] - config.AUDIT_RETENTION_DAYS * 86400)
                last_prune = snap["ts"]
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[sample] error: {type(e).__name__}: {e}", file=sys.stderr)
        await asyncio.sleep(config.SAMPLE_INTERVAL)


# -------------------------------------------------------- security headers ----
# F5: script-src uses a per-response nonce instead of 'unsafe-inline', so an
# injected inline <script> without the nonce won't execute (the dashboards carry
# no inline on*= handlers, so this loses nothing). style-src keeps 'unsafe-inline'
# because benign inline style="..." attributes are pervasive. frame-ancestors
# 'none' blocks clickjacking; the Server header is overwritten to avoid
# version fingerprinting. Pages stamp the nonce via a throwaway X-CSP-Nonce header
# that _apply_sec_headers consumes; other responses (JSON API) execute no script.
_NONCE_HDR = "X-CSP-Nonce"


def _csp(nonce: str | None = None) -> str:
    script_src = f"'self' 'nonce-{nonce}'" if nonce else "'self'"
    return (f"default-src 'self'; script-src {script_src}; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'")


def _apply_sec_headers(resp) -> None:
    nonce = resp.headers.pop(_NONCE_HDR, None)   # set by _serve_page for HTML pages
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = _csp(nonce)
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


# --------------------------------------------------------- server error log ---
def _log(msg: str) -> None:
    """Timestamped line to stderr → the server's `docker logs`."""
    print(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


# 4xx codes worth logging as a denial (skip 401 = normal unauth poll, 404 = normal).
_LOG_STATUSES = frozenset((400, 403, 409, 413, 415, 429))


@web.middleware
async def _log_mw(request: web.Request, handler):
    """Record every error on the server (security + failures), never the noisy 200s:
    unhandled exceptions (500 + traceback) and denied writes (400/403/409/429/…).
    Failed LOGINS are 302 redirects, so they are logged explicitly in the handler."""
    try:
        resp = await handler(request)
    except web.HTTPException as e:
        if e.status >= 500:
            _log(f"[error] {request.method} {request.path} -> {e.status}")
        elif e.status in _LOG_STATUSES:
            _log(f"[deny] {request.method} {request.path} -> {e.status} "
                 f"ip={_client_ip(request)}")
        raise
    except Exception:                       # unhandled -> aiohttp will 500 it
        _log(f"[error] {request.method} {request.path} -> 500\n{traceback.format_exc()}")
        raise
    if resp.status >= 500:
        _log(f"[error] {request.method} {request.path} -> {resp.status}")
    elif resp.status in _LOG_STATUSES:
        _log(f"[deny] {request.method} {request.path} -> {resp.status} "
             f"ip={_client_ip(request)}")
    return resp


# ------------------------------------------------------------------- auth -----
_COOKIE = "aimon_session"       # legacy shared-token session cookie (opaque id)
_USER_COOKIE = "aimon_user"     # per-user login session id (auth.py sessions)

# Opaque server-side sessions for legacy-token logins: the aimon_session cookie
# now holds a random id (not the master token itself), so cookie theft / a
# mis-logged Set-Cookie never leaks the actual shared secret. sid -> expiry epoch.
# In-memory like the user sessions; a restart just asks for ?token= again.
_token_sessions: dict[str, float] = {}


def _token_session_new(now: float) -> str:
    """Mint an opaque legacy-token session id (bounded, expired ones pruned)."""
    for sid in [s for s, exp in _token_sessions.items() if exp <= now]:
        _token_sessions.pop(sid, None)
    over = len(_token_sessions) - config.SESSION_MAX
    if over > 0:
        for sid, _e in sorted(_token_sessions.items(), key=lambda kv: kv[1])[:over]:
            _token_sessions.pop(sid, None)
    sid = secrets.token_urlsafe(32)
    _token_sessions[sid] = now + 7 * 24 * 3600.0
    return sid


def _token_cookie_valid(request: web.Request) -> bool:
    """True if the aimon_session cookie is a live opaque token-session id."""
    sid = request.cookies.get(_COOKIE)
    exp = _token_sessions.get(sid) if sid else None
    return exp is not None and exp > time.time()


def _is_https(request: web.Request) -> bool:
    return request.secure or \
        request.headers.get("X-Forwarded-Proto", "") == "https"


def _token_ok(tok: str | None) -> bool:
    expected = config.DASHBOARD_TOKEN or ""
    return bool(tok) and bool(expected) and \
        hmac.compare_digest(tok or "", expected)


def _request_token(request: web.Request) -> str | None:
    """Raw token from the Authorization header, then ?token=. The aimon_session
    COOKIE is intentionally NOT read here — it carries an opaque session id, not
    the token, and is validated separately via _token_cookie_valid()."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.query.get("token")


def _session_from_req(request: web.Request) -> dict | None:
    """The live per-user login session for this request, or None."""
    return auth.session_get(request.cookies.get(_USER_COOKIE))


_users_seen = {"any": False, "checked": 0.0}


def _any_users() -> bool:
    """Cached 'at least one user account exists' (15 s TTL, busted on change) so the
    auth middleware doesn't COUNT the users table on every request."""
    now = time.time()
    if now - _users_seen["checked"] > 15:
        _users_seen["any"] = db.user_count() > 0
        _users_seen["checked"] = now
    return bool(_users_seen["any"])


def _mark_users_changed() -> None:
    _users_seen["checked"] = 0.0        # force a refresh on the next check


def _auth_enabled() -> bool:
    """Auth is enforced unless explicitly opened. Active when a legacy token is set
    OR any user account exists; with neither (and not opened) the app is open —
    boot-time validate() already refuses that case unless MONITOR_ALLOW_OPEN=1."""
    if config.ALLOW_OPEN:
        return False
    return bool(config.DASHBOARD_TOKEN) or _any_users()


_PAT_PREFIX = "aimon_pat_"          # marks a personal access token
_pat_used: dict[str, float] = {}    # token-id -> last DB last_used write (throttle)


def _hash_token(tok: str) -> str:
    return hashlib.sha256(tok.encode("utf-8")).hexdigest()


def _new_pat() -> tuple[str, str, str]:
    """Mint (raw_token, public_id, display_prefix) for a new personal access token."""
    secret = secrets.token_urlsafe(32)
    raw = _PAT_PREFIX + secret
    tid = secrets.token_urlsafe(6)
    return raw, tid, raw[:len(_PAT_PREFIX) + 6]


def _pat_auth(request: web.Request) -> tuple[str, str] | None:
    """If the request carries a valid personal access token, return (owner, role).
    Throttles the last-used DB write to at most once per 60 s per token."""
    tok = _request_token(request)
    if not tok or not tok.startswith(_PAT_PREFIX):
        return None
    row = db.api_token_lookup(_hash_token(tok))
    if not row:
        return None
    now = time.time()
    if now - _pat_used.get(row["id"], 0.0) > 60:
        _pat_used[row["id"]] = now
        db.api_token_touch(row["id"], now)
    return row["owner"], row["role"]


def _auth_ctx(request: web.Request) -> tuple[bool, str | None, dict | None]:
    """(authenticated, role, session). A valid user session confirms its DB user is
    still present + enabled; the legacy master token counts as full 'admin' access
    (it is the operator's shared secret); a personal access token grants ITS role.
    Returns role=None when unauthenticated."""
    sess = _session_from_req(request)
    if sess:
        u = db.user_get(sess["user"])
        if u and not u["disabled"]:
            return True, u["role"], sess
        auth.session_drop(request.cookies.get(_USER_COOKIE))   # user gone/disabled
    if _token_ok(_request_token(request)) or _token_cookie_valid(request):
        return True, "admin", None
    pat = _pat_auth(request)
    if pat:
        return True, pat[1], None       # (owner, role) -> role
    return False, None, None


# HTML pages that require auth (static assets + /healthz + /login stay open).
_PAGES = ("/", "/spend", "/litellm", "/gpu", "/ollama", "/llamacpp", "/alerts",
          "/admin/users", "/account", "/settings")
# Reachable without a session: the login page/handlers and public assets.
_OPEN = ("/healthz", "/login", "/logout", "/metrics")
# Admin-only surfaces (role must be 'admin' — NOT a specific username — or the
# legacy master token). Enforced at the middleware in addition to each handler.
_ADMIN_PAGES = ("/admin/users", "/settings")
_ADMIN_API_PREFIX = "/api/admin/"
# The only surfaces a must-change-password session may reach before resetting.
_MUST_CHANGE_OK = ("/account", "/logout", "/api/me", "/api/account/password")


def _is_alerts_path(p: str) -> bool:
    """The Alerts page + its API. Alert config (webhook URLs, thresholds) is
    sensitive, so these must never be served without authentication — even when
    the rest of the dashboard is opened (MONITOR_ALLOW_OPEN)."""
    return p == "/alerts" or p.startswith("/api/alerts")

# Brute-force protection: per-IP failed-token counters + lockouts (in-memory;
# single-instance app, resets on restart — fine for this purpose).
_auth_fails: dict[str, collections.deque] = collections.defaultdict(
    lambda: collections.deque(maxlen=128))
_auth_locked_until: dict[str, float] = {}
# Same idea keyed by USERNAME (not IP) — a targeted account is locked even if the
# attacker spreads the guesses across many source IPs.
_user_fails: dict[str, collections.deque] = collections.defaultdict(
    lambda: collections.deque(maxlen=128))
_user_locked_until: dict[str, float] = {}


def _prune_auth_state(now: float) -> None:
    """Bound the brute-force maps so a flood of distinct source IPs / usernames
    can't grow them without limit (memory DoS). Only runs a full scan once the maps
    get large; drops expired lockouts and stale/empty fail windows. Cheap and safe —
    an active lockout (locked_until > now) is never removed early."""
    if (len(_auth_locked_until) + len(_auth_fails)
            + len(_user_locked_until) + len(_user_fails)) < 4096:
        return
    win = config.AUTH_WINDOW_S
    for locks, fails in ((_auth_locked_until, _auth_fails),
                         (_user_locked_until, _user_fails)):
        for k in [i for i, u in locks.items() if u <= now]:
            locks.pop(k, None)
        for k in [i for i, d in fails.items() if not d or now - d[-1] > win]:
            fails.pop(k, None)


def _client_ip(request: web.Request) -> str:
    """Client IP for rate-limiting. Reads X-Forwarded-For ONLY when a trusted
    proxy is declared — otherwise an attacker spoofs the header to dodge lockout.
    F4: take the RIGHTMOST entry — that one is appended by our own trusted proxy,
    so a client can't inject a fake leftmost value to evade lockout or to frame a
    victim IP into being locked out. The proxy must APPEND (not replace) XFF."""
    if config.AUTH_TRUSTED_PROXY:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[-1].strip()
    return request.remote or "?"


def _record_auth_attack(ip: str) -> None:
    print(f"[auth] lockout: {ip} hit {config.AUTH_MAX_FAILS} bad tokens in "
          f"{config.AUTH_WINDOW_S:.0f}s — locked {config.AUTH_LOCKOUT_S:.0f}s",
          file=sys.stderr)


def _audit(request: web.Request, actor: str | None, action: str,
           target: str | None = None, detail: str | None = None) -> None:
    """Append an access/admin-action row to the audit trail (best-effort)."""
    db.audit_add(time.time(), actor, action, target, _client_ip(request), detail)


def _login_dest(request: web.Request, nxt: str) -> str:
    """Location for redirecting an unauthenticated page request to the login form,
    preserving where they were headed via a validated ?next=."""
    base = _fwd_prefix(request) + "/login"
    if nxt and nxt.startswith("/") and not nxt.startswith("//") and "\\" not in nxt:
        return base + "?next=" + quote(nxt, safe="")
    return base


@web.middleware
async def _auth_mw(request: web.Request, handler):
    # Auth is enforced unless the operator explicitly opted the dashboard open
    # (MONITOR_ALLOW_OPEN=1; validate() guarantees a token or a user exists first).
    # Access = a valid per-user login session OR the legacy master token. Static
    # assets, /healthz and the login endpoints stay open so the form can render.
    if not _auth_enabled():
        # Even with the dashboard opened, alert config must not be exposed without
        # auth — and open mode has no credential to satisfy, so deny it outright.
        if _is_alerts_path(request.path):
            return web.json_response(
                {"error": "alerts require authentication"}, status=403)
        return await handler(request)
    p = request.path
    if p in _OPEN or p.startswith("/assets/"):
        return await handler(request)
    is_admin_path = p in _ADMIN_PAGES or p.startswith(_ADMIN_API_PREFIX)
    needs_auth = is_admin_path or p in _PAGES or p.startswith("/api/")
    if not needs_auth:
        return await handler(request)

    ip = _client_ip(request)
    now = time.time()
    _prune_auth_state(now)
    locked = _auth_locked_until.get(ip, 0.0)
    if locked > now:
        return web.json_response(
            {"error": "too many attempts"}, status=429,
            headers={"Retry-After": str(int(locked - now))})

    authed, role, _sess = _auth_ctx(request)
    if not authed:
        # Count a lockout strike only when a credential was actually PRESENTED and
        # rejected (real brute-force) — not for a browser that simply isn't logged
        # in yet (that just gets bounced to /login). Only a presented BEARER/query
        # TOKEN counts: it's the one guessable shared secret. A session cookie
        # (aimon_user / aimon_session) is a 256-bit opaque id — un-brute-forceable,
        # and an EXPIRED one on an auto-polling dashboard would otherwise lock the
        # operator's own IP out. Password brute-force is counted in login_submit.
        presented = bool(_request_token(request))
        if presented:
            fails = _auth_fails[ip]
            while fails and now - fails[0] > config.AUTH_WINDOW_S:
                fails.popleft()
            fails.append(now)
            if len(fails) >= config.AUTH_MAX_FAILS:
                _auth_locked_until[ip] = now + config.AUTH_LOCKOUT_S
                _record_auth_attack(ip)
                fails.clear()
        if p.startswith("/api/"):
            return web.json_response({"error": "unauthorized"}, status=401)
        raise web.HTTPFound(_login_dest(request, p))
    _auth_fails.pop(ip, None)
    _auth_locked_until.pop(ip, None)
    # First-login gate: an admin-created (or admin-reset) user must set a new
    # password before reaching anything else. Confine such a session to the
    # account page + the endpoints that flow drives, everything else is blocked.
    if _sess and _sess.get("must_change") and p not in _MUST_CHANGE_OK:
        if p.startswith("/api/"):
            return web.json_response(
                {"error": "password change required"}, status=403)
        raise web.HTTPFound(_fwd_prefix(request) + "/account?force=1")
    if is_admin_path and role != "admin":
        if p.startswith("/api/"):
            return web.json_response({"error": "forbidden"}, status=403)
        return web.Response(text="403 — admin access required", status=403)
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
                   '.open("/', 'a[href="/',
                   # form POST target (login) and JS root redirects (account) —
                   # without these the login form / post-change nav escape the
                   # sub-path and hit the proxy root instead of the app.
                   ' action="/', 'location.href="/'):
        html = html.replace(marker, marker[:-1] + p + "/")
    return html


# --------------------------------------------------------------- handlers -----
def _maybe_cookie_redirect(request: web.Request, dest: str) -> None:
    """If authed via ?token=, move it into an HttpOnly cookie and redirect to a
    clean URL — keeps the secret out of history, access logs, Referer, and the
    tunnel's request inspector after the very first hit."""
    if config.DASHBOARD_TOKEN and _token_ok(request.query.get("token")) and \
            not request.cookies.get(_COOKIE):
        resp = web.HTTPFound((_fwd_prefix(request) + dest) or dest)
        # The cookie holds an OPAQUE session id (not the master token) so the raw
        # secret never lands in a browser cookie / a mis-logged Set-Cookie. F3:
        # Secure by default (assume TLS); only conditional when the operator opts
        # into plain-HTTP testing — never ship the cookie over cleartext silently.
        secure = _is_https(request) if config.COOKIE_ALLOW_INSECURE else True
        sid = _token_session_new(time.time())
        resp.set_cookie(_COOKIE, sid, max_age=86400 * 7,
                        httponly=True, samesite="Strict",
                        secure=secure, path="/")
        raise resp


_SCRIPT_OPEN = re.compile(r"<script(?=[\s>])")


def _sidebar_extra(user: str | None, role: str | None, prefix: str) -> str:
    """Sidebar links injected server-side for a logged-in user: a Users link for
    admins, and a logout link showing the username. Empty for token-only auth."""
    if not user:
        return ""
    safe = _html_escape(user)
    links = ""
    if role == "admin":
        links += f'<a href="{prefix}/admin/users">&#128101; Users</a>'
    links += f'<a href="{prefix}/account">&#128273; Account</a>'
    links += (f'<a href="{prefix}/logout" title="Log out">&#9099; Logout '
              f'<span style="opacity:.6">({safe})</span></a>')
    return links


def _serve_page(path: Path, prefix: str = "", user: str | None = None,
                role: str | None = None, show_alerts: bool = True) -> web.Response:
    try:
        html = path.read_text(encoding="utf-8")
    except Exception:
        return web.Response(text="dashboard missing", status=500)
    # Token/PAT access has no user identity to own alert config, so drop the
    # sidebar Alerts link for it (the JS alert-dot selector is left intact — it
    # no-ops when the anchor is gone). Done before _apply_prefix so it matches
    # the raw href regardless of any sub-path prefix.
    if not show_alerts:
        # regex, not a literal: the sidebar Alerts link carries a style attr
        # (indented sub-item), so match the anchor regardless of its attributes.
        html = re.sub(r'<a href="/alerts"[^>]*>Alerts</a>', "", html)
    if prefix:
        html = _apply_prefix(html, prefix)
    extra = _sidebar_extra(user, role, prefix)
    if extra:                       # inject the user/admin links before </nav>
        html = html.replace("</nav>", extra + "</nav>", 1)
    # F5: stamp every <script> tag with a fresh nonce and hand it to the header
    # layer (via _NONCE_HDR) so the CSP allows exactly these scripts and nothing
    # injected. token_urlsafe is base64url — no ", ' or > to break the attribute.
    nonce = secrets.token_urlsafe(16)
    html = _SCRIPT_OPEN.sub(f'<script nonce="{nonce}"', html)
    resp = web.Response(text=html, content_type="text/html")
    resp.headers[_NONCE_HDR] = nonce
    return resp


def _page(request: web.Request, path: Path, dest: str) -> web.Response:
    """Serve a dashboard page: move ?token= into a cookie, then render with the
    current user's sidebar links (Users/logout) stamped in server-side."""
    _maybe_cookie_redirect(request, dest)
    _authed, role, sess = _auth_ctx(request)
    user = sess["user"] if sess else None
    # Alerts is user-owned & sensitive: only a real login session gets the link.
    # Token/PAT (sess is None) and open mode are denied at the route in _auth_mw,
    # so their link is hidden too — no dead link that just 403s.
    return _serve_page(path, _fwd_prefix(request), user=user, role=role,
                       show_alerts=sess is not None)


async def index_handler(request: web.Request) -> web.Response:
    return _page(request, _INDEX, "/")


async def litellm_page_handler(request: web.Request) -> web.Response:
    return _page(request, _WEB / "litellm.html", "/litellm")


async def spend_page_handler(request: web.Request) -> web.Response:
    # Spend & Quota is LiteLLM-derived — with no LiteLLM configured the page is
    # hidden from the nav and blocked here so a direct URL can't reach it either.
    if not _litellm_configured():
        raise web.HTTPNotFound()
    return _page(request, _WEB / "spend.html", "/spend")


async def gpu_page_handler(request: web.Request) -> web.Response:
    return _page(request, _WEB / "gpu.html", "/gpu")


async def ollama_page_handler(request: web.Request) -> web.Response:
    return _page(request, _WEB / "ollama.html", "/ollama")


async def llamacpp_page_handler(request: web.Request) -> web.Response:
    return _page(request, _WEB / "llamacpp.html", "/llamacpp")


async def alerts_page_handler(request: web.Request) -> web.Response:
    return _page(request, _WEB / "alerts.html", "/alerts")


# ───────────────────────────── login / logout ────────────────────────────────
def _cookie_secure(request: web.Request) -> bool:
    return _is_https(request) if config.COOKIE_ALLOW_INSECURE else True


# Fixed decoy hash: scrypt-verify against it for unknown users so a failed login
# takes the same time whether or not the username exists (anti-enumeration).
_DECOY_HASH = auth.hash_password(secrets.token_urlsafe(16))


def _set_user_cookie(resp, sid: str, request: web.Request) -> None:
    resp.set_cookie(_USER_COOKIE, sid, max_age=int(config.SESSION_TTL_S),
                    httponly=True, samesite="Strict",
                    secure=_cookie_secure(request), path="/")


def _safe_path(nxt: str | None) -> str:
    """A validated local redirect target (no open-redirect off-site). Rejects `//`
    AND `\\` — browsers normalise a backslash to `/`, so `/\\evil.com` would resolve
    as the protocol-relative `//evil.com` and redirect off-site."""
    if nxt and nxt.startswith("/") and not nxt.startswith("//") and "\\" not in nxt:
        return nxt
    return "/"


async def login_page_handler(request: web.Request) -> web.Response:
    authed, _role, _sess = _auth_ctx(request)
    if authed:
        raise web.HTTPFound(_fwd_prefix(request) + _safe_path(request.query.get("next")))
    return _serve_page(_WEB / "login.html", _fwd_prefix(request))


async def login_submit_handler(request: web.Request) -> web.Response:
    ip = _client_ip(request)
    now = time.time()
    locked = _auth_locked_until.get(ip, 0.0)
    if locked > now:
        raise web.HTTPFound(_fwd_prefix(request) + "/login?e=locked")
    data = await request.post()
    name = str(data.get("username") or "").strip()
    pw = str(data.get("password") or "")
    nxt = _safe_path(str(data.get("next") or "/"))
    # Per-account lockout: an account with too many recent failures is refused
    # regardless of which IP the attempt comes from (survives IP rotation).
    if name and _user_locked_until.get(name, 0.0) > now:
        _audit(request, name, "login.lockout")
        _log(f"[auth] login LOCKOUT (account) user={name!r} ip={ip}")
        raise web.HTTPFound(_fwd_prefix(request) + "/login?e=locked")
    u = db.user_get(name)
    if u is not None and not u["disabled"]:
        ok = auth.verify_password(pw, u["pw_hash"])
    else:
        # Run the (deliberately slow) scrypt against a fixed decoy hash for an
        # unknown/disabled user too, so login latency can't be used to enumerate
        # which usernames exist (timing side-channel).
        auth.verify_password(pw, _DECOY_HASH)
        ok = False
    if not ok:
        fails = _auth_fails[ip]
        while fails and now - fails[0] > config.AUTH_WINDOW_S:
            fails.popleft()
        fails.append(now)
        locked = len(fails) >= config.AUTH_MAX_FAILS
        if locked:
            _auth_locked_until[ip] = now + config.AUTH_LOCKOUT_S
            _record_auth_attack(ip)
            fails.clear()
        # Per-account counter (only meaningful for a real, non-disabled user).
        user_locked = False
        if name:
            ufails = _user_fails[name]
            while ufails and now - ufails[0] > config.AUTH_WINDOW_S:
                ufails.popleft()
            ufails.append(now)
            if len(ufails) >= config.AUTH_USER_MAX_FAILS:
                _user_locked_until[name] = now + config.AUTH_USER_LOCKOUT_S
                ufails.clear()
                user_locked = True
                _log(f"[auth] account LOCKED user={name!r} for "
                     f"{config.AUTH_USER_LOCKOUT_S:.0f}s ({config.AUTH_USER_MAX_FAILS} "
                     f"fails) — last ip={ip}")
        any_lock = locked or user_locked
        _audit(request, name or "?", "login.lockout" if any_lock else "login.fail")
        _log(f"[auth] login {'LOCKOUT' if any_lock else 'FAILED'} "
             f"user={name or '?'!r} ip={ip}")
        q = "?e=1" + ("&next=" + quote(nxt, safe="") if nxt != "/" else "")
        raise web.HTTPFound(_fwd_prefix(request) + "/login" + q)
    _auth_fails.pop(ip, None)
    _auth_locked_until.pop(ip, None)
    _user_fails.pop(name, None)
    _user_locked_until.pop(name, None)
    assert u is not None
    must_change = bool(u.get("must_change_pw"))
    sid, _csrf = auth.session_new(u["name"], u["role"], must_change)
    db.user_touch_login(u["name"], now)
    _audit(request, u["name"], "login.ok", detail=u["role"])
    # A must-change user is sent to /account and gated there until they reset.
    dest = "/account?force=1" if must_change else nxt
    resp = web.HTTPFound(_fwd_prefix(request) + dest)
    _set_user_cookie(resp, sid, request)
    raise resp


async def logout_handler(request: web.Request) -> web.Response:
    sess = _session_from_req(request)
    if sess:
        _audit(request, sess["user"], "logout")
    auth.session_drop(request.cookies.get(_USER_COOKIE))
    _token_sessions.pop(request.cookies.get(_COOKIE) or "", None)  # legacy-token sid
    resp = web.HTTPFound(_fwd_prefix(request) + "/login")
    resp.del_cookie(_USER_COOKIE, path="/")
    resp.del_cookie(_COOKIE, path="/")
    raise resp


# ───────────────────────────── self-service account ──────────────────────────
async def me_handler(request: web.Request) -> web.Response:
    """The current identity + per-session CSRF token (for any logged-in user, so a
    viewer can obtain a CSRF token for their own account writes)."""
    sess = _session_from_req(request)
    if sess:
        return web.json_response({"user": sess["user"], "role": sess["role"],
                                  "csrf": sess["csrf"],
                                  "must_change": bool(sess.get("must_change"))})
    _, role, _ = _auth_ctx(request)               # token-authed: no session/csrf
    return web.json_response({"user": None, "role": role, "csrf": "",
                              "must_change": False})


async def account_page_handler(request: web.Request) -> web.Response:
    _, role, sess = _auth_ctx(request)
    user = sess["user"] if sess else None
    return _serve_page(_WEB / "account.html", _fwd_prefix(request), user=user, role=role)


async def api_account_password(request: web.Request) -> web.Response:
    """Change YOUR OWN password. Requires the current password (proves it's really
    you) + a policy-valid new one. Only for session-authed users (a token is not a
    person). Other sessions of this user are invalidated; the current one stays."""
    sess = _session_from_req(request)
    if not sess:
        return web.json_response({"error": "log in to change your password"}, status=401)
    if not _require_csrf(request, sess):
        return web.json_response({"error": "bad csrf"}, status=403)
    data = await request.post()
    current = str(data.get("current") or "")
    new = str(data.get("new") or "")
    u = db.user_get(sess["user"])
    if not u or not auth.verify_password(current, u["pw_hash"]):
        _audit(request, sess["user"], "account.password.fail")
        return web.json_response({"error": "current password is incorrect"}, status=400)
    if (pe := auth.password_error(new)):
        return web.json_response({"error": pe}, status=400)
    if auth.verify_password(new, u["pw_hash"]):
        return web.json_response({"error": "new password must differ from the current one"}, status=400)
    db.user_set_password(sess["user"], auth.hash_password(new))
    db.user_set_must_change(sess["user"], False)        # requirement satisfied
    sess["must_change"] = False                         # lift the gate on this session
    auth.sessions_drop_user_except(sess["user"], request.cookies.get(_USER_COOKIE))
    _audit(request, sess["user"], "account.password")
    return web.json_response({"ok": True})


# ── per-user API tokens (self-service personal access tokens) ─────────────────
_MAX_TOKENS_PER_USER = 20


async def api_account_tokens_get(request: web.Request) -> web.Response:
    """List YOUR tokens (metadata only — the secret is never returned again)."""
    sess = _session_from_req(request)
    if not sess:
        return web.json_response({"error": "log in"}, status=401)
    return web.json_response({"tokens": db.api_token_list(sess["user"]),
                              "role": sess["role"]})


async def api_account_tokens_create(request: web.Request) -> web.Response:
    """Mint a personal access token. A viewer may only create a VIEWER token; an
    admin may choose the token's role (viewer or admin). The raw secret is returned
    exactly once."""
    sess = _session_from_req(request)
    if not sess:
        return web.json_response({"error": "log in"}, status=401)
    if not _require_csrf(request, sess):
        return web.json_response({"error": "bad csrf"}, status=403)
    if db.api_token_count(sess["user"]) >= _MAX_TOKENS_PER_USER:
        return web.json_response(
            {"error": f"token limit reached ({_MAX_TOKENS_PER_USER})"}, status=400)
    data = await request.post()
    label = str(data.get("label") or "").strip()[:64]
    want = str(data.get("role") or "viewer").strip()
    # Privilege guard: only an admin can mint an admin-scoped token.
    role = (want if want in auth.ROLES else "viewer") if sess["role"] == "admin" \
        else "viewer"
    raw, tid, prefix = _new_pat()
    if not db.api_token_create(tid, sess["user"], role, label,
                               _hash_token(raw), prefix, time.time()):
        return web.json_response({"error": "create failed"}, status=500)
    _audit(request, sess["user"], "token.create", target=tid, detail=role)
    # The secret is shown ONCE here and is otherwise unrecoverable (only its hash
    # is stored).
    return web.json_response({"ok": True, "id": tid, "token": raw,
                              "role": role, "label": label})


async def api_account_tokens_revoke(request: web.Request) -> web.Response:
    """Revoke (delete) one of YOUR tokens by id."""
    sess = _session_from_req(request)
    if not sess:
        return web.json_response({"error": "log in"}, status=401)
    if not _require_csrf(request, sess):
        return web.json_response({"error": "bad csrf"}, status=403)
    data = await request.post()
    tid = str(data.get("id") or "").strip()
    if not db.api_token_revoke(tid, sess["user"]):
        return web.json_response({"error": "no such token"}, status=404)
    _audit(request, sess["user"], "token.revoke", target=tid)
    return web.json_response({"ok": True})


# ── per-user alert webhook (self-service) ─────────────────────────────────────
async def api_account_webhook_get(request: web.Request) -> web.Response:
    sess = _session_from_req(request)
    if not sess:
        return web.json_response({"error": "log in"}, status=401)
    wh = db.user_get_webhook(sess["user"]) or {"url": "", "enabled": False}
    return web.json_response(wh)


async def api_account_webhook_set(request: web.Request) -> web.Response:
    """Save YOUR OWN alert webhook. User-supplied → SSRF-validated before storing."""
    sess = _session_from_req(request)
    if not sess:
        return web.json_response({"error": "log in"}, status=401)
    if not _require_csrf(request, sess):
        return web.json_response({"error": "bad csrf"}, status=403)
    data = await request.post()
    url = str(data.get("url") or "").strip()
    enabled = str(data.get("enabled") or "").lower() in ("1", "true", "on", "yes")
    if url:
        if (err := await alerts.validate_webhook_url(url)):
            return web.json_response({"error": err}, status=400)
    elif enabled:
        return web.json_response({"error": "enabling a webhook needs a URL"}, status=400)
    db.user_set_webhook(sess["user"], url, enabled and bool(url))
    _audit(request, sess["user"], "webhook.set",
           detail="on" if (enabled and url) else "off")
    return web.json_response({"ok": True})


async def api_account_webhook_test(request: web.Request) -> web.Response:
    sess = _session_from_req(request)
    if not sess:
        return web.json_response({"error": "log in"}, status=401)
    if not _require_csrf(request, sess):
        return web.json_response({"error": "bad csrf"}, status=403)
    data = await request.post()
    url = str(data.get("url") or "").strip()
    if not url:
        url = (db.user_get_webhook(sess["user"]) or {}).get("url") or ""
    if not url:
        return web.json_response({"error": "no webhook URL set"}, status=400)
    res = await alerts.send_test_url(request.app[_SESSION], url)
    _audit(request, sess["user"], "webhook.test", detail="ok" if res.get("ok") else "fail")
    return web.json_response(res)


# ───────────────────────────── admin: user mgmt ──────────────────────────────
def _require_csrf(request: web.Request, sess: dict | None) -> bool:
    """Session-authed writes need a matching CSRF token; token-authed automation
    (bearer, not a browser-auto-sent cookie) is exempt."""
    if sess is None:
        return True
    return hmac.compare_digest(
        request.headers.get("X-CSRF-Token", "") or "", sess.get("csrf", "") or "")


async def admin_users_page_handler(request: web.Request) -> web.Response:
    _, role, sess = _auth_ctx(request)
    user = sess["user"] if sess else None
    return _serve_page(_WEB / "admin.html", _fwd_prefix(request), user=user, role=role)


async def api_admin_users_list(request: web.Request) -> web.Response:
    _, _role, sess = _auth_ctx(request)
    return web.json_response({
        "users": db.user_list(),
        "csrf": (sess or {}).get("csrf", ""),
        "me": (sess or {}).get("user"),
    })


async def api_admin_users_create(request: web.Request) -> web.Response:
    _, _role, sess = _auth_ctx(request)
    actor = sess["user"] if sess else "token"
    if not _require_csrf(request, sess):
        return web.json_response({"error": "bad csrf"}, status=403)
    data = await request.post()
    name = str(data.get("username") or "").strip()
    email = str(data.get("email") or "").strip()
    pw = str(data.get("password") or "")
    role = str(data.get("role") or "viewer").strip()
    if role not in auth.ROLES:
        return web.json_response({"error": "role must be admin or viewer"}, status=400)
    if not auth.valid_username(name):
        return web.json_response({"error": "invalid username (use A-Z a-z 0-9 . _ -, ≤32)"}, status=400)
    if not auth.valid_email(email):
        return web.json_response({"error": "invalid email"}, status=400)
    if (pe := auth.password_error(pw)):
        return web.json_response({"error": pe}, status=400)
    if db.user_get(name):
        return web.json_response({"error": "user already exists"}, status=409)
    # Admin-created users must set their own password on first login.
    if not db.user_create(name, email, auth.hash_password(pw), role, time.time(),
                          must_change_pw=True):
        return web.json_response({"error": "create failed"}, status=500)
    _mark_users_changed()
    _audit(request, actor, "user.create", target=name, detail=role)
    return web.json_response({"ok": True, "user": name})


async def api_admin_users_action(request: web.Request) -> web.Response:
    _, _role, sess = _auth_ctx(request)
    actor = sess["user"] if sess else "token"
    if not _require_csrf(request, sess):
        return web.json_response({"error": "bad csrf"}, status=403)
    data = await request.post()
    name = str(data.get("username") or "").strip()
    action = str(data.get("action") or "").strip()
    target = db.user_get(name)
    if not target:
        return web.json_response({"error": "no such user"}, status=404)
    # Never remove/disable/demote the last remaining admin. The guard lives INSIDE
    # each mutation (atomic conditional write) rather than as a count-then-act here,
    # so two concurrent requests can't both pass a stale count and drop admins to
    # zero (TOCTOU). A guarded call returning False means the rail blocked it.
    if action == "disable":
        if not db.user_disable_guarded(name):
            return web.json_response({"error": "cannot disable the last admin"}, status=400)
        auth.sessions_drop_user(name)
    elif action == "enable":
        db.user_set_disabled(name, False)
    elif action == "delete":
        if not db.user_delete_guarded(name):
            return web.json_response({"error": "cannot delete the last admin"}, status=400)
        auth.sessions_drop_user(name)
        _mark_users_changed()
    elif action == "reset":
        pw = str(data.get("password") or "")
        if (pe := auth.password_error(pw)):
            return web.json_response({"error": pe}, status=400)
        db.user_set_password(name, auth.hash_password(pw))
        db.user_set_must_change(name, True)   # admin-set pw is temporary
        auth.sessions_drop_user(name)     # force re-login with the new password
    elif action == "force_reset":
        # Require the user to choose a new password on next login WITHOUT the admin
        # setting one (keeps their current password working only to reach /account).
        db.user_set_must_change(name, True)
        auth.sessions_drop_user(name)     # end active sessions so the gate applies now
    elif action == "update":
        # edit a user's profile (email + role). Role is revalidated per request in
        # _auth_ctx, so a change takes effect on the target's next request.
        email = str(data.get("email") or "").strip()
        role = str(data.get("role") or "").strip()
        if not auth.valid_email(email):
            return web.json_response({"error": "invalid email"}, status=400)
        if role not in auth.ROLES:
            return web.json_response({"error": "invalid role"}, status=400)
        if not db.user_update_guarded(name, email, role):   # atomic last-admin guard
            return web.json_response({"error": "cannot demote the last admin"}, status=400)
    else:
        return web.json_response({"error": "unknown action"}, status=400)
    _audit(request, actor, "user." + action, target=name)
    return web.json_response({"ok": True})


async def api_admin_audit(request: web.Request) -> web.Response:
    """Recent audit-trail rows for the admin UI (admin-gated by the /api/admin/*
    middleware rule). Optional ?limit= (≤1000) and ?action= prefix filter."""
    try:
        limit = int(request.query.get("limit", "200"))
    except ValueError:
        limit = 200
    prefix = request.query.get("action") or None
    if prefix not in (None, "login", "logout", "user"):
        prefix = None
    return web.json_response({"events": db.audit_list(limit, prefix)})


# ── runtime settings (admin-only via the /api/admin/* gate) ───────────────────
async def api_admin_settings_get(request: web.Request) -> web.Response:
    """Current tunable settings (live value, default, override flag) for the UI.
    Non-secret operational tuning only — see config.TUNABLES."""
    return web.json_response({"settings": config.tunables_view()})


async def api_admin_settings_set(request: web.Request) -> web.Response:
    """Set or reset one tunable. Body: action=set&name=&value=  |  action=reset&name=.
    Admin-only (gate) + CSRF; validated against config.TUNABLES; persisted; applied
    live (no restart); audited."""
    _, _role, sess = _auth_ctx(request)
    actor = sess["user"] if sess else "token"
    if not _require_csrf(request, sess):
        return web.json_response({"error": "bad csrf"}, status=403)
    data = await request.post()
    name = str(data.get("name") or "").strip()
    action = str(data.get("action") or "set").strip()
    if name not in config.TUNABLES:
        return web.json_response({"error": "unknown setting"}, status=400)
    if action == "reset":
        config.clear_override(name)
        db.settings_delete(name)
        _audit(request, actor, "settings.reset", target=name)
        return web.json_response({"ok": True, "name": name,
                                  "value": config.tunable(name), "overridden": False})
    ok, val, err = config.set_override(name, data.get("value"))
    if not ok:
        return web.json_response({"error": f"{name}: {err}"}, status=400)
    db.settings_set(name, val, time.time())
    _audit(request, actor, "settings.update", target=name, detail=val)
    return web.json_response({"ok": True, "name": name,
                             "value": config.tunable(name), "overridden": True})


async def settings_page_handler(request: web.Request) -> web.Response:
    """Admin-only Settings page. Non-admins are redirected (they can't change
    global config)."""
    _, role, sess = _auth_ctx(request)
    if _auth_enabled() and role != "admin":
        raise web.HTTPFound(_fwd_prefix(request) + "/")
    user = sess["user"] if sess else None
    return _serve_page(_WEB / "settings.html", _fwd_prefix(request), user=user, role=role)


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


async def keydelta_handler(request: web.Request) -> web.Response:
    """Timeline of CUMULATIVE requests during the window per top key — each point is
    the running total of requests made since the window start, so the line climbs to
    the key's window total and an idle key is a flat 0 line. Top-N ranked by total
    net requests over the window."""
    window = request.query.get("window", "1h")
    if window not in db.WINDOWS:
        window = "1h"
    try:
        pts = int(request.query.get("points", "200"))
    except ValueError:
        pts = 200
    pts = max(30, min(pts, 1000))
    data = db.key_delta_series(window, pts, end=_q_end(request))
    return web.json_response({"window": window, **data})


def _configured(name: str, env_ok: bool) -> bool:
    """A dashboard link is shown when its backend is configured. Prefer the
    latest live sample (handles local GPU auto-detect); fall back to env."""
    c = _latest.get("collectors", {}).get(name, {})
    if c:
        return not (c.get("available") is False and c.get("error") == "unconfigured")
    return env_ok


def _litellm_configured() -> bool:
    """Spend & Quota is entirely LiteLLM-derived — with no LiteLLM configured the
    link is hidden and the page 404s. Keyed on the env URL (not the live sample):
    "configured" is a deployment fact, so a configured-but-momentarily-down LiteLLM
    still keeps its Spend link, and the gate is deterministic."""
    return bool(config.LITELLM_BASE_URL)


async def nav_handler(request: web.Request) -> web.Response:
    """Which backend dashboards are configured — drives nav-link visibility.
    `admin` reveals admin-only links (Settings) in the sidebar."""
    _, role, _ = _auth_ctx(request)
    return web.json_response({
        "litellm": _configured("litellm", bool(config.LITELLM_BASE_URL)),
        "spend": _litellm_configured(),   # Spend & Quota — hidden with no LiteLLM
        "ollama": _configured("ollama", bool(config.OLLAMA_BASE_URL)),
        "llamacpp": _configured("llamacpp", bool(config.LLAMACPP_BASE_URL)),
        "gpu": _configured("gpu", bool(config.GPU_SSH or config.GPU_METRICS_URL)),
        "admin": (role == "admin") or not _auth_enabled(),
    })


async def litellm_models_handler(request: web.Request) -> web.Response:
    """Per-model requests + tokens for the SELECTED window, queried live from
    LiteLLM's pre-aggregated per-model endpoint so the table honors
    15m/1h/24h/30d/12mo — including prior days — instead of only the collector's
    fixed rolling window (which is today-only / last-15-min)."""
    window = request.query.get("window", "24h")
    if window not in db.WINDOWS:
        window = "24h"
    now = time.time()
    secs = db.WINDOWS[window]
    # /global/activity/model is day-granular: open at the day the window starts,
    # close tomorrow so today is fully covered. A rolling 24h thus spans yesterday
    # + today (the reported gap). Sub-day windows collapse to today (endpoint's
    # finest granularity is a day).
    start = time.strftime("%Y-%m-%d", time.gmtime(now - secs))
    end = time.strftime("%Y-%m-%d", time.gmtime(now + 86400))
    rows = await litellm.per_model_range(request.app[_SESSION], start, end,
                                         db.model_kind_overrides())
    # Estimated $ per model = tokens × LiteLLM per-model price; tagged real/estimated by
    # cost_kind so the UI can draw a 2-colour cost-by-model breakdown (free tier has no $).
    prices = await litellm.model_prices(request.app[_SESSION])
    priced = 0
    for r in rows or []:
        # real = external cash; reference = self-hosted imputed (estimated). Both priced
        # so the Spend page can show them as separate real/estimated cost series.
        rate = litellm.price_for(r.get("model", ""), prices)
        r["est_cost"] = round(int(r.get("tokens") or 0) * rate, 4)
        priced += 1 if rate > 0 else 0
    return web.json_response({"window": window, "start_date": start,
                              "end_date": end, "per_model": rows or [],
                              "usage": _usage_split(rows or []),
                              "cost_available": priced > 0,
                              "available": rows is not None})


def _usage_split(rows: list) -> dict:
    """Real (external) vs reference (self-hosted) vs unknown split by TOKENS and
    REQUESTS — works even in lite mode, where per-model *cost* is unavailable but
    per-model usage is not. Lets the page say '98% of tokens are self-hosted'."""
    buckets = {True: "reference", False: "real", None: "unknown"}
    agg: dict = {"real": {"reqs": 0, "tokens": 0},
                 "reference": {"reqs": 0, "tokens": 0},
                 "unknown": {"reqs": 0, "tokens": 0}}
    for r in rows:
        b = agg[buckets.get(r.get("internal"), "unknown")]
        b["reqs"] += int(r.get("reqs") or 0)
        b["tokens"] += int(r.get("tokens") or 0)
    tok = sum(v["tokens"] for v in agg.values())
    req = sum(v["reqs"] for v in agg.values())
    agg["tokens_total"] = tok
    agg["reqs_total"] = req
    agg["reference_token_pct"] = round(agg["reference"]["tokens"] / tok * 100, 1) if tok else 0
    agg["real_token_pct"] = round(agg["real"]["tokens"] / tok * 100, 1) if tok else 0
    return agg


# Demo/override hook: a callable fn(now) -> {"keys":[...],"summary":{...}}. The
# demo server sets this to synthesized budgets; production leaves it None and the
# handler derives rows from the live LiteLLM snapshot + MONITOR_KEY_BUDGETS.
_budgets_source = None


def _key_budget_map() -> dict:
    m: dict = {}
    raw = config.KEY_BUDGETS_JSON
    if raw:
        try:
            m = {str(k): float(v) for k, v in json.loads(raw).items()}
        except Exception:
            m = {}
    m.update(db.key_budget_overrides())     # admin UI override wins over env
    return m


def _budget_summary(rows: list) -> dict:
    spent = sum(r["spent"] for r in rows)                     # real cash, all keys
    reference = sum(r.get("reference", 0.0) for r in rows)    # self-hosted
    budgeted = [r for r in rows if r.get("budget")]
    unbudgeted = [r for r in rows if not r.get("budget")]
    # cap maths only over keys that actually HAVE a budget
    budget = sum(r["budget"] for r in budgeted)
    b_spent = sum(r["spent"] for r in budgeted)
    b_burn = sum(r["burn"] for r in budgeted)
    b_projected = sum(r["projected"] for r in budgeted)
    remaining = budget - b_spent
    return {
        "spent": round(spent, 2), "reference": round(reference, 2),
        "total": round(spent + reference, 2), "budget": round(budget, 2),
        "pct": round(b_spent / budget * 100, 1) if budget > 0 else 0,
        "projected": round(b_projected, 2),
        "burn": round(sum(r["burn"] for r in rows), 2),
        "remaining": round(remaining, 2),
        "days_to_cap": round(remaining / b_burn, 1) if b_burn > 0 else None,
        "over": b_projected > budget if budget > 0 else False,
        "keys": len(rows), "budgeted": len(budgeted),
        "unbudgeted": len(unbudgeted),
        "unbudgeted_spend": round(sum(r["spent"] for r in unbudgeted), 2),
        # reference baseline used to draw bars for keys with no budget
        "top_spend": round(max((r["spent"] for r in rows), default=0.0), 2),
    }


def merge_key_budgets(live: dict | None, snapshot_keys: list, env_map: dict) -> list:
    """Build the key list for budget_rows from BOTH LiteLLM's key API (real spend +
    max_budget) AND the collector's spend snapshot. A key can have real spend in
    /global/spend/keys yet be absent from /key/list (deleted key, scope, etc.) — the
    Spend 'Cost by key' chart must still show it, so the two sources are UNIONED (was
    live-OR-snapshot, which silently dropped those keys). MONITOR_KEY_BUDGETS always wins."""
    def _alias(k):
        return str(k.get("alias") or k.get("key_alias") or k.get("key_name")
                   or k.get("key") or "")
    keys: list = []
    seen: set = set()
    if live:
        for alias, info in live.items():
            keys.append({"alias": alias, "cost": info.get("spend", 0.0),
                         "team": info.get("team", ""), "budget": info.get("budget", 0.0)})
            seen.add(str(alias))
    for sk in (snapshot_keys or []):     # fold in snapshot spend keys not already present
        a = _alias(sk)
        if a and a not in seen:
            keys.append(dict(sk))
            seen.add(a)
    for k in keys:                       # env override wins over LiteLLM max_budget
        if _alias(k) in env_map:
            k["budget"] = env_map[_alias(k)]
    return keys


def _resolve_budget_map(keys: list) -> dict:
    """Effective monthly budget per key: an explicit per-key budget (UI override or
    MONITOR_KEY_BUDGETS) wins; otherwise the key inherits its TEAM's budget. LiteLLM's
    own max_budget stays as budget_rows' final fallback."""
    tb = db.team_budgets()
    out = dict(_key_budget_map())          # env + per-key overrides (explicit)
    for k in keys:
        kid = _team_key_id(k)
        team = str(k.get("team") or "")
        if kid not in out and team and team in tb:
            out[kid] = tb[team]            # inherit the team budget
    return out


async def budgets_handler(request: web.Request) -> web.Response:
    """Per-key spend vs budget (the Spend & Quota panel): % used, $/day burn,
    days-to-cap, projected month-end, ranked closest-to-cap first. Budgets come from
    LiteLLM's own per-key `max_budget` (/key/list), overridable by MONITOR_KEY_BUDGETS.
    A key with NO budget is still listed (status 'none') — its spend is shown, just
    without cap maths, so an undefined budget is visible instead of hidden."""
    now = time.time()
    if _budgets_source is not None:
        return web.json_response(_budgets_source(now))
    import calendar
    lt = time.gmtime(now)
    mlen = calendar.monthrange(lt.tm_year, lt.tm_mon)[1]
    live = await litellm.key_budgets(request.app[_SESSION])
    snap = _backend_latest.get("litellm", {})
    keys = merge_key_budgets(live, snap.get("top_keys") or [], _key_budget_map())
    _apply_team_overrides(keys)          # admin-assigned team wins over LiteLLM's
    rows = litellm.budget_rows(keys, _resolve_budget_map(keys), lt.tm_mday, mlen)
    return web.json_response({"keys": rows, "summary": _budget_summary(rows),
                              "available": bool(rows),
                              "budget_source": "litellm" if live else
                                               ("env" if _key_budget_map() else "none"),
                              "budget_error": None if live else litellm.last_key_list_error()})


def _team_key_id(k: dict) -> str:
    """Stable identity a team override keys on — the key alias, else the raw key."""
    return str(k.get("alias") or k.get("key_alias") or k.get("key") or "").strip()


def _apply_team_overrides(keys: list) -> None:
    """Overlay admin-assigned teams (db.key_teams) onto the LiteLLM-reported team.
    Team budgets are a LiteLLM ENTERPRISE feature, so this override is how an OSS
    LiteLLM gets managed team grouping on the Spend & Quota by-team rollup."""
    ov = db.team_overrides()
    if not ov:
        return
    for k in keys:
        t = ov.get(_team_key_id(k))
        if t:
            k["team"] = t


# Sticky cache of LiteLLM-detected teams: key_id -> {detected, user, budget, spent}.
# LiteLLM's team lookup (/key/list + /team/list + /user/list) is flaky — a 403 or a
# timeout on any tick returns EMPTY teams, which made the board blink between the right
# team and "none". We cache the last NON-EMPTY detection per key and serve that; a
# detected team only changes on an explicit Refresh (never re-fetched on every load).
_TEAMS_DETECT_CACHE: dict[str, dict] = {}


def _merge_team(kid: str, team: str, user: str, budget: float, spent: float,
                user_name: str = "") -> None:
    """Fold one key's detection into the sticky cache, filling each field from whichever
    source HAS it (first non-empty wins per field; spend refreshes when non-zero). A key
    blank in /key/list gets its team from the snapshot and vice-versa — never overwritten
    back to blank, which is why big spenders used to show teamed under /budgets but blank
    on the board."""
    kid = str(kid or "").strip()
    if not kid:
        return
    if litellm._is_team_id(team):        # a raw team_id UUID is not a team NAME → ignore
        team = ""
    if litellm._is_team_id(user_name):   # a user_id UUID is not a username → ignore
        user_name = ""
    cur = _TEAMS_DETECT_CACHE.setdefault(
        kid, {"detected": "", "user": "", "user_name": "", "budget": 0.0, "spent": 0.0})
    before = dict(cur)
    cur["detected"] = cur["detected"] or (team or "")
    cur["user"] = cur["user"] or (user or "")
    cur["user_name"] = cur.get("user_name") or (user_name or "")
    cur["budget"] = cur["budget"] or (budget or 0.0)
    cur["spent"] = (spent or 0.0) or cur["spent"]
    if cur != before:                       # persist only real changes (not every re-fold)
        db.team_detect_set(kid, cur["detected"], cur["user"], cur.get("user_name", ""),
                           cur["budget"], cur["spent"], time.time())


_TEAMS_LOADED = False


async def _detect_teams(session, force: bool) -> tuple[dict, str]:
    """Return (key_id -> detected info, source). The flaky/heavy LiteLLM `/key/list` is
    only hit on `force` (Refresh) or a cold start; the local spend snapshot (free, always
    fresh, and it carries resolved teams) is folded in on EVERY call. That fills any team
    left blank by an early cold-start detection WITHOUT re-polling LiteLLM each load — so
    the board self-heals within a poll or two instead of staying blank until Refresh.
    On first use the cache is seeded from the DB (db.team_detect) so a restart shows the
    last known teams immediately, without a LiteLLM refresh."""
    global _TEAMS_DETECT_CACHE, _TEAMS_LOADED
    if not _TEAMS_LOADED:                    # seed from DB once (survives restarts)
        saved = db.team_detect_all()
        if saved:
            # An earlier bug persisted raw team_id UUIDs as team names — scrub them on
            # load (and from the DB) so the board re-resolves to real aliases, never UUIDs.
            for kid, info in saved.items():
                if litellm._is_team_id(info.get("detected", "")):
                    info["detected"] = ""
                    db.team_detect_set(kid, "", info.get("user", ""),
                                       info.get("user_name", ""), info.get("budget", 0.0),
                                       info.get("spent", 0.0), time.time())
            _TEAMS_DETECT_CACHE = saved
        _TEAMS_LOADED = True
    hit_litellm = force or not _TEAMS_DETECT_CACHE
    if hit_litellm:
        live = await litellm.key_budgets(session)
        for alias, info in (live or {}).items():
            _merge_team(alias, str(info.get("team", "") or ""), str(info.get("user", "") or ""),
                        float(info.get("budget", 0) or 0), float(info.get("spend", 0) or 0),
                        str(info.get("user_name", "") or ""))
    for k in (_backend_latest.get("litellm", {}) or {}).get("top_keys", []):
        _merge_team(_team_key_id(k), str(k.get("team", "") or ""), str(k.get("user", "") or ""),
                    0.0, float(k.get("cost", 0) or 0))
    return _TEAMS_DETECT_CACHE, ("litellm" if hit_litellm else "cache")


async def api_admin_keys_diag(request: web.Request) -> web.Response:
    """Admin diagnostic: the raw /key/list + /user/list field structure (email VALUES
    redacted) — used to locate which LiteLLM field carries the user email when it doesn't
    show on the board. Admin-only via the /api/admin/* gate."""
    return web.json_response(await litellm.keys_diag(request.app[_SESSION]))


async def api_admin_teams_get(request: web.Request) -> web.Response:
    """Team board for the Settings page: every known key, its LiteLLM-detected team,
    the resolved team (override wins), and whether it is overridden. Admin-only.
    Serves cached team detection; pass ?refresh=1 (the Refresh button) to re-poll LiteLLM."""
    ov = db.team_overrides()
    bov = db.key_budget_overrides()          # admin per-key budget overrides
    uov = db.key_user_overrides()            # admin per-key user/email reassignment
    tb = db.team_budgets()                   # per-team monthly budgets
    seen: dict[str, dict] = {}
    force = request.query.get("refresh") in ("1", "true", "yes")
    detected, source = await _detect_teams(request.app[_SESSION], force)

    def add(key_id: str, detected: str, user: str = "", budget: float = 0.0,
            spent: float = 0.0, user_name: str = ""):
        key_id = str(key_id or "").strip()
        if not key_id or key_id in seen:
            return
        det = str(detected or "")
        tmn = ov.get(key_id, det)
        # a user/email override reassigns the key: it wins for display AND grouping
        eff_name = uov.get(key_id) or str(user_name or "")
        seen[key_id] = {"key": key_id, "user": str(user or ""),
                        "user_name": eff_name, "detected": det,
                        "user_grp": uov.get(key_id) or str(user or ""),
                        "user_overridden": key_id in uov,
                        "team": tmn, "overridden": key_id in ov,
                        "budget": bov.get(key_id, float(budget or 0)),
                        "budget_overridden": key_id in bov,
                        "team_budget": tb.get(tmn, 0.0) if tmn else 0.0,
                        "spent": float(spent or 0)}

    for kid, info in detected.items():
        add(kid, info.get("detected", ""), info.get("user", ""),
            info.get("budget", 0), info.get("spent", 0), info.get("user_name", ""))
    for key_id in set(ov) | set(bov) | set(uov):   # any key with a team/budget/user override
        if key_id not in seen:
            _tm = ov.get(key_id, "")
            seen[key_id] = {"key": key_id, "user": "", "user_name": uov.get(key_id, ""),
                            "user_grp": uov.get(key_id, ""), "user_overridden": key_id in uov,
                            "detected": "", "team": _tm, "overridden": key_id in ov,
                            "budget": bov.get(key_id, 0.0),
                            "budget_overridden": key_id in bov,
                            "team_budget": tb.get(_tm, 0.0) if _tm else 0.0, "spent": 0.0}
    rows = sorted(seen.values(), key=lambda r: r["key"].lower())
    teams = sorted({r["team"] for r in rows if r["team"]})
    # per-team rollup for the board header: monthly budget (sum of key max_budgets),
    # spend, and key count. Budgets are the LiteLLM per-key caps summed per team.
    agg: dict[str, dict] = {}
    for r in rows:
        tm = r["team"]
        if not tm:
            continue
        a = agg.setdefault(tm, {"team": tm, "budget": tb.get(tm, 0.0),
                                "budget_set": tm in tb, "spent": 0.0, "keys": 0})
        a["spent"] += r["spent"]
        a["keys"] += 1
    team_summary = sorted(agg.values(), key=lambda a: (-a["budget"], -a["spent"]))
    return web.json_response({"keys": rows, "teams": teams,
                              "team_summary": team_summary,
                              "source": source, "cached": source == "cache",
                              "error": None if source != "snapshot"
                              else litellm.last_key_list_error()})


async def api_admin_team_sync(request: web.Request) -> web.Response:
    """Per-row sync icon: re-detect from LiteLLM and return the ONE requested key's row,
    so a single stale key can be refreshed (and re-persisted) without the operator having
    to re-render the whole board. Admin + CSRF. (LiteLLM's key API is list-based, so the
    poll itself covers all keys, but only the requested row is returned/updated in the UI.)"""
    _, _role, sess = _auth_ctx(request)
    actor = sess["user"] if sess else "token"
    if not _require_csrf(request, sess):
        return web.json_response({"error": "bad csrf"}, status=403)
    data = await request.post()
    kid = str(data.get("key") or "").strip()
    if not kid:
        return web.json_response({"error": "key required"}, status=400)
    detected, _src = await _detect_teams(request.app[_SESSION], True)   # re-poll + persist
    info = detected.get(kid, {})
    det = str(info.get("detected", "") or "")
    # ⟳ means "re-pull from LiteLLM and let it WIN": drop any admin TEAM override so the
    # freshly detected team is what shows (the operator asked refresh to overwrite the
    # previously-defined name). The per-key BUDGET override is left untouched.
    if kid in db.team_overrides():
        db.team_delete(kid)
        _audit(request, actor, "team.sync_overwrite", target=kid, detail=det)
    return web.json_response({"ok": True, "key": kid,
                              "detected": det,
                              "user": info.get("user", ""),
                              "user_name": info.get("user_name", ""),
                              "team": det, "overridden": False})


_UI_LAYOUT_NAMES = {"settings_cards"}       # allow-list of persistable layout keys


def _clean_grid_layout(raw) -> dict:
    """Validate a free-form board layout {card_id: {x,y,w,h}} → clamped copy.
    x/w in 1..12 (12-col grid, x+w ≤ 13), y/h ≥ 1 (rows). Bad entries are dropped."""
    out: dict = {}
    if not isinstance(raw, dict):
        return out
    for k, v in list(raw.items())[:100]:
        if not isinstance(v, dict):
            continue
        try:
            x = max(1, min(12, int(v.get("x", 1))))
            w = max(1, min(12, int(v.get("w", 4))))
            y = max(1, int(v.get("y", 1)))
            h = max(1, min(200, int(v.get("h", 6))))
        except (TypeError, ValueError):
            continue
        if x + w > 13:
            w = 13 - x
        out[str(k)[:64]] = {"x": x, "y": y, "w": w, "h": h}
    return out


async def api_admin_ui_layout_get(request: web.Request) -> web.Response:
    """Return the persisted Settings board layout — free-form per-card {x,y,w,h} grid
    positions. `?name=settings_cards`. Admin-only via the /api/admin/* gate."""
    name = str(request.query.get("name") or "settings_cards")
    if name not in _UI_LAYOUT_NAMES:
        return web.json_response({"error": "unknown layout"}, status=400)
    saved = db.ui_layout_get(name)
    grid: dict = {}
    if isinstance(saved, dict):
        g = saved.get("grid")
        if isinstance(g, dict):
            grid = g
    return web.json_response({"name": name, "grid": _clean_grid_layout(grid)})


async def api_admin_ui_layout_set(request: web.Request) -> web.Response:
    """Persist the free-form Settings board layout (per-card x/y/w/h) server-side so the
    arrangement follows the deployment, not one browser. Body: name=&grid=<json
    {id:{x,y,w,h}}>. Admin + CSRF. Positions/sizes are clamped to the 12-col grid."""
    _, _role, sess = _auth_ctx(request)
    if not _require_csrf(request, sess):
        return web.json_response({"error": "bad csrf"}, status=403)
    data = await request.post()
    name = str(data.get("name") or "settings_cards")
    if name not in _UI_LAYOUT_NAMES:
        return web.json_response({"error": "unknown layout"}, status=400)
    try:
        grid = json.loads(str(data.get("grid") or "{}"))
    except Exception:
        return web.json_response({"error": "grid must be JSON"}, status=400)
    if not isinstance(grid, dict) or len(grid) > 100:
        return web.json_response({"error": "invalid grid"}, status=400)
    clean = _clean_grid_layout(grid)
    db.ui_layout_set(name, {"grid": clean}, time.time())
    return web.json_response({"ok": True, "name": name, "grid": clean})


async def api_admin_key_user(request: web.Request) -> web.Response:
    """Reassign (or reset) a key's user/email — the Teams key popup. Body:
    key=&user=  |  action=reset&key=. Admin + CSRF; audited. Empty user clears it,
    so the key falls back to its LiteLLM-reported user on the by-user grouping."""
    _, _role, sess = _auth_ctx(request)
    actor = sess["user"] if sess else "token"
    if not _require_csrf(request, sess):
        return web.json_response({"error": "bad csrf"}, status=403)
    data = await request.post()
    key = str(data.get("key") or "").strip()
    if not key:
        return web.json_response({"error": "key required"}, status=400)
    action = str(data.get("action") or "set").strip()
    user = str(data.get("user") or "").strip()
    if action == "reset" or not user:
        db.key_user_delete(key)
        _audit(request, actor, "key_user.reset", target=key)
        return web.json_response({"ok": True, "key": key, "user_name": "", "overridden": False})
    if len(user) > 120:
        return web.json_response({"error": "user/email too long (max 120)"}, status=400)
    # only allow reassigning to an EXISTING user (one already known from LiteLLM) — never
    # invent a new one. The known set is the emails LiteLLM reported across all keys.
    known = {str(v.get("user_name") or "").strip().lower()
             for v in _TEAMS_DETECT_CACHE.values() if str(v.get("user_name") or "").strip()}
    if known and user.lower() not in known:
        return web.json_response(
            {"error": "unknown user — pick an existing user from the list"}, status=400)
    if not db.key_user_set(key, user, time.time()):
        return web.json_response({"error": "could not save override"}, status=400)
    _audit(request, actor, "key_user.set", target=key, detail=user)
    return web.json_response({"ok": True, "key": key, "user_name": user, "overridden": True})


async def api_admin_teams_set(request: web.Request) -> web.Response:
    """Assign (or reset) a key's team override. Body: key=&team=  |  action=reset&key=.
    Admin-only (gate) + CSRF; audited. Empty team clears the override."""
    _, _role, sess = _auth_ctx(request)
    actor = sess["user"] if sess else "token"
    if not _require_csrf(request, sess):
        return web.json_response({"error": "bad csrf"}, status=403)
    data = await request.post()
    key = str(data.get("key") or "").strip()
    if not key:
        return web.json_response({"error": "key required"}, status=400)
    action = str(data.get("action") or "set").strip()
    now = time.time()
    if action == "reset":                    # clear BOTH team + budget for the key
        db.team_delete(key)
        db.key_budget_delete(key)
        _audit(request, actor, "key.reset", target=key)
        return web.json_response({"ok": True, "key": key, "team": "", "overridden": False,
                                  "budget": None, "budget_overridden": False})
    # set: apply whichever fields the form sent
    if "team" in data:
        team = str(data.get("team") or "").strip()
        if not team:
            db.team_delete(key)
        elif len(team) > 64:
            return web.json_response({"error": "team name too long (max 64)"}, status=400)
        else:
            db.team_set(key, team, now)
            _audit(request, actor, "team.set", target=key, detail=team)
    if "budget" in data:
        bval = str(data.get("budget") or "").strip()
        if bval == "":
            db.key_budget_delete(key)
        else:
            try:
                b = float(bval)
            except ValueError:
                return web.json_response({"error": "budget must be a number"}, status=400)
            if b < 0:
                return web.json_response({"error": "budget must be >= 0"}, status=400)
            db.key_budget_set(key, b, now)
            _audit(request, actor, "budget.set", target=key, detail=str(b))
    ovn = db.team_overrides()
    bovn = db.key_budget_overrides()
    return web.json_response({"ok": True, "key": key,
                              "team": ovn.get(key, ""), "overridden": key in ovn,
                              "budget": bovn.get(key), "budget_overridden": key in bovn})


async def api_admin_team_budget_set(request: web.Request) -> web.Response:
    """Set (or reset) a TEAM's monthly budget — inherited by every key in the team.
    Body: team=&budget=  |  action=reset&team=. Admin-only (gate) + CSRF; audited."""
    _, _role, sess = _auth_ctx(request)
    actor = sess["user"] if sess else "token"
    if not _require_csrf(request, sess):
        return web.json_response({"error": "bad csrf"}, status=403)
    data = await request.post()
    team = str(data.get("team") or "").strip()
    if not team:
        return web.json_response({"error": "team required"}, status=400)
    action = str(data.get("action") or "set").strip()
    bval = str(data.get("budget") or "").strip()
    if action == "reset" or bval == "":
        db.team_budget_delete(team)
        _audit(request, actor, "team_budget.reset", target=team)
        return web.json_response({"ok": True, "team": team, "budget": None})
    try:
        b = float(bval)
    except ValueError:
        return web.json_response({"error": "budget must be a number"}, status=400)
    if b < 0:
        return web.json_response({"error": "budget must be >= 0"}, status=400)
    db.team_budget_set(team, b, time.time())
    _audit(request, actor, "team_budget.set", target=team, detail=str(b))
    return web.json_response({"ok": True, "team": team, "budget": b})


async def api_admin_model_kinds_get(request: web.Request) -> web.Response:
    """Model cost-classification board for the Settings page: every known model, its
    auto-detected cost kind (real=external paid / reference=self-hosted estimated),
    the admin override (if any), the effective kind, and whether LiteLLM prices it.
    Admin-only (via the /api/admin/* gate)."""
    ov = db.model_kind_overrides()
    prices = {}
    try:
        prices = await litellm.model_prices(request.app[_SESSION])
    except Exception:
        prices = {}
    # Union of every model we can name: LiteLLM-priced models, the models the proxy
    # currently serves (/v1/models — works even without an admin key), the recent
    # per-model activity, and any model that already carries an override. This keeps
    # the board populated even when the master key can't reach the spend endpoints.
    names: set[str] = set(prices.keys())
    for mid in (_backend_latest.get("litellm", {}) or {}).get("models", []) or []:
        if mid:
            names.add(mid)
    now = time.time()
    start = time.strftime("%Y-%m-%d", time.gmtime(now - 30 * 86400))
    end = time.strftime("%Y-%m-%d", time.gmtime(now + 86400))
    try:
        recent = await litellm.per_model_range(request.app[_SESSION], start, end, ov)
        for r in recent or []:
            nm = r.get("model")
            if nm and nm != "(unattributed)":
                names.add(nm)
    except Exception:
        pass
    names.update(k for k in ov if k)
    models = []
    for name in sorted(names, key=lambda s: str(s).lower()):
        default = litellm.classify_model(name)          # heuristic, no override
        eff = litellm.classify_model(name, ov)          # override wins
        rate = litellm.price_for(name, prices)
        models.append({"model": name,
                       "default_kind": default["cost_kind"],
                       "kind": eff["cost_kind"],
                       "overridden": bool(eff.get("overridden")),
                       "priced": rate > 0,
                       "rate": rate})
    return web.json_response({"models": models,
                              "error": None if prices or models
                              else litellm.last_key_list_error()})


async def api_admin_model_kinds_set(request: web.Request) -> web.Response:
    """Pin (or reset) a model's cost classification. Body: model=&kind=real|reference
    | action=reset&model=. Admin-only (gate) + CSRF; audited."""
    _, _role, sess = _auth_ctx(request)
    actor = sess["user"] if sess else "token"
    if not _require_csrf(request, sess):
        return web.json_response({"error": "bad csrf"}, status=403)
    data = await request.post()
    model = str(data.get("model") or "").strip()
    if not model:
        return web.json_response({"error": "model required"}, status=400)
    if len(model) > 200:
        return web.json_response({"error": "model name too long (max 200)"}, status=400)
    action = str(data.get("action") or "set").strip()
    if action == "reset":
        db.model_kind_delete(model)
        _audit(request, actor, "model_kind.reset", target=model)
        default = litellm.classify_model(model)
        return web.json_response({"ok": True, "model": model,
                                  "kind": default["cost_kind"], "overridden": False})
    kind = str(data.get("kind") or "").strip().lower()
    if kind not in db.MODEL_KINDS:
        return web.json_response({"error": "kind must be 'real' or 'reference'"},
                                 status=400)
    if not db.model_kind_set(model, kind, time.time()):
        return web.json_response({"error": "could not save override"}, status=400)
    _audit(request, actor, "model_kind.set", target=model, detail=kind)
    return web.json_response({"ok": True, "model": model, "kind": kind,
                              "overridden": True})


# Demo/override hook for the spend timeline: fn(now, window) -> {...}.
_spend_series_source = None
# Last non-zero (real $/token, reference $/token) — reused when /global/activity/model
# momentarily returns empty so the estimated-cost chart stays put instead of blinking.
_COST_RATES: tuple[float, float] | None = None


def _date_epoch(date) -> float | None:
    """Day-start epoch for a date, tolerant of the formats LiteLLM emits:
    `2026-07-10`, `2026/07/10`, `2026-07-10T00:00:00Z`, a full ISO datetime, or a
    numeric epoch (s or ms). None if unparseable — a bad date skips the row rather
    than 500-ing the page."""
    import calendar
    import datetime as _dt
    if date is None or date == "":
        return None
    # numeric epoch (seconds or milliseconds) → normalise to the day start
    if isinstance(date, (int, float)) or (isinstance(date, str)
                                          and date.strip().lstrip("-").isdigit()):
        try:
            n = float(date)
        except (ValueError, TypeError):
            return None
        if n > 1e12:                      # milliseconds
            n /= 1000.0
        if n > 1e8:                       # plausible epoch (after ~1973)
            return float(int(n // 86400) * 86400)
        return None
    raw = str(date).strip()
    s = raw.replace("/", "-").replace("T", " ")[:10]
    try:
        return float(calendar.timegm(time.strptime(s, "%Y-%m-%d")))
    except (ValueError, TypeError):
        pass
    try:                                  # last resort: full ISO datetime
        dt = _dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return float(calendar.timegm(dt.utctimetuple()))
    except (ValueError, TypeError):
        return None


def bucket_spend(daily: list, window: str) -> dict:
    """Fold daily spend rows into the window's granularity (day for 30d, month for
    12mo) and roll up a per-calendar-year total. When the rows carry a real/reference
    split (external paid spend vs self-hosted reference cost), it is summed per
    bucket + per year and `split_available` is set."""
    # drop rows whose date isn't parseable so nothing downstream can raise
    daily = [r for r in daily if _date_epoch(r.get("date")) is not None]
    gran = "month" if window == "12mo" else "day"
    split = any("real" in r for r in daily)

    def _blank():
        return {"spend": 0.0, "real": 0.0, "reference": 0.0, "requests": 0, "tokens": 0}

    def _acc(b, r):
        b["spend"] += r["spend"]
        b["real"] += r.get("real", 0.0)
        b["reference"] += r.get("reference", 0.0)
        b["requests"] += r["requests"]
        b["tokens"] += r["tokens"]

    buckets: dict = {}
    for r in daily:
        key = r["date"] if gran == "day" else r["date"][:7]
        _acc(buckets.setdefault(key, _blank()), r)
    pts = []
    for k in sorted(buckets):
        b = buckets[k]
        t = _date_epoch(k if gran == "day" else k + "-01")
        if t is None:
            continue
        sp = round(b["spend"], 2)
        pt = {"t": t, "spend": sp, "requests": b["requests"], "tokens": b["tokens"]}
        if split:                      # reference = total − real, so it always adds up
            real = round(b["real"], 2)
            pt["real"] = real
            pt["reference"] = round(sp - real, 2)
        pts.append(pt)
    years: dict = {}
    for r in daily:
        y = r["date"][:4]
        if y.isdigit():
            _acc(years.setdefault(y, _blank()), r)
    year_rows = []
    for y in sorted(years):
        sp = round(years[y]["spend"], 2)
        row: dict = {"year": int(y), "spend": sp,
                     "tokens": years[y]["tokens"], "requests": years[y]["requests"]}
        if split:
            real = round(years[y]["real"], 2)
            row["real"] = real
            row["reference"] = round(sp - real, 2)
        year_rows.append(row)
    out = {"granularity": gran, "points": pts, "years": year_rows,
           "split_available": split}
    if split:
        sp_total = round(sum(r["spend"] for r in daily), 2)
        real_total = round(sum(r.get("real", 0.0) for r in daily), 2)
        out["real_total"] = real_total
        out["reference_total"] = round(sp_total - real_total, 2)
    return out


def cost_rates(per_model: list, prices: dict) -> tuple[float, float]:
    """($/token attributable to REAL external models, $/token to REFERENCE self-hosted
    models), from windowed per-model tokens × LiteLLM per-model prices. Free-tier LiteLLM
    exposes no per-day $, so cost over time is ESTIMATED = daily tokens × these rates.

    REAL is external cash spend; ESTIMATED is the imputed value of self-hosted usage
    (tokens × LiteLLM's per-model price — real hardware runs it for free, but the price
    lets you see what that volume WOULD cost on a hosted API). They are two separate
    series in the chart so the estimated one can be toggled off in the legend. Returns
    (0, 0) when nothing is priced."""
    real_c = ref_c = 0.0
    tot = 0
    for r in per_model or []:
        toks = int(r.get("tokens") or 0)
        tot += toks
        rate = litellm.price_for(r.get("model", ""), prices)
        if r.get("cost_kind") == "real":
            real_c += rate * toks
        elif r.get("cost_kind") == "reference":     # self-hosted → estimated (imputed)
            ref_c += rate * toks
    if not tot:
        return 0.0, 0.0
    return real_c / tot, ref_c / tot


def add_estimated_cost(series: dict, real_cpt: float, ref_cpt: float) -> dict:
    """Attach estimated real/estimated $ to each point + year of a usage series, from
    that bucket's token count × the per-token cost rates. `cost_available` is True only
    when at least one model is priced, so the UI can hide the $ chart otherwise."""
    avail = (real_cpt > 0 or ref_cpt > 0)
    series["cost_available"] = avail
    rt = et = 0.0
    for p in series.get("points", []):
        tk = int(p.get("tokens") or 0)
        p["real_cost"] = round(tk * real_cpt, 2)
        p["est_cost"] = round(tk * ref_cpt, 2)
        rt += p["real_cost"]
        et += p["est_cost"]
    for yr in series.get("years", []):
        tk = int(yr.get("tokens") or 0)
        yr["real_cost"] = round(tk * real_cpt, 2)
        yr["est_cost"] = round(tk * ref_cpt, 2)
    series["real_cost_total"] = round(rt, 2)
    series["est_cost_total"] = round(et, 2)
    return series


def apply_daily_cost(series: dict, daily_cost: dict) -> dict:
    """Fold ACCURATE per-day per-model costs (daily_cost: {canonical_date: {real,est}})
    onto each chart point (day or month bucket) and per-year. Unlike add_estimated_cost's
    window-blended rate × each day's TOTAL tokens, this attributes an external model's
    cost only to the days it actually ran — the days its own tokens are non-zero."""
    gran = series.get("granularity", "day")
    rt = et = 0.0
    for p in series.get("points", []):
        pref = time.strftime("%Y-%m-%d" if gran == "day" else "%Y-%m",
                             time.gmtime(p.get("t", 0)))
        n = len(pref)
        r = sum(c["real"] for dt, c in daily_cost.items() if dt[:n] == pref)
        e = sum(c["est"] for dt, c in daily_cost.items() if dt[:n] == pref)
        p["real_cost"] = round(r, 2)
        p["est_cost"] = round(e, 2)
        rt += r
        et += e
    for yr in series.get("years", []):
        ys = str(yr.get("year"))
        yr["real_cost"] = round(sum(c["real"] for dt, c in daily_cost.items()
                                    if dt[:4] == ys), 2)
        yr["est_cost"] = round(sum(c["est"] for dt, c in daily_cost.items()
                                   if dt[:4] == ys), 2)
    series["real_cost_total"] = round(rt, 2)
    series["est_cost_total"] = round(et, 2)
    series["cost_available"] = (rt > 0 or et > 0)
    return series


def cost_model_split(per_model: list) -> dict:
    """Model names grouped by effective cost bucket (real external vs reference
    self-hosted), for the cost-over-time legend tooltip. Only models with usage in the
    window, biggest first; the override-adjusted cost_kind decides the bucket."""
    out: dict = {"real": [], "reference": []}
    for r in sorted(per_model or [], key=lambda x: int(x.get("tokens") or 0),
                    reverse=True):
        kind = r.get("cost_kind")
        name = r.get("model") or ""
        if kind in out and name and name != "(unattributed)" \
                and int(r.get("tokens") or 0) > 0:
            out[kind].append(name)
    return out


def window_and_years(daily_full: list, window: str, now: float) -> dict:
    """Chart points respect the selected window (last 30 days daily, or 12 months
    monthly), but the per-year totals ALWAYS reflect the full year — so '2026 total'
    is year-to-date, not just the 30-day window's slice."""
    if window == "30d":
        cutoff = time.strftime("%Y-%m-%d", time.gmtime(now - 2592000))
        wdaily = [r for r in daily_full if r["date"] >= cutoff]
    else:
        wdaily = daily_full
    out = bucket_spend(wdaily, window)              # points + real/ref split
    out["years"] = bucket_spend(daily_full, "12mo")["years"]   # full-year totals
    return out


async def spend_series_handler(request: web.Request) -> web.Response:
    """Spend over time: daily buckets for 30d, monthly for 12mo, plus per-year
    year-to-date totals. Backed by LiteLLM /global/activity."""
    window = request.query.get("window", "30d")
    if window not in ("30d", "12mo"):
        window = "30d"
    now = time.time()
    if _spend_series_source is not None:
        return web.json_response(_spend_series_source(now, window))
    # always pull a full year so the per-year rollup is complete, regardless of window
    start = time.strftime("%Y-%m-%d", time.gmtime(now - 31536000))
    end = time.strftime("%Y-%m-%d", time.gmtime(now + 86400))
    try:
        daily = await litellm.spend_activity(request.app[_SESSION], start, end)
        if not daily:
            return web.json_response({"window": window, "available": False,
                                      "points": [], "years": []})
        out = {"window": window, "available": True,
               **window_and_years(daily, window, now)}
        # Estimated cost over time: free-tier LiteLLM has no per-day $, so multiply each
        # day's tokens by per-model prices (real external vs reference self-hosted rates).
        try:
            global _COST_RATES
            overrides = db.model_kind_overrides()
            prices = await litellm.model_prices(request.app[_SESSION])
            per_model = await litellm.per_model_range(request.app[_SESSION], start, end,
                                                      overrides)
            # ACCURATE path: per-day per-model tokens → each day's cost from its own model
            # mix, so an external model's cost lands only on the days it actually ran.
            daily_cost = await litellm.per_model_daily_cost(
                request.app[_SESSION], start, end, prices, overrides)
            if daily_cost:
                apply_daily_cost(out, daily_cost)
                out["cost_basis"] = "per-day"
            else:
                # Fallback: no per-model daily breakdown — window-blended rate × each day's
                # tokens (smears an external model's cost across the window, but keeps the
                # chart populated). /global/activity/model intermittently returns empty on a
                # busy proxy → rates 0 → reuse the last non-zero rates so it doesn't blink.
                real_cpt, ref_cpt = cost_rates(per_model or [], prices)
                if real_cpt or ref_cpt:
                    _COST_RATES = (real_cpt, ref_cpt)
                elif _COST_RATES:
                    real_cpt, ref_cpt = _COST_RATES
                add_estimated_cost(out, real_cpt, ref_cpt)
                out["cost_basis"] = "blended"
            out["cost_models"] = cost_model_split(per_model or [])
        except Exception as ce:     # cost is best-effort; usage chart must still render
            print(f"[warn] spend/series cost estimate: {type(ce).__name__}: {ce}",
                  file=sys.stderr)
            out["cost_available"] = False
        # ?diag=1: surface what the collector actually got + why rows drop, so an
        # empty chart is diagnosable from the browser (viewer-safe: own spend data).
        if request.query.get("diag"):
            _pr = await litellm.model_prices(request.app[_SESSION])
            out["diag"] = {"raw_daily_rows": len(daily), "sample_rows": daily[:3],
                           "unparseable_dates": [r.get("date") for r in daily
                                                 if _date_epoch(r.get("date")) is None][:5],
                           "any_spend": any((r.get("spend") or 0) for r in daily),
                           "priced_models": len(_pr), "prices_sample": dict(list(_pr.items())[:5]),
                           "cost_available": out.get("cost_available"),
                           "report": await litellm.spend_report_probe(
                               request.app[_SESSION], start, end),
                           "points_built": len(out.get("points", []))}
        return web.json_response(out)
    except Exception as e:      # a bad LiteLLM shape must degrade, never 500 the page
        print(f"[error] /api/spend/series {type(e).__name__}: {e}", file=sys.stderr)
        return web.json_response({"window": window, "available": False,
                                  "points": [], "years": [], "error": type(e).__name__})


async def alerts_handler(request: web.Request) -> web.Response:
    return web.json_response({
        "channels": alerts.channels_status(),
        "thresholds": alerts.thresholds_status(),
        "active": _notifier.active_keys(),
        "history": db.recent_alerts(50),
    })


async def alerts_test_handler(request: web.Request) -> web.Response:
    # Firing test notifications is an admin action (it hits the operator's real
    # webhook/channels): require the admin role and a CSRF token for a session
    # login. Token-authed automation is CSRF-exempt; open mode (no auth) allows it.
    _, role, sess = _auth_ctx(request)
    if _auth_enabled() and role != "admin":
        return web.json_response({"error": "forbidden"}, status=403)
    if not _require_csrf(request, sess):
        return web.json_response({"error": "bad csrf"}, status=403)
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


def _metrics_authed(request: web.Request) -> bool:
    """A valid session, the dashboard token, OR the dedicated scrape-only token."""
    authed, _role, _sess = _auth_ctx(request)
    if authed:
        return True
    mt = config.METRICS_TOKEN
    if mt:
        tok = _request_token(request)
        if tok and hmac.compare_digest(tok, mt):
            return True
    return False


def _lock_remaining(ip: str, now: float) -> float:
    locked = _auth_locked_until.get(ip, 0.0)
    return max(0.0, locked - now) if locked > now else 0.0


def _record_strike(ip: str, now: float) -> None:
    """Count a failed-auth attempt for ip; lock the IP out past the threshold."""
    fails = _auth_fails[ip]
    while fails and now - fails[0] > config.AUTH_WINDOW_S:
        fails.popleft()
    fails.append(now)
    if len(fails) >= config.AUTH_MAX_FAILS:
        _auth_locked_until[ip] = now + config.AUTH_LOCKOUT_S
        _record_auth_attack(ip)
        fails.clear()


async def metrics_handler(request: web.Request) -> web.Response:
    if not config.METRICS_ENABLED:
        return web.Response(text="metrics disabled\n", status=404)
    # L1: /metrics is in _OPEN (self-gated), so enforce the same brute-force lockout
    # the API middleware applies — a presented-but-wrong token counts as a strike.
    if _auth_enabled():
        ip = _client_ip(request)
        now = time.time()
        if (rem := _lock_remaining(ip, now)) > 0:
            return web.json_response({"error": "too many attempts"}, status=429,
                                     headers={"Retry-After": str(int(rem))})
        if not _metrics_authed(request):
            if _request_token(request) or request.cookies.get(_USER_COOKIE):
                _record_strike(ip, now)
            return web.Response(text="unauthorized\n", status=401)
        _auth_fails.pop(ip, None)
        _auth_locked_until.pop(ip, None)
    extra = {"users": db.user_count(), "sessions": auth.session_count(),
             "alerts": len(_notifier.active_keys())}
    body = metrics_prom.render(_latest, extra)
    resp = web.Response(text=body)
    resp.headers["Content-Type"] = metrics_prom.CONTENT_TYPE
    return resp


# --------------------------------------------------------------- lifecycle ----
async def _on_startup(app: web.Application) -> None:
    session = app[_SESSION] = aiohttp.ClientSession()
    # Apply persisted operator overrides (Settings page) over the env defaults.
    config.load_overrides(db.settings_all())
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
    # the per-user webhook sender holds its own SSRF-pinned session — close it too
    await alerts.close_webhook_session()


def build_app() -> web.Application:
    app = web.Application(middlewares=[_log_mw, _sechdr_mw, _auth_mw])
    app.router.add_get("/", index_handler)
    app.router.add_get("/litellm", litellm_page_handler)
    app.router.add_get("/spend", spend_page_handler)
    app.router.add_get("/gpu", gpu_page_handler)
    app.router.add_get("/ollama", ollama_page_handler)
    app.router.add_get("/llamacpp", llamacpp_page_handler)
    app.router.add_get("/alerts", alerts_page_handler)
    # multi-user login + admin user management
    app.router.add_get("/login", login_page_handler)
    app.router.add_post("/login", login_submit_handler)
    app.router.add_get("/logout", logout_handler)
    app.router.add_get("/account", account_page_handler)
    app.router.add_get("/api/me", me_handler)
    app.router.add_post("/api/account/password", api_account_password)
    app.router.add_get("/api/account/webhook", api_account_webhook_get)
    app.router.add_post("/api/account/webhook", api_account_webhook_set)
    app.router.add_post("/api/account/webhook/test", api_account_webhook_test)
    app.router.add_get("/api/account/tokens", api_account_tokens_get)
    app.router.add_post("/api/account/tokens", api_account_tokens_create)
    app.router.add_post("/api/account/tokens/revoke", api_account_tokens_revoke)
    app.router.add_get("/admin/users", admin_users_page_handler)
    app.router.add_get("/api/admin/users", api_admin_users_list)
    app.router.add_post("/api/admin/users", api_admin_users_create)
    app.router.add_post("/api/admin/users/action", api_admin_users_action)
    app.router.add_get("/api/admin/audit", api_admin_audit)
    app.router.add_get("/settings", settings_page_handler)
    app.router.add_get("/api/admin/settings", api_admin_settings_get)
    app.router.add_post("/api/admin/settings", api_admin_settings_set)
    app.router.add_get("/api/admin/teams", api_admin_teams_get)
    app.router.add_get("/api/admin/keys-diag", api_admin_keys_diag)
    app.router.add_post("/api/admin/teams", api_admin_teams_set)
    app.router.add_post("/api/admin/teams/sync", api_admin_team_sync)
    app.router.add_post("/api/admin/key-user", api_admin_key_user)
    app.router.add_post("/api/admin/team-budget", api_admin_team_budget_set)
    app.router.add_get("/api/admin/ui-layout", api_admin_ui_layout_get)
    app.router.add_post("/api/admin/ui-layout", api_admin_ui_layout_set)
    app.router.add_get("/api/admin/model-kinds", api_admin_model_kinds_get)
    app.router.add_post("/api/admin/model-kinds", api_admin_model_kinds_set)
    app.router.add_get("/api/data", data_handler)
    app.router.add_get("/api/series", series_handler)
    app.router.add_get("/api/uptime", uptime_handler)
    app.router.add_get("/api/events", events_handler)
    app.router.add_get("/api/stream", stream_handler)
    app.router.add_get("/api/keyseries", keyseries_handler)
    app.router.add_get("/api/keydelta", keydelta_handler)
    app.router.add_get("/api/procseries", procseries_handler)
    app.router.add_get("/api/anomalies", anomalies_handler)
    app.router.add_get("/api/nav", nav_handler)
    app.router.add_get("/api/litellm/models", litellm_models_handler)
    app.router.add_get("/api/budgets", budgets_handler)
    app.router.add_get("/api/spend/series", spend_series_handler)
    app.router.add_get("/api/alerts", alerts_handler)
    app.router.add_post("/api/alerts/test", alerts_test_handler)
    app.router.add_get("/api/export", export_handler)
    app.router.add_get("/healthz", healthz_handler)
    app.router.add_get("/metrics", metrics_handler)
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
    for need in ("/", "/spend", "/litellm", "/gpu", "/ollama", "/alerts", "/api/data",
                 "/api/series", "/api/uptime", "/api/keyseries",
                 "/api/keydelta",
                 "/api/procseries", "/api/anomalies", "/api/nav",
                 "/api/litellm/models", "/api/budgets", "/api/spend/series",
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
    db.init()
    created = auth.bootstrap_admin()
    if created:
        print(f"[auth] bootstrapped initial admin user '{created}' from env",
              file=sys.stderr)
    errs = config.validate(db.user_count())
    if errs:
        print("FATAL config errors:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 2
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
