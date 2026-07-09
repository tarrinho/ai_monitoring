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
_PAGES = ("/", "/litellm", "/gpu", "/ollama", "/llamacpp", "/alerts",
          "/admin/users", "/account")
# Reachable without a session: the login page/handlers and public assets.
_OPEN = ("/healthz", "/login", "/logout", "/metrics")
# Admin-only surfaces (role must be 'admin' or the legacy master token).
_ADMIN_PAGES = ("/admin/users",)
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
        html = html.replace('<a href="/alerts">Alerts</a>', "")
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
    # never remove/disable/lock out the last remaining admin
    last_admin = target["role"] == "admin" and db.user_count("admin") <= 1
    if action in ("disable", "delete") and last_admin:
        return web.json_response({"error": "cannot disable/delete the last admin"}, status=400)
    if action == "disable":
        db.user_set_disabled(name, True)
        auth.sessions_drop_user(name)
    elif action == "enable":
        db.user_set_disabled(name, False)
    elif action == "delete":
        db.user_delete(name)
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
        if last_admin and role != "admin":     # don't demote the last admin
            return web.json_response({"error": "cannot demote the last admin"}, status=400)
        db.user_update(name, email, role)
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


async def nav_handler(request: web.Request) -> web.Response:
    """Which backend dashboards are configured — drives nav-link visibility."""
    return web.json_response({
        "litellm": _configured("litellm", bool(config.LITELLM_BASE_URL)),
        "ollama": _configured("ollama", bool(config.OLLAMA_BASE_URL)),
        "llamacpp": _configured("llamacpp", bool(config.LLAMACPP_BASE_URL)),
        "gpu": _configured("gpu", bool(config.GPU_SSH or config.GPU_METRICS_URL)),
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
    rows = await litellm.per_model_range(request.app[_SESSION], start, end)
    return web.json_response({"window": window, "start_date": start,
                              "end_date": end, "per_model": rows or [],
                              "available": rows is not None})


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
    for need in ("/", "/litellm", "/gpu", "/ollama", "/alerts", "/api/data",
                 "/api/series", "/api/uptime", "/api/keyseries",
                 "/api/keydelta",
                 "/api/procseries", "/api/anomalies", "/api/nav",
                 "/api/litellm/models",
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
