# collectors/litellm.py — LiteLLM proxy metrics via native JSON (NO prometheus).
#
# Endpoints (master key required for the last two):
#   GET /health/liveliness  -> proxy up (no auth)
#   GET /v1/models          -> served model ids
#   GET /health/backlog     -> in-flight request count (queue depth)
#   GET /spend/logs         -> recent request logs w/ startTime/endTime
# NOTE: the deployment-probing GET /health is deliberately NOT used — it fires a
# real request to every model and can freeze a busy/unified-memory box.
#
# "Time waited for the LLM" is derived from /spend/logs timestamps aggregated
# over a rolling window (avg + max ms).
from __future__ import annotations

import asyncio
import math
import re
import time
from datetime import datetime, timedelta, timezone

import aiohttp

import config
import obslog
from collectors import fetch_json, unconfigured

_LLOG = obslog.get("litellm")


def _dbg(msg: str) -> None:
    """Diagnostic line at DEBUG level (shows in `docker logs`). Enable with LITELLM_DEBUG=1 or
    MONITOR_LOG_LEVEL_aimon.litellm=debug. Never touches the returned data."""
    _LLOG.debug(msg)


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {config.LITELLM_MASTER_KEY}"}


_TEAM_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _is_team_id(s) -> bool:
    """True if `s` looks like a raw LiteLLM team_id (UUID) rather than a human team
    alias. Such values must NEVER be surfaced as a team NAME — callers blank them so the
    sticky detection cache keeps the last readable alias instead of a UUID."""
    return bool(s) and bool(_TEAM_ID_RE.match(str(s).strip()))


# ── canonical key IDENTITY (review D-1) ──────────────────────────────────────────────────
# LiteLLM reports a key's identity under many different field names depending on the endpoint:
# `key_alias`/`key_name` on /spend/keys, `alias`/`key` on our own top_keys, `token` on
# /key/list, `api_key` on the raw list. Resolving it a slightly-different way at each call
# site (five divergent inline chains existed) is exactly what broke the recurring by-key /
# by-user attribution: a key STORED under one label (known_keys, spend_model_user_daily,
# key_series) but LOOKED UP by another silently misses the join. `key_label` is THE one
# canonical JOIN key every producer must use so the labels line up. Prefers the human alias,
# falls back to the raw key hash, never empty ("?" only when a row carries no identity at all).
_KEY_ID_FIELDS = ("alias", "key_alias", "key_name", "key", "api_key", "token")
# The identity fields that are UNIQUE per key (hash-class). The rest of _KEY_ID_FIELDS are
# alias-class and can legitimately repeat across keys — `key_name` is `sk-…` + 4 chars, and an
# alias can be reused — so a cross-class match must never be treated as "same key".
STRONG_ID_FIELDS = ("key", "api_key", "token")


def key_ids(k: dict) -> list[str]:
    """EVERY non-empty identity value on a key row, not just the canonical one.

    `key_label` collapses a key to ONE label, but the two sources describe the same key with
    different fields: /key/list often has `key_name` (masked `sk-...9f3c`) while the spend
    snapshot falls back to the full `api_key` hash. Joining on a single label therefore missed,
    which (a) let one key appear TWICE in the budget union — double-counting its spend — and
    (b) stopped the windowed cost map joining budget rows for alias-less keys, so those users
    vanished from the Cost chart. Matching on the id SET makes either representation join."""
    if not isinstance(k, dict):
        return []
    out: list[str] = []
    for f in _KEY_ID_FIELDS:
        v = k.get(f)
        if v:
            s = str(v).strip()
            if s and s not in out:
                out.append(s)
    return out


def key_label(k: dict) -> str:
    """Canonical join label for a key dict from ANY LiteLLM shape (see note above)."""
    if not isinstance(k, dict):
        return "?"
    for f in _KEY_ID_FIELDS:
        v = k.get(f)
        if v:
            return str(v).strip()
    return "?"


def _email_like(s) -> bool:
    """True if `s` looks like an email (LiteLLM shows the user's email in the key's
    'User'/'Created By' columns) — used to prefer it as the user identity."""
    s = str(s or "").strip()
    return "@" in s and "." in s.rsplit("@", 1)[-1]


def _pick_email(*vals) -> str:
    """First email-looking value among the candidates (LiteLLM carries the user email on
    the key row itself: user_email / created_by, and in /user/list). '' if none."""
    for v in vals:
        s = str(v or "").strip()
        if _email_like(s):
            return s
    return ""


# Track LiteLLM auth so a rejected master key is reported CLEARLY and ONCE (not a
# wall of "HTTP 401" debug lines), and so a dead key doesn't get hammered every tick.
_AUTH_BAD = False


def _auth_err(err) -> bool:
    """A 401/403 from LiteLLM means the master key is invalid/expired — an auth
    failure, not a transient outage."""
    return bool(err) and ("401" in str(err) or "403" in str(err))


def _note_auth(base: str, err) -> bool:
    """One-shot, always-on (non-debug) logging on the auth-state transition.
    Returns True while auth is BAD so callers can skip the key-gated calls."""
    global _AUTH_BAD
    if _auth_err(err):
        if not _AUTH_BAD:
            _LLOG.error(f"AUTH FAILED: LiteLLM rejected the master key ({err}) at "
                        f"{base} for the admin/spend endpoints — LITELLM_MASTER_KEY is invalid, "
                        f"expired, or not an admin/master key (proxy calls like /v1/models may "
                        f"still work). Spend / budgets / teams stay empty until a valid master "
                        f"key is set.")
            _AUTH_BAD = True
        return True
    if _AUTH_BAD and err is None:
        _LLOG.info(f"AUTH OK: LiteLLM accepted the master key again ({base}).")
        _AUTH_BAD = False
    return False


def _parse_ts(v) -> float | None:
    """LiteLLM timestamps are ISO-8601 strings or epoch seconds/ms."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return v / 1000.0 if v > 1e12 else float(v)
    if isinstance(v, str):
        s = v.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            try:
                return float(v)
            except ValueError:
                return None
    return None


# LiteLLM /health/backlog returns {"in_flight_requests": N} (verified against
# BerriAI/litellm docs). The rest are tolerant fallbacks for other/older shapes.
_BACKLOG_KEYS = ("in_flight_requests", "in_flight", "backlog", "queue_size",
                 "queue", "pending", "num_requests_in_queue",
                 "requests_in_queue", "in_queue", "size")


def _extract_backlog(data) -> int | None:
    """Pull an integer queue depth out of /health/backlog's response.

    Tolerant of shapes: a bare number, {"backlog": N}, {"queue_size": N}, etc.
    """
    if isinstance(data, (int, float)):
        return int(data)
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for k in _BACKLOG_KEYS:
            v = data.get(k)
            if isinstance(v, (int, float)):
                return int(v)
            if isinstance(v, list):
                return len(v)
    return None


async def _fetch_backlog(session: aiohttp.ClientSession, base: str,
                         headers: dict) -> int | None:
    data, err = await fetch_json(session, f"{base}/health/backlog", headers=headers)
    if err is not None:
        return None
    n = _extract_backlog(data)
    # LiteLLM counts the request MAKING the call (our own /health/backlog probe) as
    # in-flight, so an idle proxy reports a constant 1 — which then floods the by-key
    # attribution's "Other" band on every idle bucket. Subtract that self-probe so
    # backlog reads 0 when truly idle. Disable for a build that excludes the measuring
    # request (MONITOR_LITELLM_BACKLOG_PROBE_SELFCOUNT=0).
    if n is not None and config.LITELLM_BACKLOG_PROBE_SELFCOUNT:
        n = max(0, n - 1)
    return n


def _short_key(kid) -> str:
    s = str(kid or "?")
    return s if len(s) <= 18 else s[:8] + "…" + s[-4:]


def _error_text(row: dict, meta: dict) -> str:
    """Best-effort concise error string from a failed spend-log row.

    LiteLLM's error_information is a dict (error_class/error_message/traceback);
    prefer the class + message, drop the noisy traceback.
    """
    ei = meta.get("error_information")
    if isinstance(ei, dict):
        cls = ei.get("error_class") or ei.get("error_code") or ""
        msg = ei.get("error_message") or ei.get("message") or ""
        combined = f"{cls}: {msg}".strip(": ").strip()
        if combined:
            return combined[:200]
    for v in (row.get("exception"), row.get("error"),
              meta.get("error_str"), meta.get("error"), ei):
        if v:
            return str(v)[:200]
    return str(row.get("status") or "failure")


def _pctile(sorted_vals: list, p: float) -> float:
    """Linear-interpolated percentile of a pre-sorted list (p in 0..100)."""
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    rank = (p / 100.0) * (len(sorted_vals) - 1)
    lo = int(rank)
    frac = rank - lo
    if lo + 1 >= len(sorted_vals):
        return float(sorted_vals[-1])
    return sorted_vals[lo] + (sorted_vals[lo + 1] - sorted_vals[lo]) * frac


def _cache_is_hit(val) -> bool:
    """cache_hit may be a real bool, or the string "None"/"true" (LiteLLM
    serializes it to the spend-logs DB as text). Only real hits count."""
    return val is True or val == 1 or \
        (isinstance(val, str) and val.lower() == "true")


async def sample(session: aiohttp.ClientSession) -> dict:
    if not config.LITELLM_ENABLED:
        return unconfigured()          # monitoring turned off in Settings → Services
    base = config.LITELLM_BASE_URL
    if not base:
        return unconfigured()
    base = base.rstrip("/")

    _, err = await fetch_json(session, f"{base}/health/liveliness")
    if err is not None:
        # liveliness sometimes returns a bare string "I'm alive!" (not JSON) →
        # fetch_json raises a decode error; that IS a reachable proxy, treat as up.
        # But a transport failure (conn refused/DNS = "conn:"), a TIMEOUT, or a 5xx
        # means the proxy is unreachable/overloaded → down. Reporting it "up" here
        # would fire the heavy /spend call at an already-struggling proxy, the exact
        # hammering the circuit-breaker/decoupled-loop redesign exists to prevent.
        if err.startswith("conn") or "Timeout" in err or err.startswith("HTTP 5"):
            return {"available": False, "error": err}

    out: dict = {
        "available": True,
        "models": [],
        "wait_avg_ms": None,
        "wait_max_ms": None,
        "requests_window": 0,
    }

    # /v1/models is auth-gated on a real proxy — send the key when we have it.
    mhdr = _headers() if config.LITELLM_MASTER_KEY else None
    models, merr = await fetch_json(session, f"{base}/v1/models", headers=mhdr)
    if merr is None and models:
        out["models"] = [m.get("id") for m in models.get("data", []) if m.get("id")]
    _dbg(f"/v1/models err={merr} models={len(out['models'])}")

    # A rejected master key (401/403) is an operator problem, not a transient one:
    # log it clearly ONCE and skip the key-gated /spend calls so we stop hammering
    # a proxy that's refusing us.
    if config.LITELLM_MASTER_KEY and _note_auth(base, merr):
        out["error"] = f"master key rejected ({merr}) — check LITELLM_MASTER_KEY"
        out["auth_error"] = True
        return out
    if config.LITELLM_MASTER_KEY and merr is None:
        _note_auth(base, None)          # recovered → clear the bad-auth banner

    if not config.LITELLM_MASTER_KEY:
        out["error"] = "no master key: /spend skipped"
        _dbg("no master key -> /spend/logs skipped")
        return out

    h = _headers()

    # Cheap, every tick: queue backlog (saturation signal, single fast call).
    out["backlog"] = await _fetch_backlog(session, base, h)
    _dbg(f"/health/backlog: in_flight_requests={out['backlog']}")

    # The heavy calls (/health probes every deployment; /spend/logs returns the
    # whole day's logs) are throttled to LITELLM_HEAVY_INTERVAL and their derived
    # fields reused in between — otherwise a busy proxy gets hammered every tick.
    global _HEAVY_TS, _HEAVY
    now = time.time()
    if _HEAVY and (now - _HEAVY_TS) < config.LITELLM_HEAVY_INTERVAL:
        out.update(_HEAVY)
        _dbg(f"heavy cached age={now - _HEAVY_TS:.0f}s "
             f"(interval={config.LITELLM_HEAVY_INTERVAL:.0f}s) -> reused /spend")
        return out

    _HEAVY = await _heavy_sample(session, base, h, now)
    _HEAVY_TS = now
    out.update(_HEAVY)
    return out


# Throttled cache for the two heavy LiteLLM calls: last derived fields + when.
_HEAVY_TS: float = 0.0
_HEAVY: dict = {}


# --- circuit breaker: stop hammering a struggling proxy -----------------------
# When a heavy call keeps timing out, the WORST thing to do is keep calling it —
# each attempt still makes the proxy run the full probe/query, piling load onto
# something already at its limit (that's what froze the proxy). After N failures
# we "open" the breaker: skip the call for a cooldown, then let ONE probe through
# to test recovery. Any success closes it. Purely in-memory, per endpoint.
_CB: dict = {}   # name -> {"fails": int, "until": float}


def _cb_open(name: str, now: float) -> bool:
    st = _CB.get(name)
    return bool(st and now < st["until"])


def _cb_record(name: str, ok: bool, now: float) -> None:
    st = _CB.setdefault(name, {"fails": 0, "until": 0.0})
    if ok:
        st["fails"] = 0
        st["until"] = 0.0
    else:
        st["fails"] += 1
        if st["fails"] >= config.LITELLM_CB_THRESHOLD:
            st["until"] = now + config.LITELLM_CB_COOLDOWN


async def _fetch_spend_raw(session: aiohttp.ClientSession, url: str, headers: dict,
                           timeout_s: float, max_bytes: int) -> tuple[bytes | None, str | None]:
    """Read /spend/logs as raw bytes with a HARD size cap, so a huge day of logs
    is refused BEFORE it's loaded/deserialized (protects memory + event loop).
    Body read is async/chunked; the caller does json.loads off-thread."""
    try:
        timeout = aiohttp.ClientTimeout(total=timeout_s)
        # allow_redirects=False (SSRF guard, matches fetch_json in collectors/__init__): the
        # master-key-authenticated /spend/logs must never chase a 3xx to an attacker-chosen
        # host, which would replay the bearer token off-target. A redirect status is treated
        # as an error below (status != 200).
        async with session.get(url, headers=headers, timeout=timeout,
                               allow_redirects=False) as resp:
            if resp.status != 200:
                return None, f"HTTP {resp.status}"
            if resp.content_length and resp.content_length > max_bytes:
                return None, f"too_big:{resp.content_length}"
            buf = bytearray()
            async for chunk in resp.content.iter_chunked(65536):
                buf += chunk
                if len(buf) > max_bytes:
                    return None, f"too_big:>{max_bytes}"
            return bytes(buf), None
    except aiohttp.ClientError as e:
        return None, f"conn: {type(e).__name__}"
    except Exception as e:  # timeout, etc.
        return None, f"{type(e).__name__}"


def _parse_spend_bytes(raw: bytes, window_start: float,
                       max_rows: int) -> tuple[dict, int, int]:
    """json.loads + shape-normalize + aggregate — ALL off the event loop (this
    runs in a worker thread). Deserializing a multi-MB payload with json.loads is
    synchronous and would otherwise freeze the loop; keep it here."""
    import json
    try:
        logs = json.loads(raw)
    except Exception:
        return {}, 0, 0
    # LiteLLM ships /spend/logs as a bare list or {"data":[...]}. Accept both.
    if isinstance(logs, dict):
        logs = logs.get("data") or logs.get("logs") or []
    if not isinstance(logs, list):
        return {}, 0, 0
    return _parse_spend(logs, window_start, max_rows)


def _parse_backfill_bytes(raw: bytes) -> list[dict]:
    """json.loads + shape-normalize + per-(day,model,key) fold for the one-time spend
    rollup backfill — ALL off the event loop (runs in a worker thread; deserializing a
    multi-day payload would otherwise freeze the loop)."""
    import json
    try:
        logs = json.loads(raw)
    except Exception:
        return []
    if isinstance(logs, dict):
        logs = logs.get("data") or logs.get("logs") or []
    return _fold_model_user(logs) if isinstance(logs, list) else []


def _row_cached_tokens(row: dict) -> int:
    """Cached (prompt-cache read) tokens for a /spend/logs row, tolerant of the several
    shapes LiteLLM/providers emit: a top-level `cache_read_input_tokens`, or nested in
    `prompt_tokens_details.cached_tokens` (OpenAI/Azure usage shape), possibly under
    `metadata`. 0 when none reported. Never counts cache-CREATION tokens (a write, not a
    read) — those are billed as normal input, not the cached meter."""
    def _pick(d: object) -> int:
        if not isinstance(d, dict):
            return 0
        v = d.get("cache_read_input_tokens")
        if v is None:
            det = d.get("prompt_tokens_details")
            if isinstance(det, dict):
                v = det.get("cached_tokens")
        try:
            return max(0, int(v or 0))
        except (TypeError, ValueError):
            return 0
    return _pick(row) or _pick(row.get("metadata"))


def _fold_model_token_types(logs: list, start_epoch: float,
                            end_epoch: float | None = None) -> dict[str, dict]:
    """Aggregate raw /spend/logs rows into per-model token TYPE counts for rows in
    [start_epoch, end_epoch): {model: {"input": uncached-prompt, "cached": prompt-cache-read,
    "output": completion, "total": …}}. Input is prompt MINUS cached (the two are separate
    Azure meters and cached is a subset of prompt), clamped ≥ 0. Pure + sync — runs in the
    parse thread. The monitor's own /health-check pseudo-key is dropped.

    `end_epoch` bounds the top of the window so a per-day pull counts ONLY its own UTC day even
    if the proxy's date filtering is inclusive/local-tz — without it a boundary row could be
    double-counted across two adjacent days' pulls."""
    out: dict[str, dict] = {}
    for row in logs:
        if not isinstance(row, dict):
            continue
        st = _parse_ts(row.get("startTime") or row.get("start_time"))
        if st is None or st < start_epoch or (end_epoch is not None and st >= end_epoch):
            continue
        meta = row.get("metadata")
        meta = meta if isinstance(meta, dict) else {}
        kid = str(row.get("api_key") or meta.get("user_api_key") or "?")
        if _is_health_check_key(kid):
            continue
        alias = str(row.get("key_alias") or row.get("api_key_alias")
                    or meta.get("user_api_key_alias") or "")
        if config.key_excluded(kid, alias):
            continue
        model = str(row.get("model") or row.get("model_name") or "?")
        pt = int(row.get("prompt_tokens", 0) or 0)
        ct = int(row.get("completion_tokens", 0) or 0)
        cached = min(pt, _row_cached_tokens(row))   # cached is a subset of prompt
        e = out.setdefault(model, {"input": 0, "cached": 0, "output": 0, "total": 0})
        e["input"] += max(0, pt - cached)
        e["cached"] += cached
        e["output"] += ct
        e["total"] += pt + ct
    return out


def _parse_token_types_bytes(raw: bytes, start_epoch: float,
                             end_epoch: float | None = None) -> dict[str, dict]:
    """json.loads + shape-normalize + per-model token-type fold — ALL off the event loop
    (runs in a worker thread; deserializing a multi-day payload would freeze the loop)."""
    import json
    try:
        logs = json.loads(raw)
    except Exception:
        return {}
    if isinstance(logs, dict):
        logs = logs.get("data") or logs.get("logs") or []
    return (_fold_model_token_types(logs, start_epoch, end_epoch)
            if isinstance(logs, list) else {})


# Host load-per-core, fed in by the sampling loop each tick (the collector runs
# in its own decoupled loop and has no host data otherwise).
_LOAD_PER_CORE: float = 0.0


def note_load(load_per_core: float) -> None:
    """Called by the sampling loop with the host's 1-min load average / ncpu."""
    global _LOAD_PER_CORE
    _LOAD_PER_CORE = load_per_core


def _load_shed() -> bool:
    """True when the host is saturated enough to auto-drop the heavy LiteLLM calls."""
    return config.LITELLM_LOAD_SHED > 0 and _LOAD_PER_CORE >= config.LITELLM_LOAD_SHED


def _spend_mode() -> str:
    """Effective spend mode: 'off' | 'lite' | 'full'. SPEND_ENABLED=0 forces off."""
    if not config.LITELLM_SPEND_ENABLED:
        return "off"
    m = config.LITELLM_SPEND_MODE
    return m if m in ("full", "lite", "off") else "full"


def _is_health_check_key(*identifiers: object) -> bool:
    """True if any identifier looks like LiteLLM's internal health-check pseudo-key
    (e.g. 'litellm-internal-health-check'). Those rows are LiteLLM probing its own
    deployments — not user traffic — so they are dropped from every per-key surface.
    Single source of truth for the lite (/global/spend/keys) and full (/spend/logs)
    paths, which previously each carried their own copy of this test."""
    for v in identifiers:
        if v is None:
            continue
        if "health-check" in str(v).lower():
            return True
    return False


async def _fetch_top_keys(session: aiohttp.ClientSession, base: str,
                          h: dict) -> tuple[list[dict], str | None]:
    """Per-key CUMULATIVE spend from `/global/spend/keys` — a CHEAP server-side aggregate
    (~200 ms, ~0 CPU), NOT the heavy `/spend/logs` blob that causes the freeze. Returns
    (top_keys, err). Used by lite mode AND the 'off'/load-shed paths so the per-key charts
    (Top keys/users/over-time) stay populated even when the heavy pull is disabled. Honours
    MONITOR_EXCLUDE_KEYS and drops LiteLLM's internal health-check pseudo-key (same rule the
    full-mode /spend/logs parse applies) — it is LiteLLM probing its own deployments, not
    real usage, and it would otherwise occupy a slot in every per-key ranking.
    reqs/tokens are None here (only /spend/logs has per-key requests)."""
    ks, err = await fetch_json(session, f"{base}/global/spend/keys?limit=100",
                               headers=h, timeout_s=config.HTTP_TIMEOUT)
    keys: list[dict] = []
    if err is None and isinstance(ks, list):
        keys = [{
            "key": k.get("api_key", "?"),
            "alias": k.get("key_alias") or k.get("key_name") or "",
            "reqs": None, "tokens": None,
            "cost": round(_fnum(k.get("total_spend")), 4),
        } for k in ks
            if not _is_health_check_key(k.get("api_key"),
                                        k.get("key_alias") or k.get("key_name"))
            and not config.key_excluded(k.get("api_key"),
                                        k.get("key_alias") or k.get("key_name"))]
    return keys, err


# Previous lite-mode daily totals, for differentiating them into per-second RATES.
# Module-level like host._prev_cpu / vllm._prev_tokens: one proxy per monitor instance.
_prev_lite: dict = {"ts": None, "requests": None, "tokens": None}


def _lite_rate(cur, prev, dt: float):
    """Per-second rate from two cumulative day-total readings, or None on the first
    sample and across the UTC-midnight reset (cur < prev — the day-total rolls back to
    ~0). A negative delta would render as a huge bogus spike, so a one-sample gap is
    preferred (same guard as vllm._token_rates)."""
    if cur is None or prev is None or dt <= 0 or cur < prev:
        return None
    return round((cur - prev) / dt, 3)


async def _lite_spend(session: aiohttp.ClientSession, base: str,
                      h: dict, now: float) -> dict:
    """CPU-free spend via LiteLLM's SERVER-SIDE aggregate endpoints — no raw
    /spend/logs pull. Fills requests/tokens/cost/per-model/top-keys (tiny payloads,
    ~0 CPU). Latency percentiles are NOT available here (need raw per-request data);
    they stay None so the dashboard shows them as unavailable in lite mode."""
    out: dict = {"spend_mode": "lite", "spend_window_min": config.LITELLM_SPEND_WINDOW_MIN}
    today = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d")
    tmr = datetime.fromtimestamp(now + 86400, tz=timezone.utc).strftime("%Y-%m-%d")
    t = config.HTTP_TIMEOUT
    # daily totals
    act, e1 = await fetch_json(
        session, f"{base}/global/activity?start_date={today}&end_date={tmr}",
        headers=h, timeout_s=t)
    if e1 is None and isinstance(act, dict):
        out["requests_window"] = int(act.get("sum_api_requests") or 0)
        # /global/activity is queried today->tomorrow, so sum_api_requests is the
        # DAY-TO-DATE total (resets at UTC midnight), NOT a rolling window like the
        # full-mode figure. Declare the basis so the dashboard labels it honestly —
        # rendering a day counter under a "last 15m" badge made an idle proxy look
        # permanently busy (the number just sits at the day's total).
        out["requests_basis"] = "today_utc"
        out["tokens_today"] = int(act.get("sum_total_tokens") or 0)
        # Throughput over-time charts in lite mode: /global/activity gives only the
        # day's RUNNING TOTALS (no per-request rows), so differentiate them into
        # per-second rates across successive polls. Requests/s and total Tokens/s are
        # honest here; prompt/completion SPLIT and latency are NOT available in lite
        # (no per-request data) and stay None. cost/s needs per-day $ (Enterprise) too.
        prev = _prev_lite
        dt = (now - prev["ts"]) if prev["ts"] is not None else 0.0
        rq, tk = out["requests_window"], out["tokens_today"]
        rr = _lite_rate(rq, prev["requests"], dt)
        tr = _lite_rate(tk, prev["tokens"], dt)
        if rr is not None:
            out["req_rate"] = rr
        if tr is not None:
            out["tok_total_rate"] = tr
        prev["ts"], prev["requests"], prev["tokens"] = now, rq, tk
    # per-model requests + tokens
    pm, e2 = await fetch_json(
        session, f"{base}/global/activity/model?start_date={today}&end_date={tmr}",
        headers=h, timeout_s=t)
    if e2 is None and isinstance(pm, list):
        out["per_model"] = [{
            "model": m.get("model", "?"),
            "reqs": int(m.get("sum_api_requests") or 0),
            "tokens": int(m.get("sum_total_tokens") or 0),
            "wait_avg_ms": None, "wait_max_ms": None, "p95_ms": None,
            "slo_pct": None, "cost": None,
        } for m in pm][:20]
    # keys by spend (pre-aggregated). limit=100 (not 10) so the Spend "Cost by key" chart
    # sees EVERY key on the fallback path, not just the top 10.
    out["top_keys"], e3 = await _fetch_top_keys(session, base, h)
    _dbg(f"/spend lite: requests={out.get('requests_window')} "
         f"per_model={len(out.get('per_model', []))} top_keys={len(out.get('top_keys', []))} "
         f"errs=(activity={e1}, per_model={e2}, top_keys={e3})")
    # If every admin/spend call was rejected, say so CLEARLY (once) — a key that
    # lists models but is refused here is not a valid master/admin key.
    _note_auth(base, next((e for e in (e1, e2, e3) if _auth_err(e)), None))
    return out


async def per_model_range(session: aiohttp.ClientSession,
                          start_date: str, end_date: str,
                          kind_overrides: dict | None = None) -> list[dict] | None:
    """Per-model requests + tokens over a [start_date, end_date] day range, via the
    pre-aggregated `/global/activity/model` endpoint (day-granular, ~0 CPU — NOT the
    heavy /spend/logs). This lets the dashboard's Per-model table honor the time
    window (incl. prior days) instead of only the collector's fixed rolling window.

    Returns rows sorted by requests (top 50), or None when LiteLLM is unconfigured
    or the call fails (so the caller can tell 'no data' from 'not available')."""
    base = config.LITELLM_BASE_URL
    if not base or not config.LITELLM_MASTER_KEY:
        return None
    base = base.rstrip("/")
    pm, err = await fetch_json(
        session,
        f"{base}/global/activity/model?start_date={start_date}&end_date={end_date}",
        headers=_headers(), timeout_s=config.HTTP_TIMEOUT)
    if err is not None or not isinstance(pm, list):
        return None
    rows = []
    for m in pm:
        name = m.get("model") or ""
        cls = classify_model(name, kind_overrides)
        rows.append({
            "model": name or "(unattributed)",
            "reqs": int(m.get("sum_api_requests") or 0),
            "tokens": int(m.get("sum_total_tokens") or 0),
            "internal": cls["internal"], "cost_kind": cls["cost_kind"],
            "kind_overridden": cls.get("overridden", False),
        })
    rows.sort(key=lambda r: r["reqs"], reverse=True)
    return rows[:50]


async def per_model_daily_cost(session: aiohttp.ClientSession, start_date: str,
                               end_date: str, prices: dict,
                               kind_overrides: dict | None = None) -> dict | None:
    """Per-DAY real vs reference COST from `/global/activity/model`'s per-model
    `daily_data` — each day's cost uses THAT day's actual model mix × per-model price,
    so an external model's cost lands only on the days it actually ran (not smeared
    across the window by a blended rate). Returns {canonical_date: {"real": $, "est": $}},
    or None when the endpoint gives no per-model daily breakdown (caller then falls back
    to the window-blended estimate)."""
    base = config.LITELLM_BASE_URL
    if not base or not config.LITELLM_MASTER_KEY:
        return None
    base = base.rstrip("/")
    pm, err = await fetch_json(
        session,
        f"{base}/global/activity/model?start_date={start_date}&end_date={end_date}",
        headers=_headers(), timeout_s=config.HTTP_TIMEOUT)
    if err is not None or not isinstance(pm, list):
        return None
    out: dict = {}
    saw_daily = False
    for m in pm:
        if not isinstance(m, dict):
            continue
        name = m.get("model") or ""
        rate = price_for(name, prices)
        kind = classify_model(name, kind_overrides)["cost_kind"]
        if rate <= 0 or kind not in ("real", "reference"):
            continue                       # unpriced or unattributed → contributes no $
        daily = m.get("daily_data") or m.get("daily") or m.get("data") or []
        if not isinstance(daily, list):
            continue
        for dd in daily:
            if not isinstance(dd, dict):
                continue
            date = _norm_date(dd.get("date") or dd.get("day") or dd.get("start_date") or "")
            toks = int(dd.get("total_tokens") or dd.get("sum_total_tokens")
                       or dd.get("tokens") or 0)
            if not date or toks <= 0:
                continue
            saw_daily = True
            b = out.setdefault(date, {"real": 0.0, "est": 0.0})
            b["real" if kind == "real" else "est"] += toks * rate
    return out if saw_daily else None


async def per_model_daily_tokens(session: aiohttp.ClientSession, start_date: str,
                                 end_date: str,
                                 kind_overrides: dict | None = None) -> dict | None:
    """Per-DAY token split by cost kind — EXTERNAL (real/paid) vs INTERNAL (reference/
    self-hosted) — from `/global/activity/model`'s per-model `daily_data`. Returns
    {canonical_date: {"ext": tokens, "int": tokens}}, or None with no per-model daily
    breakdown. Unlike the cost variant this needs NO price: every token counts, priced
    or not (it's a usage split, not a cost split)."""
    base = config.LITELLM_BASE_URL
    if not base or not config.LITELLM_MASTER_KEY:
        return None
    base = base.rstrip("/")
    pm, err = await fetch_json(
        session,
        f"{base}/global/activity/model?start_date={start_date}&end_date={end_date}",
        headers=_headers(), timeout_s=config.HTTP_TIMEOUT)
    if err is not None or not isinstance(pm, list):
        return None
    out: dict = {}
    saw = False
    for m in pm:
        if not isinstance(m, dict):
            continue
        kind = classify_model(m.get("model") or "", kind_overrides)["cost_kind"]
        if kind not in ("real", "reference"):
            continue                       # unattributed / unknown → no usage bucket
        key = "ext" if kind == "real" else "int"
        daily = m.get("daily_data") or m.get("daily") or m.get("data") or []
        if not isinstance(daily, list):
            continue
        for dd in daily:
            if not isinstance(dd, dict):
                continue
            date = _norm_date(dd.get("date") or dd.get("day") or dd.get("start_date") or "")
            toks = int(dd.get("total_tokens") or dd.get("sum_total_tokens")
                       or dd.get("tokens") or 0)
            if not date or toks <= 0:
                continue
            saw = True
            b = out.setdefault(date, {"ext": 0, "int": 0})
            b[key] += toks
    return out if saw else None


async def per_model_daily_series(session: aiohttp.ClientSession, start_date: str,
                                 end_date: str, prices: dict,
                                 kind_overrides: dict | None = None) -> dict | None:
    """Like per_model_daily_cost but WITHOUT collapsing across models — keeps each
    model's per-day cost so the UI can chart cost-per-model over time. Returns
    {"models": [{"model", "kind", "total", "daily": {date: $}} …] sorted by total desc,
    "dates": [sorted union of dates]}, or None when there's no per-model daily data."""
    global _MODEL_SERIES_CACHE
    base = config.LITELLM_BASE_URL
    if not base or not config.LITELLM_MASTER_KEY:
        return None
    base = base.rstrip("/")
    pm, err = await fetch_json(
        session,
        f"{base}/global/activity/model?start_date={start_date}&end_date={end_date}",
        headers=_headers(), timeout_s=config.HTTP_TIMEOUT)
    if err is not None or not isinstance(pm, list):
        # transient failure (timeout / circuit-breaker / bad shape) → serve last-good so
        # the chart persists across the blip instead of vanishing until the next poll
        return dict(_MODEL_SERIES_CACHE) if _MODEL_SERIES_CACHE else None
    models: list = []
    dates: set[str] = set()
    unpriced: set[str] = set()
    saw = False
    n_actual = n_est = 0            # how each day's value was obtained (cash vs estimate)
    for m in pm:
        if not isinstance(m, dict):
            continue
        name = m.get("model") or ""
        rate = price_for(name, prices)
        kind = classify_model(name, kind_overrides)["cost_kind"]
        if kind not in ("real", "reference") or not name:
            continue                       # unattributed → no $ line
        daily = m.get("daily_data") or m.get("daily") or m.get("data") or []
        if not isinstance(daily, list):
            continue
        dmap: dict[str, float] = {}
        for dd in daily:
            if not isinstance(dd, dict):
                continue
            date = _norm_date(dd.get("date") or dd.get("day") or dd.get("start_date") or "")
            if not date:
                continue
            # Prefer LiteLLM's OWN per-model cash when the payload carries it: the
            # headline cost is actual spend, so a tokens x price estimate here would be a
            # parallel number that can never sum to it. Fall back to the estimate only
            # when no real figure is reported.
            val = _num_or_none(dd.get("spend"))
            if val is None:
                val = _num_or_none(dd.get("total_spend"))
            if val is None:
                val = _num_or_none(dd.get("cost"))
            if val is not None:
                n_actual += 1
            else:
                toks = int(dd.get("total_tokens") or dd.get("sum_total_tokens")
                           or dd.get("tokens") or 0)
                # No reported cash AND no known price → we cannot value this day. Skipping
                # is what silently shrank the chart below the real total, so it is counted
                # and surfaced as `unpriced` instead of vanishing.
                if toks <= 0:
                    continue
                if rate <= 0:
                    unpriced.add(name)
                    continue
                val = toks * rate
                n_est += 1
            saw = True
            dmap[date] = dmap.get(date, 0.0) + val
            dates.add(date)
        if dmap:
            models.append({"model": name, "kind": kind,
                           "total": round(sum(dmap.values()), 2),
                           "daily": {d: round(v, 4) for d, v in dmap.items()}})
    if not saw:
        # endpoint answered but priced nothing this poll (momentary empty / mid-reload) →
        # keep the last-good series so the card doesn't blink off; None only before the
        # first-ever success (genuinely no data yet), where hiding is correct
        return dict(_MODEL_SERIES_CACHE) if _MODEL_SERIES_CACHE else None
    models.sort(key=lambda x: -x["total"])
    basis = ("actual" if n_actual and not n_est
             else "estimated" if n_est and not n_actual
             else "mixed" if n_actual and n_est else "none")
    out = {"models": models, "dates": sorted(dates), "cost_basis": basis,
           # models that cost real money but could not be valued — the chart total is
           # short by whatever they spent, and the UI must say so rather than imply
           # the breakdown is complete
           "unpriced": sorted(unpriced)}
    _MODEL_SERIES_CACHE = out          # cache this good series as last-good
    return out


async def model_prices(session: aiohttp.ClientSession) -> dict:
    """{model_name: $/token} from LiteLLM `/model/info` (input+output cost). LiteLLM
    already knows external model prices (that's how it tracks real spend); self-hosted
    models are $0 until the operator sets `input/output_cost_per_token` in model_list.
    Used to ESTIMATE cost from token counts (free tier gives no per-day $)."""
    global _PRICES_CACHE
    base = config.LITELLM_BASE_URL
    if not base or not config.LITELLM_MASTER_KEY:
        return {}
    d, err = await fetch_json(session, f"{base.rstrip('/')}/model/info",
                              headers=_headers(), timeout_s=config.HTTP_TIMEOUT)
    if err is not None:
        return dict(_PRICES_CACHE)        # transient error → reuse last-good prices
    rows = (d.get("data") or d.get("model_list")) if isinstance(d, dict) else d
    out: dict = {}
    for m in rows if isinstance(rows, list) else []:
        if not isinstance(m, dict):
            continue
        lp = m.get("litellm_params") or {}
        info = m.get("model_info") or {}
        name = m.get("model_name") or lp.get("model") or ""
        ic = _fnum(lp.get("input_cost_per_token") or info.get("input_cost_per_token") or 0)
        oc = _fnum(lp.get("output_cost_per_token") or info.get("output_cost_per_token") or 0)
        # Blended per-token rate applied to TOTAL tokens. AVERAGE input+output (not SUM) so a
        # model priced with input==output (a single blended rate the operator set) reads once,
        # not doubled; a model with only one side priced (self-hosted, input-only) keeps that
        # value. Summing here was the "costs show doubled" bug.
        rate = (ic + oc) / 2 if (ic > 0 and oc > 0) else (ic + oc)
        if name and rate > 0:
            out[name] = rate
    if out:
        _PRICES_CACHE = dict(out)         # cache a non-empty result as last-good
        return out
    # endpoint answered but priced nothing (momentary empty / mid-reload) → last-good,
    # so the Cost-over-time card doesn't blink off between polls.
    return dict(_PRICES_CACHE)


async def model_price_detail(session: aiohttp.ClientSession) -> dict:
    """{model: {"in", "out", "cache"}} — the THREE per-type rates (input / output /
    cached-read) in currency per 1M tokens, from LiteLLM `/model/info`. For DISPLAY: the
    Settings model-costs card shows the breakdown instead of the summed blend (which reads
    double). Empty on error / unconfigured. Zeros are kept so an all-unset model still lists."""
    global _DETAIL_CACHE
    base = config.LITELLM_BASE_URL
    if not base or not config.LITELLM_MASTER_KEY:
        return {}
    d, err = await fetch_json(session, f"{base.rstrip('/')}/model/info",
                              headers=_headers(), timeout_s=config.HTTP_TIMEOUT)
    if err is not None:
        return dict(_DETAIL_CACHE)        # transient error → reuse last-good detail
    rows = (d.get("data") or d.get("model_list")) if isinstance(d, dict) else d
    out: dict = {}
    for m in rows if isinstance(rows, list) else []:
        if not isinstance(m, dict):
            continue
        lp = m.get("litellm_params") or {}
        info = m.get("model_info") or {}
        name = m.get("model_name") or lp.get("model") or ""
        if not name:
            continue
        ic = _fnum(lp.get("input_cost_per_token") or info.get("input_cost_per_token") or 0)
        oc = _fnum(lp.get("output_cost_per_token") or info.get("output_cost_per_token") or 0)
        cc = _fnum(lp.get("cache_read_input_token_cost")
                   or info.get("cache_read_input_token_cost") or 0)
        # Keep EVERY model /model/info names — including an all-unset (self-hosted, $0) one, as
        # the docstring promises. This is the RELIABLE model-name source for the Settings card:
        # it comes straight from /model/info on each request, so the board no longer depends on
        # the sampler's volatile /v1/models snapshot (which is absent whenever the latest sample
        # hit a transient error — the "costs only show after a manual Refresh + reload" bug).
        out[name] = {"in": round(ic * 1e6, 4), "out": round(oc * 1e6, 4),
                     "cache": round(cc * 1e6, 4)}
    if out:
        _DETAIL_CACHE = dict(out)         # cache a non-empty result as last-good
        return out
    return dict(_DETAIL_CACHE)            # answered but priced nothing → last-good


def _match_model(model: str, mapping: dict):
    """Look up `model` in `mapping` tolerant of a `provider/` prefix on EITHER side — LiteLLM
    keys the same model with/without a provider prefix across its endpoints (activity reports
    `azure_ai/gpt-5-mini`; model_list / model_info may key it bare, or vice-versa). Returns the
    matched value, or None when no key matches. Single source for price_for()/detail_for() so
    the tolerant-match rule can't drift between them (an exact-only detail_for() once returned
    {} for every model — this is the shared fix)."""
    if not mapping:
        return None
    if model in mapping:
        return mapping[model]
    bare = model.split("/", 1)[1] if "/" in model else model
    for k, v in mapping.items():
        kb = k.split("/", 1)[1] if "/" in k else k
        if k == model or kb == bare or kb == model or k == bare:
            return v
    return None


def price_for(model: str, prices: dict) -> float:
    """$/token for a model name, tolerant of `provider/model` prefixes on either side."""
    v = _match_model(model, prices)
    return v if v is not None else 0.0


def detail_for(model: str, detail: dict) -> dict:
    """The {"in","out","cache"} per-type rate breakdown for a model name, tolerant of
    `provider/model` prefixes exactly like price_for() (same `_match_model` helper)."""
    v = _match_model(model, detail)
    return v if v is not None else {}


def _override_kind(model: str, m: str, overrides: dict | None) -> str | None:
    """An admin per-model cost-kind override ('real'|'reference'), matched tolerant of
    `provider/model` prefixes (exact name, lower-case, or bare model). None if unset."""
    if not overrides:
        return None
    bare = m.split("/", 1)[1] if "/" in m else m
    for cand in (model, m, bare):
        k = overrides.get(cand)
        if k in ("real", "reference"):
            return k
    # also match an override key that differs only by provider prefix
    for ok, kind in overrides.items():
        ol = str(ok).strip().lower()
        if kind in ("real", "reference") and (ol == m or ol == bare
                or (ol.split("/", 1)[1] if "/" in ol else ol) == bare):
            return kind
    return None


def classify_model(model: str | None, overrides: dict | None = None) -> dict:
    """Classify a model as self-hosted (REFERENCE cost, no real cash), external paid
    (REAL spend), or UNKNOWN (no model name reported — must not be counted as either).
    An admin per-model override (Settings page) WINS when present. Otherwise internal
    when: the provider prefix (before '/') is in MONITOR_INTERNAL_PROVIDERS, one of those
    tokens appears in the name, OR the name matches a self-hosted open-weight FAMILY
    (gemma/qwen/mistral/…). A blank/absent model is 'unknown'."""
    m = (model or "").strip().lower()
    if not m:
        return {"internal": None, "provider": "unattributed",
                "cost_kind": "unknown", "overridden": False}
    provider = m.split("/", 1)[0] if "/" in m else ""
    ov = _override_kind(model or "", m, overrides)
    if ov is not None:
        return {"internal": ov == "reference",
                "provider": provider or ("internal" if ov == "reference" else "external"),
                "cost_kind": ov, "overridden": True}
    internal = provider in config.INTERNAL_PROVIDERS
    if not internal and not provider:
        # Name heuristic ONLY for a BARE model name (no provider prefix). When a provider
        # prefix IS present but isn't in INTERNAL_PROVIDERS, the model is external/paid and the
        # open-weight-FAMILY fallback must not reclaim it — e.g. a vendor-hosted, billed
        # `azure_ai/qwen-max` or `openai/mistral-large` is REAL spend, not self-hosted 'qwen'.
        # That substring misclassification silently dropped real cost from budgets + the split.
        internal = (any(tok in m for tok in config.INTERNAL_PROVIDERS)
                    or any(fam in m for fam in config.INTERNAL_MODEL_FAMILIES))
    return {"internal": internal,
            "provider": provider or ("internal" if internal else "external"),
            "cost_kind": "reference" if internal else "real", "overridden": False}


# LiteLLM's daily aggregates vary by version: /global/activity nests its rows under
# `daily_data`, other endpoints use `data`/`results`, and field names differ. Parse
# tolerantly rather than assuming one shape.
_DATE_KEYS = ("date", "day", "group_by_day", "spend_date", "start_date")
_SPEND_KEYS = ("spend", "total_spend", "sum_spend")
_REQ_KEYS = ("api_requests", "sum_api_requests", "total_requests", "requests")
_TOK_KEYS = ("total_tokens", "sum_total_tokens", "tokens")


def _pick(r: dict, keys):
    for k in keys:
        if r.get(k) is not None:
            return r[k]
    return None


def _rows_of(d):
    """The list of daily rows, wherever this LiteLLM version put it."""
    if isinstance(d, list):
        return d
    if isinstance(d, dict):
        for k in ("daily_data", "data", "results", "rows"):
            if isinstance(d.get(k), list):
                return d[k]
    return None


def _num_or_none(raw) -> float | None:
    """float(raw), or None when the field is absent/blank/non-numeric. Used to tell
    'LiteLLM reported no cash for this row' apart from 'it reported 0.00' — the first
    must fall back to a tokens x price estimate, the second is a real zero."""
    if raw is None or raw == "":
        return None
    try:
        v = float(raw)
    except (TypeError, ValueError):
        return None
    return v if math.isfinite(v) else None    # NaN/Inf are not real cash — treat as "no value" (T-18)


def _norm_date(raw) -> str:
    """Normalize any date LiteLLM emits to canonical `YYYY-MM-DD`, or '' if
    unparseable. Handles `2026-07-02`, `2026/07/02`, ISO datetimes, epoch s/ms, and
    LiteLLM's display format `Jul 02` / `July 2` (year assumed = most recent that
    isn't in the future). Normalizing here lets the /global/activity (reqs/tokens)
    and /global/spend/report (spend) rows MERGE by date even when the two endpoints
    format dates differently."""
    import calendar
    import datetime as _dt
    if raw is None or raw == "":
        return ""
    if isinstance(raw, (int, float)) or (isinstance(raw, str)
                                         and str(raw).strip().lstrip("-").isdigit()):
        try:
            n = float(raw)
        except (ValueError, TypeError):
            return ""
        if n > 1e12:
            n /= 1000.0
        try:
            return time.strftime("%Y-%m-%d", time.gmtime(n)) if n > 1e8 else ""
        except (OverflowError, OSError, ValueError):   # out-of-range epoch → treat as junk
            return ""
    s = str(raw).strip()
    iso = s.replace("/", "-").replace("T", " ")[:10]
    try:
        time.strptime(iso, "%Y-%m-%d")
        return iso
    except ValueError:
        pass
    for fmt in ("%b %d", "%B %d"):            # "Jul 02" / "July 2" — no year
        try:
            t = time.strptime(s, fmt)
        except ValueError:
            continue
        now = time.gmtime()
        for y in (now.tm_year, now.tm_year - 1):
            cand = f"{y:04d}-{t.tm_mon:02d}-{t.tm_mday:02d}"
            if calendar.timegm(time.strptime(cand, "%Y-%m-%d")) <= time.time() + 86400:
                return cand
        return f"{now.tm_year:04d}-{t.tm_mon:02d}-{t.tm_mday:02d}"
    try:
        return _dt.datetime.fromisoformat(s.replace("Z", "+00:00")).strftime("%Y-%m-%d")
    except ValueError:
        return ""


def _fnum(v) -> float:
    """Coerce a possibly-string/None/dict spend or count to a FINITE float — never raise.
    A backend returning NaN/Inf must not poison a stored/served number (T-18): non-finite → 0.0."""
    try:
        if isinstance(v, (int, float)):
            n = float(v)
        elif isinstance(v, str):
            n = float(v.replace(",", "").strip() or 0)
        else:
            return 0.0
    except ValueError:
        return 0.0
    return n if math.isfinite(n) else 0.0


def _parse_daily(rows) -> tuple[list[dict], bool]:
    """(parsed rows, whether any row actually carried a spend value). Values are
    coerced defensively — a stray string/None/nested field must never crash the
    Spend page (it used to 500 on unexpected LiteLLM response shapes)."""
    out: list[dict] = []
    has_spend = False
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        dt = _pick(r, _DATE_KEYS)
        if not dt:
            continue
        sp = _pick(r, _SPEND_KEYS)
        if isinstance(sp, (int, float)) or (isinstance(sp, str) and sp.strip()):
            has_spend = True
        out.append({"date": _norm_date(dt) or str(dt)[:10], "spend": _fnum(sp),
                    "requests": int(_fnum(_pick(r, _REQ_KEYS))),
                    "tokens": int(_fnum(_pick(r, _TOK_KEYS)))})
    return out, has_spend


def _spend_report_variants(base: str, start_date: str,
                           end_date: str) -> list[tuple[str, str]]:
    """(label, url) candidates for daily spend. LiteLLM's `/global/spend/report`
    400s on a FUTURE end_date (we pull start..tomorrow for the activity rollup), so
    the primary variant caps end_date to today; the others cover version drift."""
    today = time.strftime("%Y-%m-%d", time.gmtime())
    d30 = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 30 * 86400))
    end = min(end_date, today)      # report rejects a future end_date → HTTP 400
    return [
        ("report_capped", f"{base}/global/spend/report?start_date={start_date}&end_date={end}"),
        ("report_30d", f"{base}/global/spend/report?start_date={d30}&end_date={today}"),
        ("report_raw", f"{base}/global/spend/report?start_date={start_date}&end_date={end_date}"),
        ("spend_report", f"{base}/spend/report?start_date={start_date}&end_date={end}"),
    ]


async def _daily_spend_by_date(session: aiohttp.ClientSession, base: str,
                               start_date: str, end_date: str
                               ) -> tuple[dict, str, list[str]]:
    """First spend-report variant that actually yields spend, as {canonical-date:
    spend}. Returns ({}, "", attempts) when none work (e.g. report 400s on this
    LiteLLM). `attempts` records the outcome of each variant tried, in order
    (stops at the first success) — e.g. ["report_capped:err=400", "report_30d:empty",
    "report_raw:ok"] — so a terminal `via=none` is explainable instead of opaque."""
    attempts: list[str] = []
    for label, url in _spend_report_variants(base, start_date, end_date):
        d, err = await fetch_json(session, url, headers=_headers(),
                                  timeout_s=config.HTTP_TIMEOUT)
        if err is not None:
            attempts.append(f"{label}:err={err}")
            continue
        rep, rep_spend = _parse_daily(_rows_of(d) or [])
        if rep_spend:
            attempts.append(f"{label}:ok")
            return {r["date"]: r["spend"] for r in rep}, label, attempts
        attempts.append(f"{label}:empty")
    return {}, "", attempts


async def spend_report_probe(session: aiohttp.ClientSession,
                             start_date: str, end_date: str) -> dict:
    """Diagnostics only: try each spend-report variant and report status/shape, so an
    all-zero Spend chart is explainable from the browser (does ANY variant return
    spend, and in what date format?). Viewer-safe: the operator's own aggregate spend."""
    base = config.LITELLM_BASE_URL
    if not base or not config.LITELLM_MASTER_KEY:
        return {"configured": False}
    base = base.rstrip("/")
    today = time.strftime("%Y-%m-%d", time.gmtime())
    # runtime variants + extra diagnostic endpoints: is ANY daily-spend source alive?
    extra = [
        ("activity_model", f"{base}/global/activity/model?start_date={start_date}&end_date={today}"),
        ("spend_tags", f"{base}/global/spend/tags?start_date={start_date}&end_date={today}"),
        ("report_nodate", f"{base}/global/spend/report"),
        ("spend_keys", f"{base}/global/spend/keys?start_date={start_date}&end_date={today}"),
    ]
    async def _err_body(url: str) -> str:
        """Raw status + body snippet for a failing endpoint — fetch_json hides the
        body behind 'HTTP 400', but LiteLLM's 400 body says WHY (missing param vs
        spend-logs-disabled), which decides if the empty chart is fixable."""
        try:
            async with session.get(url, headers=_headers(), allow_redirects=False,
                                   timeout=aiohttp.ClientTimeout(total=config.HTTP_TIMEOUT)) as r:
                # Byte-cap the error-body read (T-23): only ~4 KiB is needed for the 280-char
                # diagnostic, so never pull a multi-GB 4xx body into memory before slicing.
                snippet = (await r.content.read(4096)).decode("utf-8", "replace")
                return f"HTTP {r.status}: {snippet[:280]}"
        except Exception as e:      # noqa: BLE001 — diagnostics must never raise
            return f"{type(e).__name__}"

    attempts: list[dict[str, object]] = []
    for label, url in list(_spend_report_variants(base, start_date, end_date)) + extra:
        d, err = await fetch_json(session, url, headers=_headers(),
                                  timeout_s=config.HTTP_TIMEOUT)
        path = url.split("?", 1)[0].split("/global/", 1)[-1]
        if err is not None:
            row: dict[str, object] = {"try": label, "path": path, "error": err}
            if err.startswith("HTTP 4"):        # capture the body that explains the 4xx
                row["body"] = await _err_body(url)
            attempts.append(row)
            continue
        rows = _rows_of(d) or []
        parsed, has_spend = _parse_daily(rows if isinstance(rows, list) else [])
        attempts.append({"try": label, "path": path,
                         "top_keys": list(d.keys())[:8] if isinstance(d, dict) else type(d).__name__,
                         "rows": len(rows) if isinstance(rows, list) else 0,
                         "has_spend": has_spend, "sample": parsed[:2]})
    # Raw /global/activity first row — reveals whether a spend field is present under a
    # key our parser doesn't cover (some LiteLLM versions ship spend on activity itself).
    act, aerr = await fetch_json(session, f"{base}/global/activity?start_date={start_date}"
                                 f"&end_date={today}", headers=_headers(),
                                 timeout_s=config.HTTP_TIMEOUT)
    raw = _rows_of(act) if aerr is None else None
    activity_raw = (raw[0] if isinstance(raw, list) and raw
                    else {"error": aerr} if aerr else {"shape": type(act).__name__})
    return {"configured": True, "attempts": attempts, "activity_first_row": activity_raw}


async def spend_activity(session: aiohttp.ClientSession,
                         start_date: str, end_date: str) -> list[dict] | None:
    """Daily spend / requests / tokens over a date range from LiteLLM's cheap daily
    aggregates (never /spend/logs). Reads `/global/activity`; when that carries no
    spend figures (common — it reports requests + tokens only), daily spend is
    merged in from `/global/spend/report`. Returns [{date, spend, requests, tokens}]
    sorted by date, or None when unconfigured / nothing usable came back."""
    base = config.LITELLM_BASE_URL
    if not base or not config.LITELLM_MASTER_KEY:
        return None
    base = base.rstrip("/")
    rng = f"start_date={start_date}&end_date={end_date}"
    daily: list[dict] = []
    has_spend = False

    d, err = await fetch_json(session, f"{base}/global/activity?{rng}",
                              headers=_headers(), timeout_s=config.HTTP_TIMEOUT)
    if err is None:
        daily, has_spend = _parse_daily(_rows_of(d))
    _dbg(f"/global/activity err={err} rows={len(daily)} has_spend={has_spend}")

    if not daily or not has_spend:
        by_date, src, attempts = await _daily_spend_by_date(session, base, start_date, end_date)
        _dbg(f"daily spend via={src or 'none'} dates={len(by_date)} tried={attempts}")
        if by_date and daily:                   # merge report spend into activity rows
            for r in daily:
                if r["date"] in by_date:
                    r["spend"] = by_date[r["date"]]
            has_spend = True
        elif by_date:                           # no activity rows — synthesize from spend
            daily = [{"date": d0, "spend": s, "requests": 0, "tokens": 0}
                     for d0, s in by_date.items()]
            has_spend = True

    if not daily:
        return None
    daily.sort(key=lambda r: str(r["date"]))
    return daily


_KEY_LIST_ERR: str | None = None
_KEY_BUDGETS_CACHE: dict | None = None  # last good /key/list result
_KEY_BUDGETS_TS = 0.0                    # when the last good walk completed (short-TTL coalesce)
_KEY_BUDGETS_TTL = 30.0                  # serve the cached walk to concurrent callers within this
# last good (by_team_id→alias, by_user_id→team_alias, by_user_id→user_name) maps
_TEAM_DIR_CACHE: tuple[dict, dict, dict] = ({}, {}, {})
_PRICES_CACHE: dict = {}  # last good /model/info {model: $/token} — prices are stable
_DETAIL_CACHE: dict = {}  # last good /model/info {model: {in,out,cache}} — the Settings card's
#                           reliable model-name + per-type source (see model_price_detail)
                          # config, so reuse them when the endpoint blips empty (else
                          # cost=0 → the Spend "Cost over time" card flickers off)
# Last good per-model daily series (the Spend "Cost per model over time" chart). The
# chart hides on an empty payload, so a single transient /global/activity/model failure
# (timeout, circuit-breaker cooldown, mid-reload) made the WHOLE card blink off between
# polls. Reuse the last-good series across a blip — same rule as _PRICES_CACHE above.
_MODEL_SERIES_CACHE: dict | None = None


async def _paginate(session: aiohttp.ClientSession, url: str, root_keys: tuple,
                    id_key: str, timeout_s: float) -> list:
    """Walk a paginated LiteLLM list endpoint, tolerant of the server capping the page
    BELOW the requested size (its default is small — a full small page is NOT the last
    page). Prefers the server's total_pages/total_count; else walks until a short page.
    De-dupes by `id_key` and STOPS when a page adds nothing new, so an endpoint that
    ignores `page=` (returns the same list every time) can't loop. [] on error."""
    out: list = []
    seen: set = set()
    page = 1
    eff: int | None = None
    while page <= 50:
        sep = "&" if "?" in url else "?"
        # page_size=100, NOT 500 — LiteLLM's /user/list rejects a large page_size with
        # HTTP 422, which silently emptied the user→email map (so no emails on the board).
        # 100 is accepted by both /user/list and /key/list; the walker fetches all pages.
        d, err = await fetch_json(session, f"{url}{sep}page={page}&size=100&page_size=100",
                                  headers=_headers(), timeout_s=timeout_s)
        if err is not None:
            break
        rows = None
        if isinstance(d, dict):
            for rk in root_keys:
                if isinstance(d.get(rk), list):
                    rows = d[rk]
                    break
        elif isinstance(d, list):
            rows = d
        if not rows:
            break
        added = 0
        for r in rows:
            rid = str(r.get(id_key)) if isinstance(r, dict) else str(r)
            if rid in seen:
                continue
            seen.add(rid)
            out.append(r)
            added += 1
        if added == 0:                     # page brought nothing new → endpoint ignores page=
            break
        total_pages = (d.get("total_pages") if isinstance(d, dict) else 0) or 0
        total_count = ((d.get("total_count") or d.get("total"))
                       if isinstance(d, dict) else 0) or 0
        if eff is None:
            eff = len(rows)
        if total_pages:
            if page >= total_pages:
                break
        elif total_count:
            if len(out) >= total_count:
                break
        elif len(rows) < (eff or 1):
            break
        page += 1
    return out


async def _team_directory(session: aiohttp.ClientSession,
                          base: str) -> tuple[dict, dict, dict]:
    """Team lookups so a key's team can be resolved via its USER when the key
    itself carries no team (LiteLLM often attaches the team to the user, not the
    key). Returns (by_team_id, by_user_id) → {id: team_alias}. Best-effort: empty
    on older/OSS LiteLLM or missing master-key scope, so resolution degrades to the
    key's own team."""
    by_id: dict[str, str] = {}
    by_user: dict[str, str] = {}
    by_user_name: dict[str, str] = {}       # user_id → human name (email/alias) for the board
    tl, err = await fetch_json(session, f"{base}/team/list",
                               headers=_headers(), timeout_s=max(config.HTTP_TIMEOUT, config.LITELLM_SPEND_TIMEOUT))
    teams = (tl.get("teams") if isinstance(tl, dict) else tl) if err is None else None
    if isinstance(teams, list):
        for t in teams:
            if not isinstance(t, dict):
                continue
            tid = str(t.get("team_id") or "")
            # ONLY a real human alias — never the team_id itself, or the board shows UUIDs.
            alias = str(t.get("team_alias") or "").strip()
            if tid and alias:
                by_id[tid] = alias
            if not alias:
                continue
            members = t.get("members_with_roles") or t.get("members") or []
            for m in members if isinstance(members, list) else []:
                uid = (m.get("user_id") if isinstance(m, dict) else m) or ""
                if uid:
                    by_user.setdefault(str(uid), alias)
    # /user/list as a secondary source (a user's own team membership). Paginated — a
    # single page silently drops every user past the server's page cap, so keys owned
    # by those users can't resolve their team.
    to = max(config.HTTP_TIMEOUT, config.LITELLM_SPEND_TIMEOUT)
    users = await _paginate(session, f"{base}/user/list", ("users", "data"), "user_id", to)
    for u in users:
        if not isinstance(u, dict):
            continue
        uid = str(u.get("user_id") or "")
        if not uid:
            continue
        _um = u.get("metadata")
        umeta = _um if isinstance(_um, dict) else {}
        name = str(u.get("user_email") or u.get("email") or u.get("user_alias")
                   or u.get("alias") or umeta.get("user_email") or "").strip()
        if name and not _is_team_id(name):    # user_id → human name for the board grouping
            by_user_name[uid] = name
        if uid in by_user:
            continue
        tms = u.get("teams") or []
        first = tms[0] if isinstance(tms, list) and tms else None
        if isinstance(first, dict):
            a = str(first.get("team_alias") or "").strip()   # alias only, never the id
            if a:
                by_user[uid] = a
        elif first:
            a = by_id.get(str(first), "")                     # resolve id→alias; blank if unknown
            if a:
                by_user[uid] = a
    # Reuse the last-good directory when /team/list (or /user/list) momentarily fails —
    # otherwise a transient blip empties the alias map and every team renders as a UUID.
    global _TEAM_DIR_CACHE
    cid, cuser, cname = _TEAM_DIR_CACHE
    if not by_id and cid:
        by_id = dict(cid)
    if not by_user and cuser:
        by_user = dict(cuser)
    if not by_user_name and cname:
        by_user_name = dict(cname)
    if by_id or by_user or by_user_name:
        _TEAM_DIR_CACHE = (dict(by_id), dict(by_user), dict(by_user_name))
    _dbg(f"/team directory: teams={len(by_id)} users_mapped={len(by_user)} "
         f"(via /team/list) names={len(by_user_name)} (via /user/list, independent "
         f"paginated walk — can differ from teams/users_mapped even when they're stuck at 0)")
    return by_id, by_user, by_user_name


async def key_budgets(session: aiohttp.ClientSession) -> dict | None:
    """Per-key `max_budget` + `spend` straight from LiteLLM's key-management API
    (`/key/list`, master-key only). Returns {alias: {budget, spend, team, user}} —
    budget is 0 when the key has no `max_budget`. The team is resolved key →
    team_id → USER (LiteLLM often puts the team on the user, not the key). None when
    LiteLLM is unconfigured or the endpoint is unavailable, so the caller can fall back."""
    global _KEY_LIST_ERR, _KEY_BUDGETS_CACHE, _KEY_BUDGETS_TS
    base = config.LITELLM_BASE_URL
    if not base or not config.LITELLM_MASTER_KEY:
        _KEY_LIST_ERR = "LiteLLM base URL or master key not set"
        return None
    base = base.rstrip("/")
    # Single-flight-ish coalesce: this ~100-page management walk is invoked by the sampler AND
    # concurrently by 3 dashboard handlers (budgets/teams/keys). Without this, N dashboard
    # refreshes each re-walk /key/list+/team/list+/user/list at once and can clobber the shared
    # cache mid-flight. Serve the last good result to any caller within _KEY_BUDGETS_TTL of it.
    if _KEY_BUDGETS_CACHE is not None and time.time() - _KEY_BUDGETS_TS < _KEY_BUDGETS_TTL:
        return _KEY_BUDGETS_CACHE
    # /key/list?return_full_object=true is a HEAVY management call — give it the
    # spend timeout, not the 4s per-collector one, or a busy LiteLLM (why
    # spend_mode=lite is common) times it out and every key silently loses its
    # team/budget. Retry with page_size= for older LiteLLM.
    to = max(config.HTTP_TIMEOUT, config.LITELLM_SPEND_TIMEOUT)
    # Paginate /key/list — LiteLLM caps each page (often ~10-50), so a single call
    # returns only the first page and every other key falls back to the spend
    # snapshot WITHOUT a team. Walk all pages so every key keeps its team/budget.
    rows: list = []
    page = 1
    eff_size: int | None = None   # server's ACTUAL page size (LiteLLM caps ~10, ignoring size=)
    truncated = False             # a later page failed → rows is only a PARTIAL set
    expected = 0                  # server-reported total_count, if any (completeness check)
    while page <= 50:
        q = f"return_full_object=true&page={page}&size=100"
        d, err = await fetch_json(session, f"{base}/key/list?{q}",
                                  headers=_headers(), timeout_s=to)
        if err is not None and page == 1:      # older LiteLLM uses page_size
            d, err = await fetch_json(
                session, f"{base}/key/list?return_full_object=true&page={page}&page_size=100",
                headers=_headers(), timeout_s=to)
        if err is not None:
            if page == 1:
                prev = _KEY_LIST_ERR
                _KEY_LIST_ERR = f"/key/list failed: {err}"
                # A 403/401 HERE is a SCOPE limit on LiteLLM's key-management API, NOT a
                # dead master key: /v1/models, /global/spend/keys and /global/activity all
                # still work with the same key (so spend, teams and cost keep flowing).
                # Do NOT flag global auth as failed — only per-key budget CAPS fall back
                # to MONITOR_KEY_BUDGETS. Log once per error-state change, not every poll.
                if prev != _KEY_LIST_ERR:
                    if _auth_err(err):
                        # 403/401 = the key lacks key-management scope. Benign: spend/teams/cost
                        # all keep flowing; only per-key budget CAPS fall back. INFO, not WARNING.
                        _LLOG.info("/key/list scope-limited — spend/teams/cost unaffected; "
                                   "per-key budgets use MONITOR_KEY_BUDGETS", extra={"err": str(err)})
                    else:
                        # Real transport/parse/5xx failure (e.g. a JSONDecodeError) → budgets are
                        # degraded. WARNING; deduped so a persistent outage is one line/window.
                        _LLOG.warning("/key/list failed — per-key budgets degraded",
                                      extra={"err": str(err),
                                             "fallback": "cache" if _KEY_BUDGETS_CACHE
                                             else "MONITOR_KEY_BUDGETS"})
                # Feed the private key_list breaker the LIVE outcome (a fast scope-limit 403 is
                # NOT the struggling/slow API the breaker guards, so only a real transport/5xx
                # failure trips it). Recorded HERE, not from the caller's memoized return value —
                # a cache-fallback return would otherwise read as "success" and never open it.
                if not _auth_err(err):
                    _cb_record("key_list", False, time.time())
                return _KEY_BUDGETS_CACHE
            truncated = True                    # page>1 failed → we have only a partial set
            break
        pg = (d.get("keys") or d.get("data")) if isinstance(d, dict) else d
        if not isinstance(pg, list) or not pg:
            break
        rows.extend(pg)
        # Stop tolerant of LiteLLM capping the page BELOW our size= (its default is ~10,
        # so a page of 10 is FULL, not the last page). Prefer the server's own totals;
        # else walk until a page shorter than the observed page size. The old `len<100`
        # test broke after page 1 whenever the server capped <100 — dropping every key
        # past the first page to the team-less spend snapshot.
        total_pages = (d.get("total_pages") if isinstance(d, dict) else 0) or 0
        total_count = ((d.get("total_count") or d.get("total")) if isinstance(d, dict) else 0) or 0
        expected = max(expected, int(total_count or 0))
        if eff_size is None:
            eff_size = len(pg)
        if total_pages:
            if page >= total_pages:
                break
        elif total_count:
            if len(rows) >= total_count:
                break
        elif len(pg) < (eff_size or 1):         # short page = last page
            break
        page += 1
    _KEY_LIST_ERR = None
    if not rows:
        return _KEY_BUDGETS_CACHE
    # Resolve a key's team through team_id and (if the key has none) its user,
    # since LiteLLM commonly attaches the team to the user, and /key/list may carry
    # only a team_id UUID rather than the human alias shown in the LiteLLM UI.
    by_id, by_user, by_user_name = await _team_directory(session, base)
    out: dict = {}
    for k in rows:
        if not isinstance(k, dict):
            continue
        alias = key_label(k)                 # D-1: canonical join label (was a local chain)
        ids = key_ids(k)                     # every identity, so the merge can join either shape
        if alias == "?":
            continue                         # a row with no identity at all — skip, as before
        # Owner user-id can live on ANY of several fields: `user_id` (owner), `created_by`
        # (a user_id string), the nested `created_by_user` object, or `user`. LiteLLM's
        # /key/list commonly leaves `user_id` NULL while the owner is only on created_by /
        # created_by_user — so gather every candidate and resolve against the /user/list
        # directory (by_user_name: user_id → email), not just `user_id`. (Was: keys with a
        # created_by-only owner all fell into "Unassigned".)
        _cbu = k.get("created_by_user")
        cbu = _cbu if isinstance(_cbu, dict) else {}
        id_cands = [c for c in (str(k.get("user_id") or ""), str(k.get("created_by") or ""),
                                str(cbu.get("user_id") or ""), str(k.get("user") or "")) if c]
        # grouping uid = the first candidate the directory can name, else the first non-empty
        uid = next((c for c in id_cands if by_user_name.get(c)),
                   id_cands[0] if id_cands else "")
        team = str(k.get("team_alias") or "").strip()
        if not team:
            tid = str(k.get("team_id") or "")
            team = by_id.get(tid, "") if tid else ""       # team_id → alias, BLANK if unknown
        if not team and uid:
            team = by_user.get(uid, "")                    # else via the user's team
        if _is_team_id(team):                              # never surface a raw UUID as a name
            team = ""
        # user's EMAIL — off the key row (user_email / created_by / the nested created_by_user
        # object) or the /user/list directory keyed by ANY candidate id. Prefer an email.
        _km = k.get("metadata")
        meta = _km if isinstance(_km, dict) else {}
        # OWNER precedence: the key's own user_email fields, then the directory-resolved email
        # for its owner id (user_id first in id_cands), and ONLY THEN the creator's email
        # (nested created_by_user). A key an admin provisions FOR a user carries the admin on
        # created_by_user — ranking it above the owner mislabelled every such key with the
        # creator's name on the by-user charts. It stays a fallback for the user_id-NULL case.
        uname = _pick_email(k.get("user_email"), k.get("litellm_user_email"),
                            meta.get("user_email"),
                            *(by_user_name.get(c, "") for c in id_cands),
                            cbu.get("user_email"),
                            k.get("created_by"), k.get("user"))
        if not uname:                                      # no email → any readable name
            uname = str(by_user_name.get(uid, "") or cbu.get("user_alias")
                        or k.get("user_alias") or "").strip()
        if _is_team_id(uname):                             # user_id-looking name → not a name
            uname = ""
        out[str(alias)] = {
            "budget": _fnum(k.get("max_budget")),
            "spend": _fnum(k.get("spend")),
            "team": team,
            "user": uid,
            "user_name": uname,                            # user_id → email/alias for grouping
            "ids": ids,                                    # every identity, for a shape-proof join
            # The HASH-class subset, kept separate: only these may match across fields when
            # deduping (an alias-class value like the masked key_name repeats across keys).
            "ids_strong": [str(k.get(f)) for f in STRONG_ID_FIELDS if k.get(f)],
        }
    _dbg(f"/key/list keys={len(out)} budgeted={sum(1 for v in out.values() if v['budget'])} "
         f"teamed={sum(1 for v in out.values() if v['team'])}")
    # A PARTIAL walk (a later page timed out, or we got fewer keys than the server's
    # reported total) must NOT shrink the board or poison the cache — that's the
    # "top spenders sometimes disappear" flicker. Keep the fuller last-good set instead.
    cache = _KEY_BUDGETS_CACHE or {}
    incomplete = truncated or (expected and len(out) < expected)
    if out and incomplete and len(out) < len(cache):
        _KEY_LIST_ERR = (f"/key/list partial: {len(out)} keys"
                         + (f"/{expected}" if expected else "")
                         + f" (page failed mid-walk) — reused {len(cache)}-key cache")
        _LLOG.warning("/key/list partial — kept fuller cache",
                      extra={"keys": len(out), "expected": expected or "?", "cached": len(cache)})
        return cache
    if out and not (incomplete and len(out) < len(cache)):
        _KEY_BUDGETS_CACHE = out
        _KEY_BUDGETS_TS = time.time()     # start the coalesce window from this good walk
        _cb_record("key_list", True, _KEY_BUDGETS_TS)   # live walk succeeded → reset the breaker
    return out or _KEY_BUDGETS_CACHE


async def keys_diag(session: aiohttp.ClientSession) -> dict:
    """Diagnostic: what do /key/list and /user/list actually return, and WHERE is the user
    email? Reports each endpoint's field names + which fields hold an EMAIL-like value
    (values REDACTED to first 2 chars + domain). Admin-only; used to wire the user-email
    display when it doesn't show up."""
    base = config.LITELLM_BASE_URL
    if not base or not config.LITELLM_MASTER_KEY:
        return {"available": False, "error": "LiteLLM base URL or master key not set"}
    base = base.rstrip("/")
    to = max(config.HTTP_TIMEOUT, config.LITELLM_SPEND_TIMEOUT)

    def _redact(v):
        s = str(v or "")
        if _email_like(s):
            u, _, dom = s.partition("@")
            return (u[:2] + "…@" + dom)
        return (s[:6] + "…") if len(s) > 8 else s

    _OWNER_IDS = ("user_id", "created_by", "user", "created_by_user", "end_user_id")

    def _probe(rows, n=5):
        rows = rows if isinstance(rows, list) else []
        if not rows:
            return {"count": 0}
        first = rows[0] if isinstance(rows[0], dict) else {}
        emf, per = set(), []
        for r in rows[:n]:
            if not isinstance(r, dict):
                continue
            ef = [f for f, v in r.items() if _email_like(v)]
            # also scan NESTED objects (e.g. created_by_user) — LiteLLM tucks the owner email
            # there, and a top-level-only scan (and the resolver) would miss it.
            nested = {}
            for f, v in r.items():
                if isinstance(v, dict):
                    ne = {k2: _redact(v2) for k2, v2 in v.items() if _email_like(v2)}
                    if ne:
                        nested[f] = ne
            emf.update(ef)
            # which owner-id fields are POPULATED (redacted) — shows where the owner actually is
            owner_ids = {f: _redact(r.get(f)) for f in _OWNER_IDS
                         if r.get(f) not in (None, "", {})}
            per.append({"ref": r.get("key_alias") or r.get("key_name") or r.get("user_id"),
                        "email_fields": ef,
                        "email_samples": {f: _redact(r.get(f)) for f in ef},
                        "nested_emails": nested,
                        "owner_ids": owner_ids})
        return {"count": len(rows), "fields": sorted(first.keys()),
                "email_fields_found": sorted(emf), "per_row": per}

    out: dict = {"available": True}
    kd, kerr = await fetch_json(
        session, f"{base}/key/list?return_full_object=true&page=1&size=5",
        headers=_headers(), timeout_s=to)
    out["key_list"] = ({"error": str(kerr)} if kerr is not None else
                       _probe((kd.get("keys") or kd.get("data")) if isinstance(kd, dict) else kd))
    ud, uerr = await fetch_json(
        session, f"{base}/user/list?page=1&page_size=5&size=5",
        headers=_headers(), timeout_s=to)
    out["user_list"] = ({"error": str(uerr)} if uerr is not None else
                        _probe((ud.get("users") or ud.get("data")) if isinstance(ud, dict) else ud))
    return out


def budget_rows(top_keys, budget_map, month_day: int, month_len: int) -> list[dict]:
    """Per-key budget rows from the snapshot's top_keys + a {alias: max_budget} map.
    Computes % used, $/day burn, days-to-cap, projected month-end spend, and a
    good/warn/critical status, ranked closest-to-cap first. A key with no budget in
    the map is skipped (real max_budget comes from LiteLLM /key/info)."""
    rows = []
    day = max(1, int(month_day))
    for k in top_keys or []:
        alias = key_label(k)                 # D-1: canonical join label
        total = _fnum(k.get("cost") or k.get("total_spend") or k.get("spend"))
        # Budgets cap REAL cash. A key can mix external (real) + self-hosted
        # (reference) usage; only the real portion counts against the budget.
        if "real" in k:
            real = float(k.get("real") or 0)
            ref = float(k["reference"] if k.get("reference") is not None
                        else total - real)
        else:
            real, ref = total, 0.0
        budget = float((budget_map or {}).get(alias) or k.get("budget") or 0)
        # `spend` and the cap must cover the same period. LiteLLM resets a key's spend
        # only when it carries budget_duration/budget_reset_at; otherwise BOTH the spend
        # and its max_budget are lifetime, and comparing them is correct (over the
        # lifetime cap is a real condition). What is NOT valid without a reset is the
        # MONTHLY framing: projecting an all-time total to "month-end", or dividing it by
        # the day of the month to get a $/day burn. Those are period figures, so they are
        # only produced for keys that actually have a period.
        resets = bool(k.get("budget_duration") or k.get("budget_reset_at"))
        burn: float | None = None
        projected: float | None = None
        pct: float | None = None
        days: float | None = None
        status = "none"      # no budget defined — still listed, just no cap maths
        cap_basis = None
        if budget > 0:
            cap_basis = "window" if resets else "lifetime"
            pct = real / budget * 100            # same period on both sides → valid
            if resets:
                burn = real / day
                projected = burn * month_len
                remaining = budget - real
                days = (remaining / burn) if burn > 0 else 999.0
            # near/over the cap now = critical; merely on pace to exceed = warning
            # (the pace test only applies where a projection exists)
            status = ("bad" if pct >= 90
                      else "warn" if pct >= 70 or (projected is not None
                                                   and projected > budget)
                      else "ok")
        rows.append({
            "key": str(alias), "role": k.get("role", "viewer"),
            # every identity for this key, so the client's windowed-cost lookup can join
            # whichever representation the cost map used (masked key_name vs full hash)
            "ids": [str(i) for i in (k.get("ids") or key_ids(k)) if i] or [str(alias)],
            "team": k.get("team") or "",
            "email": k.get("user_name") or "",   # resolved owner email/alias
            "user": k.get("user") or "",         # LiteLLM user id (the "ID" in details)
            "spent": round(real, 2),            # real cash — counts against budget
            "reference": round(ref, 2),         # self-hosted — informational only
            "total": round(real + ref, 2),
            "budget": round(budget, 2) if budget > 0 else None,
            "pct": round(pct, 1) if pct is not None else None,
            "burn": round(burn, 2) if burn is not None else None,
            "days_to_cap": round(days, 1) if days is not None else None,
            "projected": round(projected, 2) if projected is not None else None,
            "status": status,
            # "window"   → spend resets with the budget, cap maths shown
            # "lifetime" → budget set but spend is all-time, so no % / projection
            # None       → no budget defined
            "cap_basis": cap_basis,
        })
    # A key with no budget gets an IMPLIED baseline = the month's TOP SPENDER, purely
    # so its bar renders and is comparable to the others. It is NOT a budget: status
    # stays "none", there is no cap maths, and it never triggers an alert.
    top_spend = max((r["spent"] for r in rows), default=0.0)
    if top_spend > 0:
        for r in rows:
            if r["status"] == "none":
                r["implied_budget"] = round(top_spend, 2)
                r["implied_pct"] = round(r["spent"] / top_spend * 100, 1)
    # critical → watch → on-track → unbudgeted (those ranked by spend)
    order = {"bad": 0, "warn": 1, "ok": 2, "none": 3}
    rows.sort(key=lambda r: (order[r["status"]], -(r["pct"] or 0), -r["spent"]))
    return rows


async def _heavy_sample(session: aiohttp.ClientSession, base: str,
                        h: dict, now: float) -> dict:
    """Expensive half of the LiteLLM sample — the /spend/logs pull (whole-day
    payload), behind a circuit breaker + mode/load-shed gates, with JSON
    deserialization off the event loop and a response size cap. Returns the derived
    fields; sample() caches this between LITELLM_HEAVY_INTERVAL."""
    hv: dict = {"wait_avg_ms": None, "wait_max_ms": None, "requests_window": 0}
    window_start = now - config.LITELLM_SPEND_WINDOW_MIN * 60
    start_iso = datetime.fromtimestamp(window_start, tz=timezone.utc).strftime("%Y-%m-%d")

    async def _do_spend() -> None:
        mode = _spend_mode()
        if _cb_open("spend", now):
            _dbg("/spend skipped — circuit breaker OPEN (repeated failures)")
            return
        if mode == "off":
            # 'off' disables the HEAVY /spend/logs pull (the freeze source) — but the
            # per-key spend LIST comes from /global/spend/keys, a cheap aggregate that
            # never caused the freeze. Still fetch it so Top-keys/users/over-time stay
            # populated at ~0 CPU. No latency/cost-per-request (those need the raw logs).
            try:
                hv["top_keys"], ke = await _fetch_top_keys(session, base, h)
                _cb_record("spend", ke is None, now)
                _dbg(f"/spend off: cheap keys-only -> top_keys={len(hv['top_keys'])} err={ke}")
            except Exception as e:
                _cb_record("spend", False, now)
                _dbg(f"/spend off keys-only error: {type(e).__name__}")
            return
        if mode == "lite":
            # tiny aggregate GETs — no big pull, no deserialize spike, no CPU freeze
            try:
                hv.update(await _lite_spend(session, base, h, now))
                _cb_record("spend", True, now)
            except Exception as e:
                _cb_record("spend", False, now)
                _dbg(f"/spend lite error: {type(e).__name__}")
            return
        # full mode: raw /spend/logs — the heaviest call; shed it under load
        if _load_shed():
            _dbg(f"/spend/logs skipped — LOAD-SHED (load/core={_LOAD_PER_CORE:.1f} "
                 f">= {config.LITELLM_LOAD_SHED})")
            return
        raw, lerr = await _fetch_spend_raw(
            session, f"{base}/spend/logs?start_date={start_iso}", h,
            config.LITELLM_SPEND_TIMEOUT, config.LITELLM_SPEND_MAX_BYTES)
        _cb_record("spend", lerr is None, now)
        if lerr is not None or raw is None:
            _dbg(f"/spend/logs err={lerr} -> skipped")
            return
        res, kept, total = await asyncio.to_thread(
            _parse_spend_bytes, raw, window_start, config.LITELLM_SPEND_MAX_ROWS)
        hv.update(res)
        _dbg(f"/spend/logs bytes={len(raw)} rows={total} kept-in-window={kept} "
             f"requests_window={hv['requests_window']} top_keys={len(hv.get('top_keys', []))}")
        if kept == 0:
            _dbg("kept-rows=0 -> no rows in window (no traffic / key perms / date).")

    await _do_spend()
    # /key/list is LiteLLM's OWN record of which labels are real, currently (or
    # formerly) registered keys — piggy-backed on this same HEAVY cadence (it's a
    # management-API call, no cheaper than /spend/logs) so the per-key charts can
    # tell a real key from a client sending garbage (an unexpanded '${ENV_VAR}'
    # string as its bearer token, a made-up/revoked hash) and fold that into
    # 'Other' instead of it claiming its own named band. Best-effort: key_budgets()
    # already falls back to its own last-good cache (or None on a cold start with
    # no cache yet) on a transient /key/list error, so this never regresses a chart
    # over a blip — it only ever grows the known-keys set (db.known_keys_upsert
    # never deletes, so a later-rotated key still shows in HISTORY).
    # This /key/list + /team/list + /user/list walk is a HEAVY management-API pull (up to ~100
    # sequential paginated requests) — no cheaper than /spend/logs — so it MUST honour the same
    # freeze gates: skip in 'off' mode (the operator disabled heavy pulls), under load-shed, or
    # when a breaker is open. It reads the shared 'spend' breaker (respect a genuinely-down
    # endpoint) and records its OWN failures into a private 'key_list' breaker, so a struggling
    # management API can't degrade the always-on spend poll (mirrors the token_types pattern).
    if (_spend_mode() != "off" and not _load_shed()
            and not _cb_open("spend", now) and not _cb_open("key_list", now)):
        try:
            kb = await key_budgets(session)   # feeds the key_list breaker its OWN live outcome
            if kb:
                # {alias: owner-user-id}, not just the alias list — the owner is what tells an
                # UNASSIGNED key (LiteLLM reports no user) from an owned one, and it is already
                # resolved here, so persisting it costs nothing and saves the read paths from
                # re-querying LiteLLM. '' means "LiteLLM names no owner for this key".
                hv["known_keys"] = {a: str(v.get("user") or "") for a, v in kb.items()}
        except Exception as e:
            _cb_record("key_list", False, time.time())
            _dbg(f"/key/list known-keys refresh error: {type(e).__name__}")
    else:
        _dbg("/key/list known-keys refresh skipped — freeze gate (off/load-shed/breaker)")
    return hv


def _fold_model_user(logs: list) -> list[dict]:
    """Aggregate raw /spend/logs rows into per-(day, model, key) cost + tokens for the
    persisted spend rollup. `day` is the UTC date of the request's startTime; `key` is the
    hashed api-key (owner resolved downstream), `alias` its key_alias when present. The
    monitor's own /health-check pseudo-key is dropped. Pure + sync (runs in the parse
    thread). Returns [] when there's nothing to record."""
    mu: dict[tuple, dict] = {}
    for row in logs:
        if not isinstance(row, dict):
            continue
        st = _parse_ts(row.get("startTime") or row.get("start_time"))
        if st is None:
            continue
        meta = row.get("metadata")
        meta = meta if isinstance(meta, dict) else {}
        kid = str(row.get("api_key") or meta.get("user_api_key") or "?")
        if not kid or kid == "?" or _is_health_check_key(kid):
            continue
        model = str(row.get("model") or row.get("model_name") or "?")
        spend = float(row.get("response_cost",
                      row.get("spend", row.get("cost", 0))) or 0)
        tok = int(row.get("total_tokens", 0) or 0)
        day = datetime.fromtimestamp(st, tz=timezone.utc).strftime("%Y-%m-%d")
        alias = str(row.get("key_alias") or row.get("api_key_alias")
                    or meta.get("user_api_key_alias") or "")
        if config.key_excluded(kid, alias):     # monitor's own / operator-excluded key
            continue
        e = mu.setdefault((day, model, kid),
                          {"alias": alias, "cost": 0.0, "tokens": 0, "reqs": 0})
        e["cost"] += spend
        e["tokens"] += tok
        e["reqs"] += 1                          # each log row is one request
        if alias and not e["alias"]:
            e["alias"] = alias
    return [{"day": d, "model": m, "key": k, "alias": v["alias"],
             "cost": round(v["cost"], 6), "tokens": v["tokens"], "reqs": v["reqs"]}
            for (d, m, k), v in mu.items()]


async def model_user_backfill(session: aiohttp.ClientSession, days: int) -> list[dict]:
    """ONE-TIME seed for the spend rollup: pull /spend/logs over the last `days` days
    (bounded by the same byte cap as the live sampler) and aggregate to per-(day,model,key)
    rows. Heavy but runs once at first start. Returns [] if LiteLLM is unset/unreachable or
    the pull fails — the chart then just grows forward from live samples."""
    base = config.LITELLM_BASE_URL
    if not base or not config.LITELLM_MASTER_KEY:
        return []
    base = base.rstrip("/")
    start = datetime.fromtimestamp(
        time.time() - max(1, days) * 86400, tz=timezone.utc).strftime("%Y-%m-%d")
    raw, err = await _fetch_spend_raw(
        session, f"{base}/spend/logs?start_date={start}", _headers(),
        config.LITELLM_SPEND_TIMEOUT, config.LITELLM_SPEND_MAX_BYTES)
    if err is not None or not raw:
        _dbg(f"model_user_backfill: /spend/logs err={err} -> no seed")
        return []
    # Parse + fold OFF the event loop (json.loads on a multi-day payload is the exact CPU
    # spike the anti-freeze design keeps off the loop; see _heavy_sample / _parse_spend_bytes).
    rows = await asyncio.to_thread(_parse_backfill_bytes, raw)
    _dbg(f"model_user_backfill: {len(rows)} (day,model,key) rows")
    return rows


TOKEN_TYPES_MAX_DAYS = 92          # bound the on-demand pull (a quarter) — see below
TOKEN_TYPES_MAX_SECONDS = 90.0     # hard wall-clock ceiling across ALL day-pulls (see below)


async def per_model_token_types(session: aiohttp.ClientSession, start_date: str,
                                end_date: str | None = None) -> dict | None:
    """Per-model {input, cached, output, total} token counts over [start_date, end_date] (UTC,
    both inclusive; end defaults to today), from the HEAVY /spend/logs endpoint — the only
    source with the prompt/completion/cache split (`/global/activity/model` reports total
    tokens only).

    Pulled DAY-BY-DAY (`start_date=D&end_date=D`) so each request is bounded to one day's logs
    and stays under `LITELLM_SPEND_MAX_BYTES`; a single open-ended `start_date=` pull returns
    the whole firehose (LiteLLM doesn't shrink it without an end bound) and trips the byte cap.
    Each day is parsed off-thread; a day that errors (cap/timeout/HTTP) is recorded in
    `days_failed` and skipped, so a partial result still comes back instead of nothing.

    Returns None only when LiteLLM is unconfigured or the dates are unparseable. Otherwise a
    dict {"per_model": {model: {...}}, "days_ok": int, "days_failed": [{"day","err"}],
    "total_days": int} — the caller decides `available` from days_ok."""
    base = config.LITELLM_BASE_URL
    if not base or not config.LITELLM_MASTER_KEY:
        return None
    base = base.rstrip("/")
    try:
        start_dt = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        end_dt = (datetime.strptime(end_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                  if end_date else datetime.fromtimestamp(time.time(), tz=timezone.utc))
    except (TypeError, ValueError):
        return None
    # clamp: no inverted range, and cap the span so a stray far-past start can't fan out into
    # hundreds of daily pulls (each is a heavy call).
    if end_dt.date() < start_dt.date():
        return None
    max_end = start_dt + timedelta(days=TOKEN_TYPES_MAX_DAYS - 1)
    if end_dt > max_end:
        end_dt = max_end
    out: dict[str, dict] = {}
    days_ok = 0
    days_failed: list[dict] = []
    total_days = 0
    started = time.time()
    # This is a HEAVY /spend/logs fan-out (up to TOKEN_TYPES_MAX_DAYS pulls). Honour the SAME
    # freeze-safety gates as the sampler's _heavy_sample so a struggling/auth-broken proxy or a
    # saturated host can't be hammered from an HTTP handler: skip up-front on a bad key, host
    # load-shed, or an open circuit; trip out mid-loop if the breaker opens; and cap total
    # wall-clock so the caller (and its aiohttp worker) can never be wedged for minutes.
    if _AUTH_BAD:
        return {"per_model": {}, "days_ok": 0, "days_failed": [], "total_days": 0,
                "aborted": "auth_bad"}
    if _load_shed():
        return {"per_model": {}, "days_ok": 0, "days_failed": [], "total_days": 0,
                "aborted": "load_shed"}
    # Respect a genuinely-down /spend/logs (the always-on sampler opens the shared "spend"
    # breaker) AND our OWN recent-failure breaker — but this on-demand pull must NOT feed the
    # shared one: its heavy multi-day fan-out fails on modes specific to it (byte cap, time
    # budget on a big window) that don't mean the light sampler poll is down, so coupling them
    # would let a user-initiated pull degrade the always-on spend collection. Read the shared
    # breaker (protective); record failures to a private "token_types" breaker only.
    if _cb_open("spend", started) or _cb_open("token_types", started):
        return {"per_model": {}, "days_ok": 0, "days_failed": [], "total_days": 0,
                "aborted": "circuit_open"}
    aborted = None
    d = start_dt
    while d.date() <= end_dt.date():
        if time.time() - started > TOKEN_TYPES_MAX_SECONDS:
            aborted = "time_budget"       # remaining days left unpulled, surfaced to caller
            break
        ds = d.strftime("%Y-%m-%d")
        total_days += 1
        raw, err = await _fetch_spend_raw(
            session, f"{base}/spend/logs?start_date={ds}&end_date={ds}", _headers(),
            config.LITELLM_SPEND_TIMEOUT, config.LITELLM_SPEND_MAX_BYTES)
        _cb_record("token_types", err is None, time.time())  # private breaker — never the shared spend one
        if err is not None or not raw:
            days_failed.append({"day": ds, "err": err or "empty"})
            if _cb_open("token_types", time.time()):        # our own breaker tripped → stop hammering
                aborted = "circuit_open"
                break
        else:
            agg = await asyncio.to_thread(_parse_token_types_bytes, raw,
                                          d.timestamp(), d.timestamp() + 86400)
            for m, v in agg.items():
                e = out.setdefault(m, {"input": 0, "cached": 0, "output": 0, "total": 0})
                for k in ("input", "cached", "output", "total"):
                    e[k] += v[k]
            days_ok += 1
        d += timedelta(days=1)
    if days_failed or aborted:
        _dbg(f"per_model_token_types: {days_ok}/{total_days} days ok, "
             f"aborted={aborted}, failed={days_failed[:3]}")
    res = {"per_model": out, "days_ok": days_ok, "days_failed": days_failed,
           "total_days": total_days}
    if aborted:
        res["aborted"] = aborted
    return res


def _parse_spend(logs: list, window_start: float, max_rows: int) -> tuple[dict, int, int]:
    """Pure, synchronous aggregation of /spend/logs rows -> derived latency / cost
    / per-model / per-key fields. Runs in a worker thread (see _heavy_sample) so
    the per-row parsing never stalls the event loop. Returns (fields, kept, total).
    Caps to the most recent `max_rows` — the rolling window drops older rows anyway,
    so this only sheds work that would be filtered out regardless."""
    res: dict = {}
    total = len(logs)
    # Per-(day, model, key) cost/token rollup for the persisted "cost per model & user over
    # time" chart. Folded over the FULL day pulled (BEFORE the max_rows cap below), so
    # re-aggregating each sample yields the day's running total — the DB UPSERT-REPLACE is
    # then idempotent (no double-count). Owner/user is resolved later from `key`/`alias`.
    res["mu_rows"] = _fold_model_user(logs)
    if total > max_rows:
        logs = sorted(
            logs,
            key=lambda r: _parse_ts(r.get("startTime") or r.get("start_time")) or 0.0
        )[-max_rows:]
    _kept = 0
    if logs:
        waits = []
        ttfts = []               # time-to-first-token (streaming) ms
        cost_total = 0.0
        cache_saved = 0.0
        cache_hits = 0
        prompt_total = completion_total = errors = 0
        failures: list[dict] = []          # recent failed requests (#2)
        # per-model + per-key aggregation
        per: dict[str, dict] = {}
        per_key: dict[str, dict] = {}
        for row in logs:
            st = _parse_ts(row.get("startTime") or row.get("start_time"))
            en = _parse_ts(row.get("endTime") or row.get("end_time"))
            if st is None or en is None or en < window_start:
                continue
            dur_ms = (en - st) * 1000.0
            if dur_ms < 0:
                continue
            _kept += 1
            waits.append(dur_ms)
            model = row.get("model") or row.get("model_name") or "?"
            # response_cost is the canonical StandardLoggingPayload field
            spend = float(row.get("response_cost",
                          row.get("spend", row.get("cost", 0))) or 0)
            tok = int(row.get("total_tokens", 0) or 0)
            pt = int(row.get("prompt_tokens", 0) or 0)
            ct = int(row.get("completion_tokens", 0) or 0)
            status = str(row.get("status", "")).lower()
            is_err = bool(row.get("exception")) or status in ("failure", "error")
            # TTFT: completionStartTime - startTime (streaming requests only)
            cs = _parse_ts(row.get("completionStartTime")
                           or row.get("completion_start_time"))
            if cs is not None and st is not None:
                t = (cs - st) * 1000.0
                if t >= 0:
                    ttfts.append(t)
            if _cache_is_hit(row.get("cache_hit")):
                cache_hits += 1
            cache_saved += float(row.get("saved_cache_cost", 0) or 0)
            cost_total += spend
            prompt_total += pt
            completion_total += ct
            meta = row.get("metadata") or {}
            if is_err:
                errors += 1
                failures.append({
                    "t": en,
                    "model": model,
                    "key": _short_key(row.get("api_key")
                                      or meta.get("user_api_key") or "?"),
                    "error": _error_text(row, meta),
                })
            m = per.setdefault(model, {"model": model, "reqs": 0, "wait_sum": 0.0,
                                       "wait_max": 0.0, "tokens": 0, "cost": 0.0,
                                       "waits": []})
            m["reqs"] += 1
            m["wait_sum"] += dur_ms
            m["wait_max"] = max(m["wait_max"], dur_ms)
            m["waits"].append(dur_ms)
            m["tokens"] += tok
            m["cost"] += spend
            # per-key: api_key (hashed token) + best-effort alias from metadata.
            # Skip LiteLLM's internal health-check pseudo-key — it's the monitor's
            # own /health probes, not real usage, and would dominate the chart.
            kid = (row.get("api_key") or meta.get("user_api_key") or "?")
            if kid and not _is_health_check_key(kid):
                alias = (row.get("key_alias") or row.get("api_key_alias")
                         or meta.get("user_api_key_alias") or "")
                k = per_key.setdefault(kid, {"key": kid, "alias": alias,
                                             "reqs": 0, "tokens": 0, "cost": 0.0})
                k["reqs"] += 1
                k["tokens"] += tok
                k["cost"] += spend
                if alias and not k["alias"]:
                    k["alias"] = alias
        if waits:
            n = len(waits)
            win_s = max(1.0, config.LITELLM_SPEND_WINDOW_MIN * 60)
            res["requests_window"] = n
            # full mode really is a rolling LITELLM_SPEND_WINDOW_MIN window (counted
            # from per-request rows), unlike lite's day-to-date total.
            res["requests_basis"] = "window"
            res["wait_avg_ms"] = round(sum(waits) / n, 1)
            res["wait_max_ms"] = round(max(waits), 1)
            # latency percentiles (#2) — avg hides the tail; p95/p99 = real UX
            sw = sorted(waits)
            res["p50_ms"] = round(_pctile(sw, 50), 1)
            res["p95_ms"] = round(_pctile(sw, 95), 1)
            res["p99_ms"] = round(_pctile(sw, 99), 1)
            # SLO: share of requests under the target latency
            if config.SLO_LATENCY_MS > 0:
                under = sum(1 for w in sw if w <= config.SLO_LATENCY_MS)
                res["slo_target_ms"] = config.SLO_LATENCY_MS
                res["slo_pct"] = round(under / n * 100, 2)
            res["cost_window"] = round(cost_total, 4)
            # rates (Tier A) — per-second throughput + per-hour cost + error %
            res["req_rate"] = round(n / win_s, 3)
            res["tok_in_rate"] = round(prompt_total / win_s, 2)
            res["tok_out_rate"] = round(completion_total / win_s, 2)
            res["tok_total_rate"] = round((prompt_total + completion_total) / win_s, 2)
            res["cost_rate_hr"] = round(cost_total / (win_s / 3600), 4)
            res["error_pct"] = round(errors / n * 100, 1)
            # TTFT + cache economics (JSON-derived, no prometheus)
            if ttfts:
                res["ttft_avg_ms"] = round(sum(ttfts) / len(ttfts), 1)
            res["cache_hit_pct"] = round(cache_hits / n * 100, 1)
            res["cache_saved"] = round(cache_saved, 4)
            # per-model incl. p95 + SLO share (#3)
            def _model_row(m):
                mw = sorted(m["waits"])
                slo = None
                if config.SLO_LATENCY_MS > 0 and mw:
                    slo = round(sum(1 for w in mw if w <= config.SLO_LATENCY_MS)
                                / len(mw) * 100, 1)
                return {
                    "model": m["model"], "reqs": m["reqs"],
                    "wait_avg_ms": round(m["wait_sum"] / m["reqs"], 1),
                    "wait_max_ms": round(m["wait_max"], 1),
                    "p95_ms": round(_pctile(mw, 95), 1),
                    "slo_pct": slo,
                    "tokens": m["tokens"], "cost": round(m["cost"], 4),
                }
            res["per_model"] = [_model_row(m) for m in
                                sorted(per.values(), key=lambda x: -x["reqs"])]
            # recent failed requests (#2), newest first, capped
            failures.sort(key=lambda f: -(f["t"] or 0))
            res["recent_failures"] = failures[:10]
            # top-10 API keys by request count in the window
            res["spend_window_min"] = config.LITELLM_SPEND_WINDOW_MIN
            # drop excluded keys/users (e.g. the monitor's own key) BEFORE the top-10
            # slice, so the ranking isn't padded by a key the operator never sees.
            _ranked = [k for k in sorted(per_key.values(), key=lambda x: -x["reqs"])
                       if not config.key_excluded(k["key"], k["alias"])]
            res["top_keys"] = [{
                "key": k["key"], "alias": k["alias"], "reqs": k["reqs"],
                "tokens": k["tokens"], "cost": round(k["cost"], 4),
            } for k in _ranked[:10]]

    return res, _kept, total


def last_key_list_error() -> str | None:
    """Why the last key_budgets() /key/list call failed (for the UI to surface)."""
    return _KEY_LIST_ERR
