# db.py — sqlite retention for AI-Monitoring samples.
#
# One table: samples(ts, payload_json). The full merged snapshot per tick is
# stored as JSON. Small scale (one host, N-second cadence) → JSON blob is
# simplest and keeps the schema stable as panels evolve. Old rows pruned by age.
from __future__ import annotations

import bisect
import calendar
import json
import math
import os
import sqlite3
import sys
import time
from contextlib import contextmanager

import obslog
from typing import Any, cast

import config


# Swallowed-DB-error telemetry. Every db.py `except` calls _dberr, which logs AND bumps this
# counter so a persistently-failing store (disk full, locked DB, schema drift) is OBSERVABLE on
# /healthz + /metrics — otherwise the dashboard keeps serving the in-memory ring and the box
# looks healthy while nothing is being persisted. Ints/tuples → atomic under the GIL, safe from
# the worker threads (to_thread) and the loop without a lock.
_DB_ERR_COUNT = 0
_DB_LAST: tuple[str, str, float] | None = None      # (fn, "Type: msg", ts)


def db_error_stats() -> dict:
    """{count, last, last_ts} for the swallowed-DB-error counter (0/None when healthy)."""
    return {"count": _DB_ERR_COUNT,
            "last": (_DB_LAST[0] + ": " + _DB_LAST[1]) if _DB_LAST else None,
            "last_ts": _DB_LAST[2] if _DB_LAST else None}


def _dberr(exc: BaseException) -> None:
    """Log a swallowed DB error with the FAILING FUNCTION's name (review D-2) AND bump the
    observable error counter (db_error_stats). A monitoring tool must not fail its own storage
    silently: every `except Exception` in this module surfaces the exception type + where it
    happened, so a query bug / schema drift / locked DB is diagnosable instead of an
    indistinguishable empty result. Best-effort; never raises."""
    global _DB_ERR_COUNT, _DB_LAST
    try:
        fn = sys._getframe(1).f_code.co_name
        _DB_ERR_COUNT += 1
        _DB_LAST = (fn, f"{type(exc).__name__}: {exc}", time.time())
        obslog.get("db").warning(f"{fn}: {type(exc).__name__}: {exc}")
    except Exception:
        pass


_SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    ts      REAL NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);

-- Flat numeric columns for efficient time-range queries + downsampling.
CREATE TABLE IF NOT EXISTS metrics (
    ts          REAL NOT NULL,
    cpu         REAL,
    mem         REAL,
    gpu         REAL,
    vram_used   REAL,
    vram_total  REAL,
    wait        REAL,
    disk        REAL,
    load1       REAL,
    tok         REAL
);
CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics(ts);

-- Backend up/down transitions for uptime tracking.
CREATE TABLE IF NOT EXISTS events (
    ts       REAL NOT NULL,
    backend  TEXT NOT NULL,
    up       INTEGER NOT NULL,     -- 1 = came up / model loaded, 0 = down / unloaded
    detail   TEXT,
    kind     TEXT DEFAULT 'state'  -- 'state' = up/down transition, 'model' = load/unload
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
-- uptime() filters `backend=? AND ts<?/>=?` per backend; a composite index avoids a ts-range
-- scan-then-filter as the events table grows.
CREATE INDEX IF NOT EXISTS idx_events_backend_ts ON events(backend, ts);

-- Per-key request counts over time (top-N keys as separate colored lines).
-- `label` is the alias when set, else the hashed key id. Pruned at raw retention.
CREATE TABLE IF NOT EXISTS key_series (
    ts     REAL NOT NULL,
    label  TEXT NOT NULL,
    reqs   REAL
);
CREATE INDEX IF NOT EXISTS idx_key_series_ts ON key_series(ts);
-- Rollups so per-key history reaches 1 year at bounded size (raw stays 24h).
CREATE TABLE IF NOT EXISTS key_series_1m (bucket REAL, label TEXT, reqs REAL,
    PRIMARY KEY(bucket,label));
CREATE TABLE IF NOT EXISTS key_series_1h (bucket REAL, label TEXT, reqs REAL,
    PRIMARY KEY(bucket,label));

-- Per-MODEL activity over time — the model analogue of key_series, driving the
-- 'Concurrent LLM work — by model' stacked split. `label` is the model name; `reqs` is
-- that model's request count this sample (day-cumulative in lite mode, windowed in full;
-- concurrency_by_model applies the same reset-safe delta as the by-key split). Same
-- tiering/retention as key_series (raw 24h, 1-min + 1-hour rollups to 1 year).
CREATE TABLE IF NOT EXISTS model_series (
    ts     REAL NOT NULL,
    label  TEXT NOT NULL,
    reqs   REAL
);
CREATE INDEX IF NOT EXISTS idx_model_series_ts ON model_series(ts);
CREATE TABLE IF NOT EXISTS model_series_1m (bucket REAL, label TEXT, reqs REAL,
    PRIMARY KEY(bucket,label));
CREATE TABLE IF NOT EXISTS model_series_1h (bucket REAL, label TEXT, reqs REAL,
    PRIMARY KEY(bucket,label));

-- Real-time in-flight concurrency for a LOCALLY-served model (vLLM's own running/waiting
-- gauges, not LiteLLM's completed-request delta). model_series infers a model's activity
-- from the CHANGE in its completed-request/token count between samples — for a slow,
-- self-hosted model a request can take longer to finish than the polling cadence, so it
-- shows real backlog/conc but a zero completion-delta the whole time it's in flight, and
-- concurrency_by_key(source="model") folds it into "Other" despite it clearly being that
-- model's work. running/waiting are raw point-in-time gauges (not cumulative), so no
-- delta logic applies — concurrency_by_key overrides the completion-delta weight with
-- these directly wherever available. Raw tier only (≤1h window; see concurrency_by_key).
CREATE TABLE IF NOT EXISTS model_conc_series (
    ts      REAL NOT NULL,
    label   TEXT NOT NULL,
    running REAL,
    waiting REAL
);
CREATE INDEX IF NOT EXISTS idx_model_conc_series_ts ON model_conc_series(ts);

-- Labels (key alias, or hash when no alias resolves) LiteLLM's OWN /key/list has ever
-- confirmed as a currently-registered key. Written by the sampler each time
-- collectors.litellm.key_budgets() succeeds (piggy-backs on the existing
-- LITELLM_HEAVY_INTERVAL cadence — see collectors/litellm._heavy_sample), so the
-- per-key charts can tell a REAL key from a client sending garbage (an unexpanded
-- '${LITELLM_API_KEY}' env-var string, a made-up/revoked hash) without this sync,
-- SQLite-only module ever calling out to LiteLLM itself. Rows are NEVER deleted —
-- a key that was valid and later rotated/deleted must keep showing in HISTORY
-- (only its candidacy for a *new* top-N band is gated by current validity, at the
-- read functions that check this table: key_series(), key_series_window_delta(),
-- concurrency_by_key()).
CREATE TABLE IF NOT EXISTS known_keys (
    label      TEXT PRIMARY KEY,
    first_seen REAL,
    last_seen  REAL
);

-- Per-app CPU%/RAM over time (top-N apps as separate colored lines).
-- kind = 'cpu' | 'ram'. Pruned at raw retention.
CREATE TABLE IF NOT EXISTS proc_series (
    ts    REAL NOT NULL,
    kind  TEXT NOT NULL,
    app   TEXT NOT NULL,
    val   REAL
);
CREATE INDEX IF NOT EXISTS idx_proc_series_ts ON proc_series(ts);
CREATE TABLE IF NOT EXISTS proc_series_1m (bucket REAL, kind TEXT, app TEXT, val REAL,
    PRIMARY KEY(bucket,kind,app));
CREATE TABLE IF NOT EXISTS proc_series_1h (bucket REAL, kind TEXT, app TEXT, val REAL,
    PRIMARY KEY(bucket,kind,app));

-- Per-CORE CPU% over time (one series per logical CPU), so the GPU/CPU page's
-- per-core grid honours the same window + pan controls as every other chart.
-- Same shape and cardinality as proc_series (top-10 apps x 2 kinds = 20 rows/tick,
-- vs one row per core), so it reuses the identical rollup + retention tiers.
CREATE TABLE IF NOT EXISTS cpu_core_series (
    ts   REAL NOT NULL,
    core INTEGER NOT NULL,
    pct  REAL
);
CREATE INDEX IF NOT EXISTS idx_cpu_core_series_ts ON cpu_core_series(ts);
CREATE TABLE IF NOT EXISTS cpu_core_series_1m (bucket REAL, core INTEGER, pct REAL,
    PRIMARY KEY(bucket,core));
CREATE TABLE IF NOT EXISTS cpu_core_series_1h (bucket REAL, core INTEGER, pct REAL,
    PRIMARY KEY(bucket,core));

-- Dashboard user accounts (username + scrypt password hash). role: 'admin' can
-- manage users; 'viewer' can only read the dashboards. Passwords are NEVER stored
-- in plaintext; pw_hash is a self-describing scrypt string (see auth.hash_password).
CREATE TABLE IF NOT EXISTS users (
    name       TEXT PRIMARY KEY,
    email      TEXT NOT NULL DEFAULT '',
    pw_hash    TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'viewer',
    created    REAL NOT NULL,
    last_login REAL,
    disabled   INTEGER NOT NULL DEFAULT 0
);

-- Per-user API tokens (personal access tokens). A token carries its OWN role
-- (a viewer may only mint viewer tokens; an admin may mint viewer or admin). Only
-- the SHA-256 of the secret is stored — the raw value is shown once at creation.
CREATE TABLE IF NOT EXISTS api_tokens (
    id         TEXT PRIMARY KEY,          -- public id (for listing / revoke)
    owner      TEXT NOT NULL,             -- username that owns the token
    role       TEXT NOT NULL DEFAULT 'viewer',
    label      TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL UNIQUE,      -- sha256 hex of the raw token
    prefix     TEXT NOT NULL DEFAULT '',  -- first chars, for display only
    created    REAL NOT NULL,
    last_used  REAL,
    disabled   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_hash  ON api_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_api_tokens_owner ON api_tokens(owner);

-- Access + admin-action audit trail (admins review it in /admin/users). action is
-- a dotted key (login.ok, login.fail, login.lockout, logout, user.create, ...);
-- actor = who did it, target = the affected user (for user.* actions).
CREATE TABLE IF NOT EXISTS audit_log (
    ts     REAL NOT NULL,
    actor  TEXT,
    action TEXT NOT NULL,
    target TEXT,
    ip     TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

-- Fired alerts (threshold + anomaly) for the alerts UI history/timeline.
CREATE TABLE IF NOT EXISTS alert_log (
    ts    REAL NOT NULL,
    akey  TEXT NOT NULL,
    kind  TEXT NOT NULL,     -- 'fire' | 'recover'
    msg   TEXT
);
CREATE INDEX IF NOT EXISTS idx_alert_log_ts ON alert_log(ts);

-- Fired per-key anomalies (spike / budget) for history + dashboard.
CREATE TABLE IF NOT EXISTS anomalies (
    ts     REAL NOT NULL,
    label  TEXT NOT NULL,
    kind   TEXT NOT NULL,   -- 'spike' | 'budget'
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_anomalies_ts ON anomalies(ts);

-- Downsample rollups (Tier 4): 1-minute and 1-hour averaged buckets.
CREATE TABLE IF NOT EXISTS metrics_1m  (bucket REAL PRIMARY KEY,
    cpu REAL, mem REAL, gpu REAL, vram_used REAL, vram_total REAL,
    wait REAL, disk REAL, load1 REAL, tok REAL);
CREATE TABLE IF NOT EXISTS metrics_1h  (bucket REAL PRIMARY KEY,
    cpu REAL, mem REAL, gpu REAL, vram_used REAL, vram_total REAL,
    wait REAL, disk REAL, load1 REAL, tok REAL);

-- Runtime-tunable settings (operator overrides over env defaults). Only keys in
-- config.TUNABLES are honoured; secrets/infra/security switches are never stored.
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL,
    updated REAL);

-- Per-key team override (managed on the Settings page). LiteLLM reports a key's
-- team, but team BUDGETS are a LiteLLM enterprise feature — so admins can (re)assign
-- a key to a team here and the Spend & Quota by-team rollup honours this override.
CREATE TABLE IF NOT EXISTS key_teams (key TEXT PRIMARY KEY, team TEXT NOT NULL,
    updated REAL);

-- Admin-set per-key monthly budget override (Settings page). Overrides LiteLLM's
-- max_budget / MONITOR_KEY_BUDGETS on the Spend & Quota rollup.
CREATE TABLE IF NOT EXISTS key_budgets_ovr (key TEXT PRIMARY KEY, budget REAL NOT NULL,
    updated REAL);

-- Per-TEAM monthly budget (Settings page). Every key in the team inherits this
-- budget; a per-key override (key_budgets_ovr) bumps a specific member above it.
CREATE TABLE IF NOT EXISTS team_budgets (team TEXT PRIMARY KEY, budget REAL NOT NULL,
    updated REAL);

-- Admin-set per-model cost classification (Settings page). The model name heuristic
-- (collectors/litellm.classify_model) tags each model 'real' (external paid API — a
-- market price) or 'reference' (self-hosted — an ESTIMATED/imputed rate). An admin can
-- pin a model to either here; the override wins on the Spend real-vs-estimated split.
CREATE TABLE IF NOT EXISTS model_cost_kind (model TEXT PRIMARY KEY, kind TEXT NOT NULL,
    updated REAL);

-- Admin-set per-model cost override (USD per 1M tokens) — a blended effective rate that
-- pins a model's cost when LiteLLM's own price is wrong/unreliable. UI counterpart of the
-- MONITOR_MODEL_COSTS env override; the DB value (set here) takes precedence over the env.
CREATE TABLE IF NOT EXISTS model_cost_price (model TEXT PRIMARY KEY, usd_1m REAL NOT NULL,
    updated REAL);

-- Persisted UI layout (Settings page card order, etc.). Stored server-side so the
-- arrangement follows the deployment, not a single browser. value is a JSON string.
CREATE TABLE IF NOT EXISTS ui_layout (name TEXT PRIMARY KEY, value TEXT NOT NULL,
    updated REAL);

-- Admin-set per-key USER/EMAIL override (Settings → Teams key popup). Reassigns a key
-- to a different user/email for the by-user grouping, overriding LiteLLM's reported user.
CREATE TABLE IF NOT EXISTS key_user_ovr (key TEXT PRIMARY KEY, user_name TEXT NOT NULL,
    updated REAL);

-- Persisted LiteLLM team DETECTION (Settings → Teams). LiteLLM's team lookup is flaky
-- and slow, so the last good detection per key is cached here and reloaded on startup —
-- the board shows teams immediately without re-polling LiteLLM every boot. Distinct from
-- key_teams (admin OVERRIDES); this is what LiteLLM reported.
CREATE TABLE IF NOT EXISTS team_detect (key TEXT PRIMARY KEY, team TEXT, "user" TEXT,
    user_name TEXT, budget REAL, spent REAL, updated REAL);

-- Per-(day, model, key) COST + TOKENS rollup that powers the "cost per model & user over
-- time" chart (Spend page). Written by the sampler each tick via UPSERT-REPLACE: the
-- /spend/logs pull returns the WHOLE day, so re-aggregating and replacing today's rows is
-- idempotent (no double-count, no high-water mark). `key` is LiteLLM's hashed api-key;
-- `alias` is its key_alias — the READ path resolves either to an owner/user. Daily
-- granularity, pruned to 1 year (SPEND_MU_RETENTION_DAYS). Seeded once at first run by a
-- bounded 14-day backfill, then grown forward by the sampler.
CREATE TABLE IF NOT EXISTS spend_model_user_daily (
    day     TEXT NOT NULL,
    model   TEXT NOT NULL,
    key     TEXT NOT NULL,
    alias   TEXT,
    cost    REAL NOT NULL,
    tokens  REAL NOT NULL,
    reqs    REAL NOT NULL DEFAULT 0,   -- request count per (day,model,key)
    updated REAL,
    PRIMARY KEY(day, model, key)
);
CREATE INDEX IF NOT EXISTS idx_smud_day ON spend_model_user_daily(day);

-- Per-DAY usage + cost totals for the Spend page's "usage/cost over time" chart.
-- LiteLLM's free-tier /global/activity only returns the LAST 7 DAYS, so the chart is
-- otherwise capped at a week. This table captures each day as it is seen (write-through
-- from the spend-series build) and is read back MERGED with the live 7-day window, so
-- history accumulates well past LiteLLM's cap. One row per calendar day (idempotent
-- UPSERT-REPLACE — the source always reports the whole day). Pruned to SPEND_DAILY_RETENTION_DAYS.
CREATE TABLE IF NOT EXISTS spend_daily (
    date        TEXT PRIMARY KEY,   -- YYYY-MM-DD (UTC)
    requests    REAL,
    tokens      REAL,
    spend       REAL,               -- LiteLLM's actual cash for the day (0 on free tier)
    tokens_ext  REAL,               -- external-model tokens (2-colour usage bar)
    tokens_int  REAL,               -- self-hosted tokens
    real_cost   REAL,               -- external paid $ (estimated from tokens×price)
    est_cost    REAL,               -- self-hosted estimated $
    updated     REAL
);
"""

# Retention for the per-(day,model,key) spend rollup — 1 year of daily buckets.
SPEND_MU_RETENTION_DAYS = 366
# Retention for the per-day usage/cost history (Spend "over time"). Long by design —
# the whole point is to outlast LiteLLM's 7-day window; default ~5 years.
SPEND_DAILY_RETENTION_DAYS = 1826

# Columns charted over time (order must match _METRIC_COLS in queries).
_METRIC_COLS = ["cpu", "mem", "gpu", "vram_used", "vram_total",
                "wait", "disk", "load1", "tok", "power", "gtemp", "slots",
                # llama.cpp extra series: prefill tok/s, slot-busy %, context fill %
                "pptok", "busy", "ctxused",
                # host network down/up rates (bytes/sec)
                "net_down", "net_up",
                # Tier A + efficiency
                "reqrate", "tok_in", "tok_out", "toktot", "errrate", "vram_pct",
                "costrate", "kvcache", "tokwatt", "backlog",
                "ttft", "cachehit",
                # latency percentiles (#2)
                "p50", "p95", "p99",
                # Ollama
                "orun", "oram", "ovram",
                # vLLM — its own columns, NOT the llama.cpp ones. Both engines can run
                # side by side, so charting vLLM on `tok`/`slots`/`kvcache` would plot
                # llama.cpp's numbers under a vLLM label.
                "vrun", "vwait", "vkv", "vttft", "vtpot", "ve2e", "vqueue", "vhit",
                "vptps", "vgtps",
                # stack-wide concurrent LLM work
                "conc"]

# Tables that carry the metric columns (raw + rollups).
_METRIC_TABLES = ["metrics", "metrics_1m", "metrics_1h"]

# Window math + the shared per-key hide predicate live in dbutil (review D-4): pure helpers
# with no DB/state coupling. Re-exported so db.window_secs / db.norm_window / db.WINDOWS /
# db.month_start / db._pos_step / db._label_hidden / … keep resolving from here unchanged.
from dbutil import (  # noqa: E402,F401  (deliberate re-export facade, beside its callers)
    CUSTOM_WIN_MAX,
    CUSTOM_WIN_MIN,
    VALID_WINDOWS,
    WINDOWS,
    _custom_secs,
    _label_hidden,
    _pos_step,
    month_start,
    norm_window,
    window_secs,
)


@contextmanager
def _connect():
    """Open a SQLite connection, commit on success / rollback on error, and ALWAYS
    close it. sqlite3's own `with conn:` commits but never closes — leaking the
    connection until GC (ResourceWarning). This wrapper closes deterministically."""
    path = config.DB_PATH or "/data/ai-monitoring.db"
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    # Wait up to 5s for a write lock at STATEMENT level (the connect `timeout` only covers
    # acquiring the connection). Without it, a reader/writer colliding with the rollup/prune
    # transaction fails immediately with 'database is locked' instead of briefly waiting.
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        yield conn
        conn.commit()
    except Exception as _e:
        _dberr(_e)
        conn.rollback()
        raise
    finally:
        conn.close()


def init() -> None:
    with _connect() as conn:
        conn.executescript(_SCHEMA)
        # idempotent migration: ensure every metric column exists on raw + rollup
        # tables (covers DBs created before power/gtemp/slots/etc. were added)
        for tbl in _METRIC_TABLES:
            existing = {r[1] for r in conn.execute(f"PRAGMA table_info({tbl})")}
            for col in _METRIC_COLS:
                if col not in existing:
                    try:
                        conn.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} REAL")
                    except Exception as _e:
                        _dberr(_e)
                        pass
        # events.kind: split up/down transitions ('state') from model load/unload
        # ('model') so the model timeline never pollutes the uptime calc.
        # spend_model_user_daily.reqs: per-key request count (drives the cumulative
        # "Top 10 API keys over time" chart). Existing rows keep reqs=0; the column
        # populates from live full-mode folds going forward. Do NOT clear the
        # spend_mu_backfill marker here — that would re-run the 14-day /spend/logs
        # backfill on upgrade, which is the heavy pull a spend-off box disabled on
        # purpose (freeze safety). Not worth re-freezing the proxy to fill 14 days.
        if "reqs" not in {r[1] for r in conn.execute("PRAGMA table_info(spend_model_user_daily)")}:
            try:
                conn.execute("ALTER TABLE spend_model_user_daily ADD COLUMN reqs REAL NOT NULL DEFAULT 0")
            except Exception as _e:
                _dberr(_e)
                pass
        if "kind" not in {r[1] for r in conn.execute("PRAGMA table_info(events)")}:
            try:
                conn.execute("ALTER TABLE events ADD COLUMN kind TEXT DEFAULT 'state'")
            except Exception as _e:
                _dberr(_e)
                pass
        # Owner (LiteLLM user-id) per known key, so the read paths can tell an
        # UNASSIGNED key (no owner anywhere) from an owned one without re-querying
        # LiteLLM. Empty string = LiteLLM reports no user for this key. Existing rows
        # backfill to '' and are corrected on the next /key/list poll.
        _kkcols = {r[1] for r in conn.execute("PRAGMA table_info(known_keys)")}
        if "owner" not in _kkcols:
            try:
                conn.execute("ALTER TABLE known_keys ADD COLUMN owner TEXT DEFAULT ''")
            except Exception as _e:
                _dberr(_e)
                pass
        # How many CONSECUTIVE successful polls have reported this key's owner as blank
        # while we still hold a known owner. A key transitions owned -> unassigned only
        # after the streak reaches OWNER_BLANK_THRESHOLD, so a one-off owner-resolution
        # blip inside a successful /key/list poll never flaps it (see known_keys_upsert).
        if "owner_blank_streak" not in _kkcols:
            try:
                conn.execute("ALTER TABLE known_keys "
                             "ADD COLUMN owner_blank_streak INTEGER DEFAULT 0")
            except Exception as _e:
                _dberr(_e)
                pass
        # Resolved owner NAME (email/alias) per known key — the human label the by-user charts
        # need, distinct from `owner` (the user-id they key off). LiteLLM's /user/list directory
        # is flaky, so the live email blips empty on some polls; persisting the last-known name
        # here (cleared only when the owner itself clears, via the same streak) lets the budgets
        # path fall back to it instead of dropping the key to "Unassigned" on a one-off blip.
        if "owner_name" not in _kkcols:
            try:
                conn.execute("ALTER TABLE known_keys ADD COLUMN owner_name TEXT DEFAULT ''")
            except Exception as _e:
                _dberr(_e)
                pass
        # Per-type cost overrides (input / output / cache-read $ per 1M tokens) so an admin
        # can pin each rate individually, not just the single blended usd_1m. usd_1m stays
        # the value the cost pipeline reads (derived from these when they're set), so this
        # is additive — old rows keep working with in/out/cache NULL.
        _mcp = {r[1] for r in conn.execute("PRAGMA table_info(model_cost_price)")}
        for col in ("in_1m", "out_1m", "cache_1m"):
            if col not in _mcp:
                try:
                    conn.execute(f"ALTER TABLE model_cost_price ADD COLUMN {col} REAL")
                except Exception as _e:
                    _dberr(_e)
        # per-user alert webhook (1.2.2): each user can set their own webhook URL.
        _ucols = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
        for col, ddl in (("webhook_url", "TEXT"),
                         ("webhook_enabled", "INTEGER NOT NULL DEFAULT 0"),
                         ("must_change_pw", "INTEGER NOT NULL DEFAULT 0")):
            if col not in _ucols:
                try:
                    conn.execute(f"ALTER TABLE users ADD COLUMN {col} {ddl}")
                except Exception as _e:
                    _dberr(_e)
                    pass
        # team_detect.user_name (Settings → Teams, user-grouped view): resolved
        # LiteLLM username persisted so the board groups by user without a re-poll.
        if "user_name" not in {r[1] for r in conn.execute("PRAGMA table_info(team_detect)")}:
            try:
                conn.execute("ALTER TABLE team_detect ADD COLUMN user_name TEXT")
            except Exception as _e:
                _dberr(_e)
                pass


def insert(ts: float, payload: dict[str, Any]) -> None:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO samples(ts, payload) VALUES (?, ?)",
                (ts, json.dumps(payload, separators=(",", ":"))),
            )
    except Exception as _e:
        _dberr(_e)
        # Persistence is best-effort; a failed write must never break sampling.
        pass


def insert_metrics(ts: float, row: dict[str, Any]) -> None:
    cols = ",".join(_METRIC_COLS)
    ph = ",".join("?" for _ in _METRIC_COLS)
    vals = [row.get(c) for c in _METRIC_COLS]
    try:
        with _connect() as conn:
            conn.execute(
                f"INSERT INTO metrics(ts,{cols}) VALUES (?,{ph})", (ts, *vals))
    except Exception as _e:
        _dberr(_e)
        pass


def _pick_tier(secs: float, end: float, now: float,
               raw_tbl: str, m1_tbl: str, h1_tbl: str) -> tuple[str, str]:
    """Pick the storage tier for a windowed read from BOTH the window LENGTH (resolution) AND how
    far back the window START (end-secs) reaches vs each tier's retention. A short window that is
    panned / drag-zoomed deep into history must NOT read the RAW table (pruned at
    ROLLUP_RAW_HOURS): it holds only the last 24h, so the read came back empty — a blank chart —
    even though the coarser _1m (ROLLUP_MIN_DAYS, default 30d but operator-configurable — the
    live box runs 730) / _1h (ROLLUP_HOUR_DAYS, default 365d) tiers still hold that range.
    Returns (table, ts_column)."""
    oldest_age = now - (end - secs)
    if secs <= WINDOWS["1h"] and oldest_age <= config.ROLLUP_RAW_HOURS * 3600:
        return raw_tbl, "ts"
    if secs <= WINDOWS["24h"] and oldest_age <= config.ROLLUP_MIN_DAYS * 86400:
        return m1_tbl, "bucket"
    return h1_tbl, "bucket"


def series(window: str, max_points: int = 300,
           end: float | None = None) -> list[dict[str, Any]]:
    """Downsampled metric series for a named window (SQL time-bucket average).

    Long windows read the pre-aggregated rollup tables (Tier 4) so a 30-day
    query touches ~43k 1-min rows, not millions of raw samples. The rollup
    tables key on `bucket` (a timestamp) rather than `ts`.

    `end` (epoch) shifts the window back in time for pan/scroll; defaults to now.
    """
    secs = window_secs(window)
    end = end or time.time()
    start = end - secs
    bsize = max(1.0, secs / max_points)
    table, tcol = _pick_tier(secs, end, time.time(), "metrics", "metrics_1m", "metrics_1h")
    avg = ", ".join(f"AVG({c})" for c in _METRIC_COLS)
    try:
        with _connect() as conn:
            rows = conn.execute(
                f"SELECT AVG({tcol}), {avg} FROM {table} "
                f"WHERE {tcol} >= ? AND {tcol} <= ? "
                f"GROUP BY CAST(({tcol} - ?) / ? AS INT) ORDER BY 1",
                (start, end, start, bsize),
            ).fetchall()
        out = []
        for r in rows:
            pt = {"t": r[0]}
            pt.update({c: r[i + 1] for i, c in enumerate(_METRIC_COLS)})
            out.append(pt)
        return out
    except Exception as _e:
        _dberr(_e)
        return []


def insert_key_series(ts: float, top_keys: list[dict[str, Any]]) -> None:
    """Store this tick's per-key ranking value (one row per key). In full mode
    that's request count; in **lite** mode LiteLLM gives no per-key requests (only
    spend), so fall back to spend/cost — the same metric the top-keys bar shows —
    instead of storing zeros that leave the over-time chart empty."""
    if not top_keys:
        return
    rows = []
    for k in top_keys:
        label = k.get("alias") or k.get("key") or "?"
        val = k.get("reqs")
        if val is None:      # lite: rank by spend (cost / total_spend / spend)
            val = k.get("cost") or k.get("total_spend") or k.get("spend") or 0
        rows.append((ts, str(label)[:80], float(val or 0)))
    try:
        with _connect() as conn:
            conn.executemany(
                "INSERT INTO key_series(ts,label,reqs) VALUES (?,?,?)", rows)
    except Exception as _e:
        _dberr(_e)
        pass


def insert_model_series(ts: float, per_model: list[dict[str, Any]]) -> None:
    """Store this tick's per-MODEL activity (one row per model) — the model analogue of
    insert_key_series, feeding the 'Concurrent LLM work — by model' split. Value is the
    model's request count (falls back to tokens if reqs is absent); day-cumulative in
    lite mode, windowed in full — concurrency_by_model applies the reset-safe delta."""
    if not per_model:
        return
    rows = []
    for m in per_model:
        label = m.get("model") or ""
        if not label or label == "?":
            continue
        val = m.get("reqs")
        if val is None:
            val = m.get("tokens") or 0
        rows.append((ts, str(label)[:80], float(val or 0)))
    if not rows:
        return
    try:
        with _connect() as conn:
            conn.executemany(
                "INSERT INTO model_series(ts,label,reqs) VALUES (?,?,?)", rows)
    except Exception as _e:
        _dberr(_e)


def insert_model_conc_series(ts: float, label: str, running: float | None,
                             waiting: float | None) -> None:
    """Store this tick's REAL-TIME in-flight count for a locally-served model (vLLM's own
    running/waiting gauges) — see the model_conc_series schema comment for why this exists
    alongside model_series's completion-delta. No-op when there's nothing to attribute
    (no label, or both gauges absent)."""
    if not label or (running is None and waiting is None):
        return
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO model_conc_series(ts,label,running,waiting) VALUES (?,?,?,?)",
                (ts, str(label)[:80], float(running) if running is not None else None,
                 float(waiting) if waiting is not None else None))
    except Exception as _e:
        _dberr(_e)


def known_keys_upsert(labels: list[str] | set[str] | dict[str, str], ts: float,
                      names: dict[str, str] | None = None) -> None:
    """Record `labels` (aliases, or hashes for alias-less keys) as CONFIRMED-valid by
    LiteLLM's own /key/list as of `ts`. Called by the sampler whenever
    collectors.litellm.key_budgets() succeeds. Rows accumulate forever (no delete) —
    see the known_keys table comment for why a rotated/deleted key must keep its
    history.

    Accepts either a plain sequence of labels or a {label: owner} mapping. The owner is
    LiteLLM's user-id for the key ('' when it reports none) and is what
    unassigned_labels() keys off. A plain SEQUENCE carries no owner information (owner
    "unknown", NOT "blank"), so it only records validity/last_seen and never touches a
    stored owner; prefer the mapping, which drives the owned<->unassigned transition.

    `names` (optional {label: owner_name}) persists the resolved owner EMAIL/alias alongside
    the owner-id, so the by-user charts can fall back to it when LiteLLM's live /user/list
    resolution blips empty. Only meaningful with a {label: owner} mapping."""
    if not labels:
        return
    try:
        with _connect() as conn:
            if isinstance(labels, dict):
                _upsert_known_with_owners(conn, labels, ts, names)
            else:
                # owner UNKNOWN (no per-key owner info): touch last_seen only, insert new
                # rows with a blank owner, and leave any existing owner/streak untouched.
                conn.executemany(
                    "INSERT INTO known_keys(label, first_seen, last_seen, owner, "
                    "owner_blank_streak) VALUES (?,?,?,'',0) "
                    "ON CONFLICT(label) DO UPDATE SET last_seen=excluded.last_seen",
                    [(str(lab)[:80], ts, ts) for lab in labels if lab])
    except Exception as _e:
        _dberr(_e)
        pass


# Consecutive successful polls that must all report a key's owner as blank before we
# accept the owned -> unassigned transition. At the 60s heavy-poll cadence this is a few
# minutes — long enough to ride out a one-off owner-resolution blip, short enough that a
# genuine un-assignment shows up promptly.
OWNER_BLANK_THRESHOLD = 3


def _upsert_known_with_owners(conn: Any, owners: dict[str, str], ts: float,
                              names: dict[str, str] | None = None) -> None:
    """UPSERT known_keys from a {label: owner} map with a DEBOUNCED owner transition.

    Per key, on each successful poll:
      * owner reported NON-blank -> take it, reset the blank streak (the common case);
      * owner blank while we already hold one -> DON'T blank it yet; count the blank. Only
        once OWNER_BLANK_THRESHOLD consecutive polls agree the owner is gone do we clear it
        (owned -> unassigned). One transient blip resets on the next non-blank poll, so the
        key never flaps in/out of "Unassigned";
      * owner blank while already unassigned -> stays unassigned (no-op).

    `names` (optional {label: owner_name email/alias}) rides alongside the owner: a fresh
    non-blank name is taken; a blank name is HELD while the owner is still held (so the by-user
    charts keep the last-known email through a /user/list blip) and is cleared only when the
    owner itself clears. A name-less caller (names=None) never blanks a stored name.

    Done in a single UPSERT: every SET expression reads the OLD row (`known_keys.*`) and the
    proposed insert (`excluded.*`), so the streak increment and the owner decision use the
    same pre-update streak value and stay consistent without a read-then-write race."""
    t = int(OWNER_BLANK_THRESHOLD)
    nm = names or {}
    rows = [(str(lab)[:80], ts, ts, str(owners.get(lab, "") or "")[:120],
             str(nm.get(lab, "") or "")[:200])
            for lab in owners if lab]
    if not rows:
        return
    conn.executemany(
        "INSERT INTO known_keys(label, first_seen, last_seen, owner, owner_blank_streak, "
        "owner_name) VALUES (?,?,?,?,0,?) "
        "ON CONFLICT(label) DO UPDATE SET last_seen=excluded.last_seen, "
        "owner_blank_streak = CASE "
        "    WHEN excluded.owner <> '' THEN 0 "                       # owner seen → reset
        "    WHEN known_keys.owner = '' THEN 0 "                      # already unassigned
        "    ELSE known_keys.owner_blank_streak + 1 END, "            # blank + owned → count
        "owner = CASE "
        "    WHEN excluded.owner <> '' THEN excluded.owner "          # trust a named owner
        "    WHEN known_keys.owner = '' THEN '' "                     # already unassigned
        f"    WHEN known_keys.owner_blank_streak + 1 >= {t} THEN '' " # streak met → clear
        "    ELSE known_keys.owner END, "                            # else hold the owner
        "owner_name = CASE "
        "    WHEN excluded.owner_name <> '' THEN excluded.owner_name "  # fresh email → take it
        "    WHEN known_keys.owner = '' THEN '' "                       # unassigned → no name
        f"    WHEN known_keys.owner_blank_streak + 1 >= {t} "
        "         AND excluded.owner = '' THEN '' "                     # owner clearing → drop name
        "    ELSE known_keys.owner_name END",                          # else hold last-known email
        rows)


def hidden_unassigned() -> set[str]:
    """Labels the per-key charts must drop because the "Unassigned" group is hidden
    (Settings → Keys → Hide unassigned keys). Empty — a pure no-op — while the toggle
    is off, so the default costs nothing and changes nothing. Read through
    `config.HIDE_UNASSIGNED_KEYS` at CALL time, not import time, because the tunable is
    live-editable and `config._apply()` rebinds the module constant."""
    if not getattr(config, "HIDE_UNASSIGNED_KEYS", False):
        return set()
    return unassigned_labels()


def unassigned_labels() -> set[str]:
    """Labels LiteLLM reports NO owner for and that carry no admin user override — the
    keys the Settings board groups under "Unassigned". Mirrors that grouping exactly
    (settings.html: `k.user_grp || k.user || "__unassigned__"`), so hiding the group in
    Settings hides the same set of keys the board shows under it.

    CRITICAL guard: "owner is empty" means UNASSIGNED only once owner resolution has
    actually run. If NOT ONE row in known_keys carries a non-empty owner, owner data was
    never populated (an image predating owner emission, or no /key/list poll has resolved
    a user yet) — and "empty owner" is then indistinguishable from "owner not known". In
    that state EVERY key looks unassigned, so returning them would blank every band on a
    populated deployment (observed live: 61/61 keys owner-empty → the whole chart hidden).
    Treat it as a no-op until at least one owner is known — only then is empty-owner a
    trustworthy signal that LiteLLM genuinely names no owner."""
    try:
        ovr = key_user_overrides()
        with _connect() as conn:
            rows = conn.execute("SELECT label, owner FROM known_keys").fetchall()
        if not any((o or "") for _, o in rows):
            return set()                     # owner never resolved → hide is a no-op
        return {lab for lab, o in rows if not (o or "") and not ovr.get(lab)}
    except Exception as _e:
        _dberr(_e)
        return set()


def known_keys_set() -> set[str]:
    """All labels LiteLLM's /key/list has EVER confirmed valid (empty until the first
    successful key_budgets() poll — callers must treat 'empty' as 'no baseline yet',
    NOT as 'nothing is valid', or every by-key chart would blank out before the first
    poll completes)."""
    try:
        with _connect() as conn:
            return {r[0] for r in conn.execute("SELECT label FROM known_keys")}
    except Exception as _e:
        _dberr(_e)
        return set()


def known_owner_names() -> dict[str, str]:
    """{label: owner_name} for every known key that carries a persisted owner EMAIL/alias.
    The last-known name, held through a /user/list blip (see _upsert_known_with_owners) and
    cleared with the owner. Lets the budgets path name a key whose live email came back empty
    instead of dropping it to "Unassigned". Empty labels/names are omitted."""
    try:
        with _connect() as conn:
            return {r[0]: r[1] for r in
                    conn.execute("SELECT label, owner_name FROM known_keys "
                                 "WHERE owner_name IS NOT NULL AND owner_name <> ''")}
    except Exception as _e:
        _dberr(_e)
        return {}


def key_series(window: str, max_points: int = 300,
               top_n: int = 10, end: float | None = None,
               monotonic: bool = False) -> dict[str, Any]:
    """Multi-series per-key request counts for the top-N keys in the window.

    Returns {"labels": [...top-N labels...], "points": [{t, <label>: v, ...}]}.
    Each label becomes its own line on the chart. `end` shifts the window back.

    `monotonic=True` makes each line non-decreasing for an "over time" cumulative view:
    it plots a running total seeded at the first in-window value, adding only POSITIVE
    steps. The raw stored value is LiteLLM's cumulative spend, which RE-BASES DOWN when a
    key is re-issued / a budget period rolls (observed live: Rodolfo 699 -> 1), so the
    raw line falls — wrong for an "only rises" chart. Summing positive steps ignores the
    drop while still counting activity after it (reset-safe, same kernel as key_delta)."""
    secs = window_secs(window)
    end = end or time.time()
    start = end - secs
    bsize = max(1.0, secs / max_points)
    # tier by window: raw ≤1h, 1-min ≤24h, 1-hour beyond (1-year history)
    table, tc = _pick_tier(secs, end, time.time(), "key_series", "key_series_1m", "key_series_1h")
    try:
        known = known_keys_set()
        hidden = hidden_unassigned()
        with _connect() as conn:
            # over-fetch, then drop excluded labels (the monitor's own key etc.) AND labels
            # LiteLLM's own /key/list has never confirmed as a real key (an unexpanded
            # '${ENV_VAR}' string, a made-up/revoked hash — a real but INVALID auth attempt)
            # so the historical per-key chart matches the live one, and still show a full top-N.
            # NOTE (deferred, see UNBUILT/registry): SUM(reqs) ranks correctly in FULL mode
            # (reqs is a per-bucket count) but by lifetime-magnitude in LITE/OFF mode (reqs is
            # day-CUMULATIVE spend), where an idle-but-huge key can take a slot. A correct fix
            # must be mode-aware (window-delta for cumulative, SUM for windowed) — key_series
            # alone can't tell the two apart, so it is intentionally left as SUM for now.
            ranked = [r[0] for r in conn.execute(
                f"SELECT label, SUM(reqs) s FROM {table} "
                f"WHERE {tc} >= ? AND {tc} <= ? "
                f"GROUP BY label ORDER BY s DESC LIMIT ?", (start, end, top_n * 3))]
            top = [lab for lab in ranked
                   if not config.key_excluded(lab) and config.key_known(lab, known)
                   and lab not in hidden][:top_n]
            if not top:
                return {"labels": [], "points": []}
            ph = ",".join("?" for _ in top)
            rows = conn.execute(
                f"SELECT CAST(({tc} - ?) / ? AS INT) AS bkt, AVG({tc}), label, "
                f"AVG(reqs) FROM {table} "
                f"WHERE {tc} >= ? AND {tc} <= ? AND label IN ({ph}) "
                f"GROUP BY bkt, label ORDER BY bkt",
                (start, bsize, start, end, *top),
            ).fetchall()
        buckets: dict[int, dict] = {}
        for bkt, avg_ts, label, avg_reqs in rows:
            b = buckets.setdefault(bkt, {"t": avg_ts})
            b[label] = round(avg_reqs, 2)
        ordered = [buckets[k] for k in sorted(buckets)]
        if monotonic:
            # per label, replace the raw (possibly re-basing) value with a running total
            # of positive steps seeded at its first in-window value → never decreases
            for lab in top:
                prev_raw = None
                cum = None
                for pt in ordered:
                    if lab not in pt:
                        continue
                    raw = pt[lab]
                    cum = raw if cum is None else cum + _pos_step(raw, prev_raw)
                    prev_raw = raw
                    pt[lab] = round(cum, 2)
        return {"labels": top, "points": ordered}
    except Exception as _e:
        _dberr(_e)
        return {"labels": [], "points": []}


def _prewindow_baseline(conn: Any, table: str, tc: str, start: float,
                        bsize: float = 0.0,
                        labels: list[str] | None = None) -> dict[str, float]:
    """Last per-key CUMULATIVE value observed strictly BEFORE `start`.

    Every per-key chart derives activity from the STEP between consecutive samples of a
    cumulative counter. Seeding that step from the first sample INSIDE the window makes
    that sample contribute 0, which silently deletes the leading-edge activity — and when
    a window is narrow enough to hold only ONE per-key sample (zooming in on a spike),
    it deletes ALL of it: every key weighs 0 and the entire aggregate falls into "Other".
    Reading the previous sample gives the first in-window bucket a real step, so the same
    spike attributes identically at any zoom level.

    Bounded lookback: per-key samples land at most one collector interval apart, so a few
    buckets back (at least 1h) finds the predecessor without scanning the whole history.
    No predecessor (key first seen inside the window, or older than the lookback) → the
    label is absent and the caller keeps the old first-sample-is-baseline behaviour."""
    lb = start - max(4.0 * bsize, 3600.0)
    try:
        q = f"SELECT label, {tc}, reqs FROM {table} WHERE {tc} < ? AND {tc} >= ?"
        params: list[Any] = [start, lb]
        if labels:
            q += " AND label IN (%s)" % ",".join("?" for _ in labels)
            params += list(labels)
        q += f" ORDER BY label, {tc}"
        out: dict[str, float] = {}
        for label, _t, v in conn.execute(q, params):
            if v is not None:
                out[label] = float(v)          # ascending ts → last write = latest before start
        return out
    except Exception as _e:
        _dberr(_e)
        return {}


def key_series_window_delta(window: str, top_n: int = 10,
                            end: float | None = None,
                            require_known: bool = True) -> dict[str, Any]:
    """Top-N keys by NET requests made DURING the window — the SUM OF POSITIVE STEPS
    across every sample in the window, per key. A key whose count is unchanged
    (e.g. 1000 → 1000) yields 0: this shows *activity in the window*, not the running
    total the over-time chart plots.

    Summing steps rather than last-minus-first is what makes this reset-safe HONESTLY.
    Comparing only the endpoints cannot distinguish "counter reset to 0, then 50 real
    requests" from "baseline re-based to 50 with no traffic at all" — both read
    900 → 50 — and the old fallback (credit the end value) guessed the first. Live,
    that guess invented a band: a key sat flat at 2.72, re-based to 0.86, then sat flat
    again, and was charged 0.86 of activity on an idle proxy. Walking the samples tells
    the two apart: a genuine reset shows a climb AFTER the drop and still scores it,
    while a plateau-drop-plateau scores 0. Matches key_delta_series exactly, so a key
    can never rank here and draw flat there.

    Returns {"labels": [...], "deltas": [...]} aligned by index (bar chart)."""
    secs = window_secs(window)
    end = end or time.time()
    start = end - secs
    table, tc = _pick_tier(secs, end, time.time(), "key_series", "key_series_1m", "key_series_1h")
    try:
        known = known_keys_set()
        hidden = hidden_unassigned()
        with _connect() as conn:
            rows = conn.execute(
                f"SELECT label, {tc}, reqs FROM {table} "
                f"WHERE {tc} >= ? AND {tc} <= ? ORDER BY label, {tc}",
                (start, end)).fetchall()
            # baseline from the sample BEFORE the window, so activity at the leading edge
            # (and a window holding a single sample) is not lost — see _prewindow_baseline
            base = _prewindow_baseline(conn, table, tc, start)
        # sum the positive steps per label; a backwards step contributes 0 (baseline
        # change — unknowable), and the climb after it is picked up normally
        totals: dict[str, float] = {}
        prev: dict[str, float] = dict(base)
        for label, _ts, v in rows:
            if v is None:
                continue
            totals[label] = totals.get(label, 0.0) + _pos_step(v, prev.get(label))
            prev[label] = v
        out = []
        for label, delta in totals.items():
            # require_known=False for the spend-context caller (spend_keycost lite-mode fallback):
            # a key with real windowed request activity is self-evidence of a real key, so don't
            # silently DROP it just because /key/list hasn't confirmed the label (master key /
            # ephemeral virtual key) — same rationale as the rollup paths' _label_hidden opt-out.
            # Default True keeps every other caller (ranking, request charts) gating as before.
            if (config.key_excluded(label) or label in hidden
                    or (require_known and not config.key_known(label, known))):
                continue
            out.append({"label": label, "delta": max(0.0, round(delta, 2))})
        out.sort(key=lambda x: cast(float, x["delta"]), reverse=True)
        out = out[:top_n]
        return {"labels": [o["label"] for o in out],
                "deltas": [o["delta"] for o in out]}
    except Exception as _e:
        _dberr(_e)
        return {"labels": [], "deltas": []}


def key_delta_series(window: str, max_points: int = 300, top_n: int = 10,
                     end: float | None = None) -> dict[str, Any]:
    """Timeline of CUMULATIVE requests over the window for the top-N keys (ranked by
    their total net requests). Each point is the running total of requests made
    *since the window start* — so the line climbs from ~0 to the key's window total,
    and an idle key (1000 → 1000) stays a flat 0 line. Built by summing per-bucket
    increases (reset-safe: a negative step from a daily counter reset contributes the
    bucket's own value instead). Same tiering as `key_series`.

    Returns {"labels": [...], "points": [{t, <label>: cumulative, ...}]} for the chart."""
    secs = window_secs(window)
    end = end or time.time()
    start = end - secs
    bsize = max(1.0, secs / max_points)
    table, tc = _pick_tier(secs, end, time.time(), "key_series", "key_series_1m", "key_series_1h")
    try:
        ranked = key_series_window_delta(window, top_n, end)["labels"]
        if not ranked:
            return {"labels": [], "points": []}
        ph = ",".join("?" for _ in ranked)
        with _connect() as conn:
            rows = conn.execute(
                f"SELECT CAST(({tc} - ?) / ? AS INT) AS bkt, AVG({tc}), label, "
                f"AVG(reqs) FROM {table} "
                f"WHERE {tc} >= ? AND {tc} <= ? AND label IN ({ph}) "
                f"GROUP BY bkt, label ORDER BY bkt",
                (start, bsize, start, end, *ranked)).fetchall()
            base = _prewindow_baseline(conn, table, tc, start, bsize, ranked)
        # absolute per-bucket value per label -> per-bucket step -> running total
        buckets: dict[int, dict] = {}
        for bkt, avg_ts, label, avg_reqs in rows:
            b = buckets.setdefault(bkt, {"t": avg_ts, "_abs": {}})
            b["_abs"][label] = avg_reqs
        prev: dict[str, float] = dict(base)
        cum: dict[str, float] = {}
        points = []
        for k in sorted(buckets):
            b = buckets[k]
            pt = {"t": b["t"]}
            for label, v in b["_abs"].items():
                step = _pos_step(v, prev.get(label))     # reset-safe; 0 on first/backwards
                cum[label] = cum.get(label, 0.0) + step
                pt[label] = round(cum[label], 2)         # cumulative since window start
                prev[label] = v
            points.append(pt)
        return {"labels": ranked, "points": points}
    except Exception as _e:
        _dberr(_e)
        return {"labels": [], "points": []}


def prune_key_series() -> None:
    """Tiered retention for per-key / per-app series + alert/anomaly history.
    Raw kept ROLLUP_RAW_HOURS; 1-min rollup ROLLUP_MIN_DAYS; 1-hour rollup +
    alert/anomaly history kept ROLLUP_HOUR_DAYS (1 year by default)."""
    now = time.time()
    raw_cut = now - config.ROLLUP_RAW_HOURS * 3600
    min_cut = now - config.ROLLUP_MIN_DAYS * 86400
    hour_cut = now - config.ROLLUP_HOUR_DAYS * 86400
    try:
        with _connect() as conn:
            conn.execute("DELETE FROM key_series WHERE ts < ?", (raw_cut,))
            conn.execute("DELETE FROM model_series WHERE ts < ?", (raw_cut,))
            conn.execute("DELETE FROM model_conc_series WHERE ts < ?", (raw_cut,))
            conn.execute("DELETE FROM proc_series WHERE ts < ?", (raw_cut,))
            conn.execute("DELETE FROM key_series_1m WHERE bucket < ?", (min_cut,))
            conn.execute("DELETE FROM model_series_1m WHERE bucket < ?", (min_cut,))
            conn.execute("DELETE FROM proc_series_1m WHERE bucket < ?", (min_cut,))
            conn.execute("DELETE FROM key_series_1h WHERE bucket < ?", (hour_cut,))
            conn.execute("DELETE FROM model_series_1h WHERE bucket < ?", (hour_cut,))
            conn.execute("DELETE FROM proc_series_1h WHERE bucket < ?", (hour_cut,))
            conn.execute("DELETE FROM cpu_core_series WHERE ts < ?", (raw_cut,))
            conn.execute("DELETE FROM cpu_core_series_1m WHERE bucket < ?", (min_cut,))
            conn.execute("DELETE FROM cpu_core_series_1h WHERE bucket < ?", (hour_cut,))
            # keep alert/anomaly history for the full hour-rollup horizon (1y)
            conn.execute("DELETE FROM anomalies WHERE ts < ?", (hour_cut,))
            conn.execute("DELETE FROM alert_log WHERE ts < ?", (hour_cut,))
    except Exception as _e:
        _dberr(_e)
        pass


def key_rate_baselines(recent_s: float = 300.0,
                       base_s: float = 3600.0) -> dict[str, dict]:
    """Per-key recent vs baseline request rate for spike detection.

    recent = AVG(reqs) over the last `recent_s` seconds.
    baseline = AVG(reqs) over [now-base_s, now-recent_s] (excludes the recent
    window so a spike doesn't inflate its own baseline).
    """
    now = time.time()
    try:
        with _connect() as conn:
            recent = dict(conn.execute(
                "SELECT label, AVG(reqs) FROM key_series WHERE ts >= ? "
                "GROUP BY label", (now - recent_s,)).fetchall())
            base = dict(conn.execute(
                "SELECT label, AVG(reqs) FROM key_series "
                "WHERE ts >= ? AND ts < ? GROUP BY label",
                (now - base_s, now - recent_s)).fetchall())
        out = {}
        for label, r in recent.items():
            out[label] = {"recent": r or 0.0, "baseline": base.get(label) or 0.0}
        return out
    except Exception as _e:
        _dberr(_e)
        return {}


def concurrency_by_key(window: str, metric: str, max_points: int = 200,
                       top_n: int = 12, end: float | None = None,
                       cumulative: bool = False, source: str = "key") -> dict[str, Any]:
    """ESTIMATED per-key attribution of a proxy-wide aggregate over time.

    `source` selects the label dimension: 'key' splits by API key (key_series), 'model'
    splits by model (model_series) for the 'Concurrent LLM work — by model' card. Model
    labels are not keys, so the key-only candidacy filters (key_excluded / key_known /
    hidden_unassigned) are skipped for source='model'. Everything else — the reset-safe
    delta, the nearest-bucket bridging, and 'Other' preserving the total — is identical.

    For source='model' on a ≤1h window, a bucket/label with real-time data in
    model_conc_series (vLLM's own running/waiting gauges) uses THAT instead of the
    completion-delta weight above: a slow, self-hosted model's request can still be
    generating when the bucket closes, so its completed-request count (and therefore its
    delta) reads zero the entire time it's in flight, even though it clearly has real
    backlog/conc — the exact live symptom was MiniMax's own concurrent work folding
    into "Other" while a fast API model (quick completions) attributed correctly.

    `metric` is 'conc' (concurrent LLM work) or 'backlog' (in-flight requests). LiteLLM
    reports ONE total for these with no per-key breakdown, so each time bucket's total is
    SPLIT across the top-N keys by their share of key_series activity in that bucket
    (requests in full spend mode; in off/lite key_series holds CUMULATIVE spend, so with
    `cumulative=True` the caller has us weight by the per-bucket spend DELTA = recent
    activity, NOT the lifetime total — else idle-but-once-active keys get phantom bands).
    The stacked bands therefore sum to the
    real measured aggregate; only the split is inferred. Activity we can't attribute to a
    top-N key (or any key) goes to 'Other', so the total height always equals the aggregate.

    The aggregate and key_series are polled on independent cadences (SAMPLE_INTERVAL vs
    LITELLM_HEAVY_INTERVAL), so a bucket can have an aggregate value with no key_series row
    of its own — most often a single isolated request, whose backlog blip and matching
    spend-delta sample rarely land in the same bucket. Such a bucket borrows the nearest
    bucket's key-mix within ~two heavy-poll intervals (`max_gap`, below — 2× tolerates the
    poll's real-world jitter) instead of dumping
    straight to 'Other'; beyond that distance the mix is stale enough that 'Other' is still
    the honest answer.

    key_series + the metrics series bucket on the SAME grid (CAST((t-start)/bsize)), so the
    two reads align by bucket index. Returns {labels, metric, series:[{label,data}]}."""
    if metric not in ("conc", "backlog"):
        return {"labels": [], "metric": metric, "series": []}
    secs = window_secs(window)
    end = end or time.time()
    start = end - secs
    bsize = max(1.0, secs / max_points)
    stab = "model_series" if source == "model" else "key_series"
    # both the aggregate (metrics) and the per-key (stab) source must come from the SAME tier;
    # _pick_tier also steps down when the window is panned/zoomed past a tier's retention.
    mtab, tc = _pick_tier(secs, end, time.time(), "metrics", "metrics_1m", "metrics_1h")
    ktab = stab + ("" if tc == "ts" else ("_1m" if mtab.endswith("_1m") else "_1h"))
    # Real-time override source (model_conc_series): raw tier only — see the schema
    # comment for why the completion-delta weight above can be misleadingly zero for a
    # slow, still-running request, and why this is scoped to the raw (≤1h, unpanned) window.
    rt_col = "running" if metric == "conc" else "waiting"
    fetch_rt = source == "model" and tc == "ts"
    try:
        with _connect() as conn:
            agg = conn.execute(
                f"SELECT CAST(({tc}-?)/? AS INT) bkt, AVG({tc}), AVG({metric}) "
                f"FROM {mtab} WHERE {tc}>=? AND {tc}<=? GROUP BY bkt ORDER BY bkt",
                (start, bsize, start, end)).fetchall()
            krows = conn.execute(
                f"SELECT CAST(({tc}-?)/? AS INT) bkt, label, AVG(reqs) "
                f"FROM {ktab} WHERE {tc}>=? AND {tc}<=? GROUP BY bkt, label",
                (start, bsize, start, end)).fetchall()
            kbase = _prewindow_baseline(conn, ktab, tc, start, bsize)
            rt_rows = conn.execute(
                f"SELECT CAST((ts-?)/? AS INT) bkt, label, AVG({rt_col}) "
                f"FROM model_conc_series WHERE ts>=? AND ts<=? AND {rt_col} IS NOT NULL "
                f"GROUP BY bkt, label", (start, bsize, start, end)).fetchall() if fetch_rt else []
        aggv: dict[int, float] = {}
        ts: dict[int, float] = {}
        for bkt, t, v in agg:
            if v is None:
                continue
            aggv[bkt] = float(v)
            ts[bkt] = t
        if not aggv:
            return {"labels": [], "metric": metric, "series": []}
        weights: dict[int, dict[str, float]] = {}
        for bkt, label, val in krows:
            weights.setdefault(bkt, {})[label] = float(val or 0)
        if cumulative:
            # key_series stored a CUMULATIVE per-key value (lite/off = lifetime spend).
            # Weighting instantaneous concurrency by a lifetime total attributes work to
            # keys that only spent in the PAST — so convert each key's series to per-bucket
            # DELTAS (spend DURING the bucket = recent activity). Idle keys → 0 → no band.
            labels = {lab for bw in weights.values() for lab in bw}
            for lab in labels:
                # Seed from the sample BEFORE the window (else the first in-window sample
                # is its own baseline and scores 0 — which is why zooming into a single
                # spike used to attribute the whole aggregate to "Other": the zoomed
                # window held only that one per-key sample). See _prewindow_baseline.
                prev = kbase.get(lab)
                for bkt in sorted(weights):
                    if lab not in weights[bkt]:
                        continue
                    cur = weights[bkt][lab]
                    weights[bkt][lab] = _pos_step(cur, prev)   # reset-safe; shared kernel
                    prev = cur                       # baseline against the raw cumulative
        # Overwrite (not add — the two signals measure the same concept for the same
        # label) with vLLM's real-time gauge wherever available. Point-in-time, not
        # cumulative, so no delta logic applies — a direct replacement of whatever the
        # completion-delta computed for that exact bucket/label.
        for bkt, label, val in rt_rows:
            if val is None:
                continue
            weights.setdefault(bkt, {})[label] = float(val)
        totals: dict[str, float] = {}
        for bw in weights.values():
            for label, f in bw.items():
                totals[label] = totals.get(label, 0.0) + f
        # Lite/off only: no per-key SPEND activity across the whole window (an idle hour)
        # → return empty so the by-key chart HIDES, rather than painting an "Other" band
        # from a baseline aggregate that isn't real per-key work (e.g. a constant backlog
        # of 1 from LiteLLM counting the monitor's own /health/backlog probe as in-flight).
        # Full mode keeps the "unattributed → Other preserves the total" behaviour.
        if cumulative and not any(v > 0 for v in totals.values()):
            return {"labels": [], "metric": metric, "series": []}
        # Drop excluded labels (MONITOR_EXCLUDE_KEYS — the monitor's own key etc.) from
        # TOP-N candidacy, same as key_series()/key_series_window_delta() already do.
        # This function was missing that filter: a key added to MONITOR_EXCLUDE_KEYS
        # (or the monitor's own self/probe traffic recorded before the config existed)
        # still had rows in key_series from BEFORE it was excluded, and — unlike every
        # other by-key chart — kept surfacing here as its own named band instead of
        # being hidden. Its weight stays in `weights`/`tot` below (so the proportional
        # split for the real, non-excluded keys is unaffected); only dropping it from
        # `top` means its share now correctly flows into 'Other' like any other
        # unattributed activity, instead of leaking through as a labelled key.
        #
        # ALSO drop labels LiteLLM's own /key/list has never confirmed as a real key
        # (config.key_known() against db.known_keys_set()) — some clients hit the
        # gateway with a real but INVALID bearer token (an unexpanded '${ENV_VAR}'
        # string, a made-up/revoked hash) and key_series faithfully records whatever
        # string was presented. That activity is genuine backlog/concurrency load —
        # its weight stays in the split denominator below — but it must fold into
        # 'Other' rather than get its own named band, same as an excluded key.
        # The aggregate (fast, ~SAMPLE_INTERVAL) and per-key spend (slow,
        # ~LITELLM_HEAVY_INTERVAL) are polled independently, so a short, isolated
        # request's backlog blip and its matching key_series sample rarely land in
        # the SAME bucket — without bridging, every isolated request washes into
        # "Other" even though the key that made it is known. Borrow the nearest
        # bucket's key-mix; beyond the bridge distance the mix is stale enough that
        # "Other" is still the honest answer. Compute the bridged per-bucket mix ONCE
        # (`eff`) and reuse it for both ranking and drawing.
        #
        # Bridge up to ~TWO heavy-poll intervals, not one: the per-key spend poll fires every
        # ~LITELLM_HEAVY_INTERVAL, but with real jitter — a short (e.g. 1h) window regularly has
        # a conc/backlog bucket whose nearest key-sample sits just past one interval, so a 1×
        # bridge stranded a small honest-but-avoidable "Other" residual (visible at 1h, ~0 by
        # 24h once samples align). A 2× bridge still borrows the REAL nearest key-mix (nothing
        # fabricated, total preserved) — it just tolerates poll jitter — and the mix is stable
        # across ~2 min of a 60s-cadence signal, so attribution stays correct.
        nonempty_bkts = sorted(b for b, bw in weights.items() if sum(bw.values()) > 0)
        max_gap = max(1, math.ceil(2 * config.LITELLM_HEAVY_INTERVAL / bsize)) + 1
        buckets = sorted(aggv)
        eff: dict[int, tuple] = {}
        # ATTRIBUTABLE weight per label = its share of the REAL aggregate summed over the
        # buckets that actually get drawn. Rank the top-N by THIS, not by raw total in-window
        # activity (`totals`). The aggregate (conc/backlog) is a sparse point-in-time gauge, so
        # the key that is "biggest" over the whole window and the key doing the work in the few
        # nonzero-aggregate buckets are routinely different keys: a key busy only while the
        # gauge read 0 contributes nothing to any drawn band, yet ranking by `totals` gave it a
        # named top-N slot (a flat-zero lane) and pushed the real contributor past the cutoff
        # into "Other". That was the live '/litellm shows all-Other with empty named lanes' bug
        # (aggregate=N, attributed=0, the active keys stranded in the "why Other?" list).
        attributable: dict[str, float] = {}
        for b in buckets:
            a = aggv[b]
            bw = weights.get(b, {})
            tot = sum(bw.values())
            if tot <= 0 and nonempty_bkts:
                i = bisect.bisect_left(nonempty_bkts, b)
                cands = [c for c in (nonempty_bkts[i - 1] if i > 0 else None,
                                      nonempty_bkts[i] if i < len(nonempty_bkts) else None)
                         if c is not None]
                if cands:
                    mind = min(abs(c - b) for c in cands)
                    # On a tie (a gap bucket sits exactly between two donors), blend both
                    # instead of arbitrarily favouring one side — neither is more likely to
                    # represent the isolated request than the other.
                    nearest = [c for c in cands if abs(c - b) == mind]
                    if mind <= max_gap:
                        bw = {}
                        for c in nearest:
                            for lab, v in weights[c].items():
                                bw[lab] = bw.get(lab, 0.0) + v
                        tot = sum(bw.values())
            eff[b] = (a, bw, tot)
            if a > 0 and tot > 0:
                for lab, v in bw.items():
                    attributable[lab] = attributable.get(lab, 0.0) + a * (v / tot)
        # ELIGIBLE labels = those allowed to be NAMED (as a band or in the "why Other?"
        # popover's list), ranked by attributable weight and restricted to labels that
        # actually contribute (>0) — a zero-contribution label is neither drawn nor "in"
        # Other, so it must not be named or inflate the "N beyond the top-N" count. Model
        # labels are always eligible; key labels also drop the ones excluded/hidden/
        # never-confirmed — their weight still counts in the split denominator, but they
        # must never be surfaced by name (the whole point of MONITOR_EXCLUDE_KEYS /
        # hide-unassigned / key_known). Computed ONCE so top, other_labels and labels_total
        # all agree.
        ranked = sorted(attributable.items(), key=lambda kv: -kv[1])
        if source == "model":
            eligible = [lab for lab, w in ranked if w > 0]
        else:
            known = known_keys_set()
            hidden = hidden_unassigned()
            eligible = [lab for lab, w in ranked
                        if w > 0 and not config.key_excluded(lab)
                        and config.key_known(lab, known) and lab not in hidden]
        top = eligible[:top_n]
        data: dict[str, list] = {lab: [] for lab in top}
        other: list = []
        for b in buckets:
            a, bw, tot = eff[b]
            if tot <= 0:                          # aggregate present but nothing to attribute
                for lab in top:
                    data[lab].append(0.0)
                other.append(round(a, 3))         # keep the real total as unattributed
                continue
            assigned = 0.0
            for lab in top:
                band = round(a * (bw.get(lab, 0.0) / tot), 3)
                data[lab].append(band)
                assigned += band
            other.append(round(max(0.0, a - assigned), 3))
        series = [{"label": lab, "data": data[lab]} for lab in top]
        if any(o > 0 for o in other):
            series.append({"label": "Other", "data": other})
        # Diagnostics for the "why Other?" popover: how much of the measured aggregate we
        # could attribute vs not, and whether "Other" hides labels BEYOND the top-N or is
        # purely unattributed spikes (labels seen in the window vs shown as bands).
        agg_sum = round(sum(aggv.values()), 3)
        attr_sum = round(sum(sum(v for v in data[lab]) for lab in top), 3)
        # NAMES of the ELIGIBLE labels folded into "Other" because they ranked beyond the
        # top-N — so the popover can list which models/keys are in there, not just count
        # them. Drawn from `eligible` (not `totals`), so excluded/hidden/unconfirmed key
        # labels are never named and never inflate the count. Capped for the tooltip.
        other_labels = eligible[top_n:top_n + 12]
        return {"labels": [ts[b] for b in buckets], "metric": metric, "series": series,
                "attribution": {"aggregate": agg_sum, "attributed": attr_sum,
                                "other": round(max(0.0, agg_sum - attr_sum), 3),
                                "labels_total": len(eligible), "shown": len(top),
                                "other_labels": other_labels}}
    except Exception as _e:
        _dberr(_e)
        return {"labels": [], "metric": metric, "series": []}


def insert_proc_series(ts: float, kind: str, items: list[dict],
                       val_field: str) -> None:
    """Store this tick's top apps for a metric (kind='cpu'|'ram')."""
    if not items:
        return
    rows = [(ts, kind, str(i.get("app", "?"))[:60], float(i.get(val_field, 0) or 0))
            for i in items]
    try:
        with _connect() as conn:
            conn.executemany(
                "INSERT INTO proc_series(ts,kind,app,val) VALUES (?,?,?,?)", rows)
    except Exception as _e:
        _dberr(_e)
        pass


def proc_series(kind: str, window: str, max_points: int = 200,
                top_n: int = 10, end: float | None = None) -> dict[str, Any]:
    """Multi-series per-app values for the top-N apps of a metric in the window.
    Returns {"apps": [...], "points": [{t, <app>: v, ...}]}. `end` shifts back."""
    secs = window_secs(window)
    end = end or time.time()
    start = end - secs
    bsize = max(1.0, secs / max_points)
    table, tc = _pick_tier(secs, end, time.time(), "proc_series", "proc_series_1m", "proc_series_1h")
    try:
        with _connect() as conn:
            top = [r[0] for r in conn.execute(
                f"SELECT app, AVG(val) a FROM {table} "
                f"WHERE kind=? AND {tc}>=? AND {tc}<=? GROUP BY app ORDER BY a DESC LIMIT ?",
                (kind, start, end, top_n))]
            if not top:
                return {"apps": [], "points": []}
            ph = ",".join("?" for _ in top)
            rows = conn.execute(
                f"SELECT CAST(({tc}-?)/? AS INT) bkt, AVG({tc}), app, AVG(val) "
                f"FROM {table} WHERE kind=? AND {tc}>=? AND {tc}<=? AND app IN ({ph}) "
                f"GROUP BY bkt, app ORDER BY bkt",
                (start, bsize, kind, start, end, *top)).fetchall()
        buckets: dict[int, dict] = {}
        for bkt, avg_ts, app, val in rows:
            b = buckets.setdefault(bkt, {"t": avg_ts})
            b[app] = round(val, 2)
        # Densify: every top-N app carries a value at EVERY bucket (0 when it had no
        # sample there — process absent / not in top-N then). A stacked chart must
        # get real 0s, not gaps, or it draws phantom diagonals across the missing
        # points instead of a flat 0.
        pts = []
        for k in sorted(buckets):
            b = buckets[k]
            for app in top:
                b.setdefault(app, 0)
            pts.append(b)
        return {"apps": top, "points": pts}
    except Exception as _e:
        _dberr(_e)
        return {"apps": [], "points": []}


def insert_cpu_core_series(ts: float, per_core: list | None) -> None:
    """Store this tick's per-core CPU%. `per_core` is host.sample()'s `cpu_per_core`
    (index = logical CPU id); an empty list (first tick / core-count change) is a no-op."""
    if not per_core:
        return
    rows = [(ts, i, float(v or 0)) for i, v in enumerate(per_core)]
    try:
        with _connect() as conn:
            conn.executemany(
                "INSERT INTO cpu_core_series(ts,core,pct) VALUES (?,?,?)", rows)
    except Exception as _e:
        _dberr(_e)
        pass


def cpu_core_series(window: str, max_points: int = 200,
                    end: float | None = None) -> dict[str, Any]:
    """Per-core CPU% over the window, bucketed like every other chart series.
    Returns {"cores": [0,1,…], "points": [{t, "0": v, "1": v, …}]} — core ids are
    stringified so the payload is plain JSON. `end` shifts the window back (pan).

    Reads the raw table inside 1h, the 1-minute rollup to 24h, the 1-hour rollup
    beyond — the same tiering proc_series uses, so long windows stay cheap."""
    secs = window_secs(window)
    end = end or time.time()
    start = end - secs
    bsize = max(1.0, secs / max_points)
    table, tc = _pick_tier(secs, end, time.time(),
                           "cpu_core_series", "cpu_core_series_1m", "cpu_core_series_1h")
    try:
        with _connect() as conn:
            cores = [int(r[0]) for r in conn.execute(
                f"SELECT DISTINCT core FROM {table} "
                f"WHERE {tc}>=? AND {tc}<=? ORDER BY core", (start, end))]
            if not cores:
                return {"cores": [], "points": []}
            rows = conn.execute(
                f"SELECT CAST(({tc}-?)/? AS INT) bkt, AVG({tc}), core, AVG(pct) "
                f"FROM {table} WHERE {tc}>=? AND {tc}<=? "
                f"GROUP BY bkt, core ORDER BY bkt", (start, bsize, start, end)).fetchall()
        buckets: dict[int, dict] = {}
        for bkt, avg_ts, core, pct in rows:
            b = buckets.setdefault(bkt, {"t": avg_ts})
            b[str(int(core))] = round(pct, 1)
        pts = [buckets[k] for k in sorted(buckets)]
        return {"cores": cores, "points": pts}
    except Exception as _e:
        _dberr(_e)
        return {"cores": [], "points": []}


def ncpu(window: str = "1h", end: float | None = None) -> int:
    """Logical-core count over the window, from the per-core samples. Used to
    normalize top-style per-process %CPU (relative to ONE core, so up to
    n_cores×100%) down to a share of TOTAL capacity (0–100). 0 when no per-core
    data exists (caller then leaves the value un-normalized)."""
    secs = window_secs(window)
    end = end or time.time()
    start = end - secs
    table, tc = _pick_tier(secs, end, time.time(),
                           "cpu_core_series", "cpu_core_series_1m", "cpu_core_series_1h")
    try:
        with _connect() as conn:
            r = conn.execute(
                f"SELECT COUNT(DISTINCT core) FROM {table} WHERE {tc}>=? AND {tc}<=?",
                (start, end)).fetchone()
        return int(r[0]) if r and r[0] else 0
    except Exception as _e:
        _dberr(_e)
        return 0


def record_alert(ts: float, akey: str, kind: str, msg: str = "") -> None:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO alert_log(ts,akey,kind,msg) VALUES (?,?,?,?)",
                (ts, str(akey)[:80], kind, str(msg)[:300]))
    except Exception as _e:
        _dberr(_e)
        pass


def recent_alerts(limit: int = 50) -> list[dict[str, Any]]:
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT ts,akey,kind,msg FROM alert_log ORDER BY ts DESC LIMIT ?",
                (int(limit),)).fetchall()
        return [{"ts": t, "key": k, "kind": kd, "msg": m}
                for t, k, kd, m in rows]
    except Exception as _e:
        _dberr(_e)
        return []


def record_anomaly(ts: float, label: str, kind: str, detail: str = "") -> None:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO anomalies(ts,label,kind,detail) VALUES (?,?,?,?)",
                (ts, str(label)[:80], kind, detail[:200]))
    except Exception as _e:
        _dberr(_e)
        pass


def recent_anomalies(limit: int = 30) -> list[dict[str, Any]]:
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT ts,label,kind,detail FROM anomalies "
                "ORDER BY ts DESC LIMIT ?", (int(limit),)).fetchall()
        return [{"ts": t, "label": lbl, "kind": k, "detail": d}
                for t, lbl, k, d in rows]
    except Exception as _e:
        _dberr(_e)
        return []


def record_event(ts: float, backend: str, up: bool, detail: str = "",
                 kind: str = "state") -> None:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO events(ts,backend,up,detail,kind) VALUES (?,?,?,?,?)",
                (ts, backend, 1 if up else 0, detail[:200], kind))
    except Exception as _e:
        _dberr(_e)
        pass


def recent_events(limit: int = 50, kind: str | None = None) -> list[dict[str, Any]]:
    """Recent events, newest first. `kind` filters to 'state' or 'model' (None=all)."""
    try:
        with _connect() as conn:
            if kind is None:
                rows = conn.execute(
                    "SELECT ts,backend,up,detail,kind FROM events "
                    "ORDER BY ts DESC LIMIT ?", (int(limit),)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT ts,backend,up,detail,kind FROM events WHERE kind=? "
                    "ORDER BY ts DESC LIMIT ?", (kind, int(limit))).fetchall()
        return [{"ts": t, "backend": b, "up": bool(u), "detail": d, "kind": k}
                for t, b, u, d, k in rows]
    except Exception as _e:
        _dberr(_e)
        return []


def uptime(window: str) -> dict[str, dict]:
    """Per-backend uptime% over a window, derived from transition events.

    Integrates time-up between transitions. A backend with no events in the
    window inherits its last-known state before the window (assumed up if none).
    """
    secs = window_secs(window)   # handles month/custom:<secs>, not just the fixed named windows
    now = time.time()
    start = now - secs
    try:
        with _connect() as conn:
            # only 'state' (up/down) events feed uptime — never 'model' timeline
            # events (NULL kind = legacy row, treated as state).
            backends = [r[0] for r in conn.execute(
                "SELECT DISTINCT backend FROM events "
                "WHERE kind='state' OR kind IS NULL")]
            out = {}
            for b in backends:
                # state at window start = last event before start (default up)
                pre = conn.execute(
                    "SELECT up FROM events WHERE backend=? AND ts<? "
                    "AND (kind='state' OR kind IS NULL) "
                    "ORDER BY ts DESC LIMIT 1", (b, start)).fetchone()
                state = pre[0] if pre else 1
                evs = conn.execute(
                    "SELECT ts,up FROM events WHERE backend=? AND ts>=? "
                    "AND (kind='state' OR kind IS NULL) "
                    "ORDER BY ts", (b, start)).fetchall()
                up_time = 0.0
                cursor = start
                down_count = 0
                for ts, up in evs:
                    if state:
                        up_time += ts - cursor
                    if up == 0:
                        down_count += 1
                    state = up
                    cursor = ts
                if state:
                    up_time += now - cursor
                out[b] = {"uptime_pct": round(up_time / secs * 100, 2),
                          "outages": down_count}
            return out
    except Exception as _e:
        _dberr(_e)
        return {}


def status_segments(window: str, backends: list[str],
                    end: float | None = None) -> dict[str, dict]:
    """Per-backend up/down SEGMENTS over a window, for the status timeline.

    Same step reconstruction as uptime() (state at window start = last 'state'
    event before the window, default up), but emits the actual [from,to,up] runs
    so the frontend can draw a stepped line per service. Honours `end` (pan
    cursor). `no_data` = the backend has no 'state' event at all before or within
    the window (enabled-but-never-sampled → draw a dashed "no data yet" lane).
    """
    secs = window_secs(window)
    now = end or time.time()
    start = now - secs
    out: dict[str, dict] = {}
    try:
        with _connect() as conn:
            for b in backends:
                pre = conn.execute(
                    "SELECT up FROM events WHERE backend=? AND ts<? "
                    "AND (kind='state' OR kind IS NULL) "
                    "ORDER BY ts DESC LIMIT 1", (b, start)).fetchone()
                evs = conn.execute(
                    "SELECT ts,up FROM events WHERE backend=? AND ts>=? AND ts<=? "
                    "AND (kind='state' OR kind IS NULL) "
                    "ORDER BY ts", (b, start, now)).fetchall()
                state = pre[0] if pre else 1
                segs: list[dict] = []
                up_time = 0.0
                cursor = start
                for ts, up in evs:
                    if ts > cursor:
                        segs.append({"from": cursor, "to": ts, "up": bool(state)})
                        if state:
                            up_time += ts - cursor
                    state = up
                    cursor = ts
                if now > cursor:
                    segs.append({"from": cursor, "to": now, "up": bool(state)})
                    if state:
                        up_time += now - cursor
                out[b] = {
                    "segments": segs,
                    "uptime_pct": round(up_time / secs * 100, 2) if secs else 0.0,
                    "no_data": pre is None and not evs,
                }
        return out
    except Exception as _e:
        _dberr(_e)
        return {}


def self_uptime_segments(window: str, end: float | None = None,
                         gap_factor: float = 3.0) -> dict:
    """Monitoring-site up/down segments, derived from metrics-row cadence.

    The site cannot record its own downtime while down, so infer it: a gap
    between consecutive metrics rows larger than gap_factor x the sample interval
    means the site (or its host) was down for that gap. Returns the same shape as
    one status_segments() entry. Reads a hair before `start` so a run straddling
    the window boundary isn't misread as a fresh start-of-window outage.
    """
    import config as _cfg
    secs = window_secs(window)
    real_now = time.time()
    now = end or real_now
    start = now - secs
    # Tier the cadence source by retention: the raw `metrics` table is pruned to ROLLUP_RAW_HOURS
    # (~24h), so a 30d / 12mo window read ONLY from raw would see samples for the last day and
    # fabricate weeks/months of false "down" on the site lane. Pick the tier that covers the
    # window's oldest point: raw (ts, SAMPLE_INTERVAL cadence, ~24h retention) → metrics_1m (bucket,
    # 60 s, up to 30 d) → metrics_1h (bucket, 3600 s, ROLLUP_HOUR_DAYS ~365 d). A missing bucket
    # (gap > gap_factor x the tier's interval) means the monitor wasn't sampling.
    #
    # `oldest_age` = age of the window's START from REAL now (live window ⇒ exactly `secs`; a
    # window PANNED into history is old even if its span is short, so it too skips the pruned raw
    # table). The raw boundary carries a +60 s tolerance ONLY to absorb the sub-second epsilon of a
    # live/near-live window landing on the exact 24h edge — a genuinely panned 24h window (minutes
    # back) exceeds it and correctly tiers to metrics_1m instead of showing a false leading gap.
    oldest_age = real_now - start
    if oldest_age <= getattr(_cfg, "ROLLUP_RAW_HOURS", 24) * 3600.0 + 60.0:
        table, tcol, interval = "metrics", "ts", float(getattr(_cfg, "SAMPLE_INTERVAL", 5.0))
    # metrics_1m only for windows up to 30 d (like _pick_tier) — never pull ~525k per-minute rows
    # for a 12mo window just because 1m retention (ROLLUP_MIN_DAYS, 730 on the live box) reaches it.
    elif oldest_age <= getattr(_cfg, "ROLLUP_MIN_DAYS", 30) * 86400.0 and secs <= 30 * 86400:
        table, tcol, interval = "metrics_1m", "bucket", 60.0
    else:
        # metrics_1h is the floor: a window older than ROLLUP_HOUR_DAYS shows a leading edge gap
        # (no deeper tier exists) — same as series()/_pick_tier.
        table, tcol, interval = "metrics_1h", "bucket", 3600.0
    thresh = max(15.0, gap_factor * interval)
    try:
        with _connect() as conn:
            # table/tcol are fixed literals assigned just above (never caller input) — SQL-safe.
            rows = [r[0] for r in conn.execute(
                f"SELECT {tcol} FROM {table} WHERE {tcol}>=? AND {tcol}<=? ORDER BY {tcol}",  # noqa: S608
                (start - thresh, now)).fetchall()]
    except Exception as _e:
        _dberr(_e)
        return {}
    if not rows:
        return {"segments": [], "uptime_pct": 0.0, "no_data": True}
    # collapse dense samples into up-runs (consecutive samples within thresh)
    runs: list[tuple[float, float]] = []
    run_start = run_end = rows[0]
    for ts in rows[1:]:
        if ts - run_end > thresh:
            runs.append((run_start, run_end))
            run_start = ts
        run_end = ts
    runs.append((run_start, run_end))
    segs: list[dict] = []
    up_time = 0.0
    cursor = start
    for a, b in runs:
        a2, b2 = max(a, start), min(b, now)
        if b2 <= start or a2 >= now:
            continue
        if a2 > cursor:                       # down gap before this run
            segs.append({"from": cursor, "to": a2, "up": False})
            cursor = a2
        if b2 > cursor:                       # the up-run itself
            segs.append({"from": cursor, "to": b2, "up": True})
            up_time += b2 - cursor
            cursor = b2
    if now > cursor:                          # tail: up only if a sample is recent
        if (now - rows[-1]) > thresh:
            segs.append({"from": cursor, "to": now, "up": False})
        else:
            segs.append({"from": cursor, "to": now, "up": True})
            up_time += now - cursor
    return {"segments": segs,
            "uptime_pct": round(up_time / secs * 100, 2) if secs else 0.0,
            "no_data": False}


# High-water mark for incremental rollup (see rollup()). Module global, reset to 0 on process
# start: the FIRST rollup after start re-aggregates all retained raw; subsequent ones only
# re-touch the buckets that could have received new raw since. Advanced only on success.
_ROLLUP_HWM = 0.0
_ROLLUP_GRACE = 2 * 3600     # re-touch window past the HWM: covers the open + previous 1h bucket


def rollup() -> None:
    """Fold raw rows into 1-minute and 1-hour averaged buckets (Tier 4).

    INCREMENTAL: the first rollup after start scans ALL retained raw (so a fresh/restarted
    process folds pre-existing raw into the tiers before prune removes it — the 1h tier serves
    30d/12mo windows that outlive the 24h raw window). After that, only rows newer than the last
    successful rollup minus `_ROLLUP_GRACE` are re-aggregated: raw only ever arrives at ~now, so
    only the open (+ previous) bucket changes between the 60s runs — the rest are already stored.
    This is what keeps the per-minute rollup from re-scanning the whole raw table every tick.
    """
    global _ROLLUP_HWM
    now = time.time()
    # `min(_ROLLUP_HWM, now)` so a BACKWARD wall-clock step (NTP correction / manual set) can't
    # strand data: without it, samples recorded at the new, earlier time would have ts < the
    # old high HWM − grace and never fold. Taking the min re-scans from the current clock, so the
    # jumped-back samples are caught on the next run.
    look_from = 0.0 if _ROLLUP_HWM <= 0.0 else max(0.0, min(_ROLLUP_HWM, now) - _ROLLUP_GRACE)
    try:
        with _connect() as conn:
            # metrics
            for tbl, bsize in (("metrics_1m", 60), ("metrics_1h", 3600)):
                cols = ", ".join(f"AVG({c}) AS {c}" for c in _METRIC_COLS)
                conn.execute(
                    f"INSERT OR REPLACE INTO {tbl} "
                    f"(bucket,{','.join(_METRIC_COLS)}) "
                    f"SELECT CAST(ts/{bsize} AS INT)*{bsize} AS bucket, {cols} "
                    f"FROM metrics WHERE ts >= ? GROUP BY bucket", (look_from,))
            # key_series (per-key) + model_series (per-model) — identical shape
            for src in ("key_series", "model_series"):
                for tbl, bsize in ((f"{src}_1m", 60), (f"{src}_1h", 3600)):
                    conn.execute(
                        f"INSERT OR REPLACE INTO {tbl}(bucket,label,reqs) "
                        f"SELECT CAST(ts/{bsize} AS INT)*{bsize} AS bucket, label, "
                        f"AVG(reqs) FROM {src} WHERE ts >= ? "
                        f"GROUP BY bucket, label", (look_from,))
            # proc_series (per-app)
            for tbl, bsize in (("proc_series_1m", 60), ("proc_series_1h", 3600)):
                conn.execute(
                    f"INSERT OR REPLACE INTO {tbl}(bucket,kind,app,val) "
                    f"SELECT CAST(ts/{bsize} AS INT)*{bsize} AS bucket, kind, app, "
                    f"AVG(val) FROM proc_series WHERE ts >= ? "
                    f"GROUP BY bucket, kind, app", (look_from,))
            # cpu_core_series (per-core CPU%)
            for tbl, bsize in (("cpu_core_series_1m", 60), ("cpu_core_series_1h", 3600)):
                conn.execute(
                    f"INSERT OR REPLACE INTO {tbl}(bucket,core,pct) "
                    f"SELECT CAST(ts/{bsize} AS INT)*{bsize} AS bucket, core, "
                    f"AVG(pct) FROM cpu_core_series WHERE ts >= ? "
                    f"GROUP BY bucket, core", (look_from,))
        _ROLLUP_HWM = now       # advance ONLY on success (a failed run re-covers the gap next time)
    except Exception as _e:
        _dberr(_e)
        pass


def prune_metrics() -> int:
    """Tiered retention (Tier 4): raw kept ROLLUP_RAW_HOURS, 1-min kept
    ROLLUP_MIN_DAYS, 1-hour kept ROLLUP_HOUR_DAYS. Returns raw rows removed."""
    now = time.time()
    raw_cut = now - config.ROLLUP_RAW_HOURS * 3600
    min_cut = now - config.ROLLUP_MIN_DAYS * 86400
    hour_cut = now - config.ROLLUP_HOUR_DAYS * 86400
    removed = 0
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM metrics WHERE ts < ?", (raw_cut,))
            removed = cur.rowcount or 0
            conn.execute("DELETE FROM metrics_1m WHERE bucket < ?", (min_cut,))
            conn.execute("DELETE FROM metrics_1h WHERE bucket < ?", (hour_cut,))
            conn.execute("DELETE FROM events WHERE ts < ?", (hour_cut,))
    except Exception as _e:
        _dberr(_e)
        pass
    return removed


def recent(limit: int = 720) -> list[dict[str, Any]]:
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM samples ORDER BY ts DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        out = []
        for (payload,) in reversed(rows):
            try:
                out.append(json.loads(payload))
            except Exception as _e:
                _dberr(_e)
                continue
        return out
    except Exception as _e:
        _dberr(_e)
        return []


def prune() -> int:
    """Delete `samples` rows older than the retention window. Returns rows removed.

    `samples` is read only by db.recent() at startup (ring warm-up), so it prunes on the short
    SAMPLES_RETENTION_HOURS window rather than the full DB_RETENTION_HOURS — capped by the
    latter so an operator who deliberately set a smaller on-disk window still wins."""
    hours = min(config.DB_RETENTION_HOURS, config.SAMPLES_RETENTION_HOURS)
    cutoff = time.time() - hours * 3600
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))
            return cur.rowcount or 0
    except Exception as _e:
        _dberr(_e)
        return 0


# ─────────────────────────────── user accounts ───────────────────────────────
# CRUD for the dashboard `users` table. pw_hash is opaque here (auth.py owns the
# hashing); db.py only stores/reads it. Every function degrades safely.
def user_create(name: str, email: str, pw_hash: str, role: str,
                created: float, must_change_pw: bool = False) -> bool:
    """Insert a new user. Returns False if the name already exists (or on error).
    `must_change_pw` forces a password change on first login (admin-created users)."""
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO users(name, email, pw_hash, role, created, disabled, "
                "must_change_pw) VALUES (?,?,?,?,?,0,?)",
                (name, email, pw_hash, role, created, 1 if must_change_pw else 0))
        return True
    except Exception as _e:
        _dberr(_e)
        return False


def user_get(name: str) -> dict[str, Any] | None:
    """Full row incl. pw_hash (for login verification). None if absent."""
    try:
        with _connect() as conn:
            r = conn.execute(
                "SELECT name, email, pw_hash, role, created, last_login, disabled, "
                "must_change_pw FROM users WHERE name = ?", (name,)).fetchone()
        if not r:
            return None
        return {"name": r[0], "email": r[1], "pw_hash": r[2], "role": r[3],
                "created": r[4], "last_login": r[5], "disabled": bool(r[6]),
                "must_change_pw": bool(r[7])}
    except Exception as _e:
        _dberr(_e)
        return None


def user_list() -> list[dict[str, Any]]:
    """All users WITHOUT pw_hash — safe to serialise to the admin UI."""
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT name, email, role, created, last_login, disabled, "
                "must_change_pw FROM users ORDER BY name").fetchall()
        return [{"name": r[0], "email": r[1], "role": r[2], "created": r[3],
                 "last_login": r[4], "disabled": bool(r[5]),
                 "must_change_pw": bool(r[6])} for r in rows]
    except Exception as _e:
        _dberr(_e)
        return []


def user_count(role: str | None = None) -> int:
    """Total users, or users of a given role when `role` is set."""
    try:
        with _connect() as conn:
            if role:
                r = conn.execute("SELECT COUNT(*) FROM users WHERE role = ?",
                                 (role,)).fetchone()
            else:
                r = conn.execute("SELECT COUNT(*) FROM users").fetchone()
        return int(r[0]) if r else 0
    except Exception as _e:
        _dberr(_e)
        return 0


def user_set_disabled(name: str, disabled: bool) -> bool:
    try:
        with _connect() as conn:
            cur = conn.execute("UPDATE users SET disabled = ? WHERE name = ?",
                               (1 if disabled else 0, name))
        return (cur.rowcount or 0) > 0
    except Exception as _e:
        _dberr(_e)
        return False


def user_set_password(name: str, pw_hash: str) -> bool:
    try:
        with _connect() as conn:
            cur = conn.execute("UPDATE users SET pw_hash = ? WHERE name = ?",
                               (pw_hash, name))
        return (cur.rowcount or 0) > 0
    except Exception as _e:
        _dberr(_e)
        return False


def user_set_must_change(name: str, must_change: bool) -> bool:
    """Force (or clear) the first-login password-change requirement for a user."""
    try:
        with _connect() as conn:
            cur = conn.execute("UPDATE users SET must_change_pw = ? WHERE name = ?",
                               (1 if must_change else 0, name))
        return (cur.rowcount or 0) > 0
    except Exception as _e:
        _dberr(_e)
        return False


def user_delete(name: str) -> bool:
    try:
        with _connect() as conn:
            conn.execute("DELETE FROM api_tokens WHERE owner = ?", (name,))  # cascade
            cur = conn.execute("DELETE FROM users WHERE name = ?", (name,))
        return (cur.rowcount or 0) > 0
    except Exception as _e:
        _dberr(_e)
        return False


# ── last-admin-safe mutations (atomic guard) ──────────────────────────────────
# The "you can't remove the last admin" rail must be enforced INSIDE the write,
# not as a separate count-then-mutate in the handler: two concurrent demote/
# disable/delete requests could each read admin_count == 2 and both proceed,
# leaving zero admins (TOCTOU). SQLite serialises writers, so a conditional
# statement whose WHERE re-counts admins is atomic — the second writer sees the
# first's committed effect and its guard fails. Each returns True iff it applied.
_ADMIN_LEFT = "(SELECT COUNT(*) FROM users WHERE role = 'admin') > 1"


def user_delete_guarded(name: str) -> bool:
    """DELETE the user unless it is the last admin. Cascades tokens only if the
    delete applied. Atomic (see note above)."""
    try:
        with _connect() as conn:
            cur = conn.execute(
                f"DELETE FROM users WHERE name = ? AND (role != 'admin' OR {_ADMIN_LEFT})",
                (name,))
            deleted = (cur.rowcount or 0) > 0
            if deleted:
                conn.execute("DELETE FROM api_tokens WHERE owner = ?", (name,))
        return deleted
    except Exception as _e:
        _dberr(_e)
        return False


def user_disable_guarded(name: str) -> bool:
    """Set disabled=1 unless it is the last admin. Atomic."""
    try:
        with _connect() as conn:
            cur = conn.execute(
                f"UPDATE users SET disabled = 1 WHERE name = ? "
                f"AND (role != 'admin' OR {_ADMIN_LEFT})", (name,))
        return (cur.rowcount or 0) > 0
    except Exception as _e:
        _dberr(_e)
        return False


def user_update_guarded(name: str, email: str, role: str) -> bool:
    """Edit email + role, but refuse to demote the last admin. Allowed when the
    new role is admin, or the current row is not an admin, or another admin
    remains. Atomic — replaces the handler's count-then-check. Returns True iff
    the row was updated."""
    try:
        with _connect() as conn:
            cur = conn.execute(
                "UPDATE users SET email = ?, role = ? WHERE name = ? "
                f"AND (? = 'admin' OR role != 'admin' OR {_ADMIN_LEFT})",
                (email, role, name, role))
        return (cur.rowcount or 0) > 0
    except Exception as _e:
        _dberr(_e)
        return False


# ── runtime settings (operator overrides persisted across restarts) ───────────
def settings_all() -> dict[str, str]:
    """Every stored setting override as {key: raw-value-string}."""
    try:
        with _connect() as conn:
            return {r[0]: r[1] for r in
                    conn.execute("SELECT key, value FROM settings").fetchall()}
    except Exception as _e:
        _dberr(_e)
        return {}


def settings_set(key: str, value: str, now: float) -> bool:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO settings(key, value, updated) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                "updated = excluded.updated", (key, str(value), now))
        return True
    except Exception as _e:
        _dberr(_e)
        return False


def settings_delete(key: str) -> bool:
    """Remove an override so the key falls back to its env/default value."""
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM settings WHERE key = ?", (key,))
        return (cur.rowcount or 0) > 0
    except Exception as _e:
        _dberr(_e)
        return False


# ── per-(day,model,key) spend rollup: "cost per model & user over time" ───────
def spend_model_user_upsert(rows: list[dict[str, Any]], now: float) -> None:
    """REPLACE the per-(day,model,key) cost/token totals for the given rows. Idempotent:
    the sampler re-aggregates the whole day each tick and passes the running full-day
    totals, so an UPSERT that OVERWRITES (not adds) can't double-count. `rows` items carry
    day/model/key/alias/cost/tokens. No-op on empty / error (best-effort telemetry)."""
    if not rows:
        return
    try:
        payload = [(str(r["day"])[:10], str(r["model"])[:200], str(r["key"])[:200],
                    str(r.get("alias") or "")[:120], float(r.get("cost") or 0),
                    float(r.get("tokens") or 0), float(r.get("reqs") or 0), now) for r in rows]
    except (KeyError, TypeError, ValueError):
        return
    try:
        with _connect() as conn:
            conn.executemany(
                "INSERT INTO spend_model_user_daily(day,model,key,alias,cost,tokens,reqs,updated) "
                "VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(day,model,key) DO UPDATE SET "
                "alias=excluded.alias, cost=excluded.cost, tokens=excluded.tokens, "
                "reqs=excluded.reqs, updated=excluded.updated", payload)
    except Exception as _e:
        _dberr(_e)
        pass


def spend_model_user_rows(days_back: int, end: float | None = None) -> list[dict[str, Any]]:
    """Raw per-(day,model,key) rows within the last `days_back` days (inclusive). The
    caller resolves key/alias → owner and buckets into the chart series. Empty on error."""
    end = end or time.time()
    start_day = time.strftime("%Y-%m-%d", time.gmtime(end - max(0, days_back) * 86400))
    end_day = time.strftime("%Y-%m-%d", time.gmtime(end))   # bound the TOP edge too (a panned/historical `end` must not pull days after the window)
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT day, model, key, alias, cost, tokens FROM spend_model_user_daily "
                "WHERE day >= ? AND day <= ? ORDER BY day", (start_day, end_day)).fetchall()
        return [{"day": r[0], "model": r[1], "key": r[2], "alias": r[3] or "",
                 "cost": float(r[4] or 0), "tokens": float(r[5] or 0)} for r in rows]
    except Exception as _e:
        _dberr(_e)
        return []


def key_cumulative(metric: str = "reqs", days_back: int = 366, top_n: int = 10,
                   end: float | None = None) -> dict[str, Any]:
    """CUMULATIVE per-key metric over time, from the persisted per-(day,model,key) rollup.

    `metric` is "reqs" (request count, the default — drives 'Top 10 API keys over time')
    or "cost". Each point is a key's running total up to that day, so every line only ever
    RISES (never the rolling-window decay of the live request-rate view). Keys are labelled
    by alias (falling back to the key hash) and ranked by their total over the span; the
    top-N are returned. Day-granular; reads the local rollup only (no /spend/logs pull).

    Returns {"labels": [...top-N...], "metric": <metric>, "points": [{t, <label>: cum, ...}]}
    with `t` the UTC epoch of each day. Empty on error / unknown metric / no data."""
    col = {"reqs": "reqs", "cost": "cost"}.get(metric)
    if col is None:
        return {"labels": [], "metric": metric, "points": []}
    ndp = 0 if col == "reqs" else 4          # requests are whole numbers; cost keeps cents
    end = end or time.time()
    start_day = time.strftime("%Y-%m-%d", time.gmtime(end - max(0, days_back) * 86400))
    end_day = time.strftime("%Y-%m-%d", time.gmtime(end))   # bound the TOP edge too (a panned/historical `end` must not pull days after the window)
    try:
        with _connect() as conn:
            rows = conn.execute(
                f"SELECT day, COALESCE(NULLIF(alias,''), key) AS label, SUM({col}) v "
                "FROM spend_model_user_daily WHERE day >= ? AND day <= ? "
                "GROUP BY day, label ORDER BY day", (start_day, end_day)).fetchall()
        if not rows:
            return {"labels": [], "metric": metric, "points": []}
        # rank keys by total over the span; keep the top-N
        totals: dict[str, float] = {}
        days: list[str] = []
        by_day: dict[str, dict[str, float]] = {}
        for day, label, val in rows:
            totals[label] = totals.get(label, 0.0) + float(val or 0)
            d = by_day.setdefault(day, {})
            d[label] = d.get(label, 0.0) + float(val or 0)
            if day not in days:
                days.append(day)
        # drop excluded / unconfirmed / hidden-unassigned labels from top-N candidacy, same
        # as the sibling over-time chart (key_series) — this rollup-backed chart used to skip
        # the filter and surface them as their own lines.
        known = known_keys_set()
        hidden = hidden_unassigned()
        # require_known=False: a spend-rollup label is self-evidence of a real key (it billed a
        # completed request), so don't fold real spend into a vanished top-N slot just because
        # /key/list doesn't currently list it (master key / ephemeral virtual key). See _label_hidden.
        top = [lab for lab, _ in sorted(totals.items(), key=lambda kv: -kv[1])
               if not _label_hidden(lab, known, hidden, require_known=False)][:top_n]
        if not top:
            return {"labels": [], "metric": metric, "points": []}
        # accumulate each top key's daily value into a running total across the days
        cum: dict[str, float] = {lab: 0.0 for lab in top}
        pts: list[dict[str, Any]] = []
        for day in days:
            t = float(calendar.timegm(time.strptime(day, "%Y-%m-%d")))
            d = by_day.get(day, {})
            for lab in top:
                cum[lab] += float(d.get(lab, 0.0))
            pt: dict[str, Any] = {"t": t}
            for lab in top:
                pt[lab] = round(cum[lab], ndp)
            pts.append(pt)
        return {"labels": top, "metric": metric, "points": pts}
    except Exception as _e:
        _dberr(_e)
        return {"labels": [], "metric": metric, "points": []}


def key_cost_window(days_back: int, end: float | None = None) -> dict[str, float]:
    """Total spend per key WITHIN the window (last `days_back` days), from the persisted
    per-(day,model,key) rollup. Keyed by alias (falling back to the key hash) to match the
    /api/budgets key rows. Powers the windowed 'Cost by user/key/team' chart so it follows
    the page time-window instead of showing LiteLLM's all-time per-key total. Empty on error."""
    end = end or time.time()
    start_day = time.strftime("%Y-%m-%d", time.gmtime(end - max(0, days_back) * 86400))
    end_day = time.strftime("%Y-%m-%d", time.gmtime(end))   # bound the TOP edge too (a panned/historical `end` must not pull days after the window)
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT COALESCE(NULLIF(alias,''), key) AS label, SUM(cost) c "
                "FROM spend_model_user_daily WHERE day >= ? AND day <= ? GROUP BY label", (start_day, end_day)).fetchall()
        # Fold excluded / unconfirmed / hidden-unassigned keys into "Other" rather than showing
        # them as named bands (this rollup-backed chart used to skip the filter entirely). Cost
        # is FOLDED, not dropped, so the window's total spend is preserved — a hidden key's
        # money stays visible in aggregate, it just loses its own labelled band.
        known = known_keys_set()
        hidden = hidden_unassigned()
        out: dict[str, float] = {}
        other = 0.0
        for label, c in rows:
            cost = float(c or 0)
            # require_known=False: this spend came from a billed, completed request, so attribute
            # it to the key even if /key/list hasn't confirmed the label (see _label_hidden). Only
            # an operator-excluded or hidden-unassigned key still folds into 'Other'.
            if _label_hidden(str(label), known, hidden, require_known=False):
                other += cost
            else:
                out[str(label)] = out.get(str(label), 0.0) + cost
        if other > 0:
            out["Other"] = out.get("Other", 0.0) + other
        return {k: round(v, 4) for k, v in out.items()}
    except Exception as _e:
        _dberr(_e)
        return {}


def prune_spend_model_user() -> int:
    """Drop rollup rows older than the 1-year retention. Returns rows removed."""
    cutoff = time.strftime(
        "%Y-%m-%d", time.gmtime(time.time() - SPEND_MU_RETENTION_DAYS * 86400))
    try:
        with _connect() as conn:
            cur = conn.execute(
                "DELETE FROM spend_model_user_daily WHERE day < ?", (cutoff,))
            return cur.rowcount or 0
    except Exception as _e:
        _dberr(_e)
        return 0


# ── per-DAY usage+cost history (Spend "over time" chart, past LiteLLM's 7-day cap) ──
_SPEND_DAILY_COLS = ("requests", "tokens", "spend", "tokens_ext", "tokens_int",
                     "real_cost", "est_cost")


def spend_daily_upsert(rows: list[dict[str, Any]], now: float) -> None:
    """REPLACE per-day usage+cost totals. Idempotent: the source always reports the
    whole day, so overwriting a date can't double-count. Each row needs `date`
    (YYYY-MM-DD) plus any of _SPEND_DAILY_COLS (missing → 0.0). No-op on empty/error
    — this is best-effort history capture, never allowed to break the page."""
    if not rows:
        return
    payload = []
    for r in rows:
        d = str((r or {}).get("date") or "")[:10]
        if not d:
            continue
        payload.append((d, *[float(r.get(c) or 0) for c in _SPEND_DAILY_COLS], now))
    if not payload:
        return
    cols = ",".join(_SPEND_DAILY_COLS)
    # The cost/token-split columns come from a BEST-EFFORT pull (`daily_cost`/`daily_tok`) that
    # can fail independently of the always-present usage pull; on failure the caller emits 0 for
    # them. Overwriting unconditionally then REPLACEd a previously-good day's cost with zeros —
    # permanent once the date aged out of LiteLLM's 7-day live window. Keep the existing value
    # when the incoming one is 0 (cost/tokens are day-cumulative, never legitimately drop to 0).
    _COST_COLS = ("tokens_ext", "tokens_int", "real_cost", "est_cost")
    setter = ", ".join(
        (f"{c}=COALESCE(NULLIF(excluded.{c},0), {c})" if c in _COST_COLS else f"{c}=excluded.{c}")
        for c in _SPEND_DAILY_COLS)
    try:
        with _connect() as conn:
            conn.executemany(
                f"INSERT INTO spend_daily(date,{cols},updated) "
                f"VALUES (?,{','.join('?' for _ in _SPEND_DAILY_COLS)},?) "
                f"ON CONFLICT(date) DO UPDATE SET {setter}, updated=excluded.updated",
                payload)
    except Exception as _e:
        _dberr(_e)
        pass


def spend_daily_range(start: str, end: str) -> list[dict[str, Any]]:
    """Stored per-day rows with start <= date <= end (YYYY-MM-DD), sorted by date.
    Empty on error — the caller falls back to the live 7-day window."""
    try:
        with _connect() as conn:
            cur = conn.execute(
                f"SELECT date,{','.join(_SPEND_DAILY_COLS)} FROM spend_daily "
                "WHERE date >= ? AND date <= ? ORDER BY date", (start[:10], end[:10]))
            out = []
            for row in cur.fetchall():
                rec = {"date": row[0]}
                rec.update({c: row[i + 1] for i, c in enumerate(_SPEND_DAILY_COLS)})
                out.append(rec)
            return out
    except Exception as _e:
        _dberr(_e)
        return []


def prune_spend_daily() -> int:
    """Drop day rows older than the retention horizon. Returns rows removed."""
    cutoff = time.strftime(
        "%Y-%m-%d", time.gmtime(time.time() - SPEND_DAILY_RETENTION_DAYS * 86400))
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM spend_daily WHERE date < ?", (cutoff,))
            return cur.rowcount or 0
    except Exception as _e:
        _dberr(_e)
        return 0


# ── per-key team overrides (Settings page → Teams) ────────────────────────────
def team_overrides() -> dict[str, str]:
    """Every admin-assigned key→team override as {key: team}."""
    try:
        with _connect() as conn:
            return {r[0]: r[1] for r in
                    conn.execute("SELECT key, team FROM key_teams").fetchall()}
    except Exception as _e:
        _dberr(_e)
        return {}


def team_set(key: str, team: str, now: float) -> bool:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO key_teams(key, team, updated) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET team = excluded.team, "
                "updated = excluded.updated", (key, str(team), now))
        return True
    except Exception as _e:
        _dberr(_e)
        return False


def team_delete(key: str) -> bool:
    """Drop an override so the key falls back to its LiteLLM-reported team."""
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM key_teams WHERE key = ?", (key,))
        return (cur.rowcount or 0) > 0
    except Exception as _e:
        _dberr(_e)
        return False


def ui_layout_get(name: str) -> list | dict | None:
    """Return the persisted UI layout value for `name` (JSON-decoded), or None."""
    try:
        with _connect() as conn:
            r = conn.execute("SELECT value FROM ui_layout WHERE name = ?",
                             (str(name),)).fetchone()
        return json.loads(r[0]) if r and r[0] else None
    except Exception as _e:
        _dberr(_e)
        return None


def ui_layout_set(name: str, value, now: float) -> bool:
    """Persist a UI layout value (list/dict → JSON) under `name` (upsert)."""
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO ui_layout(name, value, updated) VALUES (?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET value = excluded.value, "
                "updated = excluded.updated",
                (str(name), json.dumps(value, separators=(",", ":")), now))
        return True
    except Exception as _e:
        _dberr(_e)
        return False


def key_user_overrides() -> dict[str, str]:
    """Admin-assigned per-key user/email overrides as {key: user_name}."""
    try:
        with _connect() as conn:
            return {r[0]: r[1] for r in
                    conn.execute("SELECT key, user_name FROM key_user_ovr").fetchall()}
    except Exception as _e:
        _dberr(_e)
        return {}


def key_user_set(key: str, user_name: str, now: float) -> bool:
    """Reassign a key to a user/email (upsert)."""
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO key_user_ovr(key, user_name, updated) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET user_name = excluded.user_name, "
                "updated = excluded.updated", (str(key), str(user_name), now))
        return True
    except Exception as _e:
        _dberr(_e)
        return False


def key_user_delete(key: str) -> bool:
    """Drop a user override so the key falls back to its LiteLLM-reported user."""
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM key_user_ovr WHERE key = ?", (key,))
        return (cur.rowcount or 0) > 0
    except Exception as _e:
        _dberr(_e)
        return False


def team_detect_all() -> dict[str, dict]:
    """Persisted LiteLLM team detection, {key: {detected, user, user_name, budget, spent}}
    — loaded into the in-memory cache on startup so the board is populated without a refresh."""
    try:
        with _connect() as conn:
            return {r[0]: {"detected": r[1] or "", "user": r[2] or "",
                           "user_name": r[3] or "",
                           "budget": float(r[4] or 0), "spent": float(r[5] or 0)}
                    for r in conn.execute(
                        'SELECT key, team, "user", user_name, budget, spent '
                        "FROM team_detect").fetchall()}
    except Exception as _e:
        _dberr(_e)
        return {}


def team_detect_set(key: str, team: str, user: str, user_name: str, budget: float,
                    spent: float, now: float) -> bool:
    """Persist one key's detected team/user/user_name/budget/spend (upsert)."""
    try:
        with _connect() as conn:
            conn.execute(
                'INSERT INTO team_detect(key, team, "user", user_name, budget, spent, updated) '
                "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET "
                'team = excluded.team, "user" = excluded."user", '
                "user_name = excluded.user_name, budget = excluded.budget, "
                "spent = excluded.spent, updated = excluded.updated",
                (str(key), str(team or ""), str(user or ""), str(user_name or ""),
                 float(budget or 0), float(spent or 0), now))
        return True
    except Exception as _e:
        _dberr(_e)
        return False


# ── per-key monthly budget overrides (Settings page) ──────────────────────────
def key_budget_overrides() -> dict[str, float]:
    """Admin-set per-key monthly budgets {key: budget}. These override LiteLLM's
    reported max_budget and MONITOR_KEY_BUDGETS on the Spend & Quota rollup."""
    try:
        with _connect() as conn:
            return {r[0]: float(r[1]) for r in
                    conn.execute("SELECT key, budget FROM key_budgets_ovr").fetchall()}
    except Exception as _e:
        _dberr(_e)
        return {}


def key_budget_set(key: str, budget: float, now: float) -> bool:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO key_budgets_ovr(key, budget, updated) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET budget = excluded.budget, "
                "updated = excluded.updated", (key, float(budget), now))
        return True
    except Exception as _e:
        _dberr(_e)
        return False


def key_budget_delete(key: str) -> bool:
    """Drop a budget override so the key falls back to LiteLLM / env."""
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM key_budgets_ovr WHERE key = ?", (key,))
        return (cur.rowcount or 0) > 0
    except Exception as _e:
        _dberr(_e)
        return False


# ── per-team monthly budget (inherited by every key in the team) ──────────────
def team_budgets() -> dict[str, float]:
    """Admin-set per-team monthly budgets {team: budget}. Each key in a team
    inherits its budget unless it has a per-key override."""
    try:
        with _connect() as conn:
            return {r[0]: float(r[1]) for r in
                    conn.execute("SELECT team, budget FROM team_budgets").fetchall()}
    except Exception as _e:
        _dberr(_e)
        return {}


def team_budget_set(team: str, budget: float, now: float) -> bool:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO team_budgets(team, budget, updated) VALUES (?, ?, ?) "
                "ON CONFLICT(team) DO UPDATE SET budget = excluded.budget, "
                "updated = excluded.updated", (team, float(budget), now))
        return True
    except Exception as _e:
        _dberr(_e)
        return False


def team_budget_delete(team: str) -> bool:
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM team_budgets WHERE team = ?", (team,))
        return (cur.rowcount or 0) > 0
    except Exception as _e:
        _dberr(_e)
        return False


# ── per-model cost classification override (real vs reference/estimated) ──────
MODEL_KINDS = ("real", "reference")


def model_kind_overrides() -> dict[str, str]:
    """Admin-set per-model cost classification {model: 'real'|'reference'}. Overrides
    the name-based classify_model heuristic on the Spend real-vs-estimated split."""
    try:
        with _connect() as conn:
            return {r[0]: r[1] for r in
                    conn.execute("SELECT model, kind FROM model_cost_kind").fetchall()}
    except Exception as _e:
        _dberr(_e)
        return {}


def model_kind_set(model: str, kind: str, now: float) -> bool:
    """Pin a model to 'real' or 'reference'. False on an invalid kind or DB error."""
    if kind not in MODEL_KINDS:
        return False
    model = str(model or "").strip()
    if not model:
        return False
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO model_cost_kind(model, kind, updated) VALUES (?, ?, ?) "
                "ON CONFLICT(model) DO UPDATE SET kind = excluded.kind, "
                "updated = excluded.updated", (model, kind, now))
        return True
    except Exception as _e:
        _dberr(_e)
        return False


def model_cost_prices() -> dict[str, float]:
    """Admin-set per-model cost overrides {model: USD per 1M tokens}. Highest-precedence
    price source (UI counterpart of MONITOR_MODEL_COSTS); pins a model's cost when
    LiteLLM's own price is wrong/unreliable."""
    try:
        with _connect() as conn:
            return {r[0]: float(r[1]) for r in
                    conn.execute("SELECT model, usd_1m FROM model_cost_price").fetchall()}
    except Exception as _e:
        _dberr(_e)
        return {}


def _ok_rate(x: object) -> float | None:
    """Parse a non-negative finite rate, or None if blank/absent; raises on a bad value."""
    if x is None or (isinstance(x, str) and not x.strip()):
        return None
    v = float(cast(Any, x))                       # ValueError → caller rejects
    if v < 0 or v != v or v == float("inf"):
        raise ValueError("rate must be finite and >= 0")
    return v


def _blend_1m(in_1m: float | None, out_1m: float | None,
              cache_1m: float | None = None,
              vin: float | None = None, vout: float | None = None,
              vcache: float | None = None) -> float:
    """Blended $/1M from per-type rates — the single number the cost pipeline multiplies by a
    model's TOTAL tokens.

    VOLUME-WEIGHTED when token volumes are supplied: usd_1m = Σ(rate·volume) / Σ(volume) over
    input+cached+output, i.e. total-cost ÷ total-tokens — the only blend that keeps
    usd_1m·total_tokens equal to the real bill. A naive (in+out)/2 average over-weights the
    (expensive, low-volume) output rate and can inflate cost many-fold; that's the trap the
    volume weighting removes.

    NAIVE FALLBACK when no volumes are given: AVERAGE when both input+output are priced (so an
    input==output blended rate reads once, not doubled); the single non-zero side otherwise —
    cache stays out of this legacy path (a read-discount, not the headline token cost)."""
    i, o, c = in_1m or 0.0, out_1m or 0.0, cache_1m or 0.0
    wi, wo, wc = vin or 0.0, vout or 0.0, vcache or 0.0
    tot = wi + wo + wc
    if tot > 0:                                   # volume-weighted = total cost ÷ total tokens
        return (i * wi + o * wo + c * wc) / tot
    return (i + o) / 2 if (i > 0 and o > 0) else (i + o)


def model_cost_price_set(model: str, usd_1m: float, now: float,
                         in_1m: object = None, out_1m: object = None,
                         cache_1m: object = None,
                         vol_in: object = None, vol_out: object = None,
                         vol_cache: object = None,
                         fill_in: object = None, fill_out: object = None,
                         fill_cache: object = None) -> bool:
    """Pin a model's cost. Either a single blended `usd_1m`, or per-type in/out/cache rates
    ($ per 1M tokens) — when any per-type rate is given, `usd_1m` (what the cost pipeline
    reads) is DERIVED from the per-type rates so both stay consistent.

    When per-type token VOLUMES are also supplied (vol_in/vol_out/vol_cache, e.g. from
    /api/admin/model-token-types), the derived usd_1m is VOLUME-WEIGHTED (total-cost ÷
    total-tokens) instead of a naive input/output average — so usd_1m·total_tokens matches the
    real bill even when output is expensive but low-volume.

    A PARTIAL per-type override (e.g. only `out_1m`, leaving input/cache blank) would otherwise
    blend the blank types as $0 and zero-deflate the derived usd_1m. `fill_in/fill_out/fill_cache`
    (LiteLLM's own live rate for the model, passed by the handler) fill ONLY the blanks for the
    blend; the stored per-type columns still hold just the operator's explicit overrides, so the
    card keeps showing which types were pinned. False on a bad value/DB error."""
    model = str(model or "").strip()
    if not model:
        return False
    try:
        pin, pout, pcache = _ok_rate(in_1m), _ok_rate(out_1m), _ok_rate(cache_1m)
        wi, wo, wc = _ok_rate(vol_in), _ok_rate(vol_out), _ok_rate(vol_cache)
        per_type = any(x is not None for x in (pin, pout, pcache))
        if per_type:
            # Blend from EFFECTIVE rates: the explicit override where set, else LiteLLM's live
            # rate for the un-overridden type — a partial override never counts a blank type as $0.
            fin, fout, fcache = _ok_rate(fill_in), _ok_rate(fill_out), _ok_rate(fill_cache)
            ein = pin if pin is not None else fin
            eout = pout if pout is not None else fout
            ecache = pcache if pcache is not None else fcache
            v = _blend_1m(ein, eout, ecache, wi, wo, wc)
        else:
            v = float(usd_1m)
        if v < 0 or v != v or v == float("inf"):
            return False
    except (TypeError, ValueError):
        return False
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO model_cost_price(model, usd_1m, in_1m, out_1m, cache_1m, "
                "updated) VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(model) DO UPDATE SET usd_1m=excluded.usd_1m, "
                "in_1m=excluded.in_1m, out_1m=excluded.out_1m, "
                "cache_1m=excluded.cache_1m, updated=excluded.updated",
                (model, v, pin if per_type else None, pout if per_type else None,
                 pcache if per_type else None, now))
        return True
    except Exception as _e:
        _dberr(_e)
        return False


def model_cost_details() -> dict[str, dict]:
    """Per-model per-type cost overrides {model: {in,out,cache}} — only the rates an admin
    pinned individually (NULLs omitted). The GET merges these over LiteLLM's own rates so
    the card shows (and edits) the effective per-type values."""
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT model, in_1m, out_1m, cache_1m FROM model_cost_price").fetchall()
    except Exception as _e:
        _dberr(_e)
        return {}
    out: dict[str, dict] = {}
    for m, i, o, c in rows:
        d = {}
        if i is not None:
            d["in"] = float(i)
        if o is not None:
            d["out"] = float(o)
        if c is not None:
            d["cache"] = float(c)
        if d:
            out[m] = d
    return out


def model_cost_price_delete(model: str) -> bool:
    """Drop a cost override so the model falls back to env / LiteLLM pricing."""
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM model_cost_price WHERE model = ?", (model,))
        return (cur.rowcount or 0) > 0
    except Exception as _e:
        _dberr(_e)
        return False


def model_kind_delete(model: str) -> bool:
    """Drop an override so the model falls back to name-based classification."""
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM model_cost_kind WHERE model = ?", (model,))
        return (cur.rowcount or 0) > 0
    except Exception as _e:
        _dberr(_e)
        return False


# ── per-user API tokens ───────────────────────────────────────────────────────
def api_token_create(tid: str, owner: str, role: str, label: str,
                     token_hash: str, prefix: str, created: float) -> bool:
    """Persist a new personal access token (only its hash). False on error/dup."""
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO api_tokens(id, owner, role, label, token_hash, prefix, "
                "created) VALUES (?,?,?,?,?,?,?)",
                (tid, owner, role, label, token_hash, prefix, created))
        return True
    except Exception as _e:
        _dberr(_e)
        return False


def api_token_lookup(token_hash: str) -> dict[str, Any] | None:
    """Resolve a presented token (by hash) to its owner + EFFECTIVE role, but only if the
    token is enabled AND its owner still exists and is not disabled. None otherwise.

    The effective role is the LOWER of the token's stored role and the owner's CURRENT role:
    a token carries its own role, so a user who minted an admin PAT and was later demoted to
    viewer must not keep admin via that token. Capping at read time closes the gap without
    having to mutate every PAT on a role change."""
    try:
        with _connect() as conn:
            r = conn.execute(
                "SELECT t.id, t.owner, t.role, u.role FROM api_tokens t "
                "JOIN users u ON u.name = t.owner "
                "WHERE t.token_hash = ? AND t.disabled = 0 AND u.disabled = 0",
                (token_hash,)).fetchone()
        if not r:
            return None
        eff_role = "admin" if (r[2] == "admin" and r[3] == "admin") else "viewer"
        return {"id": r[0], "owner": r[1], "role": eff_role}
    except Exception as _e:
        _dberr(_e)
        return None


def api_token_list(owner: str) -> list[dict[str, Any]]:
    """A user's tokens WITHOUT the hash — safe for the account UI."""
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT id, role, label, prefix, created, last_used, disabled "
                "FROM api_tokens WHERE owner = ? ORDER BY created DESC",
                (owner,)).fetchall()
        return [{"id": r[0], "role": r[1], "label": r[2], "prefix": r[3],
                 "created": r[4], "last_used": r[5], "disabled": bool(r[6])}
                for r in rows]
    except Exception as _e:
        _dberr(_e)
        return []


def api_token_count(owner: str) -> int:
    try:
        with _connect() as conn:
            r = conn.execute("SELECT COUNT(*) FROM api_tokens WHERE owner = ?",
                             (owner,)).fetchone()
        return int(r[0]) if r else 0
    except Exception as _e:
        _dberr(_e)
        return 0


def api_token_revoke(tid: str, owner: str) -> bool:
    """Delete a token — scoped to its owner so a user can only revoke their own."""
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM api_tokens WHERE id = ? AND owner = ?",
                               (tid, owner))
        return (cur.rowcount or 0) > 0
    except Exception as _e:
        _dberr(_e)
        return False


def api_token_touch(tid: str, ts: float) -> None:
    """Best-effort last-used stamp (throttled by the caller)."""
    try:
        with _connect() as conn:
            conn.execute("UPDATE api_tokens SET last_used = ? WHERE id = ?", (ts, tid))
    except Exception as _e:
        _dberr(_e)
        pass


def user_update(name: str, email: str, role: str) -> bool:
    """Edit an existing user's profile (email + role). Returns True if a row was
    updated. Caller validates email/role and the last-admin guard."""
    try:
        with _connect() as conn:
            cur = conn.execute("UPDATE users SET email = ?, role = ? WHERE name = ?",
                               (email, role, name))
        return (cur.rowcount or 0) > 0
    except Exception as _e:
        _dberr(_e)
        return False


def user_get_webhook(name: str) -> dict[str, Any] | None:
    """A user's alert-webhook config: {url, enabled}. None if the user is absent."""
    try:
        with _connect() as conn:
            r = conn.execute(
                "SELECT webhook_url, webhook_enabled FROM users WHERE name = ?",
                (name,)).fetchone()
        if not r:
            return None
        return {"url": r[0] or "", "enabled": bool(r[1])}
    except Exception as _e:
        _dberr(_e)
        return None


def user_set_webhook(name: str, url: str, enabled: bool) -> bool:
    try:
        with _connect() as conn:
            cur = conn.execute(
                "UPDATE users SET webhook_url = ?, webhook_enabled = ? WHERE name = ?",
                (url or None, 1 if enabled else 0, name))
        return (cur.rowcount or 0) > 0
    except Exception as _e:
        _dberr(_e)
        return False


def user_webhooks_enabled() -> list[dict[str, Any]]:
    """Every enabled, non-empty webhook for a NON-disabled user — the alert fan-out
    recipient list. Disabled users never receive alerts."""
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT name, webhook_url FROM users WHERE webhook_enabled = 1 "
                "AND webhook_url IS NOT NULL AND webhook_url <> '' "
                "AND disabled = 0 ORDER BY name").fetchall()
        return [{"user": r[0], "url": r[1]} for r in rows]
    except Exception as _e:
        _dberr(_e)
        return []


def user_touch_login(name: str, ts: float) -> None:
    try:
        with _connect() as conn:
            conn.execute("UPDATE users SET last_login = ? WHERE name = ?",
                         (ts, name))
    except Exception as _e:
        _dberr(_e)
        pass


# ─────────────────────────────── audit trail ─────────────────────────────────
# Append-only access/admin log. audit_add never raises (like every writer);
# audit_list feeds the admin UI. Old rows are pruned by age with the metrics.
def audit_add(ts: float, actor: str | None, action: str,
              target: str | None = None, ip: str | None = None,
              detail: str | None = None) -> None:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO audit_log(ts, actor, action, target, ip, detail) "
                "VALUES (?,?,?,?,?,?)", (ts, actor, action, target, ip, detail))
    except Exception as _e:
        _dberr(_e)
        pass


def audit_list(limit: int = 200, action_prefix: str | None = None
               ) -> list[dict[str, Any]]:
    """Most-recent-first audit rows (capped). Optional action_prefix filter
    ('login', 'user', …) — matched as a `prefix.%` LIKE on a fixed, non-user string."""
    limit = max(1, min(int(limit), 1000))
    try:
        with _connect() as conn:
            if action_prefix:
                rows = conn.execute(
                    "SELECT ts, actor, action, target, ip, detail FROM audit_log "
                    "WHERE action LIKE ? ORDER BY ts DESC LIMIT ?",
                    (action_prefix + ".%", limit)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT ts, actor, action, target, ip, detail FROM audit_log "
                    "ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [{"ts": r[0], "actor": r[1], "action": r[2], "target": r[3],
                 "ip": r[4], "detail": r[5]} for r in rows]
    except Exception as _e:
        _dberr(_e)
        return []


def audit_prune(cutoff: float) -> int:
    """Delete audit rows older than `cutoff` (epoch). Returns rows removed."""
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff,))
            return cur.rowcount or 0
    except Exception as _e:
        _dberr(_e)
        return 0
