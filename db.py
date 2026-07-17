# db.py — sqlite retention for AI-Monitoring samples.
#
# One table: samples(ts, payload_json). The full merged snapshot per tick is
# stored as JSON. Small scale (one host, N-second cadence) → JSON blob is
# simplest and keeps the schema stable as panels evolve. Old rows pruned by age.
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any

import config

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
"""

# Columns charted over time (order must match _METRIC_COLS in queries).
_METRIC_COLS = ["cpu", "mem", "gpu", "vram_used", "vram_total",
                "wait", "disk", "load1", "tok", "power", "gtemp", "slots",
                # Tier A + efficiency
                "reqrate", "tok_in", "tok_out", "errrate", "vram_pct",
                "costrate", "kvcache", "tokwatt", "backlog",
                "ttft", "cachehit",
                # latency percentiles (#2)
                "p50", "p95", "p99",
                # Ollama
                "orun", "oram", "ovram",
                # stack-wide concurrent LLM work
                "conc"]

# Tables that carry the metric columns (raw + rollups).
_METRIC_TABLES = ["metrics", "metrics_1m", "metrics_1h"]

# Named windows -> seconds.
WINDOWS = {"15m": 900, "1h": 3600, "24h": 86400, "30d": 2592000,
           "12mo": 31536000}


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
    try:
        yield conn
        conn.commit()
    except Exception:
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
                    except Exception:
                        pass
        # events.kind: split up/down transitions ('state') from model load/unload
        # ('model') so the model timeline never pollutes the uptime calc.
        if "kind" not in {r[1] for r in conn.execute("PRAGMA table_info(events)")}:
            try:
                conn.execute("ALTER TABLE events ADD COLUMN kind TEXT DEFAULT 'state'")
            except Exception:
                pass
        # per-user alert webhook (1.2.2): each user can set their own webhook URL.
        _ucols = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
        for col, ddl in (("webhook_url", "TEXT"),
                         ("webhook_enabled", "INTEGER NOT NULL DEFAULT 0"),
                         ("must_change_pw", "INTEGER NOT NULL DEFAULT 0")):
            if col not in _ucols:
                try:
                    conn.execute(f"ALTER TABLE users ADD COLUMN {col} {ddl}")
                except Exception:
                    pass
        # team_detect.user_name (Settings → Teams, user-grouped view): resolved
        # LiteLLM username persisted so the board groups by user without a re-poll.
        if "user_name" not in {r[1] for r in conn.execute("PRAGMA table_info(team_detect)")}:
            try:
                conn.execute("ALTER TABLE team_detect ADD COLUMN user_name TEXT")
            except Exception:
                pass


def insert(ts: float, payload: dict[str, Any]) -> None:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO samples(ts, payload) VALUES (?, ?)",
                (ts, json.dumps(payload, separators=(",", ":"))),
            )
    except Exception:
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
    except Exception:
        pass


def series(window: str, max_points: int = 300,
           end: float | None = None) -> list[dict[str, Any]]:
    """Downsampled metric series for a named window (SQL time-bucket average).

    Long windows read the pre-aggregated rollup tables (Tier 4) so a 30-day
    query touches ~43k 1-min rows, not millions of raw samples. The rollup
    tables key on `bucket` (a timestamp) rather than `ts`.

    `end` (epoch) shifts the window back in time for pan/scroll; defaults to now.
    """
    secs = WINDOWS.get(window, WINDOWS["1h"])
    end = end or time.time()
    start = end - secs
    bsize = max(1.0, secs / max_points)
    # pick source table by window length
    if secs <= WINDOWS["1h"]:
        table, tcol = "metrics", "ts"
    elif secs <= WINDOWS["24h"]:
        table, tcol = "metrics_1m", "bucket"
    else:
        table, tcol = "metrics_1h", "bucket"
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
    except Exception:
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
    except Exception:
        pass


def key_series(window: str, max_points: int = 300,
               top_n: int = 10, end: float | None = None) -> dict[str, Any]:
    """Multi-series per-key request counts for the top-N keys in the window.

    Returns {"labels": [...top-N labels...], "points": [{t, <label>: v, ...}]}.
    Each label becomes its own line on the chart. `end` shifts the window back.
    """
    secs = WINDOWS.get(window, WINDOWS["1h"])
    end = end or time.time()
    start = end - secs
    bsize = max(1.0, secs / max_points)
    # tier by window: raw ≤1h, 1-min ≤24h, 1-hour beyond (1-year history)
    if secs <= WINDOWS["1h"]:
        table, tc = "key_series", "ts"
    elif secs <= WINDOWS["24h"]:
        table, tc = "key_series_1m", "bucket"
    else:
        table, tc = "key_series_1h", "bucket"
    try:
        with _connect() as conn:
            top = [r[0] for r in conn.execute(
                f"SELECT label, SUM(reqs) s FROM {table} "
                f"WHERE {tc} >= ? AND {tc} <= ? "
                f"GROUP BY label ORDER BY s DESC LIMIT ?", (start, end, top_n))]
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
        return {"labels": top,
                "points": [buckets[k] for k in sorted(buckets)]}
    except Exception:
        return {"labels": [], "points": []}


def key_series_window_delta(window: str, top_n: int = 10,
                            end: float | None = None) -> dict[str, Any]:
    """Top-N keys by NET requests made DURING the window: value at the end minus
    value at the start (per key). A key whose count is unchanged over the window
    (e.g. 1000 → 1000) yields 0 — this shows *activity in the window*, not the
    running total the over-time chart plots. Reset-safe: if the counter dropped
    (daily reset), the end value is used instead of a negative delta.

    Returns {"labels": [...], "deltas": [...]} aligned by index (bar chart)."""
    secs = WINDOWS.get(window, WINDOWS["1h"])
    end = end or time.time()
    start = end - secs
    if secs <= WINDOWS["1h"]:
        table, tc = "key_series", "ts"
    elif secs <= WINDOWS["24h"]:
        table, tc = "key_series_1m", "bucket"
    else:
        table, tc = "key_series_1h", "bucket"
    try:
        with _connect() as conn:
            rows = conn.execute(
                f"SELECT b.label, "
                f"  (SELECT reqs FROM {table} WHERE label=b.label AND {tc}=b.mx) AS lastv, "
                f"  (SELECT reqs FROM {table} WHERE label=b.label AND {tc}=b.mn) AS firstv "
                f"FROM (SELECT label, MIN({tc}) mn, MAX({tc}) mx FROM {table} "
                f"      WHERE {tc} >= ? AND {tc} <= ? GROUP BY label) b",
                (start, end)).fetchall()
        out = []
        for label, lastv, firstv in rows:
            if lastv is None:
                continue
            fv = firstv if firstv is not None else 0.0
            delta = (lastv - fv) if lastv >= fv else lastv     # reset-safe
            out.append({"label": label, "delta": max(0.0, round(delta, 2))})
        out.sort(key=lambda x: x["delta"], reverse=True)
        out = out[:top_n]
        return {"labels": [o["label"] for o in out],
                "deltas": [o["delta"] for o in out]}
    except Exception:
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
    secs = WINDOWS.get(window, WINDOWS["1h"])
    end = end or time.time()
    start = end - secs
    bsize = max(1.0, secs / max_points)
    if secs <= WINDOWS["1h"]:
        table, tc = "key_series", "ts"
    elif secs <= WINDOWS["24h"]:
        table, tc = "key_series_1m", "bucket"
    else:
        table, tc = "key_series_1h", "bucket"
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
        # absolute per-bucket value per label -> per-bucket step -> running total
        buckets: dict[int, dict] = {}
        for bkt, avg_ts, label, avg_reqs in rows:
            b = buckets.setdefault(bkt, {"t": avg_ts, "_abs": {}})
            b["_abs"][label] = avg_reqs
        prev: dict[str, float] = {}
        cum: dict[str, float] = {}
        points = []
        for k in sorted(buckets):
            b = buckets[k]
            pt = {"t": b["t"]}
            for label, v in b["_abs"].items():
                if label in prev:
                    step = v - prev[label]
                    step = step if step >= 0 else v      # reset-safe
                else:
                    step = 0.0                            # first observed bucket
                cum[label] = cum.get(label, 0.0) + step
                pt[label] = round(cum[label], 2)         # cumulative since window start
                prev[label] = v
            points.append(pt)
        return {"labels": ranked, "points": points}
    except Exception:
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
            conn.execute("DELETE FROM proc_series WHERE ts < ?", (raw_cut,))
            conn.execute("DELETE FROM key_series_1m WHERE bucket < ?", (min_cut,))
            conn.execute("DELETE FROM proc_series_1m WHERE bucket < ?", (min_cut,))
            conn.execute("DELETE FROM key_series_1h WHERE bucket < ?", (hour_cut,))
            conn.execute("DELETE FROM proc_series_1h WHERE bucket < ?", (hour_cut,))
            # keep alert/anomaly history for the full hour-rollup horizon (1y)
            conn.execute("DELETE FROM anomalies WHERE ts < ?", (hour_cut,))
            conn.execute("DELETE FROM alert_log WHERE ts < ?", (hour_cut,))
    except Exception:
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
    except Exception:
        return {}


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
    except Exception:
        pass


def proc_series(kind: str, window: str, max_points: int = 200,
                top_n: int = 10, end: float | None = None) -> dict[str, Any]:
    """Multi-series per-app values for the top-N apps of a metric in the window.
    Returns {"apps": [...], "points": [{t, <app>: v, ...}]}. `end` shifts back."""
    secs = WINDOWS.get(window, WINDOWS["1h"])
    end = end or time.time()
    start = end - secs
    bsize = max(1.0, secs / max_points)
    if secs <= WINDOWS["1h"]:
        table, tc = "proc_series", "ts"
    elif secs <= WINDOWS["24h"]:
        table, tc = "proc_series_1m", "bucket"
    else:
        table, tc = "proc_series_1h", "bucket"
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
    except Exception:
        return {"apps": [], "points": []}


def record_alert(ts: float, akey: str, kind: str, msg: str = "") -> None:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO alert_log(ts,akey,kind,msg) VALUES (?,?,?,?)",
                (ts, str(akey)[:80], kind, str(msg)[:300]))
    except Exception:
        pass


def recent_alerts(limit: int = 50) -> list[dict[str, Any]]:
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT ts,akey,kind,msg FROM alert_log ORDER BY ts DESC LIMIT ?",
                (int(limit),)).fetchall()
        return [{"ts": t, "key": k, "kind": kd, "msg": m}
                for t, k, kd, m in rows]
    except Exception:
        return []


def record_anomaly(ts: float, label: str, kind: str, detail: str = "") -> None:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO anomalies(ts,label,kind,detail) VALUES (?,?,?,?)",
                (ts, str(label)[:80], kind, detail[:200]))
    except Exception:
        pass


def recent_anomalies(limit: int = 30) -> list[dict[str, Any]]:
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT ts,label,kind,detail FROM anomalies "
                "ORDER BY ts DESC LIMIT ?", (int(limit),)).fetchall()
        return [{"ts": t, "label": lbl, "kind": k, "detail": d}
                for t, lbl, k, d in rows]
    except Exception:
        return []


def record_event(ts: float, backend: str, up: bool, detail: str = "",
                 kind: str = "state") -> None:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO events(ts,backend,up,detail,kind) VALUES (?,?,?,?,?)",
                (ts, backend, 1 if up else 0, detail[:200], kind))
    except Exception:
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
    except Exception:
        return []


def uptime(window: str) -> dict[str, dict]:
    """Per-backend uptime% over a window, derived from transition events.

    Integrates time-up between transitions. A backend with no events in the
    window inherits its last-known state before the window (assumed up if none).
    """
    secs = WINDOWS.get(window, WINDOWS["24h"])
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
    except Exception:
        return {}


def rollup() -> None:
    """Fold raw rows into 1-minute and 1-hour averaged buckets (Tier 4).

    Aggregation is BOUNDED to recent rows (not the whole raw table) so each
    per-minute rollup is a small scan regardless of retention — this is what
    keeps 1-year history cheap. INSERT OR REPLACE refreshes the in-progress
    bucket; older buckets are already stored.
    """
    now = time.time()
    try:
        with _connect() as conn:
            # metrics — recent lookback per tier
            for tbl, bsize, look in (("metrics_1m", 60, 2 * 3600),
                                     ("metrics_1h", 3600, 3 * 86400)):
                cols = ", ".join(f"AVG({c}) AS {c}" for c in _METRIC_COLS)
                conn.execute(
                    f"INSERT OR REPLACE INTO {tbl} "
                    f"(bucket,{','.join(_METRIC_COLS)}) "
                    f"SELECT CAST(ts/{bsize} AS INT)*{bsize} AS bucket, {cols} "
                    f"FROM metrics WHERE ts >= ? GROUP BY bucket", (now - look,))
            # key_series (per-key)
            for tbl, bsize, look in (("key_series_1m", 60, 2 * 3600),
                                     ("key_series_1h", 3600, 3 * 86400)):
                conn.execute(
                    f"INSERT OR REPLACE INTO {tbl}(bucket,label,reqs) "
                    f"SELECT CAST(ts/{bsize} AS INT)*{bsize} AS bucket, label, "
                    f"AVG(reqs) FROM key_series WHERE ts >= ? "
                    f"GROUP BY bucket, label", (now - look,))
            # proc_series (per-app)
            for tbl, bsize, look in (("proc_series_1m", 60, 2 * 3600),
                                     ("proc_series_1h", 3600, 3 * 86400)):
                conn.execute(
                    f"INSERT OR REPLACE INTO {tbl}(bucket,kind,app,val) "
                    f"SELECT CAST(ts/{bsize} AS INT)*{bsize} AS bucket, kind, app, "
                    f"AVG(val) FROM proc_series WHERE ts >= ? "
                    f"GROUP BY bucket, kind, app", (now - look,))
    except Exception:
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
    except Exception:
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
            except Exception:
                continue
        return out
    except Exception:
        return []


def prune() -> int:
    """Delete rows older than retention window. Returns rows removed."""
    cutoff = time.time() - config.DB_RETENTION_HOURS * 3600
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))
            return cur.rowcount or 0
    except Exception:
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
    except Exception:
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
    except Exception:
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
    except Exception:
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
    except Exception:
        return 0


def user_set_disabled(name: str, disabled: bool) -> bool:
    try:
        with _connect() as conn:
            cur = conn.execute("UPDATE users SET disabled = ? WHERE name = ?",
                               (1 if disabled else 0, name))
        return (cur.rowcount or 0) > 0
    except Exception:
        return False


def user_set_password(name: str, pw_hash: str) -> bool:
    try:
        with _connect() as conn:
            cur = conn.execute("UPDATE users SET pw_hash = ? WHERE name = ?",
                               (pw_hash, name))
        return (cur.rowcount or 0) > 0
    except Exception:
        return False


def user_set_must_change(name: str, must_change: bool) -> bool:
    """Force (or clear) the first-login password-change requirement for a user."""
    try:
        with _connect() as conn:
            cur = conn.execute("UPDATE users SET must_change_pw = ? WHERE name = ?",
                               (1 if must_change else 0, name))
        return (cur.rowcount or 0) > 0
    except Exception:
        return False


def user_delete(name: str) -> bool:
    try:
        with _connect() as conn:
            conn.execute("DELETE FROM api_tokens WHERE owner = ?", (name,))  # cascade
            cur = conn.execute("DELETE FROM users WHERE name = ?", (name,))
        return (cur.rowcount or 0) > 0
    except Exception:
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
    except Exception:
        return False


def user_disable_guarded(name: str) -> bool:
    """Set disabled=1 unless it is the last admin. Atomic."""
    try:
        with _connect() as conn:
            cur = conn.execute(
                f"UPDATE users SET disabled = 1 WHERE name = ? "
                f"AND (role != 'admin' OR {_ADMIN_LEFT})", (name,))
        return (cur.rowcount or 0) > 0
    except Exception:
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
    except Exception:
        return False


# ── runtime settings (operator overrides persisted across restarts) ───────────
def settings_all() -> dict[str, str]:
    """Every stored setting override as {key: raw-value-string}."""
    try:
        with _connect() as conn:
            return {r[0]: r[1] for r in
                    conn.execute("SELECT key, value FROM settings").fetchall()}
    except Exception:
        return {}


def settings_set(key: str, value: str, now: float) -> bool:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO settings(key, value, updated) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                "updated = excluded.updated", (key, str(value), now))
        return True
    except Exception:
        return False


def settings_delete(key: str) -> bool:
    """Remove an override so the key falls back to its env/default value."""
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM settings WHERE key = ?", (key,))
        return (cur.rowcount or 0) > 0
    except Exception:
        return False


# ── per-key team overrides (Settings page → Teams) ────────────────────────────
def team_overrides() -> dict[str, str]:
    """Every admin-assigned key→team override as {key: team}."""
    try:
        with _connect() as conn:
            return {r[0]: r[1] for r in
                    conn.execute("SELECT key, team FROM key_teams").fetchall()}
    except Exception:
        return {}


def team_set(key: str, team: str, now: float) -> bool:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO key_teams(key, team, updated) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET team = excluded.team, "
                "updated = excluded.updated", (key, str(team), now))
        return True
    except Exception:
        return False


def team_delete(key: str) -> bool:
    """Drop an override so the key falls back to its LiteLLM-reported team."""
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM key_teams WHERE key = ?", (key,))
        return (cur.rowcount or 0) > 0
    except Exception:
        return False


def ui_layout_get(name: str) -> list | dict | None:
    """Return the persisted UI layout value for `name` (JSON-decoded), or None."""
    try:
        with _connect() as conn:
            r = conn.execute("SELECT value FROM ui_layout WHERE name = ?",
                             (str(name),)).fetchone()
        return json.loads(r[0]) if r and r[0] else None
    except Exception:
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
    except Exception:
        return False


def key_user_overrides() -> dict[str, str]:
    """Admin-assigned per-key user/email overrides as {key: user_name}."""
    try:
        with _connect() as conn:
            return {r[0]: r[1] for r in
                    conn.execute("SELECT key, user_name FROM key_user_ovr").fetchall()}
    except Exception:
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
    except Exception:
        return False


def key_user_delete(key: str) -> bool:
    """Drop a user override so the key falls back to its LiteLLM-reported user."""
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM key_user_ovr WHERE key = ?", (key,))
        return (cur.rowcount or 0) > 0
    except Exception:
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
    except Exception:
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
    except Exception:
        return False


# ── per-key monthly budget overrides (Settings page) ──────────────────────────
def key_budget_overrides() -> dict[str, float]:
    """Admin-set per-key monthly budgets {key: budget}. These override LiteLLM's
    reported max_budget and MONITOR_KEY_BUDGETS on the Spend & Quota rollup."""
    try:
        with _connect() as conn:
            return {r[0]: float(r[1]) for r in
                    conn.execute("SELECT key, budget FROM key_budgets_ovr").fetchall()}
    except Exception:
        return {}


def key_budget_set(key: str, budget: float, now: float) -> bool:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO key_budgets_ovr(key, budget, updated) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET budget = excluded.budget, "
                "updated = excluded.updated", (key, float(budget), now))
        return True
    except Exception:
        return False


def key_budget_delete(key: str) -> bool:
    """Drop a budget override so the key falls back to LiteLLM / env."""
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM key_budgets_ovr WHERE key = ?", (key,))
        return (cur.rowcount or 0) > 0
    except Exception:
        return False


# ── per-team monthly budget (inherited by every key in the team) ──────────────
def team_budgets() -> dict[str, float]:
    """Admin-set per-team monthly budgets {team: budget}. Each key in a team
    inherits its budget unless it has a per-key override."""
    try:
        with _connect() as conn:
            return {r[0]: float(r[1]) for r in
                    conn.execute("SELECT team, budget FROM team_budgets").fetchall()}
    except Exception:
        return {}


def team_budget_set(team: str, budget: float, now: float) -> bool:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO team_budgets(team, budget, updated) VALUES (?, ?, ?) "
                "ON CONFLICT(team) DO UPDATE SET budget = excluded.budget, "
                "updated = excluded.updated", (team, float(budget), now))
        return True
    except Exception:
        return False


def team_budget_delete(team: str) -> bool:
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM team_budgets WHERE team = ?", (team,))
        return (cur.rowcount or 0) > 0
    except Exception:
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
    except Exception:
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
    except Exception:
        return False


def model_cost_prices() -> dict[str, float]:
    """Admin-set per-model cost overrides {model: USD per 1M tokens}. Highest-precedence
    price source (UI counterpart of MONITOR_MODEL_COSTS); pins a model's cost when
    LiteLLM's own price is wrong/unreliable."""
    try:
        with _connect() as conn:
            return {r[0]: float(r[1]) for r in
                    conn.execute("SELECT model, usd_1m FROM model_cost_price").fetchall()}
    except Exception:
        return {}


def model_cost_price_set(model: str, usd_1m: float, now: float) -> bool:
    """Pin a model's cost to USD-per-1M-tokens. False on a bad value or DB error."""
    model = str(model or "").strip()
    if not model:
        return False
    try:
        v = float(usd_1m)
    except (TypeError, ValueError):
        return False
    if v < 0 or v != v or v == float("inf"):     # reject negative / NaN / inf
        return False
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO model_cost_price(model, usd_1m, updated) VALUES (?, ?, ?) "
                "ON CONFLICT(model) DO UPDATE SET usd_1m = excluded.usd_1m, "
                "updated = excluded.updated", (model, v, now))
        return True
    except Exception:
        return False


def model_cost_price_delete(model: str) -> bool:
    """Drop a cost override so the model falls back to env / LiteLLM pricing."""
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM model_cost_price WHERE model = ?", (model,))
        return (cur.rowcount or 0) > 0
    except Exception:
        return False


def model_kind_delete(model: str) -> bool:
    """Drop an override so the model falls back to name-based classification."""
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM model_cost_kind WHERE model = ?", (model,))
        return (cur.rowcount or 0) > 0
    except Exception:
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
    except Exception:
        return False


def api_token_lookup(token_hash: str) -> dict[str, Any] | None:
    """Resolve a presented token (by hash) to its owner + role, but only if the
    token is enabled AND its owner still exists and is not disabled. None otherwise."""
    try:
        with _connect() as conn:
            r = conn.execute(
                "SELECT t.id, t.owner, t.role FROM api_tokens t "
                "JOIN users u ON u.name = t.owner "
                "WHERE t.token_hash = ? AND t.disabled = 0 AND u.disabled = 0",
                (token_hash,)).fetchone()
        if not r:
            return None
        return {"id": r[0], "owner": r[1], "role": r[2]}
    except Exception:
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
    except Exception:
        return []


def api_token_count(owner: str) -> int:
    try:
        with _connect() as conn:
            r = conn.execute("SELECT COUNT(*) FROM api_tokens WHERE owner = ?",
                             (owner,)).fetchone()
        return int(r[0]) if r else 0
    except Exception:
        return 0


def api_token_revoke(tid: str, owner: str) -> bool:
    """Delete a token — scoped to its owner so a user can only revoke their own."""
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM api_tokens WHERE id = ? AND owner = ?",
                               (tid, owner))
        return (cur.rowcount or 0) > 0
    except Exception:
        return False


def api_token_touch(tid: str, ts: float) -> None:
    """Best-effort last-used stamp (throttled by the caller)."""
    try:
        with _connect() as conn:
            conn.execute("UPDATE api_tokens SET last_used = ? WHERE id = ?", (ts, tid))
    except Exception:
        pass


def user_update(name: str, email: str, role: str) -> bool:
    """Edit an existing user's profile (email + role). Returns True if a row was
    updated. Caller validates email/role and the last-admin guard."""
    try:
        with _connect() as conn:
            cur = conn.execute("UPDATE users SET email = ?, role = ? WHERE name = ?",
                               (email, role, name))
        return (cur.rowcount or 0) > 0
    except Exception:
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
    except Exception:
        return None


def user_set_webhook(name: str, url: str, enabled: bool) -> bool:
    try:
        with _connect() as conn:
            cur = conn.execute(
                "UPDATE users SET webhook_url = ?, webhook_enabled = ? WHERE name = ?",
                (url or None, 1 if enabled else 0, name))
        return (cur.rowcount or 0) > 0
    except Exception:
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
    except Exception:
        return []


def user_touch_login(name: str, ts: float) -> None:
    try:
        with _connect() as conn:
            conn.execute("UPDATE users SET last_login = ? WHERE name = ?",
                         (ts, name))
    except Exception:
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
    except Exception:
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
    except Exception:
        return []


def audit_prune(cutoff: float) -> int:
    """Delete audit rows older than `cutoff` (epoch). Returns rows removed."""
    try:
        with _connect() as conn:
            cur = conn.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff,))
            return cur.rowcount or 0
    except Exception:
        return 0
