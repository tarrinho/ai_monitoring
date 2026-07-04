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
WINDOWS = {"15m": 900, "1h": 3600, "24h": 86400, "30d": 2592000}


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
                top_n: int = 5, end: float | None = None) -> dict[str, Any]:
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
        return {"apps": top, "points": [buckets[k] for k in sorted(buckets)]}
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
