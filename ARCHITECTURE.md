# Architecture

AI-Monitoring is a single aiohttp process with two concurrent concerns: a
**background sampling loop** that pulls data and writes SQLite, and an **HTTP
server** that serves dashboards + a JSON API reading from that same store.

```
                    ┌──────────────────────── app.py (aiohttp) ────────────────────────┐
                    │                                                                   │
  every 5s   ┌──────▼─────── sampling loop ───────┐        HTTP ┌── dashboards (web/) ──┐
  ───────────►  gather() all collectors           │        ◄────►  poll JSON API every 5s│
             │  → snapshot {collectors:{…}}        │             └───────────────────────┘
             │  → _metrics_row() flatten to cols   │                        ▲
             │  → db.insert / insert_metrics       │                        │
             │  → db.insert_key_series/proc_series │        ┌── JSON API handlers ──┐
             │  → _track_events (uptime)           │        │ /api/series /api/data │
             │  → anomaly.detect → notifier.process│        │ /api/keyseries …      │
             │  → every 60s: db.rollup()           │        └───────────┬───────────┘
             │  → every 1h:  db.prune*()           │                    │
             └──────┬─────────────────────────────┘                    │
                    │                                                    │
                    ▼                        SQLite (/data) ◄────────────┘
        collectors/ (host, procs, gpu,     metrics(+_1m,_1h) key_series(+rollups)
        litellm, ollama, llamacpp)         proc_series(+rollups) events anomalies
                                           alert_log samples
```

## Sampling loop (`app.py:_sampling_loop`)

Each tick (`MONITOR_SAMPLE_INTERVAL`, default 5s):

1. **Collect** — `asyncio.gather` runs all collectors concurrently. Host/GPU/
   procs are sync (`asyncio.to_thread`, they read `/proc` / run `nvidia-smi`);
   LiteLLM/Ollama/llama.cpp are async HTTP. Every collector returns a dict with
   an `available` bool and never raises — one dead backend can't stall the loop.
2. **Flatten** — `_metrics_row(snap)` maps the nested snapshot into ~24 flat
   numeric columns (`cpu`, `mem`, `gpu`, `wait`, `p95`, `reqrate`, `conc`, …),
   deriving VRAM% / tokens-per-watt / concurrency, with fallbacks (VRAM from
   Ollama when no GPU CLI).
3. **Persist** — `db.insert` (full JSON snapshot), `db.insert_metrics` (numeric
   columns), `db.insert_key_series` / `insert_proc_series` (per-key / per-app
   top-N).
4. **Derive** — `_track_events` records backend up/down transitions; `anomaly.detect`
   compares each key's recent rate to its baseline; both feed `notifier.process`,
   which debounces and delivers to the webhook + records to `alert_log`.
5. **Maintain** — `db.rollup()` every 60s (bounded to recent rows);
   `db.prune*()` every hour (tiered retention).

## Storage tiers (`db.py`)

| Table | Written | Retention | Read by |
|-------|---------|-----------|---------|
| `metrics` | every tick | `ROLLUP_RAW_HOURS` (24h) | series ≤1h |
| `metrics_1m` / `metrics_1h` | rollup() | `ROLLUP_MIN_DAYS` / `ROLLUP_HOUR_DAYS` | series ≤24h / beyond |
| `key_series` (+`_1m`/`_1h`) | every tick / rollup | raw 24h / 30d / 1y | `/api/keyseries` |
| `proc_series` (+`_1m`/`_1h`) | every tick / rollup | raw 24h / 30d / 1y | `/api/procseries` |
| `samples` | every tick | `MONITOR_DB_RETENTION_HOURS` | boot warm-load |
| `events` | on transition | `ROLLUP_HOUR_DAYS` | `/api/uptime` |
| `anomalies` / `alert_log` | on fire | `ROLLUP_HOUR_DAYS` | `/api/anomalies` / `/api/alerts` |

**Windowed reads** (`series`, `key_series`, `proc_series`) pick the table by
window length and accept an `end` epoch to pan back through history. All
downsampling is a single SQL `GROUP BY CAST((ts-start)/bucket)` averaging pass.
**Rollup is incremental** — it only re-aggregates the last few hours/days, so
per-minute cost is constant regardless of how much history is retained (this is
what makes multi-year retention cheap). SQLite runs in WAL mode; the `/data`
volume makes everything survive restarts.

## HTTP layer (`app.py`)

Middlewares (outer→inner): `_sechdr_mw` (security headers on every response) →
`_auth_mw` (token gate on `/` + `/api/*`, constant-time). Dashboard pages set an
HttpOnly cookie from `?token=` then 302 to a clean URL. Handlers read the
in-memory ring (`_latest`, `_ring`) for "now" and SQLite for history. An
in-process `startup_selfcheck()` verifies dashboards/assets/metrics/routes at
boot and logs the result.

## Collectors (`collectors/`)

Each exposes `sample()` returning `{available, …}` and degrades to
`{available: False, error}` on failure. Sources are all **native JSON / procfs**
— no Prometheus:

- `host` — `/proc/stat` (delta CPU%), `/proc/meminfo`, `statvfs`, loadavg.
- `procs` — per-PID `/proc/*/stat` + `statm`, aggregated by executable → top-N
  by CPU% (delta) and RSS. `pid: host` to see host processes.
- `gpu` — `nvidia-smi`/`rocm-smi` locally, **or remote** via SSH (`GPU_SSH`) or
  an HTTP agent (`GPU_METRICS_URL`); util/VRAM/power/temp/throttle.
- `litellm` — `/health/liveliness`, `/v1/models`, `/health`, `/health/backlog`
  (in-flight), `/spend/logs` → latency (avg/p50/p95/p99/SLO), rates, tokens,
  cost, cache, TTFT, per-model + per-key aggregation, recent failures.
- `ollama` — `/api/ps` (running + RAM/VRAM + params/quant), `/api/tags`,
  `/api/version`.
- `llamacpp` — `/health`, `/props`, `/slots` (active slots, tokens/s, kv-cache).

## Extension points

- **New metric** → add a key to `_METRIC_COLS` (auto-migrated across raw+rollup
  tables), emit it in `_metrics_row`, add a chart entry in a dashboard's `CHARTS`
  array. A test asserts every column is charted somewhere.
- **New collector** → add `collectors/x.py` with `sample()`, wire into
  `_sample_once`, add a dashboard.
- **New alert** → extend `alerts.evaluate` (threshold) or `anomaly.detect`
  (stateful). Both flow through the same debounced notifier.

## Dashboards (`web/`)

Each is a self-contained HTML page (inline CSS/JS, vendored Chart.js + DOMPurify
— no CDN). Shared conventions applied uniformly: theme head-script (day/night +
nav-visibility + alert-dot), collapsible sidebar, window + pan controls, one
DOMPurify-sanitised `innerHTML` sink (§17). They poll the JSON API every 5s.
