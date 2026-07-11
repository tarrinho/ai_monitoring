# Architecture

AI-Monitoring is a single aiohttp process with two concurrent concerns: a
**background sampling loop** that pulls data and writes SQLite, and an **HTTP
server** that serves dashboards + a JSON API reading from that same store.

```
                    ┌──────────────────────── app.py (aiohttp) ────────────────────────┐
                    │                                                                   │
  every 5s   ┌──────▼─────── sampling loop ───────┐        HTTP ┌── dashboards (web/) ──┐
  ───────────►  host+procs → _latest              │        ◄────►  SSE push + 5s poll     │
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
        litellm, ollama, llamacpp,         proc_series(+rollups) events anomalies
        containers)                        alert_log samples
```

## Sampling loop (`app.py:_sampling_loop`)

Each tick (`MONITOR_SAMPLE_INTERVAL`, default 5s):

1. **Collect (decoupled — the anti-freeze guarantee)** — the tick only `await`s
   the two cheap, always-fast collectors: `host` and `procs` (sync `/proc` reads
   via `asyncio.to_thread`). Every heavier backend — `gpu` (subprocess
   `nvidia-smi`), `litellm`, `ollama`, `llamacpp`, `containers` (HTTP / socket) —
   runs in its **own `_backend_loop`** on its own cadence, each call HARD-bounded
   by `asyncio.wait_for`, writing its latest result into `_backend_latest`. The
   tick reads that cache, so a wedged `nvidia-smi` (D-state) or a hung proxy can
   never stall sampling. Every collector returns `{available, …}` and never
   raises. The main tick is itself `wait_for`-bounded as a final backstop.
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
| `events` (`kind` state/model) | on transition / model swap | `ROLLUP_HOUR_DAYS` | `/api/uptime` (state) · `/api/events` (model) |
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
`_auth_mw` (token gate on `/` + `/api/*`, constant-time compare, HttpOnly-cookie
session). `_auth_mw` also does **per-IP brute-force lockout**: after
`AUTH_MAX_FAILS` bad tokens in `AUTH_WINDOW_S` an IP gets `429 + Retry-After` for
`AUTH_LOCKOUT_S` (client IP from `X-Forwarded-For` only when
`AUTH_TRUSTED_PROXY` is set, so the header can't be spoofed to dodge it); the
per-IP maps are pruned so they can't grow without bound, and server-side sessions
are hard-capped (`SESSION_MAX`). Dashboard pages set the cookie from `?token=`
then 302 to a clean URL — the cookie holds an **opaque session id, not the raw
token**, so the shared secret never lands in a browser cookie. A too-short
`MONITOR_DASHBOARD_TOKEN` (<16 chars) is refused at boot by `validate()`.
**Privilege tiers** (`_auth_ctx` / `_is_master_token_auth`): a login **session**
carries its DB role (admin/viewer) and a **PAT** carries its own role, but the
**shared master token** is dashboards-only — `_auth_mw` returns `403` when it hits an
admin path (`/settings`, `/admin/users`, `/api/admin/*`) or the Alerts surface
(`/alerts`, `/api/alerts*`), and `/api/nav` drops the Settings/Alerts links for it.
Handlers read the in-memory ring (`_latest`, `_ring`) for "now" and SQLite for
history.
`GET /api/stream` is a **Server-Sent Events** channel that pushes each new
snapshot over one connection (the Overview uses it and falls back to polling on
error); `/api/events?kind=model` serves the model load/unload timeline. An
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
- `litellm` — `/health/liveliness`, `/v1/models`, `/health/backlog` (in-flight),
  and `/spend/logs` → latency (avg/p50/p95/p99/SLO), rates, tokens, cost, cache,
  TTFT, per-model + per-key aggregation, recent failures. `spend_mode=lite` swaps
  the heavy whole-day log pull for server-side aggregates (`/global/activity`,
  `/global/spend/keys`). The per-deployment `/health` probe was removed — it
  exhausted unified-memory GPUs (see §6 load-safety).
- `ollama` — `/api/ps` (running + RAM/VRAM + params/quant), `/api/tags`,
  `/api/version`.
- `llamacpp` — `/health`, `/props`, `/slots` (active slots, tokens/s, kv-cache).
- `containers` — Docker Engine API over the mounted `docker.sock` (read-only
  GETs): liveness + uptime / down-duration per container; auto-discovers all host
  containers when `MONITOR_CONTAINERS` is empty. Per-container inspects run
  concurrently so the sample can't overrun its loop's `wait_for` bound.

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
nav-visibility + alert-dot), collapsible sidebar, window + pan controls (default
window 24h on the LiteLLM/Ollama/llama.cpp pages), one DOMPurify-sanitised
`innerHTML` sink (§17). The Overview takes live snapshots over the `/api/stream`
SSE channel and falls back to a 5s poll on any stream error; the windowed
time-series are always fetched on demand.
