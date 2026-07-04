# AI-Monitoring

![AI-Monitoring](docs/img/banner.svg)

[![CI](https://github.com/tarrinho/ai_monitoring/actions/workflows/ci.yml/badge.svg)](https://github.com/tarrinho/ai_monitoring/actions/workflows/ci.yml)

Single-binary observability for a self-hosted LLM stack — **LiteLLM**, **Ollama**,
**llama.cpp**, **GPU**, and **host** — in one aiohttp app. Collectors poll each
backend's **native JSON** endpoints (no Prometheus, no exporters, no agents),
store to SQLite with tiered rollups, and serve six live dashboards.

<p align="center">
  <img src="docs/img/dash-ov-dark.png" alt="Overview dashboard" width="100%">
  <br><em>Overview — host, GPU, containers, top apps, and every metric as live time-series.</em>
</p>

- **Zero external deps to monitor** — reads `/proc`, Ollama `/api/*`, LiteLLM
  `/spend/logs` + `/health/*`, llama.cpp `/slots`, and `nvidia-smi` (local or
  over SSH). aiohttp + a couple pure-python libs; nothing else.
- **Six dashboards** — Overview, LiteLLM, GPU, Ollama, llama.cpp, Alerts.
  Collapsible sidebar, day/night, time-window + pan, CSV export.
- **Retention up to years** — raw 24h, 1-minute + 1-hour rollups (configurable,
  default 1 year) so charts stay fast and the DB stays bounded.
- **Alerting + anomaly detection** — thresholds, per-key spike/budget detection,
  webhook delivery, live "test" button, persisted history.
- **Hardened + multi-arch** — Alpine base (0 Trivy HIGH/CRITICAL), non-root,
  security headers, constant-time auth, cookie sessions; builds for
  amd64 / arm64 / arm/v7.

---

## Quick start

```bash
cp .env.example .env
$EDITOR .env          # set MONITOR_DASHBOARD_TOKEN + backend URLs
docker compose up -d
# dashboard: http://localhost:9925/?token=<your token>
```

With no backends configured it still runs — host CPU/RAM/disk + top-apps work
standalone, and the LLM/GPU dashboard links hide until their backend is set.

---

## Dashboards

| Path | Shows |
|------|-------|
| `/` (Overview) | Host CPU/mem/disk/load, **top-5 apps by CPU & RAM** + per-app evolution, uptime, and all metrics as time-series grouped into collapsible **Host / GPU / LLM** sections |
| `/litellm` | wait avg + **p50/p95/p99 + SLO**, req/s, prompt/completion tok/s, error %, cost/h, **backlog** (in-flight), TTFT, cache hit; per-model table (with p95/SLO); **top-10 keys** (bar + over-time, colored); **failed-request viewer**; **key anomalies**; concurrency-vs-latency |
| `/gpu` | util, VRAM used/%/total, power, temp, throttle, per-GPU table, tokens/watt — local `nvidia-smi`/`rocm-smi` **or a remote GPU box over SSH / HTTP agent** |
| `/ollama` | running/installed models, RAM/VRAM, %-on-GPU, per-model params/quant/unload-countdown, over-time charts |
| `/llamacpp` | tokens/s, active/total slots, busy %, KV-cache %, context size, status, loaded-model card, over-time charts |
| `/alerts` | configured channel, thresholds, active breaches, **"Send test alert"**, fired-alert history |

Common controls on every windowed page: **15m / 1h / 24h / 30d** buttons, **◀ ▶
pan** through history, **🌙/☀️ day-night** (persisted), **collapsible sidebar**,
**⬇ CSV** export. A pulsing red dot on the sidebar **Alerts** item appears from
any page when an alert is firing.

### Gallery

<table>
  <tr>
    <td width="50%"><img src="docs/img/dash-litellm-dark.png" alt="LiteLLM dashboard"><br><sub><b>LiteLLM</b> — latency p50/p95/p99, req/s, cost, backlog, per-model + top keys.</sub></td>
    <td width="50%"><img src="docs/img/dash-llamacpp-dark.png" alt="llama.cpp dashboard"><br><sub><b>llama.cpp</b> — tokens/s, slots, KV-cache, context, loaded model.</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/img/dash-gpu-dark.png" alt="GPU dashboard"><br><sub><b>GPU</b> — util, power, temp, tokens/watt, per-GPU table.</sub></td>
    <td width="50%"><img src="docs/img/dash-ollama-dark.png" alt="Ollama dashboard"><br><sub><b>Ollama</b> — running/installed models, %-on-GPU, RAM/VRAM, unload countdown.</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/img/dash-alerts-dark.png" alt="Alerts dashboard"><br><sub><b>Alerts</b> — channel, thresholds, active breaches, test button, history.</sub></td>
    <td width="50%"><img src="docs/img/dash-ov-light.png" alt="Light theme"><br><sub><b>Light theme</b> — every page is day/night, persisted per browser.</sub></td>
  </tr>
</table>

---

## Configuration (`.env`)

All settings are environment variables (git-ignored `.env`). Fail-fast at boot;
secrets are never logged or persisted. `0` / empty disables a feature.

### Core
| Var | Default | Meaning |
|-----|---------|---------|
| `MONITOR_HOST` / `MONITOR_PORT` | `0.0.0.0` / `9925` | listen address |
| `MONITOR_DB_PATH` | `/data/ai-monitoring.db` | SQLite path (on the `/data` volume) |
| `MONITOR_SAMPLE_INTERVAL` | `5` | seconds between samples |
| `MONITOR_HTTP_TIMEOUT` | `4` | per-collector request timeout |
| `MONITOR_DASHBOARD_TOKEN` | *(empty)* | if set, dashboard + API require it (Bearer / `?token=` → cookie). Empty = open |

### Backends (each optional)
| Var | Example | Meaning |
|-----|---------|---------|
| `LITELLM_BASE_URL` / `LITELLM_MASTER_KEY` | `http://host:4000` / `sk-…` | LiteLLM proxy + master key (for `/spend`,`/health`) |
| `LITELLM_SPEND_WINDOW_MIN` | `15` | rolling window for LiteLLM rates/latency |
| `LITELLM_HEAVY_INTERVAL` | `60` | seconds between the **heavy** LiteLLM calls (`/health` probes every deployment; `/spend/logs` pulls the whole day). Cheap signals (liveliness, backlog, models) still refresh every `SAMPLE_INTERVAL`. Raise it to lighten a busy proxy |
| `LITELLM_SPEND_ENABLED` | `1` | `0` = stop pulling `/spend/logs` (drops latency/cost/key panels, keeps cheap backlog/health) — the biggest load-shedder on a very busy proxy |
| `LITELLM_SPEND_MODE` | `full` | `full` = raw `/spend/logs` (latency percentiles, but pulls the whole growing day — heavy). **`lite` = server-side aggregates** (`/global/activity`, `/global/spend/keys`): tiny payloads, **~0 CPU, no freeze**; gives requests/tokens/cost/per-model/top-keys but **no latency**. Recommended on a busy proxy |
| `LITELLM_LOAD_SHED` | `0` | **adaptive kill-switch**: when host 1-min load **per core** ≥ this, the monitor auto-drops the two heavy calls (`/health` + full `/spend/logs`) and resumes when load falls. `0` = off; `~4` = "load is 4× the cores". Cheap calls keep running |
| `LITELLM_SPEND_MAX_ROWS` | `20000` | cap on `/spend/logs` rows parsed per poll (most-recent kept); bounds CPU/memory |
| `LITELLM_SPEND_TIMEOUT` | `20` | timeout (s) for the heavy `/health` + `/spend/logs` calls; the 4s default is too short for a busy proxy's whole-day query and blanks the panels |
| `LITELLM_CB_THRESHOLD` / `LITELLM_CB_COOLDOWN` | `3` / `300` | circuit breaker — after N consecutive heavy-call failures, stop calling for the cooldown (s), then probe once. Stops the monitor hammering (and freezing) a struggling proxy; auto-recovers |
| `LITELLM_SPEND_MAX_BYTES` | `67108864` | refuse a `/spend/logs` response larger than this (bytes) before deserializing |
| `LITELLM_DEBUG` | `0` | `1` = verbose per-call logging to `docker logs` (diagnose empty panels) |
| `SLO_LATENCY_MS` | `2000` | latency SLO target (% of requests under it) |
| `OLLAMA_BASE_URL` | `http://host:11434` | Ollama (no key needed) |
| `LLAMACPP_BASE_URL` / `LLAMACPP_API_KEY` | `http://host:8080` / *(opt)* | llama.cpp server |
| `GPU_METRICS_FILE` / `GPU_FILE_MAX_AGE` | `/gpu/gpu.csv` / `60` | **LOCAL host GPU, safest**: host writes `nvidia-smi` CSV to a file (see `deploy/gpu-metrics.service`); monitor reads it **read-only** — no SSH/network/shell. Stale file (> max-age) → panel hides |
| `GPU_SSH` / `GPU_SSH_PORT` / `GPU_SSH_KEY` | `user@gpuhost` / `22` / `/keys/id` | **remote** GPU via agentless SSH `nvidia-smi` |
| `GPU_METRICS_URL` | `http://gpuhost:9835/gpu` | **remote** GPU via an HTTP agent returning `{gpus:[…]}` |
| `MONITOR_CONTAINERS` | *(empty = all)* | **Containers** card: liveness + alive-time via the Docker API. **Empty → auto-discovers ALL host containers**; a comma-separated list restricts to those names. Needs the Docker socket mounted (compose does this) + `DOCKER_GID` set to the host `docker` group id so the non-root monitor can read it. **Note:** mounting `docker.sock` grants Docker control — the monitor only issues read-only GETs, but treat it accordingly. |

*(No GPU vars → local `nvidia-smi`/`rocm-smi`; no GPU present → the GPU dashboard hides.)*

### GPU setup

The monitor runs on Alpine and **can't run a passed-through `nvidia-smi`**, so it
never touches the GPU directly. Pick **one** of three ways to feed it GPU metrics:

**Mode 0 — local host GPU via a file (recommended, safest).** The host writes
`nvidia-smi` CSV to a file on a timer; the monitor bind-mounts it **read-only** —
no SSH, no network, no shell into the host.

```bash
# on the GPU host:
sudo mkdir -p /var/lib/aimon-gpu && sudo chmod 755 /var/lib/aimon-gpu
sudo cp deploy/gpu-metrics.service /etc/systemd/system/
sudo systemctl enable --now gpu-metrics.service      # writes /var/lib/aimon-gpu/gpu.csv
```
```yaml
# in the monitor's docker-compose.yml:
    volumes:
      - /var/lib/aimon-gpu:/gpu:ro
```
```bash
# in .env:
GPU_METRICS_FILE=/gpu/gpu.csv        # GPU_FILE_MAX_AGE=60 → stale file hides the panel
```

**Mode 1 — remote GPU over SSH** (agentless): `GPU_SSH=user@gpuhost` +
`GPU_SSH_KEY=/keys/id` (mount the key). The monitor runs `nvidia-smi` over SSH.

**Mode 2 — remote GPU over HTTP**: `GPU_METRICS_URL=http://gpuhost:9835/gpu`, an
endpoint returning `{"gpus":[{util,vram_used,vram_total,power,temp,…}]}`.

> **Unified-memory GPUs (e.g. NVIDIA GB10 / DGX Spark):** `nvidia-smi` reports no
> separate VRAM, so **VRAM tiles/charts are intentionally hidden** — util, power,
> temperature and tokens/watt still work. This is expected, not a misconfiguration.

### Alerting (threshold `0` = off)
| Var | Default | Fires when |
|-----|---------|-----------|
| `ALERT_CPU_PCT` / `ALERT_MEM_PCT` / `ALERT_DISK_PCT` | `0` | host CPU / mem / disk % ≥ value |
| `ALERT_GPU_PCT` / `ALERT_VRAM_PCT` | `0` | GPU util / VRAM % ≥ value |
| `ALERT_LLM_WAIT_MS` / `ALERT_BACKLOG` | `0` | LiteLLM avg wait / in-flight backlog ≥ value |
| `ALERT_ON_BACKEND_DOWN` | `1` | a configured backend goes down |
| `ALERT_REPEAT_MIN` | `30` | cooldown before a still-firing alert re-notifies |
| `ALERT_WEBHOOK_URL` | *(empty)* | delivery target — `POST {source, text}` |

### Per-key anomaly / abuse detection (`0` = off)
| Var | Default | Meaning |
|-----|---------|---------|
| `ANOMALY_FACTOR` | `4` | alert when a key's recent req-rate ≥ N× its hourly baseline |
| `ANOMALY_MIN_REQS` | `20` | ignore keys below this many reqs (noise floor) |
| `ANOMALY_KEY_BUDGET_HR` | `0` | alert when a key's spend exceeds $/hour |

### Retention (tiered rollups)
| Var | Default | Keeps |
|-----|---------|-------|
| `ROLLUP_RAW_HOURS` | `24` | raw 5-second samples + per-key/app detail |
| `ROLLUP_MIN_DAYS` | `30` | 1-minute averaged rollups |
| `ROLLUP_HOUR_DAYS` | `365` | 1-hour averaged rollups (the long horizon) |
| `MONITOR_DB_RETENTION_HOURS` | `720` | full JSON snapshots |

Charts pick the tier by window: raw ≤1h, 1-min ≤24h, 1-hour beyond. Aggregation
is bounded to recent rows, so retention length doesn't affect per-tick cost.
Steady-state size ≈ a few hundred MB at 1 year; set the rollup days higher for
multi-year (e.g. `ROLLUP_HOUR_DAYS=730`).

---

## Deployment

### Docker Compose (default)
```bash
docker compose up -d          # builds locally, runs the QA gate, serves :9925
```
`pid: host` (in compose) lets the top-apps view see host processes.

### Multi-arch (amd64 / arm64 / arm/v7)
Pure-python → one Alpine Dockerfile serves all arches.
```bash
docker run --privileged --rm tonistiigi/binfmt --install arm   # one-time (armv7 QEMU)
deploy/build-multiarch.sh                                       # builds + Trivy-scans all three
```
arm64/amd64 run the full pytest gate natively; armv7 builds emulated with
`RUN_TESTS=0` (already validated on the native arch).

### Ship a pre-built image to a server (no registry)
```bash
docker save ai-monitoring:1.0.0-armv7 | gzip > aimon.tar.gz
scp aimon.tar.gz deploy/docker-compose.server.yml .env.example user@server:~/aimon/
# on the server:
docker load < aimon.tar.gz && docker tag ai-monitoring:1.0.0-armv7 ai-monitoring:1.0.0
mv docker-compose.server.yml docker-compose.yml && cp .env.example .env  # fill in
docker compose up -d
```

### Behind a reverse proxy at a sub-path
The app honours `X-Forwarded-Prefix`, so it can live under a path (not just its
own vhost). Apache example — serve it at `https://host/ai_monitoring/`:
```apache
ProxyPreserveHost On
RequestHeader set X-Forwarded-Proto  "https"
RequestHeader set X-Forwarded-Prefix "/ai_monitoring"
ProxyPass        /ai_monitoring/ http://127.0.0.1:9925/
ProxyPassReverse /ai_monitoring/ http://127.0.0.1:9925/
```
The proxy strips the prefix (app routes stay unprefixed); the app rewrites the
absolute links/fetches in its HTML + the auth cookie-redirect to include it. No
header → served at root, unchanged. Requires `MONITOR_HOST=0.0.0.0` in `.env` so
Docker's port-forward reaches the app (binding container-loopback makes the
published port reset the connection).

### Public tunnel + boot autostart
- `deploy/tunnel.sh [ngrok|cloudflared]` — persistent tunnel via a `systemd --user`
  unit (survives shell exit), prints the URL.
- `deploy/ai-monitoring.container.service` — systemd unit to auto-start on boot.

---

## Local test environment

`test-env/` spins up **real** backends for the monitor to read:
```bash
docker compose -f test-env/docker-compose.yml up -d   # Ollama + LiteLLM + Postgres (+ traffic gen)
docker exec aimon-ollama ollama pull qwen2.5:0.5b
```
Loopback-bound, secrets in a git-ignored `test-env/.env`. Point the monitor's
`.env` at `http://litellm:4000` / `http://ollama:11434` (shared network) or the
localhost ports.

---

## API

All gated by the dashboard token when set; `/healthz` is always open.

| Endpoint | Returns |
|----------|---------|
| `GET /api/data?history=N` | latest snapshot + recent samples |
| `GET /api/series?window=&end=` | downsampled metric series (panning via `end`) |
| `GET /api/keyseries?window=&end=` | top-10 API keys over time (multi-line) |
| `GET /api/procseries?kind=cpu\|ram&window=&end=` | top-5 apps over time |
| `GET /api/uptime?window=` | per-backend uptime % + transition events |
| `GET /api/anomalies` | active + recent per-key anomalies |
| `GET /api/alerts` · `POST /api/alerts/test` | channels/thresholds/active/history · fire a test |
| `GET /api/nav` | which backend dashboards are configured (nav visibility) |
| `GET /api/export?window=&format=csv\|json` | export a window |
| `GET /healthz` | liveness (container probe) |

---

## Architecture

![Architecture](docs/img/architecture.svg)

See [ARCHITECTURE.md](ARCHITECTURE.md). In short: a background loop samples all
collectors every `SAMPLE_INTERVAL`, flattens them into numeric metric columns
+ per-key/per-app series, writes SQLite (with hourly rollup + prune), evaluates
alerts + anomalies through a debounced webhook notifier, and serves the
dashboards which poll the JSON API.

```
app.py           aiohttp app: routes, sampling loop, auth, security headers
config.py        env-driven config (fail-fast)
db.py            SQLite: metrics + rollups, key/proc series, events, alerts, uptime
alerts.py        threshold eval + webhook notifier (debounce + recovery + history)
anomaly.py       per-key spike / budget detection
collectors/      host, procs, gpu, litellm, ollama, llamacpp
web/             six dashboards (index, litellm, gpu, ollama, llamacpp, alerts)
deploy/          multi-arch build, tunnel, systemd, server compose
test-env/        real Ollama + LiteLLM + Postgres for integration
tests/           full QA suite (static + dynamic + live-integration)
```

---

## Security

- **Auth**: optional dashboard token — constant-time compare, HttpOnly
  `SameSite=Strict` cookie session (token leaves the URL after first load).
- **Headers**: `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, nosniff,
  no-referrer, server-version hidden.
- **XSS**: every dynamic value HTML-escaped; single DOMPurify-sanitised
  `innerHTML` sink per page; tracked timers.
- **SSRF**: GPU-agent fetch restricted to `http(s)`, bypasses proxy env.
- **Secrets**: env-only, git-ignored, never logged or stored; boot banner
  redacts. Container runs **non-root** on **Alpine** (0 Trivy HIGH/CRITICAL).

---

## Testing

`pytest tests/` — static (source/dashboard/Dockerfile invariants) + dynamic
(collectors vs stub servers, endpoints, DB rollup/pan/retention) + live
(real test-env, auto-skipped when down). **The Docker build runs the full suite
as a gate** — a failing test aborts `docker build` before an image exists.
```bash
pip install -r requirements-dev.txt && pytest
```
