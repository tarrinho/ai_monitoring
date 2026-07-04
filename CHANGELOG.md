# Changelog

All notable changes to AI-Monitoring are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) ·
Versioning: [SemVer](https://semver.org/).

## [1.0.4] — 2026-07-04

### Added
- **LiteLLM "Load vs resource impact" chart** — a dual-axis correlation chart on
  the LiteLLM dashboard plotting request rate (req/s) against the per-execution
  cost signals of a GPU-served LLM: GPU util %, KV-cache %, and the llama.cpp
  process CPU %. (Exact per-request CPU/RAM isn't measurable with interval
  sampling and is mostly noise for a GPU-bound model — this shows the honest
  correlation. Host RAM is static; KV-cache is the real per-request memory.)
- **Per-model resource columns** — the LiteLLM per-model table gained **svc CPU**
  and **svc RAM** columns: each model's serving-process CPU % and RSS, mapped via
  its served-by backend (llama.cpp → `llama-server`, ollama → `ollama`) from the
  existing procs collector — no new sampling, no observer-effect.

### Fixed
- **CI (GitHub Actions)** — pinned `aquasecurity/trivy-action` to an existing
  release (`@0.35.0`; `@0.24.0` no longer resolves) in both the filesystem and
  image scans, and added a `ruff.toml` so `ruff check .` passes: test fixtures may
  use compact semicolon one-liners / grouped imports (E701/E702/E401/E402 relaxed
  in `tests/**` only — app code stays strict). Overview: Uptime card stacked under
  the GPU card; the GPU card badge shows `live` instead of the `file nvidia` mode.

### Docs
- **README GPU-setup section** — consolidated step-by-step for the three GPU
  feed modes (local file via `deploy/gpu-metrics.service`, remote SSH, remote
  HTTP agent) plus the unified-memory GB10 caveat (VRAM reads N/A by design).
- **`rules.md`: documentation is English-only** — a global convention (enforced at
  §15) that everything committed to the repo is written in English.
- **`rules.md`: never run the monitored backends on the monitor host** — a global
  constraint that LiteLLM / Ollama / llama.cpp must not be installed or run
  alongside AI-Monitoring (they would compete for GPU/CPU/RAM with the server it
  watches); the monitor only reaches REMOTE backends over the network.

## [1.0.3] — 2026-07-04

### Added
- **Auth brute-force protection** — per-IP failed-token rate limiting: after
  `MONITOR_AUTH_MAX_FAILS` (10) bad tokens within `MONITOR_AUTH_WINDOW_S` (300s),
  that IP is locked out (**HTTP 429** + `Retry-After`) for `MONITOR_AUTH_LOCKOUT_S`
  (900s) — a correct token is refused while locked. `MONITOR_AUTH_TRUSTED_PROXY`
  gates whether the client IP is read from `X-Forwarded-For` (off by default so the
  header can't be spoofed to dodge the lockout). Weak tokens (<16 chars) are
  flagged at boot. Essential now that the dashboard can be exposed via a tunnel.
- **Live push over SSE** — new `GET /api/stream` (`text/event-stream`) pushes the
  latest snapshot every `SAMPLE_INTERVAL` over one connection. The Overview uses it
  in place of the 5 s snapshot poll and is self-healing — on any stream error it
  falls back to polling and the browser auto-reconnects. Windowed series still poll.
- **Model load/unload timeline** — the sampling loop now records `kind='model'`
  events when Ollama models load/unload or llama.cpp swaps its loaded model. New
  `GET /api/events?kind=model` and a **Model activity** card on the Ollama page.
  The `events` table gained a `kind` column (idempotent migration); uptime only
  counts `kind='state'`, so the model timeline never distorts uptime %.
- **GitHub Actions CI** (`.github/workflows/ci.yml`) running the rules.md controls
  on every push/PR: TruffleHog secret scan, lint+type (ruff/bandit/semgrep/mypy/
  vulture), pytest (static+dynamic), a Trivy **filesystem** scan (deps/config/
  secrets) and a **build-gate + Trivy image** scan (HIGH/CRITICAL → fail). The
  workflow and `.trufflehog-exclude` are now in the publish allow-list so they
  actually reach GitHub.

## [1.0.2] — 2026-07-03

### Changed
- **LiteLLM dashboard, lite mode** — hide the metrics that only exist under
  `spend_mode=full` (p50/p95/p99, SLO, wait, req/s, error %, cost/h, TTFT, cache)
  instead of a wall of "—"; the per-model table drops the same columns. Header
  badge now reads `live · lite`, a **Tokens today** tile is always shown, and the
  note explains latency **+ rates + cost + cache** are aggregate-mode-only.
- **Overview** — the Host card now carries a CPU/Mem sparkline (fills the card so
  it matches its row height); top cards size to their content (`align-items:start`)
  instead of stretching; a single-GPU host shows a compact GPU caption instead of
  the redundant per-GPU table.

### Added
- **Host RAM-pressure banner** on the Overview when memory ≥ 90% (with a
  stop-containers / reduce-context hint).

### Fixed
- LiteLLM per-model rows with an empty model name now render as `(unnamed)`
  instead of a blank cell.
- **LiteLLM down-detection** — a `/health/liveliness` **timeout or 5xx** is now
  reported as the backend being **down** instead of up. Previously only a raw
  connection error counted as down, so a saturated/timing-out proxy read as
  healthy and the heavy `/spend` call still fired at it — the exact hammering the
  circuit-breaker/decoupled-loop design exists to prevent.
- **Container collector** — per-container inspects now run **concurrently**, so
  the aggregate sample time stays ≈ one timeout regardless of container count and
  can no longer overrun the backend loop's `wait_for` bound (which previously
  cancelled the sample every tick on a busy host → permanently stale panel).
  `_last_seen` is also pruned (>1 week, auto-discover mode) to bound memory.

## [1.0.0] — 2026-07-03

First public release. AI-Monitoring is a **read-only**, dependency-light aiohttp
monitor for a local LLM stack: it samples host, GPU, Ollama, llama.cpp, LiteLLM
and containers, stores tiered time-series in SQLite, evaluates alerts + per-key
anomalies, and serves token-gated dashboards — without ever mutating or
overloading the systems it watches.

### Added — Collectors
- **host** — CPU %, memory %, disk %, load average, core count (pure `/proc`).
- **procs** — top-5 apps by CPU and by RAM, with per-app time-series.
- **gpu** — util, VRAM used/total/%, power, temperature, throttle, per-GPU table,
  tokens/watt. Sources: local `nvidia-smi`/`rocm-smi`, a file written by a host
  agent, a remote GPU box over SSH, or an HTTP metrics agent. Handles
  unified-memory GPUs (e.g. GB10) that report no separate VRAM.
- **ollama** — running/installed models, model RAM/VRAM, %-resident-on-GPU,
  params/quant/family, keep-alive unload countdown, version.
- **llamacpp** — `/health` status (incl. `loading`), model path, context size,
  slot count/active/busy %, KV-cache %, tokens/s (reads both top-level and
  nested `.timings` slot shapes).
- **litellm** — requests, tokens/day, backlog (in-flight), per-model breakdown,
  top-10 keys, spend; latency (wait/p50/p95/p99/TTFT/SLO), req/s, prompt &
  completion tok/s, error %, cost/h, cache-hit in full mode.
- **containers** — Docker liveness + uptime / down-duration per container.

### Added — Dashboards (six, token-gated)
- **Overview `/`** — host CPU/mem/disk/load, top-5 apps by CPU & RAM with per-app
  evolution, uptime, and every metric as time-series grouped into collapsible
  **Host / GPU / LLM** sections.
- **LiteLLM `/litellm`** — wait avg + p50/p95/p99 + SLO, req/s, prompt/completion
  tok/s, error %, cost/h, backlog, TTFT, cache-hit; per-model table; top-10 keys
  (bar + colored over-time); failed-request viewer; key anomalies;
  concurrency-vs-latency.
- **GPU `/gpu`** — util, power, temp, throttle, per-GPU table, tokens/watt
  (VRAM tiles shown only on discrete GPUs).
- **Ollama `/ollama`** — running/installed models, RAM/VRAM, %-on-GPU, per-model
  params/quant/unload-countdown, over-time charts.
- **llama.cpp `/llamacpp`** — tokens/s, active/total slots, busy %, KV-cache %,
  context size, status, loaded-model card, over-time charts.
- **Alerts `/alerts`** — configured channel, thresholds, active breaches, "Send
  test alert", fired-alert history.
- Common controls on every windowed page: **15m / 1h / 24h / 30d** windows,
  **◀ ▶ history pan**, **🌙/☀️ day-night** (persisted), **collapsible sidebar**,
  **⬇ CSV export**, and a pulsing red dot on the sidebar Alerts item while an
  alert is firing.
- **Empty-chart auto-hide** — a metric with no data in the window hides its tile
  (self-healing: reappears when data returns); collapsed groups re-count visible
  tiles.
- **Containers card** — show/hide-exited toggle (exited hidden by default),
  persisted; down-duration for stopped containers.

### Added — API (JSON, token-gated; `/healthz` open)
- `GET /api/data?history=N` — latest snapshot + recent samples.
- `GET /api/series?window=&end=` — downsampled metric series (history pan via `end`).
- `GET /api/keyseries` — top-10 API keys over time.
- `GET /api/procseries?kind=cpu|ram` — top-5 apps over time.
- `GET /api/uptime?window=` — per-backend uptime % + transition events.
- `GET /api/anomalies` — active + recent per-key anomalies.
- `GET /api/alerts` · `POST /api/alerts/test` — channels/thresholds/active/history · fire test.
- `GET /api/nav` — which backends are configured (drives nav visibility).
- `GET /api/export?window=&format=csv|json` — export a window.
- `GET /healthz` — liveness (container probe).

### Added — Storage & processing
- SQLite store: flat numeric metric columns + per-key / per-app series, events,
  alerts, uptime.
- **Tiered retention** — raw 24h + 1-minute and 1-hour rollups, configurable to
  years; hourly rollup + prune.
- **Alerting** — threshold evaluation with a debounced webhook notifier
  (recovery + history); channel test.
- **Anomaly detection** — per-key spike and budget-abuse detection.

### Added — Load-safety (observer-effect guards)
- LiteLLM `/spend/logs` JSON parsed **off the event loop**, throttled, byte-capped,
  timeout-bounded; **lite spend mode** using `/global/activity` aggregates
  (~200 ms, ~0 CPU) vs the whole-day raw pull.
- **Circuit breaker** for a failing/slow proxy (stop-and-recover).
- Per-deployment `/health` probing off by default.
- **GPU sampling decoupled** into its own loop; every backend loop and the main
  tick are `asyncio.wait_for`-bounded so a wedged `nvidia-smi` (D-state) can never
  freeze the sampler.

### Added — Deployment & ops
- Single Alpine **Dockerfile** with an in-image test gate (`RUN_TESTS=1` runs the
  suite; no pass → no image / `/qa-passed` marker).
- **Multi-arch** build (`deploy/build-multiarch.sh`): amd64 / arm64 / arm/v7 +
  Trivy scan each.
- `docker-compose.yml` (+ override), server compose, systemd unit
  (`deploy/ai-monitoring.container.service`), host GPU-metrics service, and a
  persistent tunnel helper (`deploy/tunnel.sh` — ngrok / cloudflared).
- Reverse-proxy sub-path support; ship-a-tarball flow (no registry needed).
- `deploy/publish-github.sh` — publish source to GitHub via an allow-list +
  secret-scan gate (no secrets / artefacts / internal references).

### Added — Security
- Optional dashboard token — constant-time compare, HttpOnly cookie flow.
- Security headers: `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`,
  nosniff, referrer-policy; self-hosted assets (no CDN).
- XSS: single DOMPurify-sanitised `innerHTML` sink per page + `escapeHtml`;
  `setInterval` leak prevention (`_timers` + `beforeunload`).
- SSRF: GPU-agent fetch restricted to `http(s)`, bypasses proxy env.
- Secrets env-only, git-ignored, never logged or stored; boot banner on weak/missing.

### Added — Quality pipeline
- Full QA suite: `tests/test_static_qa.py` (HTML/JS + source invariants),
  `tests/test_dynamic_qa.py` (collectors, endpoints, series, alerts),
  `tests/test_testenv.py` (live Ollama + LiteLLM + Postgres integration).
- **`rules.md`** — 0–18 build/test/security/release pipeline (version, static +
  dynamic tests, observer-effect, secret-leak, Bandit/Semgrep/ruff/mypy/vulture,
  Trivy, dashboard-security, black-box dynamic check, multi-arch gate, status
  report). Validation records under `validation/<version>.md`.

[1.0.4]: https://github.com/tarrinho/ai_monitoring/releases/tag/v1.0.4
[1.0.3]: https://github.com/tarrinho/ai_monitoring/releases/tag/v1.0.3
[1.0.2]: https://github.com/tarrinho/ai_monitoring/releases/tag/v1.0.2
[1.0.0]: https://github.com/tarrinho/ai_monitoring/releases/tag/v1.0.0
