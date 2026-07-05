# Changelog

All notable changes to AI-Monitoring are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) ·
Versioning: [SemVer](https://semver.org/).

## [1.2.2] — 2026-07-05

### Added
- **Per-user alert webhooks.** Each user configures **their own** webhook at
  `/account` (Slack / Discord / generic JSON POST) with an enable toggle and a
  *Send test* button. When an alert fires, the notifier fans out to every enabled
  webhook (of non-disabled users) **plus** the operator-set global
  `ALERT_WEBHOOK_URL` (backward compatible); recipients are resolved + validated
  once per tick. Backed by `GET/POST /api/account/webhook` and
  `POST /api/account/webhook/test` (session-only, CSRF-protected); set/test are
  audited (`webhook.set`, `webhook.test`).

### Security
Per-user webhooks are user-supplied, so they are **SSRF-guarded**: a URL is refused
(on save **and** re-checked before each send — DNS-rebinding aware) when it resolves
to a private / loopback / link-local / reserved / metadata address; only `http(s)`
schemes are allowed and redirects are not followed. Opt-in hardening:
`MONITOR_WEBHOOK_HTTPS_ONLY=1`, host allowlist `MONITOR_WEBHOOK_ALLOW_HOSTS`, and
`MONITOR_WEBHOOK_ALLOW_PRIVATE=1` to relax the block on a trusted LAN. The
operator-set global `ALERT_WEBHOOK_URL` is trusted and unchecked.

Plus hardening from a full secure code review (no Critical/High found; these close
the Medium/Low findings). No functional change — all existing auth/cookie/stream/login
flows are unchanged and regression-tested (`test_sec_*`).
- **Opaque legacy-token cookie.** The `aimon_session` cookie now holds a random
  server-side session id instead of the master token itself, so cookie theft or a
  mis-logged `Set-Cookie` can no longer leak the raw shared secret.
- **Collector response size cap.** `fetch_json` caps a backend body at
  `MONITOR_HTTP_MAX_BYTES` (16 MiB) *before* deserialising, so a compromised/MITM'd
  backend can't stream a huge body and OOM the monitor. Outbound calls also stop
  following redirects (`allow_redirects=False`; urllib `_NoRedirect` for the GPU
  HTTP feed) — an SSRF-to-metadata guard.
- **Open-redirect fixed.** `_safe_path`/`_login_dest` now reject a backslash, so
  `?next=/\evil.com` (which browsers normalise to `//evil.com`) can't bounce a user
  off-site.
- **Alerts test is admin-only + CSRF.** `POST /api/alerts/test` now requires the
  admin role and a CSRF token (was reachable by any logged-in viewer); the *test*
  button is hidden for non-admins.
- **Login timing equalised.** An unknown username now runs a decoy scrypt verify,
  removing the response-time side-channel that revealed which usernames exist.
- **Weak shared token refused at boot.** `validate()` now rejects a
  `MONITOR_DASHBOARD_TOKEN` shorter than 16 chars (was only a skippable warning).
- **Bounded auth/session state.** Server-side sessions are hard-capped
  (`MONITOR_SESSION_MAX`, default 2000, oldest-expiring evicted) and the per-IP
  brute-force maps are pruned, so neither can grow without bound.
- **SSH argument-injection hardening.** The GPU-over-SSH command refuses a host or
  key path beginning with `-` and inserts `--` before the host, so a config value
  like `-oProxyCommand=…` can't be parsed by `ssh` as an option.
- **Webhook SSRF: DNS-rebinding closed + CGNAT blocked.** Per-user webhooks now send
  over a dedicated session whose resolver re-checks the IP aiohttp actually connects
  to (`ttl_dns_cache=0`), so a low-TTL rebind after validation can't reach an internal
  host; the checked IP is the connected IP. `_ip_blocked` also rejects RFC 6598 CGNAT
  (`100.64.0.0/10`) and collapses IPv4-mapped IPv6. The `WEBHOOK_ALLOW_PRIVATE` opt-in
  is still honoured for trusted-LAN targets.
- **Webhook fan-out can't wedge the sampling loop (§6).** Per-user webhook resolution
  + delivery is now capped (`MONITOR_WEBHOOK_MAX_RECIPIENTS`, default 50), run
  concurrently, and time-boxed (`HTTP_TIMEOUT` per validate); the notifier tick is
  wrapped in a 15 s `wait_for`. A user pointing their webhook at a slow/blackholed
  host can no longer stall monitoring for everyone. The webhook POST is also released
  via `async with` (was leaking connections).
- **Auth lockout no longer self-locks the operator.** An expired opaque session
  cookie on an auto-polling dashboard is no longer counted as a brute-force strike —
  only a presented (guessable) bearer/query token is. A 256-bit session cookie can't
  be brute-forced, and counting an expired one locked the operator's own IP out.

## [1.2.1] — 2026-07-05

### Added
- **Self-service password change.** Every logged-in user (admin or viewer) now has
  an *Account* link in the sidebar → `/account`, where they can change their own
  password. Changing it **requires the current password** (proves it's really them)
  plus a policy-valid, different new one. On success the user's other sessions are
  signed out (the current one stays); the change is audited as `account.password`
  (and a wrong current password as `account.password.fail`). Backed by
  `GET /api/me` (session identity + CSRF) and `POST /api/account/password`
  (CSRF-protected, session-only — a bearer token is not a person).

## [1.2.0] — 2026-07-05

### Added
- **Audit trail.** The platform now records access + admin actions to a SQLite
  `audit_log` table, and admins review them in the *Activity log* section of
  `/admin/users` (filter by logins / user changes). Logged events: `login.ok`,
  `login.fail`, `login.lockout`, `logout`, and `user.create` / `user.disable` /
  `user.enable` / `user.delete` / `user.reset` — each with actor, target, client
  IP, and timestamp. Read via `GET /api/admin/audit` (admin-only). Rows are pruned
  by age (`MONITOR_AUDIT_RETENTION_DAYS`, default 90) alongside the metrics prune.

## [1.1.0] — 2026-07-05

### Added
- **Multi-user access (username + password login).** External users no longer
  share one token. Each account has a username, an **email**, a scrypt-hashed
  password (`hashlib.scrypt` — no new image dependency), and a role:
  - **admin** — full dashboard access **plus** a *Users* menu to create, disable,
    reset-password, and delete users (view-only or admin).
  - **viewer** — read-only dashboard access.
  Accounts live in SQLite (`users` table); admins manage them from `/admin/users`
  (UI) or `/api/admin/users` (JSON). The first admin is seeded from
  `MONITOR_ADMIN_USER` / `MONITOR_ADMIN_PASSWORD` / `MONITOR_ADMIN_EMAIL` on an
  empty users table (idempotent).
- **Login/session flow.** `/login` + `/logout`; server-side sessions
  (`aimon_user` cookie: HttpOnly, SameSite=Strict, Secure by default per F3),
  revalidated against the DB every request so disabling/deleting a user takes
  effect immediately. Login is IP rate-limited (reuses the F4 lockout). Session
  TTL via `MONITOR_SESSION_TTL_S` (default 7 days).
- Admins get a **Users** link + a **Logout** link injected into the sidebar;
  viewers see only Logout.

### Security
- Admin write endpoints are **CSRF-protected** (per-session token via
  `X-CSRF-Token`); bearer-token automation is exempt (not a browser-auto cookie).
- The last remaining admin cannot be disabled or deleted (lock-out guard).
- The legacy single `MONITOR_DASHBOARD_TOKEN` keeps working alongside user login
  (counts as admin for automation/bootstrap). F2 now treats *either* a token *or*
  at least one user account as configured auth.

## [1.0.7] — 2026-07-04

### Security
Internal secure code review hardening (no remotely-exploitable bug found; these
raise the floor and shrink blast radius):
- **F1 — Docker socket no longer host-root-by-default.** A `:ro` socket mount does
  not make the Docker API read-only. `docker-compose.yml` now runs a read-only
  `docker-socket-proxy` (allows only `GET /containers`) and the monitor reaches it
  over TCP via `MONITOR_DOCKER_API_URL`; the raw socket is not mounted into the
  monitor. Legacy direct-socket mode still works when the URL is unset.
- **F2 — no-token no longer boots silently open.** Running without
  `MONITOR_DASHBOARD_TOKEN` now fails config validation unless `MONITOR_ALLOW_OPEN=1`
  is set explicitly, so a forgotten token can't silently expose metrics.
- **F3 — session cookie is `Secure` by default.** The cookie carries the bearer
  token; it is now marked `Secure` unless `MONITOR_COOKIE_ALLOW_INSECURE=1`
  (local plain-HTTP testing only).
- **F4 — lockout no longer evadable via `X-Forwarded-For`.** With
  `AUTH_TRUSTED_PROXY=1` the client IP is now taken from the rightmost XFF entry
  (appended by the trusted proxy), so a client can't spoof a leftmost value to
  dodge the lockout or frame a victim IP.
- **F5 — CSP `script-src` uses a per-response nonce instead of `'unsafe-inline'`.**
  Inline `<script>` tags are stamped with a fresh nonce; an injected script without
  it won't execute. `style-src` keeps `'unsafe-inline'` for benign inline styles.

## [1.0.6] — 2026-07-04

### Added
- **gitleaks in the CI secret-scan** — a second, independent secret scanner now
  runs alongside TruffleHog in the `secret-scan` job, driven by a `.gitleaks.toml`
  (built-in rule set + an allowlist for the synthetic values in `tests/` and
  `.env.example`, which are the only non-real "secrets" committed). Fails the job
  on any leak in the working tree or commit history.

### Fixed
- **ruff E702 in `collectors/host.py`** — the `cpu_cores` parse used a
  `…; break` one-liner; split so `ruff check .` stays clean (source is strict;
  E70x are only relaxed under `tests/`).

### Docs
- **`ARCHITECTURE.md` brought in line with the code** — documents the `containers`
  collector, the **decoupled backend loops** (`_backend_loop` + `asyncio.wait_for`
  → `_backend_latest`) that keep a wedged `nvidia-smi`/proxy from stalling the tick,
  the `/api/stream` SSE channel + `/api/events` model timeline, the per-IP auth
  brute-force lockout, and that the per-deployment LiteLLM `/health` probe was
  removed (+ `spend_mode=lite` aggregates). Version bump cuts a clean release.

## [1.0.5] — 2026-07-04

### Tests
- **+7 QA tests** for the 1.0.5 changes: sidebar order (Overview→GPU→LiteLLM),
  full-width "metrics over time" (regression), default 24h window on the LLM pages,
  GPU name rendered in the header via `textContent` (security — no new HTML sink),
  the window start→end date range wiring, the Apache-2.0 LICENSE + README + publish
  allow-list, and the consolidated `ci.yml` (five control jobs + a badges job, old
  split workflows removed, per-control README endpoint badges).

### Changed
- **CI consolidated into one workflow with per-control badges** — the five split
  workflows were merged back into a single `ci.yml` (secret-scan / lint / tests /
  trivy-fs / build-scan run as jobs), so the Actions page shows **one aggregated
  run per push**. A final `badges` job writes each control's status as a shields
  "endpoint" JSON to an orphan `badges` branch, so the README keeps **individual
  per-control badges** (plus one overall CI badge). No third-party services.
- **Publish auto-tags the release** — after a successful `publish-github.sh` push,
  it pushes an annotated `v<version>` tag (unless it already exists, or
  `SKIP_TAG=yes`), which triggers the release workflow. Commit subjects are
  version+timestamp stamped so each push is distinct.
- **Full-width "metrics over time"** — the charts card on the GPU and LiteLLM
  dashboards now spans every grid column (`grid-column: 1 / -1`) instead of two,
  so on wide screens it uses the whole width instead of ~50%.
- **Default time window is now 24h** on the LiteLLM, Ollama, and llama.cpp
  dashboards (was 1h) — their charts open on a full day by default; the 15m / 1h /
  30d buttons and history pan are unchanged.

## [1.0.4] — 2026-07-04

### Added
- **Release workflow** (`.github/workflows/release.yml`) — pushing a `vX.Y.Z` tag
  now publishes a **GitHub Release** (notes pulled from this CHANGELOG) and pushes
  the **multi-arch container image** (amd64 / arm64 / armv7) to GitHub Packages
  (`ghcr.io/tarrinho/ai_monitoring`), using the built-in `GITHUB_TOKEN` — no extra
  secrets. Each publish commit is now titled with the version + a UTC timestamp so
  successive pushes have distinct descriptions.
- **Per-control CI badges** — the single `ci.yml` workflow was split into five
  independent workflows (`secret-scan`, `lint`, `tests`, `trivy-fs`, `build-scan`),
  each surfacing its own GitHub Actions status badge in the README so a failure is
  attributable to a specific control at a glance.
- **LiteLLM "Load vs resource impact" chart** — a dual-axis correlation chart on
  the LiteLLM dashboard plotting request rate (req/s) against the per-execution
  cost signals of a GPU-served LLM: GPU util %, KV-cache %, the llama.cpp process
  **CPU %** and **RAM %** (RSS / host memory). (Exact per-request CPU/RAM isn't
  measurable with interval sampling and is mostly noise for a GPU-bound model —
  this shows the honest correlation. Host RAM is static; KV-cache is the real
  per-request memory.)
- **Dedicated CPU + RAM over-time charts** on the LiteLLM dashboard — one line per
  LLM serving process (`llama-server`, `ollama`): CPU % over time, and RSS (RAM)
  over time. Fed from the procs collector (`/api/procseries`) — no new sampling.
- **Per-model resource columns** — the LiteLLM per-model table gained **svc CPU**
  and **svc RAM** columns: each model's serving-process CPU % and RSS, mapped via
  its served-by backend (llama.cpp → `llama-server`, ollama → `ollama`) from the
  existing procs collector — no new sampling, no observer-effect.

### Tests
- **Expanded QA coverage (+13)** across categories: **security** (CSP
  script/object-src lock-down, HttpOnly+SameSite=Strict session cookie, GPU HTTP-
  agent SSRF scheme guard), **functional** (`/api/export` CSV+JSON shapes, robust
  `/api/series` bounds), **unit** (`config.validate` clean, redacted-summary key
  hiding, `_parse_spend_bytes` junk tolerance), **regression** (LiteLLM down-on-5xx
  liveliness; Overview GPU-badge `live`, Uptime-under-GPU, RAM-banner threshold),
  and **performance** (`_metrics_row` 500× pure builds < 2 s). Suite: 176 passing.

### Fixed
- **CI (GitHub Actions)** — pinned `aquasecurity/trivy-action` to an existing
  release (`@0.35.0`; `@0.24.0` no longer resolves) in both the filesystem and
  image scans, and added a `ruff.toml` so `ruff check .` passes: test fixtures may
  use compact semicolon one-liners / grouped imports (E701/E702/E401/E402 relaxed
  in `tests/**` only — app code stays strict). Cleared the Node.js-20 deprecation
  warnings: `actions/checkout@v4`→`v5`, `actions/setup-python@v5`→`v6` (both now
  node24), and `cache: "false"` on the Trivy steps to skip trivy-action's internal
  node20 `actions/cache`. Overview: Uptime card stacked under the GPU card; the GPU
  card badge shows `live` instead of the `file nvidia` mode.

### Docs
- **Apache-2.0 license** — added a `LICENSE` file (Apache License 2.0, © 2026
  Pedro Tarrinho) plus a README "License" section and license badge, matching the
  other projects. README badges: added `release` + `ghcr.io`; the image-size badge
  was dropped rather than depend on a small third-party badge service for GHCR.
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
