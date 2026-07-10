# config.py — AI-Monitoring configuration (env-driven, fail-fast).
#
# ALL secrets and endpoints come from the environment. Nothing sensitive is
# hard-coded, logged, or persisted. Missing *required* values fail fast at
# boot with a clear message (never a silent default).
from __future__ import annotations

import os

VERSION = "AI-Monitoring_1.5.2"

# --- optional local .env support (dev convenience; no-op if absent) ----------
try:
    from dotenv import load_dotenv  # python-dotenv, optional
    load_dotenv()
except Exception:
    pass


def _str(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name, default)
    return v.strip() if isinstance(v, str) else v


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


# --- listen / storage --------------------------------------------------------
MONITOR_HOST = _str("MONITOR_HOST", "0.0.0.0")
MONITOR_PORT = _int("MONITOR_PORT", 9925)
DB_PATH      = _str("MONITOR_DB_PATH", "/data/ai-monitoring.db")

# --- sampling / retention ----------------------------------------------------
SAMPLE_INTERVAL   = _float("MONITOR_SAMPLE_INTERVAL", 5.0)     # seconds
RETENTION_SAMPLES = _int("MONITOR_RETENTION_SAMPLES", 8640)    # in-mem ring
DB_RETENTION_HOURS = _int("MONITOR_DB_RETENTION_HOURS", 720)   # on-disk prune
HTTP_TIMEOUT      = _float("MONITOR_HTTP_TIMEOUT", 4.0)        # per collector call
# Hard cap on a single collector response body (defends against a compromised /
# MITM'd backend returning a multi-GB body and OOM-ing the monitor). Generous —
# real backend JSON is tiny; /spend/logs uses its own dedicated byte cap.
HTTP_MAX_BYTES    = _int("MONITOR_HTTP_MAX_BYTES", 16 * 1024 * 1024)   # 16 MiB

# --- optional dashboard auth (token gate) ------------------------------------
# If set, dashboard + data endpoints require  Authorization: Bearer <token>
# or  ?token=<token>. If unset, dashboard is open (loopback/behind-proxy use).
DASHBOARD_TOKEN = _str("MONITOR_DASHBOARD_TOKEN")  # optional
# Security F2: running WITHOUT a token serves every page + the data API open. That
# is only safe on loopback / behind an authenticating proxy, so it must be an
# explicit choice — validate() turns a missing token into a FATAL boot error unless
# MONITOR_ALLOW_OPEN=1 is set. Prevents a forgotten token silently exposing metrics.
ALLOW_OPEN = (_str("MONITOR_ALLOW_OPEN", "0") or "0").lower() in ("1", "true", "yes", "on")
# Security F3: the session cookie carries the bearer token, so it must be marked
# Secure (HTTPS-only) by default. Set MONITOR_COOKIE_ALLOW_INSECURE=1 ONLY for local
# plain-HTTP testing, where the browser would otherwise drop a Secure cookie.
COOKIE_ALLOW_INSECURE = (_str("MONITOR_COOKIE_ALLOW_INSECURE", "0") or "0").lower() in ("1", "true", "yes", "on")

# --- multi-user access (username + password, SQLite-backed; see auth.py) -------
# Each user has an email, a role ('admin' can manage users, 'viewer' is read-only),
# and a scrypt password hash. The legacy single MONITOR_DASHBOARD_TOKEN keeps
# working alongside user sessions (automation / bootstrap). The first admin is
# seeded from these on an empty users table (idempotent — ignored once users exist).
ADMIN_USER     = _str("MONITOR_ADMIN_USER")
ADMIN_PASSWORD = _str("MONITOR_ADMIN_PASSWORD")
ADMIN_EMAIL    = _str("MONITOR_ADMIN_EMAIL")
# How long a login session stays valid before re-auth (seconds; default 7 days).
SESSION_TTL_S  = _float("MONITOR_SESSION_TTL_S", 7 * 24 * 3600.0)
# Hard ceiling on concurrent server-side sessions (login + legacy-token), so the
# in-memory session stores can't grow without bound. Oldest-expiring are evicted.
SESSION_MAX    = _int("MONITOR_SESSION_MAX", 2000)
# How long the access/admin audit trail is kept (days; admins review it in the UI).
AUDIT_RETENTION_DAYS = _int("MONITOR_AUDIT_RETENTION_DAYS", 90)

# --- Prometheus / OpenMetrics export -----------------------------------------
# GET /metrics exposes the latest snapshot in Prometheus text format so an existing
# Prometheus / Grafana / Datadog / AlertManager stack can scrape it (and a central
# Prometheus can aggregate a whole fleet of AI-Monitoring instances). It is gated
# like the rest of the API: a valid session, the dashboard token, OR a dedicated
# scrape-only token below. Set that so Prometheus gets a least-privilege credential
# instead of the full dashboard token.
METRICS_ENABLED = (_str("MONITOR_METRICS_ENABLED", "1") or "1").lower() in ("1", "true", "yes", "on")
METRICS_TOKEN   = _str("MONITOR_METRICS_TOKEN")   # optional scrape-only bearer
# Brute-force protection on the dashboard token: after AUTH_MAX_FAILS bad tokens
# from one client IP within AUTH_WINDOW_S seconds, that IP is locked out (429)
# for AUTH_LOCKOUT_S. Behind a reverse proxy, set AUTH_TRUSTED_PROXY=1 to read the
# real client IP from X-Forwarded-For (leave 0 if directly exposed, or an attacker
# can spoof the header to dodge the lockout).
AUTH_MAX_FAILS   = _int("MONITOR_AUTH_MAX_FAILS", 10)
AUTH_WINDOW_S    = _float("MONITOR_AUTH_WINDOW_S", 300.0)
AUTH_LOCKOUT_S   = _float("MONITOR_AUTH_LOCKOUT_S", 900.0)
# Per-ACCOUNT lockout (independent of the per-IP one above): after
# AUTH_USER_MAX_FAILS bad password attempts on the same username within
# AUTH_WINDOW_S, that account is locked for AUTH_USER_LOCKOUT_S — this protects a
# targeted account even when the attacker rotates source IPs.
AUTH_USER_MAX_FAILS  = _int("MONITOR_AUTH_USER_MAX_FAILS", 10)
AUTH_USER_LOCKOUT_S  = _float("MONITOR_AUTH_USER_LOCKOUT_S", 300.0)
AUTH_TRUSTED_PROXY = (_str("MONITOR_AUTH_TRUSTED_PROXY", "0") or "0").lower() in ("1", "true", "yes", "on")
# Log each collector's availability + error to stderr (docker logs) on startup
# and whenever it changes — so you can see WHY a panel is missing (e.g. GPU).
MONITOR_DEBUG = (_str("MONITOR_DEBUG", "0") or "0").lower() in ("1", "true", "yes", "on")

# --- backends (all optional; a missing backend is reported "unconfigured") ---
# LiteLLM (JSON endpoints only — NO prometheus).
LITELLM_BASE_URL   = _str("LITELLM_BASE_URL")           # e.g. http://host:4000
LITELLM_MASTER_KEY = _str("LITELLM_MASTER_KEY")         # Bearer for /spend,/health
LITELLM_SPEND_WINDOW_MIN = _int("LITELLM_SPEND_WINDOW_MIN", 15)  # latency window
# Optional per-key monthly budgets as JSON {"key-alias": 2000, ...} — drives the
# Spend & Quota panel until real max_budget is read from LiteLLM /key/info.
KEY_BUDGETS_JSON   = _str("MONITOR_KEY_BUDGETS", "")
# Self-hosted / internal model providers: their cost is a REFERENCE (imputed
# electricity/amortization), not real cash. Only external providers spend money.
# Matched against the model's provider prefix (before '/') or as a name substring.
INTERNAL_PROVIDERS = {
    p.strip().lower() for p in (_str(
        "MONITOR_INTERNAL_PROVIDERS",
        "ollama,llama-cpp,llama_cpp,llamacpp,vllm,huggingface,hf,"
        "gpt-oss,local,self-hosted,text-completion-openai",
    ) or "").split(",") if p.strip()
}
# Open-weight model FAMILIES that are self-hosted here even without a provider
# prefix (e.g. a bare "gemma4" or "qwen2.5"). Matched as a substring of the model
# name. Set MONITOR_INTERNAL_MODEL_FAMILIES="" to disable (rely on the provider
# prefix only) if you route open weights through a paid API.
INTERNAL_MODEL_FAMILIES = {
    p.strip().lower() for p in (_str(
        "MONITOR_INTERNAL_MODEL_FAMILIES",
        "gemma,qwen,mistral,mixtral,deepseek,starcoder,codellama,command-r,"
        "granite,phi-,phi3,phi4,yi-,llama",
    ) or "").split(",") if p.strip()
}
SLO_LATENCY_MS      = _float("SLO_LATENCY_MS", 2000.0)  # SLO target; % under this
# Verbose per-call logging for the LiteLLM collector (diagnose empty dashboards).
LITELLM_DEBUG = (_str("LITELLM_DEBUG", "0") or "0").lower() in ("1", "true", "yes", "on")
# The two heavy LiteLLM calls — /health (forces a probe of every deployment) and
# /spend/logs (returns the whole day's request logs) — poll on THIS slower cadence
# instead of every SAMPLE_INTERVAL, so a busy proxy isn't hammered. Cheap signals
# (liveliness, backlog, /v1/models) still refresh every sample.
LITELLM_HEAVY_INTERVAL = _float("LITELLM_HEAVY_INTERVAL", 60.0)  # seconds
# Escape hatches for a very busy proxy:
#   *_SPEND_ENABLED=0  -> stop pulling /spend/logs entirely (drops the whole-day
#                         query + transfer; loses latency/cost/key panels, keeps
#                         backlog/health/up-down which are cheap).
#   *_HEALTH_ENABLED=0 -> stop calling /health (no per-deployment probing).
#   *_SPEND_MAX_ROWS   -> hard cap on rows parsed per poll; only the most recent
#                         are kept (the window drops older ones anyway). Bounds
#                         CPU/memory when a day accumulates huge log volume.
LITELLM_SPEND_ENABLED = (_str("LITELLM_SPEND_ENABLED", "1") or "1").lower() in ("1", "true", "yes", "on")
# How to gather spend/usage:
#   full = raw /spend/logs (whole-day pull; gives latency percentiles but heavy)
#   lite = server-side aggregates (/global/activity[/model], /global/spend/keys) —
#          tiny payloads, ~0 CPU; gives requests/tokens/cost/per-model/top-keys but
#          NO latency. Best for a busy proxy. (SPEND_ENABLED=0 overrides to off.)
LITELLM_SPEND_MODE = (_str("LITELLM_SPEND_MODE", "full") or "full").lower()
# Adaptive load-shedding: when the host's 1-min load average PER CORE reaches this,
# the monitor automatically STOPS the heavy /spend/logs pull (full mode) and
# resumes when load drops. 0 = disabled. ~4 = "load is 4x the core count"
# (saturated). Cheap calls (backlog, liveliness, models, lite aggregates) keep
# running. (The deployment-probing /health call is not used at all — removed.)
LITELLM_LOAD_SHED = _float("LITELLM_LOAD_SHED", 0.0)  # load-per-core threshold
LITELLM_SPEND_MAX_ROWS = _int("LITELLM_SPEND_MAX_ROWS", 20000)
# Heavy calls (/health, /spend/logs) get a longer timeout than the 4s default —
# on a busy proxy the whole-day /spend/logs query easily exceeds 4s, and a 4s
# timeout there means it ALWAYS times out and the latency/cost/key panels stay
# blank. Bounded by the sampling cadence (these calls run at most once per
# LITELLM_HEAVY_INTERVAL).
LITELLM_SPEND_TIMEOUT = _float("LITELLM_SPEND_TIMEOUT", 20.0)  # seconds
# Circuit breaker: if a heavy call (/health or /spend/logs) fails this many times
# in a row, stop calling it for the cooldown, then probe once — so the monitor
# never keeps hammering a struggling/frozen proxy. Auto-recovers on success.
LITELLM_CB_THRESHOLD = _int("LITELLM_CB_THRESHOLD", 3)
LITELLM_CB_COOLDOWN = _float("LITELLM_CB_COOLDOWN", 300.0)  # seconds
# Hard cap on the /spend/logs response size. A huge day of logs is refused before
# it's deserialized — protects the monitor's own memory + event loop.
LITELLM_SPEND_MAX_BYTES = _int("LITELLM_SPEND_MAX_BYTES", 67108864)  # 64 MiB

# Ollama.
OLLAMA_BASE_URL = _str("OLLAMA_BASE_URL")               # e.g. http://host:11434

# llama.cpp server (native JSON: /slots /props /health — no --metrics needed).
LLAMACPP_BASE_URL = _str("LLAMACPP_BASE_URL")           # e.g. http://host:8080
LLAMACPP_API_KEY  = _str("LLAMACPP_API_KEY")            # optional Bearer

# Container liveness / alive-time via the Docker Engine API. Comma-separated
# container names to watch; empty = feature off. Requires the Docker socket
# mounted into the monitor (see docker-compose.yml) + membership in its group.
MONITOR_CONTAINERS = [c.strip() for c in (_str("MONITOR_CONTAINERS", "") or "").split(",") if c.strip()]
DOCKER_SOCKET = _str("MONITOR_DOCKER_SOCKET", "/var/run/docker.sock")
# Security F1: talking straight to the Docker socket grants effective host root
# (a :ro mount does NOT make the API read-only). Prefer a read-only socket proxy
# (e.g. tecnativa/docker-socket-proxy with CONTAINERS=1, everything else 0) and
# point MONITOR_DOCKER_API_URL at it (http://docker-socket-proxy:2375). When set,
# the collector uses this TCP endpoint and the raw socket is NOT mounted into the
# monitor. Unset → legacy direct-socket mode (backward compatible).
DOCKER_API_URL = _str("MONITOR_DOCKER_API_URL")

# GPU — the GPU box may be a DIFFERENT host. Three modes, in precedence order:
#   1. SSH (agentless): run nvidia-smi on the remote box over SSH.
#   2. HTTP agent: GET GPU JSON from a small endpoint on the GPU box.
#   3. local: nvidia-smi / rocm-smi on this host.
GPU_SSH          = _str("GPU_SSH")            # "user@gpuhost" -> remote nvidia-smi
GPU_SSH_PORT     = _int("GPU_SSH_PORT", 22)
GPU_SSH_KEY      = _str("GPU_SSH_KEY")        # path to private key (mount into container)
GPU_METRICS_URL  = _str("GPU_METRICS_URL")    # http agent returning GPU JSON
# Safest for a LOCAL host GPU + a musl/Alpine container: the host writes
# `nvidia-smi --query-gpu=... --format=csv,noheader,nounits` to a file on a timer,
# and the monitor reads it (bind-mounted read-only). No SSH, no network, no shell.
GPU_METRICS_FILE = _str("GPU_METRICS_FILE")   # path to the nvidia-smi CSV file
GPU_FILE_MAX_AGE = _float("GPU_FILE_MAX_AGE", 60.0)  # stale-if-older-than (seconds)

# --- alert thresholds (0/empty disables each) --------------------------------
ALERT_CPU_PCT       = _float("ALERT_CPU_PCT", 0.0)
ALERT_MEM_PCT       = _float("ALERT_MEM_PCT", 0.0)
ALERT_DISK_PCT      = _float("ALERT_DISK_PCT", 0.0)
ALERT_GPU_PCT       = _float("ALERT_GPU_PCT", 0.0)
ALERT_VRAM_PCT      = _float("ALERT_VRAM_PCT", 0.0)     # vram_used/vram_total
ALERT_LLM_WAIT_MS   = _float("ALERT_LLM_WAIT_MS", 0.0)  # LiteLLM avg wait
ALERT_BACKLOG       = _float("ALERT_BACKLOG", 0.0)      # LiteLLM queue depth
ALERT_ON_BACKEND_DOWN = _str("ALERT_ON_BACKEND_DOWN", "1") not in ("0", "false", "")
ALERT_REPEAT_MIN    = _float("ALERT_REPEAT_MIN", 30.0)  # re-notify cooldown

# --- per-key anomaly / abuse detection (0 disables each) ---------------------
# Spike: a key's recent request rate >= FACTOR × its own hourly baseline.
ANOMALY_FACTOR      = _float("ANOMALY_FACTOR", 4.0)     # 0 disables spike detect
ANOMALY_MIN_REQS    = _float("ANOMALY_MIN_REQS", 20.0)  # floor to ignore tiny keys
# Budget: a key's spend rate over this $/hour fires an alert.
ANOMALY_KEY_BUDGET_HR = _float("ANOMALY_KEY_BUDGET_HR", 0.0)

# --- alert channel (webhook) -------------------------------------------------
ALERT_WEBHOOK_URL     = _str("ALERT_WEBHOOK_URL")          # operator-set global (trusted)
# Per-user webhooks (each user configures their own at /account) are USER-supplied,
# so they are SSRF-validated: by default a URL that resolves to a private/loopback/
# link-local/metadata address is refused (both when saved and before each send —
# DNS-rebinding aware). Set WEBHOOK_ALLOW_PRIVATE=1 only for trusted LANs.
WEBHOOK_ALLOW_PRIVATE = (_str("MONITOR_WEBHOOK_ALLOW_PRIVATE", "0") or "0").lower() in ("1", "true", "yes", "on")
# Require https for user webhooks (recommended when the monitor is internet-facing).
WEBHOOK_HTTPS_ONLY    = (_str("MONITOR_WEBHOOK_HTTPS_ONLY", "0") or "0").lower() in ("1", "true", "yes", "on")
# Optional comma-separated host allowlist for user webhooks (empty = any public
# host). e.g. hooks.slack.com,discord.com — a subdomain of an entry is allowed too.
WEBHOOK_ALLOW_HOSTS   = _str("MONITOR_WEBHOOK_ALLOW_HOSTS", "") or ""
# Cap on how many per-user webhooks the notifier resolves + posts to per alert
# tick, so a large user base (or a user with a slow-resolving host) can't make the
# fan-out unbounded. Validation + delivery are also run concurrently + time-bounded.
WEBHOOK_MAX_RECIPIENTS = _int("MONITOR_WEBHOOK_MAX_RECIPIENTS", 50)

# --- retention rollups (Tier 4) ----------------------------------------------
ROLLUP_RAW_HOURS   = _int("ROLLUP_RAW_HOURS", 24)      # keep raw samples
ROLLUP_MIN_DAYS    = _int("ROLLUP_MIN_DAYS", 30)       # 1-min rollup retention
ROLLUP_HOUR_DAYS   = _int("ROLLUP_HOUR_DAYS", 365)     # 1-hour rollup retention


def redacted_summary() -> dict:
    """Boot banner — endpoints shown, secrets shown only as present/absent."""
    return {
        "version": VERSION,
        "listen": f"{MONITOR_HOST}:{MONITOR_PORT}",
        "db_path": DB_PATH,
        "sample_interval_s": SAMPLE_INTERVAL,
        "litellm": LITELLM_BASE_URL or "(unconfigured)",
        "litellm_key": "set" if LITELLM_MASTER_KEY else "absent",
        "ollama": OLLAMA_BASE_URL or "(unconfigured)",
        "llamacpp": LLAMACPP_BASE_URL or "(unconfigured)",
        "gpu_mode": ("ssh:" + GPU_SSH) if GPU_SSH else (
            "http" if GPU_METRICS_URL else "local"),
        "dashboard_auth": "token" if DASHBOARD_TOKEN else "open",
    }


def validate(user_count: int = 0) -> list[str]:
    """Return list of fatal config errors (empty = OK). Fail-fast at boot.
    `user_count` is the number of dashboard user accounts — passed in by main()
    after db.init(), so F2 treats a populated users table as configured auth."""
    errs: list[str] = []
    if not (1 <= MONITOR_PORT <= 65535):
        errs.append(f"MONITOR_PORT out of range: {MONITOR_PORT}")
    if SAMPLE_INTERVAL < 1.0:
        errs.append("MONITOR_SAMPLE_INTERVAL must be >= 1.0s")
    # At least one LLM backend should be configured to be useful, but this is a
    # warning, not fatal — host metrics still work standalone.
    if LITELLM_BASE_URL and not LITELLM_MASTER_KEY:
        errs.append("LITELLM_BASE_URL set but LITELLM_MASTER_KEY missing "
                    "(/spend and /health need the master key)")
    # A too-short shared token is brute-forceable; refuse to boot with one so it
    # can't silently protect the dashboard with ~nothing. Use a long random token.
    if DASHBOARD_TOKEN and len(DASHBOARD_TOKEN) < 16:
        errs.append("MONITOR_DASHBOARD_TOKEN too short (<16 chars) — use a long, "
                    "random token (e.g. `openssl rand -base64 24`)")
    # F2: refuse to boot fully open unless the operator opted in explicitly.
    # Auth is "configured" when a legacy token is set OR at least one user account
    # exists (username+password login). Neither → fatal unless MONITOR_ALLOW_OPEN=1.
    if not DASHBOARD_TOKEN and user_count == 0 and not ALLOW_OPEN:
        errs.append("no auth configured — no MONITOR_DASHBOARD_TOKEN and no user "
                    "accounts, so the dashboard + API would be fully open. Set a "
                    "token, create a user (MONITOR_ADMIN_USER/PASSWORD/EMAIL), or "
                    "MONITOR_ALLOW_OPEN=1 to run open on purpose (loopback / behind "
                    "an authenticating proxy only).")
    return errs
