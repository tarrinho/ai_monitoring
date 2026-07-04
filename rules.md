# Rules of Engagement — AI-Monitoring build pipeline

AI-Monitoring is a **read-only** aiohttp monitor for an LLM stack (host / GPU /
Ollama / llama.cpp / LiteLLM / containers). It serves a token-gated dashboard and
a JSON API; it does **not** mutate state, proxy user traffic, or store PII — it
stores time-series metrics only. The pipeline below is scoped to that reality:
the GW's ban/Redis/honeypot/upstream-DAST stages do **not** apply and are dropped.

The **signature stage is §6 (observer-effect / load-safety)** — the monitor must
never overload or freeze the very backends it watches (this is the whole reason
fixes F1–F5 + the GPU-decouple watchdog exist).

Run stages in order. A stage that is not run is reported `⏭️ SKIP` with a reason —
never silently omitted (see §18). The build gate is **in the Dockerfile**:
`--build-arg RUN_TESTS=1` runs `pytest tests/` inside the image; no pass → no image.

Project facts:
- Version string: `config.VERSION` (e.g. `AI-Monitoring_1.0.0`); UI copy in each
  `web/*.html` `#sidebar-brand-ver`.
- Tests: `tests/test_static_qa.py` (HTML/JS + source invariants),
  `tests/test_dynamic_qa.py` (collectors, endpoints, series, alerts),
  `tests/test_testenv.py` (live against `test-env/`).
- Arches: `arm64` (native gate), `amd64` (emulated, gated), `armv7`
  (emulated — suite skipped, already ran on native). One Alpine Dockerfile.
- Auth: `MONITOR_DASHBOARD_TOKEN`; `?token=` → cookie `aimon_session` (302 flow).
- Disk pre-check: ≥1 GB free before any build/file op.

---

## 0. Zombie process cleanup

Kill stray pytest/docker-build processes from prior runs before starting. Kill by
**PID**, never `pkill -f pytest` (it self-kills the current runner → instant exit).

```bash
ps -eo pid,cmd | grep -E '[p]ytest|[d]ocker build' | awk '{print $1}'   # inspect, then kill wanted PIDs
```

## 0a. Version consistency

`config.VERSION`, every `web/*.html` `#sidebar-brand-ver`, the `Dockerfile`, and
`docker-compose*.yml` image tag must agree. One bump touches all.

```bash
V=$(python3 -c 'import config;print(config.VERSION)')
grep -rn "sidebar-brand-ver" web/*.html          # must all read the same vX.Y.Z
grep -n "ai-monitoring:" docker-compose*.yml deploy/*.yml
```
Pass: one version everywhere; no stale previous string in tracked files.

## 1. Static / source invariant tests

```bash
python3 -m pytest tests/test_static_qa.py -q
```
Covers: page-invariant loops (nav links, alert-dot, collapsible sidebar, theme
toggle across **all** pages incl. `/llamacpp`), chart config integrity,
VRAM-removed-on-unified-memory, empty-tile auto-hide, container down-duration +
show/hide-exited default, `escapeHtml`/`DOMPurify` presence, single `innerHTML`
sink per file, `_timers`/`beforeunload`, `/health` fully removed.

## 2. Dynamic tests (collectors + API)

```bash
python3 -m pytest tests/test_dynamic_qa.py -q
```
Covers: each collector's parse (host/procs/gpu/ollama/llamacpp/litellm/containers),
page-served-and-gated for every route, `/api/nav` shape (incl. `llamacpp`),
`/api/series` row builder keys, `_metrics_row` derivations, alerts evaluation,
llama.cpp nested-`timings` parse.

## 3. Test-env integration (live stack)

```bash
python3 -m pytest tests/test_testenv.py -q     # needs test-env/ up
# bring up: cd test-env && docker compose up -d
```
Skip only when the test-env stack is unavailable — mark `⏭️ SKIP (no test-env)`.

## 4. Sufficient logs

Every backend loop must emit a diagnosable trail. Confirm `LITELLM_DEBUG=1` prints
per-call timing/bytes/rows for the spend path, and each collector loop logs its
`wait_for` timeout on wedge. No silent empty panels.

## 5. Regression

Diff the full-suite result against the last green run. Any **new** failure blocks;
pre-existing knowns are classified at the top of the report (§18), never inherited
silently.

## 6. Observer-effect / load-safety  ⭐ (signature stage)

The monitor must not become the incident. Verify every guard that keeps it cheap
and un-wedgeable:

- **Spend cost** — `/spend/logs` pulls the whole day (tens of MB); `json.loads`
  must run **off the event loop** (`asyncio.to_thread`/`_parse_spend_bytes`), be
  throttled (`LITELLM_HEAVY_INTERVAL`), byte-capped (`LITELLM_SPEND_MAX_BYTES`),
  and honour `LITELLM_SPEND_TIMEOUT`. `LITELLM_SPEND_MODE=lite` uses
  `/global/activity` aggregates (~200 ms, ~0 CPU) instead of raw logs.
- **Circuit breaker** — after `LITELLM_CB_THRESHOLD` fails, stop calling for
  `LITELLM_CB_COOLDOWN`, auto-recover. A dead/slow proxy must not compound load.
- **Health probing** — `/health` per-deployment probing is removed; only cheap
  liveliness/backlog remain (`LITELLM_HEALTH_ENABLED=0` safe default).
- **GPU never wedges the loop** — `nvidia-smi` can hang in D-state under overload;
  it runs in a **decoupled loop**, and every backend loop + the main tick are
  `asyncio.wait_for`-bounded (GPU 8 s, main 15 s). No single stuck call freezes
  sampling.

Measure, don't assume:
```bash
docker exec ai-monitoring python -c "import time,urllib.request as u; \
  d=u.build_opener(u.ProxyHandler({})).open('$LITELLM_BASE_URL/spend/logs?start_date='+__import__('datetime').date.today().isoformat()).read(); \
  t=time.time(); __import__('json').loads(d); print(len(d),'bytes', round(time.time()-t,3),'s json.loads')"
docker stats --no-stream ai-monitoring    # per-poll CPU must not peg a core
```
Pass: lite-mode poll < ~300 ms & ~0 CPU; snapshot AGE ticks 0–5 s (loop not wedged);
proxy + DB CPU do not spike on each poll.

## 7. Secret-leak scan

No tokens/keys/DSNs committed; `.env` is **not** baked into the image (`.dockerignore`).

```bash
git grep -nE '(sk-[A-Za-z0-9]{16,}|MONITOR_DASHBOARD_TOKEN=.+|POSTGRES_DSN=.+)' -- . ':!*.example' || echo "clean"
grep -q '^\.env$' .dockerignore && echo ".env ignored"
```

## 8. Input sanitisation

Read-only, but still validate the surfaces that exist: `?token=` (constant-time
compare), reverse-proxy sub-path prefix, `window`/`end` query params bounded, and
the auth middleware gates every `/api/*` + page (only `/healthz` + `/assets/*` open).

## 9. Static hardening (Bandit + Semgrep + lint)

```bash
bandit -r . -x tests,web -ll
semgrep --config p/python --config p/security-audit --error .   # OSS mode; NEVER --config=auto
ruff check .
mypy --ignore-missing-imports app.py config.py collectors/ db.py
vulture . --min-confidence 90 --exclude tests
```
Pass: 0 High/Critical Bandit; 0 Semgrep error-level; ruff clean; no real dead code.

## 10. Image CVE scan (Trivy ×3 arch)

```bash
for a in arm64 amd64 armv7; do
  trivy image --scanners vuln --severity HIGH,CRITICAL --no-progress ai-monitoring:${VER}-$a
done
```
Pass: 0 Critical, 0 High (Alpine base keeps this small).

## 11. Automated + secure code review

`ruff`/`mypy`/`vulture`/`radon` (flag complexity grade C+) plus a human-style pass:
no unescaped sinks, no blocking I/O on the event loop, every new collector field
propagated to series + row builder + a chart (or explicitly excluded, §12/§13).

## 12. Dashboard security standards

Every `web/*.html` must comply:

- **XSS sink** — exactly **one** `innerHTML` write per file, and it goes through
  `DOMPurify.sanitize(...)` (via the shared `setHtml` helper). Any interpolated
  server value additionally wrapped in `escapeHtml()`.
- **`escapeHtml`** — one global definition at top scope; full charset; null-guarded.
- **Timer leaks** — every `setInterval` pushed to `_timers`; `beforeunload` clears.
- **No silent catch** — fetch errors surface to the UI (`updated`/`unavail`), not
  swallowed.
- **CSP** — served headers keep `default-src 'self'`, `object-src 'none'`,
  `frame-ancestors 'none'`; assets self-hosted (no CDN).
- **Chart integrity** — empty tiles auto-hide (`pts.some(p=>p[key]!=null)`); no
  permanently-empty chart ships (VRAM removed on unified memory).

```bash
for f in web/*.html; do
  echo "$f innerHTML=$(grep -c 'innerHTML' "$f") sanitize=$(grep -c 'DOMPurify.sanitize' "$f") \
timers=$(grep -c '_timers' "$f") beforeunload=$(grep -c 'beforeunload' "$f")"; done
```

## 13. Dynamic dashboard check (black-box HTTP)

Run the running image and probe it (bypass any host proxy for localhost):

```bash
docker run -d --name aimon-dast -u 0 -e MONITOR_DASHBOARD_TOKEN=T \
  -p 127.0.0.1:19925:9925 -v /var/run/docker.sock:/var/run/docker.sock:ro ai-monitoring:${VER}-arm64
curl(){ command curl --noproxy 127.0.0.1 "$@"; }
# auth: /healthz 200 open; /, /api/*, pages → 401 without token; bad token → 401
# nav: /api/nav includes llamacpp
# pages: /, /litellm, /gpu, /ollama, /llamacpp, /alerts → 200 via cookie flow
# collectors: host/procs/containers available=true
# content: VRAM chart absent, auto-hide present, exited default hidden
docker rm -f aimon-dast
```
Pass: all auth codes correct, all pages 200, nav shape right, no 5xx/traceback.

## 14. Multi-arch build + gate

Disk pre-check (≥1 GB), then:
```bash
DOCKER_BUILDKIT=1 docker build --platform linux/arm64 --target runtime \
  --build-arg RUN_TESTS=1 -t ai-monitoring:${VER}-arm64 .        # in-image pytest gate
# full three-arch + Trivy:
VERSION=${VER} ./deploy/build-multiarch.sh
```
Verify `/qa-passed` exists in the runtime image (proves the gate passed). Publish
as `docker save | gzip` tar per arch, or a registry manifest list.

## 15. Docs + version sweep

- **Language: ALL documentation is written in English — no exceptions.** This
  covers `README.md`, `ARCHITECTURE.md`, `CHANGELOG.md`, `rules.md`, `validation/*`,
  every comment in `.env.example` and source files, commit messages, and code
  identifiers. Chat/interactive replies may be in the operator's language, but
  anything committed to the repo is English. Reject a doc/PR that ships non-English
  prose.
- `README.md` / `ARCHITECTURE.md` reflect current collectors, routes, env vars,
  and include a **GPU setup** section (file / SSH / HTTP modes + the unified-memory
  GB10 caveat that VRAM reads as N/A).
- `.env.example` lists every var `config.py` reads (parity check).
- No stale previous version string anywhere:
```bash
grep -rn --include='*.py' --include='*.html' --include='*.yml' --include='Dockerfile' \
  -E '[0-9]+\.[0-9]+\.[0-9]+' . | grep -v "$VER" || echo "no stale versions"
```
PDF docs (if any): WeasyPrint is broken → use `chromium --headless --no-sandbox
--print-to-pdf`.

## 16. Post-release bug watch

Append every field-found bug to the registry below (cumulative — append, never
delete): id, symptom, root cause, fix, regression test.

| # | Symptom | Root cause | Fix | Regression test |
|---|---------|-----------|-----|-----------------|
| — | (none yet) | | | |

## 17. Deploy + smoke

```bash
cd /home/appsec && docker compose up -d --force-recreate ai-monitoring
curl -s "$BASE/healthz" | jq .status                       # ok
curl -s "$BASE/api/nav?token=$T" | jq                       # llamacpp:true
curl -s -L -c cj -b cj "$BASE/?token=$T" | grep -c chart-grid   # page renders
```
Confirm `/api/data` snapshot AGE stays 0–5 s for 60 s (loop live, not wedged).

## 18. Pipeline status report (mandatory)

Every run ends by printing (a) a per-stage table (one row per stage 0–17, none
omitted; `⏭️ SKIP`+reason for unrun) and (b) the aggregate `pytest` totals from the
**full-suite** summary line. Announcing "done" without this is a protocol
violation. Append the same to `validation/<version>.md`.

Legend: `✅ PASS` · `❌ FAIL` · `⏭️ SKIP (reason)` · `⚠️ KNOWN (documented)`.

```
Tests:   <collected> collected · <passed> passed · <failed> failed · <skipped> skipped
Image:   ai-monitoring:<ver>  arm64 <sha> · amd64 <sha> · armv7 <sha>
VERDICT: RELEASE-READY ✅   (all gates pass / only documented KNOWNs)
   — or —
VERDICT: BLOCKED ❌         (N unresolved FAIL(s): <list>)
```

A release is announced **only when `failed == 0`** (or every remainder is an
explicit `⚠️ KNOWN` with rationale). Every `❌ FAIL` is expanded below the table
with the failing test and its fix or classification.

---

## Findings policy

Fix before declaring the build done. Pre-existing failures are classified at the
top of the report — never silently inherited. The Dockerfile gate (`RUN_TESTS=1`)
is the hard floor: an image cannot be produced with a failing suite.
