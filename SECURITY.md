# Security Policy

AI-Monitoring is a **read-only** observability dashboard for a self-hosted LLM
stack. It reads metrics and cost data from LiteLLM, Ollama, llama.cpp, the host,
GPUs, and the Docker API, and never mutates the systems it watches. Even so, it
handles bearer tokens, renders upstream-supplied data in a browser, and ships as
a container image — so it takes security seriously and welcomes reports.

## Supported Versions

Security fixes land on the **latest minor release only**. Older minors are
end-of-life; the fix for any issue is to upgrade to the newest `1.5.x`.

| Version | Supported          |
| ------- | ------------------ |
| `1.5.x` | :white_check_mark: |
| `< 1.5` | :x: (upgrade)      |

The current version is stamped in `config.py` (`VERSION`) and shown by the
`release` badge in the README.

## Reporting a Vulnerability

**Please report privately — do not open a public issue, pull request, or
discussion for a security bug.** Public disclosure before a fix puts every
operator running the tool at risk.

Two private channels, in order of preference:

1. **GitHub private vulnerability reporting** (preferred) — go to the repository
   **Security** tab → **Report a vulnerability**
   (https://github.com/tarrinho/ai_monitoring/security/advisories/new). This
   keeps the report, discussion, and eventual advisory in one place.
2. **Email** — if you cannot use GitHub advisories, email
   **tarrinho@gmail.com** with `AI-Monitoring security` in the subject.

To help triage quickly, please include:

- affected version(s) and, ideally, the commit or image tag;
- component and endpoint involved (e.g. `/api/...`, the login flow, a collector);
- a clear description of the impact (what an attacker gains);
- a **proof of concept** — the exact request(s), payload, or steps to reproduce;
- any suggested remediation, if you have one.

### What to expect

This is a solo-maintained project, so timelines are best-effort:

| Stage                          | Target                         |
| ------------------------------ | ------------------------------ |
| Acknowledge your report        | within **15 business days**    |
| Initial severity assessment    | within **30 business days**    |
| Fix or mitigation for a valid, high-impact issue | as fast as practical, tracked in a private advisory |

You will be kept informed through the advisory (or email thread), and credited
in the release notes and advisory when the fix ships — unless you ask to remain
anonymous.

### Coordinated disclosure

Please give a reasonable window to ship a fix before any public disclosure —
**90 days** is the default, or sooner once a fixed release is out. A public
advisory (with a CVE where warranted) is published alongside the fix. Reports
are handled under good-faith **safe harbor**: research conducted in line with
this policy — no data destruction, no privacy violations, no service disruption,
no access beyond what is needed to demonstrate the issue — will not be pursued.

## Scope

**In scope** — vulnerabilities in the AI-Monitoring code and its published
artifacts, for example:

- authentication / session flaws (token compare, cookie handling, session limits);
- authorization gaps between the `admin` and read-only `viewer` roles;
- XSS / injection in the dashboard, or SSRF via the remote GPU-agent fetch;
- secret leakage (tokens/keys written to logs, responses, the DB, or the image);
- anything that lets the read-only tool write to, or pivot into, a monitored
  backend or the host.

**Out of scope** — issues that are not defects in this project:

- vulnerabilities in the monitored backends themselves (LiteLLM, Ollama,
  llama.cpp, the Docker daemon) — report those upstream;
- risks from running the dashboard **without** a token where you have not set
  `MONITOR_ALLOW_OPEN=1` deliberately, or exposing it to the internet without a
  TLS-terminating reverse proxy (see *Hardening* below);
- consequences of mounting `docker.sock` — this is a documented, operator-chosen
  trade-off (the tool issues read-only GETs, but the socket grants Docker control);
- missing security hardening on *your* deployment (weak reverse-proxy config,
  outdated host, exposed backends).

## Security posture

Defense-in-depth is built in; see the **Security** section of the README for the
current detail. In summary:

- **Auth** — optional dashboard token with constant-time compare; HttpOnly,
  `SameSite=Strict` cookie session (the token leaves the URL after first load).
  Booting **without** a token is a fatal error unless `MONITOR_ALLOW_OPEN=1` is
  set explicitly, so metrics are never exposed by a forgotten token.
- **Least-privilege scrape** — a separate `MONITOR_METRICS_TOKEN` gives
  Prometheus a scrape-only credential instead of the full dashboard token.
- **Roles** — `admin` (user management) vs read-only `viewer`; admin-created and
  admin-reset accounts must set their own password on first login.
- **Headers** — `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, nosniff,
  no-referrer, server version hidden.
- **XSS** — every dynamic value is HTML-escaped; a single DOMPurify-sanitised
  `innerHTML` sink per page.
- **SSRF** — the GPU-agent fetch is restricted to `http(s)` and bypasses proxy env.
- **Secrets** — env-only, git-ignored, never logged or stored; the boot banner
  redacts them.
- **Container** — runs **non-root** (uid 10001) on an Alpine base with **0 Trivy
  HIGH/CRITICAL**.
- **Supply chain** — every push runs ruff / semgrep / bandit, gitleaks +
  trufflehog secret scanning, and Trivy CVE scans (filesystem + image); release
  images are **cosign keyless-signed**.

## Verifying image authenticity

Release images are signed with cosign (keyless / Sigstore). Verify before running:

```bash
cosign verify ghcr.io/tarrinho/ai_monitoring:<version> \
  --certificate-identity-regexp 'https://github.com/tarrinho/ai_monitoring/\.github/workflows/release\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Hardening checklist for operators

The project ships secure defaults, but a safe deployment is a shared
responsibility:

- **Set a dashboard token** (`MONITOR_DASHBOARD_TOKEN`) — do not rely on
  `MONITOR_ALLOW_OPEN=1` except on a trusted loopback.
- **Terminate TLS** at a reverse proxy; never expose the plain HTTP port to an
  untrusted network.
- **Give Prometheus its own** `MONITOR_METRICS_TOKEN` rather than the full token.
- **Treat `docker.sock` as sensitive** — mount it only if you use the Containers
  card, and understand it grants Docker control to whatever can read it.
- **Restrict `MONITOR_CONTAINERS`** to the names you actually want to watch
  instead of auto-discovering every container, if that surface concerns you.
- **Keep the image current** — pull the latest supported `1.5.x` for fixes.

Thank you for helping keep AI-Monitoring and everyone who runs it safe.
