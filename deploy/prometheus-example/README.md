# Demo stack — AI-Monitoring + Prometheus + Grafana

A one-command local stack that wires the three together so you can see the
`/metrics` export flow end-to-end.

> **Local demo only.** The tokens/passwords in `docker-compose.yml` are placeholders
> (`CHANGE_ME_*`). Change them (and match `MONITOR_METRICS_TOKEN` in the compose file
> with `authorization.credentials` in `prometheus.yml`) before using this anywhere real.

## Start

```bash
cd deploy/prometheus-example
docker compose up -d
```

| Service | URL | Login |
|---------|-----|-------|
| AI-Monitoring | http://localhost:9925/ | `admin` / `CHANGE_ME_admin_pw` |
| Prometheus | http://localhost:9090/ | — |
| Grafana | http://localhost:3000/ | `admin` / `admin` |

Prometheus scrapes AI-Monitoring's `/metrics` every 5 s (bearer-token auth). Grafana
auto-provisions the Prometheus datasource **and** the AI-Monitoring dashboard
(`../grafana/ai-monitoring-dashboard.json`) — open Grafana → Dashboards → *AI-Monitoring (fleet)*.

## Verify the scrape

```bash
# Prometheus target should be health="up"
curl -s localhost:9090/api/v1/targets | jq '.data.activeTargets[].health'
# query an exported metric
curl -s 'localhost:9090/api/v1/query?query=aimon_up' | jq '.data.result'
```

## Use a locally-built image instead of ghcr

```bash
AIMON_IMAGE=ai-monitoring:1.8.1-arm64 docker compose up -d
```

## Stop

```bash
docker compose down
```
