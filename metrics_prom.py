# metrics_prom.py — render the latest snapshot as Prometheus / OpenMetrics text.
#
# Read-only: turns the in-memory `_latest` snapshot (host / GPU / LiteLLM /
# llama.cpp / Ollama / containers) into `aimon_*` gauges so an existing Prometheus
# / Grafana / Datadog / AlertManager stack can scrape it — and a central Prometheus
# can aggregate a whole fleet of AI-Monitoring instances. No new dependency; pure
# text. Samples are grouped per metric family (TYPE/HELP once) regardless of the
# order they are added, which the Prometheus text-exposition format requires.
from __future__ import annotations

import math
from typing import Any

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _fmt(v: float) -> str:
    return str(int(v)) if float(v).is_integer() else repr(v)


class _Out:
    def __init__(self) -> None:
        self._m: dict[str, dict[str, Any]] = {}

    def gauge(self, name: str, value: Any, labels: dict | None = None,
              help: str = "") -> None:
        if value is None:
            return
        try:
            v = float(value)
        except (TypeError, ValueError):
            return
        # M1: skip non-finite values — `inf`/`nan` render as invalid Prometheus
        # floats (it wants +Inf/-Inf/NaN) and a single bad line rejects the WHOLE
        # scrape, silently dropping every metric for this instance.
        if not math.isfinite(v):
            return
        m = self._m.setdefault(name, {"help": help, "samples": []})
        if help and not m["help"]:
            m["help"] = help
        lbl = ""
        if labels:
            parts = [f'{k}="{_esc(str(x))}"' for k, x in labels.items()
                     if x is not None and x != ""]
            if parts:
                lbl = "{" + ",".join(parts) + "}"
        m["samples"].append((lbl, v))

    def text(self) -> str:
        out: list[str] = []
        for name, m in self._m.items():
            if m["help"]:
                out.append(f"# HELP {name} {m['help']}")
            out.append(f"# TYPE {name} gauge")
            for lbl, v in m["samples"]:
                out.append(f"{name}{lbl} {_fmt(v)}")
        return "\n".join(out) + "\n"


def render(latest: dict, extra: dict | None = None) -> str:
    """Prometheus text for one snapshot. `extra` may carry {users, sessions, alerts}."""
    o = _Out()
    o.gauge("aimon_up", 1, help="1 if the monitor is serving")
    o.gauge("aimon_snapshot_timestamp_seconds", latest.get("ts") or 0,
            help="unix time of the latest sample")
    c = latest.get("collectors", {})

    h = c.get("host", {})
    if h.get("available"):
        o.gauge("aimon_host_cpu_percent", h.get("cpu_pct"), help="host CPU utilisation %")
        o.gauge("aimon_host_mem_percent", h.get("mem_pct"), help="host memory used %")
        o.gauge("aimon_host_mem_used_bytes", h.get("mem_used"))
        o.gauge("aimon_host_mem_total_bytes", h.get("mem_total"))
        o.gauge("aimon_host_disk_percent", (h.get("disk") or {}).get("pct"))
        load = h.get("load") or []
        if load:
            o.gauge("aimon_host_load1", load[0], help="host 1-minute load average")
        o.gauge("aimon_host_cpus", h.get("ncpu"))

    # backend reachability — one family for all backends
    for name in ("gpu", "litellm", "ollama", "llamacpp", "vllm", "containers"):
        b = c.get(name, {})
        o.gauge("aimon_backend_up", 1 if b.get("available") else 0,
                {"backend": name}, "1 if the backend is reachable")

    g = c.get("gpu", {})
    if g.get("available"):
        gpus = g.get("gpus") or [{"name": "", "util": g.get("util"),
                                  "power": g.get("power"), "temp": g.get("temp_max"),
                                  "vram_used": g.get("vram_used"),
                                  "vram_total": g.get("vram_total")}]
        for i, gp in enumerate(gpus):
            lbl = {"gpu": str(i), "name": gp.get("name", "")}
            o.gauge("aimon_gpu_utilization_percent", gp.get("util"), lbl, "GPU utilisation %")
            o.gauge("aimon_gpu_power_watts", gp.get("power"), lbl)
            o.gauge("aimon_gpu_temperature_celsius", gp.get("temp"), lbl)
            o.gauge("aimon_gpu_vram_used_bytes", gp.get("vram_used"), lbl)
            o.gauge("aimon_gpu_vram_total_bytes", gp.get("vram_total"), lbl)

    ll = c.get("litellm", {})
    if ll.get("available"):
        o.gauge("aimon_litellm_request_rate", ll.get("req_rate"), help="LiteLLM requests/sec")
        o.gauge("aimon_litellm_tokens_in_rate", ll.get("tok_in_rate"))
        o.gauge("aimon_litellm_tokens_out_rate", ll.get("tok_out_rate"))
        o.gauge("aimon_litellm_error_percent", ll.get("error_pct"))
        o.gauge("aimon_litellm_cost_rate_hourly", ll.get("cost_rate_hr"),
                help="LiteLLM spend rate ($/hour)")
        o.gauge("aimon_litellm_wait_ms", ll.get("wait_avg_ms"))
        o.gauge("aimon_litellm_backlog", ll.get("backlog"))
        for p in ("p50", "p95", "p99"):
            o.gauge(f"aimon_litellm_latency_{p}_ms", ll.get(f"{p}_ms"))

    lc = c.get("llamacpp", {})
    if lc.get("available"):
        o.gauge("aimon_llamacpp_tokens_per_second", lc.get("predicted_per_second"))
        o.gauge("aimon_llamacpp_kv_cache_percent", lc.get("kv_cache_pct"))
        o.gauge("aimon_llamacpp_slots_active", lc.get("slots_active"))
        o.gauge("aimon_llamacpp_slots_total", lc.get("n_slots"))

    vl = c.get("vllm", {})
    if vl.get("available"):
        # Queue depth is the one an alert should watch: running means busy, WAITING
        # means over capacity. Preemptions >0 means eviction under memory pressure.
        o.gauge("aimon_vllm_requests_running", vl.get("running"))
        o.gauge("aimon_vllm_requests_waiting", vl.get("waiting"),
                help="vLLM queued requests waiting for a slot")
        o.gauge("aimon_vllm_kv_cache_percent", vl.get("kv_cache_pct"))
        o.gauge("aimon_vllm_ttft_seconds", vl.get("ttft_avg"))
        o.gauge("aimon_vllm_preemptions_total", vl.get("preemptions"))

    ol = c.get("ollama", {})
    if ol.get("available"):
        o.gauge("aimon_ollama_models_running", ol.get("models_running"))
        o.gauge("aimon_ollama_vram_used_bytes", ol.get("vram_used"))

    for cc in (c.get("containers", {}).get("containers") or []):
        o.gauge("aimon_container_up", 1 if cc.get("running") else 0,
                {"name": cc.get("name", "")}, "1 if the container is running")

    for p in (c.get("procs", {}).get("top_cpu") or [])[:10]:
        o.gauge("aimon_proc_cpu_percent", p.get("cpu"), {"app": p.get("app", "")},
                "per-process CPU % (top-N)")

    if extra:
        o.gauge("aimon_users_total", extra.get("users"), help="dashboard user accounts")
        o.gauge("aimon_sessions_active", extra.get("sessions"))
        o.gauge("aimon_alerts_active", extra.get("alerts"))
    return o.text()
