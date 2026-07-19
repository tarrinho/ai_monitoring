# collectors/vllm.py — vLLM (OpenAI-compatible server) sampling.
#
# Endpoints used:
#   GET /health      -> 200 with an empty body: liveness only
#   GET /v1/models   -> loaded model id(s)
#   GET /metrics     -> vLLM's OWN metrics, Prometheus text format
#
# On /metrics: this needs no Prometheus server, exporter or agent — it is vLLM
# reporting its own state over HTTP, exactly like llama.cpp serving /slots. It is
# the ONLY source for the numbers an operator actually watches (queue depth,
# KV-cache pressure, TTFT, throughput), so JSON-only leaves the dashboard unable to
# answer the questions it exists for. Set VLLM_METRICS_ENABLED=0 to stay on the JSON
# endpoints (status + model list) if that trade is preferred.
from __future__ import annotations

import time

import aiohttp

import config
from collectors import fetch_json, unconfigured


# Previous counter reading, for differentiating cumulative token counters into a rate.
# Module-level like host.py's CPU delta state: one vLLM per monitor instance.
_prev_tokens: dict = {"ts": None, "prompt": None, "gen": None}


def _token_rates(prompt_total, gen_total) -> tuple[float | None, float | None]:
    """Cumulative token counters -> tokens/sec since the previous sample.

    Returns (None, None) on the first sample (no baseline) and whenever a counter goes
    BACKWARDS — vLLM restarting resets its counters to 0, and a negative delta would
    otherwise render as a huge negative or bogus spike. Better a one-sample gap than a
    wrong number."""
    now = time.time()
    prev = _prev_tokens
    p_rate = g_rate = None
    if prev["ts"] is not None:
        dt = now - prev["ts"]
        if dt > 0:
            for key, cur, prior in (("p", prompt_total, prev["prompt"]),
                                    ("g", gen_total, prev["gen"])):
                if cur is None or prior is None or cur < prior:
                    continue            # first sample, missing series, or counter reset
                rate = round((cur - prior) / dt, 2)
                if key == "p":
                    p_rate = rate
                else:
                    g_rate = rate
    prev["ts"], prev["prompt"], prev["gen"] = now, prompt_total, gen_total
    return p_rate, g_rate


def _headers() -> dict[str, str] | None:
    return ({"Authorization": f"Bearer {config.VLLM_API_KEY}"}
            if config.VLLM_API_KEY else None)


def parse_prom(text: str, labels_out: set | None = None) -> dict[str, float]:
    """Fold Prometheus text into {metric_name: value}, summing across label sets.

    Deliberately tiny: no label matching, no histogram bucket maths — vLLM's gauges
    and counters are what we chart, and summing across label sets is right for a
    single-model server (and still meaningful for multi-model). Histograms are read
    via their _sum/_count pair, which is enough for an average. Unparseable lines are
    skipped rather than raising: a metrics-format change must degrade the panel, not
    kill the collector."""
    out: dict[str, float] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # `name{labels} value [timestamp]`  ->  name, value
        try:
            left, _, rest = line.partition(" ")
            if not rest:
                continue
            name = left.split("{", 1)[0]
            val = float(rest.split()[0])
            # Record which models the series belong to. Summing across label sets is
            # right for one model but silently merges two — the caller needs to know
            # so the UI can say so rather than present a blended number as one model's.
            if labels_out is not None and "model_name=" in left:
                labels_out.add(left.split('model_name="', 1)[1].split('"', 1)[0])
        except (ValueError, IndexError):
            continue
        out[name] = out.get(name, 0.0) + val
    return out


def _avg(sums: dict, base: str) -> float | None:
    """Average from a Prometheus histogram's _sum/_count pair, or None."""
    s, c = sums.get(f"{base}_sum"), sums.get(f"{base}_count")
    if s is None or not c:
        return None
    return round(s / c, 4)


def _pick(m: dict, *names: str) -> float | None:
    """First metric present. vLLM renamed several series across versions (and the V1
    engine dropped the `vllm:` prefix on some), so accept every known spelling rather
    than pin one and silently show nothing on a different build."""
    for n in names:
        if n in m:
            return m[n]
    return None


async def sample(session: aiohttp.ClientSession) -> dict:
    base = (config.VLLM_BASE_URL or "").rstrip("/")
    if not base:
        return unconfigured()
    h = _headers()

    out: dict = {
        "available": True,
        "status": "ok",
        "models": [],
        "model": None,
        "metrics_available": False,
        "running": None,          # requests currently generating
        "waiting": None,          # queue depth — the headline pressure signal
        "kv_cache_pct": None,     # GPU KV-cache utilisation
        "ttft_avg": None,         # seconds to first token
        "tpot_avg": None,         # seconds per output token
        "prompt_tokens": None,
        "generation_tokens": None,
        "preemptions": None,      # >0 means vLLM is evicting under memory pressure
        "e2e_avg": None,          # end-to-end request latency
        "queue_avg": None,        # time a request spends queued before prefill
        "prefix_hit_pct": None,   # prefix-cache hit rate (V1)
        "swapped": None,
        "prompt_tps": None,       # tokens/sec, differentiated from the counters
        "generation_tps": None,
        "metrics_models": [],     # model_name label values seen in /metrics
        "multi_model": False,     # True -> the figures are SUMMED across models
        # Prometheus clients create GAUGES at startup but only emit counters/histograms
        # after the first observation. A freshly (re)started vLLM that has served no
        # requests therefore exposes running/waiting and nothing else — which is
        # indistinguishable from "broken" if the UI just prints "—" everywhere.
        "awaiting_traffic": False,
        "series_count": None,
    }

    # Liveness. /health returns an empty 200, so a JSON decode failure here is NOT a
    # failure — only a transport error is.
    _, herr = await fetch_json(session, f"{base}/health", headers=h)
    models, merr = await fetch_json(session, f"{base}/v1/models", headers=h)
    if herr is not None and merr is not None:
        return {"available": False, "error": herr}

    if merr is None and isinstance(models, dict):
        ids = [m.get("id") for m in (models.get("data") or []) if isinstance(m, dict)]
        out["models"] = [i for i in ids if i]
        out["model"] = out["models"][0] if out["models"] else None

    if not config.VLLM_METRICS_ENABLED:
        return out

    raw, perr = await fetch_text(session, f"{base}/metrics", headers=h)
    if perr is not None or not raw:
        return out                      # JSON-only view; panel shows "—", not an error
    seen_models: set = set()
    m = parse_prom(raw, seen_models)
    if not m:
        return out
    out["metrics_available"] = True
    out["metrics_models"] = sorted(seen_models)
    out["multi_model"] = len(seen_models) > 1
    out["series_count"] = len(m)
    # Gauges present but no cumulative series at all => vLLM is up and idle since a
    # restart, not misreporting. Distinguishing these is the difference between
    # "wait for a request" and "go debug the exporter".
    _has_gauge = any(k.endswith(("num_requests_running", "num_requests_waiting"))
                     for k in m)
    _has_counters = any(k.endswith(("_total", "_sum", "_count")) for k in m)
    out["awaiting_traffic"] = bool(_has_gauge and not _has_counters)
    out["running"] = _pick(m, "vllm:num_requests_running", "num_requests_running")
    out["waiting"] = _pick(m, "vllm:num_requests_waiting", "num_requests_waiting")
    # V1 name first — V1 renamed gpu_cache_usage_perc to kv_cache_usage_perc.
    kv = _pick(m,
               "vllm:kv_cache_usage_perc", "kv_cache_usage_perc",
               "vllm:gpu_cache_usage_perc", "gpu_cache_usage_perc")
    # vLLM documents these as a 0-1 FRACTION ("1 means 100 percent usage") despite the
    # `_perc` suffix, so a known series is scaled unconditionally. Guessing by magnitude
    # (the previous `<= 1.5` test) rendered a real 0.5% as 50% — a silent 100x error in
    # the alarming direction.
    out["kv_cache_pct"] = round(min(kv, 1.0) * 100, 1) if kv is not None else None
    out["ttft_avg"] = _avg(m, "vllm:time_to_first_token_seconds")
    # V1 replaced time_per_output_token_seconds with inter_token_latency_seconds
    out["tpot_avg"] = (_avg(m, "vllm:inter_token_latency_seconds")
                       or _avg(m, "vllm:time_per_output_token_seconds")
                       or _avg(m, "inter_token_latency_seconds"))
    out["prompt_tokens"] = _pick(m, "vllm:prompt_tokens_total", "prompt_tokens_total")
    out["generation_tokens"] = _pick(m, "vllm:generation_tokens_total",
                                     "generation_tokens_total")
    out["preemptions"] = _pick(m, "vllm:num_preemptions_total", "num_preemptions_total")
    out["swapped"] = _pick(m, "vllm:num_requests_swapped", "num_requests_swapped")
    out["e2e_avg"] = (_avg(m, "vllm:e2e_request_latency_seconds")
                      or _avg(m, "e2e_request_latency_seconds"))
    out["queue_avg"] = (_avg(m, "vllm:request_queue_time_seconds")
                        or _avg(m, "request_queue_time_seconds"))
    # Prefix-cache hit rate: a ratio of two counters, not a gauge. High is good — it is
    # why a repeated system prompt gets cheap.
    q = _pick(m, "vllm:prefix_cache_queries_total", "prefix_cache_queries_total")
    hit = _pick(m, "vllm:prefix_cache_hits_total", "prefix_cache_hits_total")
    if q:
        out["prefix_hit_pct"] = round(hit / q * 100, 1) if hit is not None else None
    # Token counters are cumulative since server start, so they only ever rise and say
    # nothing about NOW. Differentiate them into tokens/sec — the headline throughput
    # number an inference server is judged on.
    out["prompt_tps"], out["generation_tps"] = _token_rates(
        out["prompt_tokens"], out["generation_tokens"])
    return out


async def fetch_text(session: aiohttp.ClientSession, url: str, *,
                     headers: dict | None = None) -> tuple[str | None, str | None]:
    """Read a text/plain body (Prometheus exposition) with the same byte cap and error
    shape as fetch_json — /metrics is not JSON, so it needs its own reader."""
    try:
        timeout = aiohttp.ClientTimeout(total=config.HTTP_TIMEOUT)
        async with session.get(url, headers=headers, timeout=timeout) as resp:
            if resp.status >= 400:
                return None, f"http {resp.status}"
            raw = await resp.content.read(config.HTTP_MAX_BYTES)
            return raw.decode("utf-8", "replace"), None
    except aiohttp.ClientError as e:
        return None, f"conn: {type(e).__name__}"
    except Exception as e:                      # never let a backend kill the loop
        return None, f"{type(e).__name__}"
