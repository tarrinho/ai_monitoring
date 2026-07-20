# collectors/llamacpp.py — llama.cpp server state via native JSON.
#
# No prometheus / no --metrics flag needed:
#   GET /health -> ok / loading
#   GET /props  -> model path, ctx size, n_slots
#   GET /slots  -> per-slot state + timings (may be disabled with --no-slots)
# tokens/s derived from slot timings when present.
from __future__ import annotations

import aiohttp

import config
from collectors import fetch_json, unconfigured


def _first_num(*vals):
    """First value that is a real positive number, else None. llama.cpp reports absent
    settings as null/0/"" depending on build, and a 0-thread reading would be misread as
    'starved' — so only a genuine positive count counts as reported."""
    for v in vals:
        try:
            n = int(v)
        except (TypeError, ValueError):
            continue
        if n > 0:
            return n
    return None


def _deep_num(obj, key, _depth=0):
    """First positive-integer value stored under `key` anywhere in a nested /props
    response, searched breadth-first with a small depth cap.

    llama.cpp keeps relocating the run params across builds — top level, then
    `default_generation_settings`, then `default_generation_settings.params` — so a
    fixed list of paths goes stale on the next release and the field silently reads
    '—' even though /props carries it (observed live: model/ctx/slots populated but
    n_threads null). A bounded walk finds it wherever this build put it; the depth cap
    and dict/list-only recursion keep it cheap and loop-free."""
    if _depth > 5 or not isinstance(obj, (dict, list)):
        return None
    if isinstance(obj, dict):
        if key in obj:
            n = _first_num(obj[key])
            if n is not None:
                return n
        children = obj.values()
    else:
        children = obj
    for child in children:
        n = _deep_num(child, key, _depth + 1)
        if n is not None:
            return n
    return None


def _headers() -> dict[str, str] | None:
    if config.LLAMACPP_API_KEY:
        return {"Authorization": f"Bearer {config.LLAMACPP_API_KEY}"}
    return None


async def sample(session: aiohttp.ClientSession) -> dict:
    base = config.LLAMACPP_BASE_URL
    if not base:
        return unconfigured()
    base = base.rstrip("/")
    h = _headers()

    health, err = await fetch_json(session, f"{base}/health", headers=h)
    if err is not None:
        return {"available": False, "error": err}

    out: dict = {
        "available": True,
        "status": (health or {}).get("status", "ok"),
        "model": None,
        "ctx_size": None,
        "n_slots": None,
        "slots_active": 0,
        "predicted_per_second": None,
        "prompt_per_second": None,      # prefill tok/s (distinct from decode above)
        "slots_busy_pct": 0.0,          # active / total slots — concurrency saturation
        "ctx_used_pct": None,           # context-window fill %, where the build reports it
        # CPU threads llama.cpp was started with. Without these you cannot tell an idle
        # CPU that is idle BY DESIGN (layers offloaded to the GPU) from one starved by a
        # low --threads — the question the per-core grid otherwise leaves unanswered.
        "n_threads": None,
        "n_threads_batch": None,
    }

    props, perr = await fetch_json(session, f"{base}/props", headers=h)
    if perr is None and props:
        dm = props.get("default_generation_settings", {}) or {}
        pr = props.get("params") or {}          # some builds nest the run params here
        dp = dm.get("params") or {}             # newer builds: nested under gen-settings
        out["model"] = props.get("model_path") or props.get("model") or dm.get("model")
        out["ctx_size"] = dm.get("n_ctx") or props.get("n_ctx")
        out["n_slots"] = props.get("total_slots") or props.get("n_slots")
        # llama.cpp keeps relocating these (top level -> default_generation_settings ->
        # .params). Try the known shapes first, then fall back to a bounded deep walk so
        # a future move doesn't silently blank the panel (see _deep_num).
        out["n_threads"] = _first_num(
            props.get("n_threads"), dm.get("n_threads"),
            pr.get("n_threads"), dp.get("n_threads")) or _deep_num(props, "n_threads")
        out["n_threads_batch"] = _first_num(
            props.get("n_threads_batch"), dm.get("n_threads_batch"),
            pr.get("n_threads_batch"), dp.get("n_threads_batch")
        ) or _deep_num(props, "n_threads_batch")

    slots, serr = await fetch_json(session, f"{base}/slots", headers=h)
    if serr is None and isinstance(slots, list):
        active = 0
        pps_vals = []       # generation (decode) tok/s
        prompt_vals = []    # prompt (prefill) tok/s
        kv_vals = []
        ctx_ratios = []     # per-slot context-window fill ratio
        for s in slots:
            if s.get("is_processing") or s.get("state", 0):
                active += 1
            # newer llama.cpp nests generation timings under a "timings" object;
            # older builds put them at the slot top level. Read both.
            tim = s.get("timings") or {}
            pps = (s.get("predicted_per_second")
                   or s.get("n_predict_per_second")
                   or tim.get("predicted_per_second"))
            if isinstance(pps, (int, float)) and pps > 0:
                pps_vals.append(pps)
            # Prompt/prefill throughput — how fast the context is ingested, distinct
            # from decode speed above. On a big-context request the two diverge a lot,
            # and prefill is what a long system prompt actually pays for.
            pp = (s.get("prompt_per_second")
                  or tim.get("prompt_per_second"))
            if isinstance(pp, (int, float)) and pp > 0:
                prompt_vals.append(pp)
            kv = (s.get("kv_cache_usage_ratio")
                  if s.get("kv_cache_usage_ratio") is not None
                  else tim.get("kv_cache_usage_ratio"))
            if isinstance(kv, (int, float)):
                kv_vals.append(kv)
            # Context-window fill: used tokens / n_ctx. llama.cpp spells "used" a few
            # ways across builds (n_past / n_ctx_used / cache_tokens); take the first
            # present so the chart works where the build reports it and stays empty
            # (auto-hidden) where it does not.
            n_ctx = s.get("n_ctx") or out.get("ctx_size")
            used = _first_num(s.get("n_past"), s.get("n_ctx_used"),
                              s.get("cache_tokens"))
            if used and isinstance(n_ctx, (int, float)) and n_ctx > 0:
                ctx_ratios.append(min(used / n_ctx, 1.0))
        out["slots_active"] = active
        if out["n_slots"] is None:
            out["n_slots"] = len(slots)
        if pps_vals:
            out["predicted_per_second"] = round(sum(pps_vals) / len(pps_vals), 1)
        if prompt_vals:
            out["prompt_per_second"] = round(sum(prompt_vals) / len(prompt_vals), 1)
        # KV-cache saturation % (Tier A) + concurrency headroom
        if kv_vals:
            out["kv_cache_pct"] = round(sum(kv_vals) / len(kv_vals) * 100, 1)
        if out["n_slots"]:
            out["slots_busy_pct"] = round(active / out["n_slots"] * 100, 1)
        if ctx_ratios:
            out["ctx_used_pct"] = round(sum(ctx_ratios) / len(ctx_ratios) * 100, 1)

    return out
