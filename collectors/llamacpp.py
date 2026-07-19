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
        out["model"] = props.get("model_path") or props.get("model") or dm.get("model")
        out["ctx_size"] = dm.get("n_ctx") or props.get("n_ctx")
        out["n_slots"] = props.get("total_slots") or props.get("n_slots")
        # llama.cpp has moved these between top level / default_generation_settings /
        # params across builds, so read all three rather than pin one shape.
        out["n_threads"] = _first_num(
            props.get("n_threads"), dm.get("n_threads"), pr.get("n_threads"))
        out["n_threads_batch"] = _first_num(
            props.get("n_threads_batch"), dm.get("n_threads_batch"),
            pr.get("n_threads_batch"))

    slots, serr = await fetch_json(session, f"{base}/slots", headers=h)
    if serr is None and isinstance(slots, list):
        active = 0
        pps_vals = []
        kv_vals = []
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
            kv = (s.get("kv_cache_usage_ratio")
                  if s.get("kv_cache_usage_ratio") is not None
                  else tim.get("kv_cache_usage_ratio"))
            if isinstance(kv, (int, float)):
                kv_vals.append(kv)
        out["slots_active"] = active
        if out["n_slots"] is None:
            out["n_slots"] = len(slots)
        if pps_vals:
            out["predicted_per_second"] = round(sum(pps_vals) / len(pps_vals), 1)
        # KV-cache saturation % (Tier A) + concurrency headroom
        if kv_vals:
            out["kv_cache_pct"] = round(sum(kv_vals) / len(kv_vals) * 100, 1)
        if out["n_slots"]:
            out["slots_busy_pct"] = round(active / out["n_slots"] * 100, 1)

    return out
