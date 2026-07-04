# collectors/ollama.py — Ollama running/installed models + RAM/VRAM.
#
# JSON only (verified against ollama/ollama docs/api.md):
#   GET /api/ps      -> running models: size (RAM), size_vram, expires_at, details
#   GET /api/tags    -> installed models
#   GET /api/version -> ollama version
# Ollama exposes no request-latency; that comes from LiteLLM.
from __future__ import annotations

import aiohttp

import config
from collectors import fetch_json, unconfigured


def _gpu_pct(size: int, vram: int) -> float:
    """Share of the loaded model resident on GPU (size_vram / size)."""
    return round(vram / size * 100, 1) if size else 0.0


async def sample(session: aiohttp.ClientSession) -> dict:
    base = config.OLLAMA_BASE_URL
    if not base:
        return unconfigured()
    base = base.rstrip("/")

    ps, err = await fetch_json(session, f"{base}/api/ps")
    if err is not None:
        return {"available": False, "error": err}

    running = []
    ram_total = vram_total = 0
    for m in (ps or {}).get("models", []) or []:
        size = int(m.get("size", 0) or 0)
        vram = int(m.get("size_vram", 0) or 0)
        det = m.get("details") or {}
        ram_total += size
        vram_total += vram
        running.append({
            "name": m.get("name") or m.get("model") or "?",
            "size": size,
            "size_vram": vram,
            "gpu_pct": _gpu_pct(size, vram),   # GPU vs CPU split of the model
            "params": det.get("parameter_size"),
            "quant": det.get("quantization_level"),
            "family": det.get("family"),
            "expires_at": m.get("expires_at"),
        })

    installed = 0
    tags, terr = await fetch_json(session, f"{base}/api/tags")
    if terr is None and tags:
        installed = len(tags.get("models", []) or [])

    version = None
    ver, verr = await fetch_json(session, f"{base}/api/version")
    if verr is None and ver:
        version = ver.get("version")

    # overall GPU-resident share across all running models
    gpu_pct = round(vram_total / ram_total * 100, 1) if ram_total else 0.0

    return {
        "available": True,
        "version": version,
        "models_running": len(running),
        "models_installed": installed,
        "ram_used": ram_total,
        "vram_used": vram_total,
        "gpu_pct": gpu_pct,
        "models": running,
    }
