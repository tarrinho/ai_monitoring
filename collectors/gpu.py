# collectors/gpu.py — GPU utilization + VRAM, local OR on a remote GPU box.
#
# The GPU host is often a different machine. Three modes (precedence order):
#   1. SSH  (config.GPU_SSH="user@host")  -> run nvidia-smi over SSH, agentless.
#   2. HTTP (config.GPU_METRICS_URL)      -> GET GPU JSON from an agent endpoint.
#   3. local nvidia-smi / rocm-smi.
# In every mode a missing GPU / missing nvidia-smi yields available=False with a
# reason, so the dashboard shows whether the target box actually has a GPU.
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import urllib.request

import config

_MiB = 1024 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses to follow 3xx — returning None makes urllib
    raise the HTTPError instead of chasing the Location (SSRF guard for _http)."""
    def redirect_request(self, *_args, **_kwargs):   # noqa: D102
        return None

_NVIDIA_QUERY = [
    "nvidia-smi",
    "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,"
    "power.draw,power.limit,clocks_throttle_reasons.hw_slowdown",
    "--format=csv,noheader,nounits",
]


def _run(cmd: list[str], timeout: float = 6.0) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if out.returncode == 0:
            return out.stdout
    except Exception:
        pass
    return None


def _ssh_prefix() -> list[str] | None:
    if not config.GPU_SSH:
        return None
    # Reject a host or key path that begins with '-': although _run uses an argv
    # list (no shell → no command injection), ssh would parse a '-'-prefixed value
    # as an OPTION (e.g. GPU_SSH="-oProxyCommand=…" → local command execution).
    if config.GPU_SSH.startswith("-") or \
            (config.GPU_SSH_KEY and config.GPU_SSH_KEY.startswith("-")):
        return None
    pre = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=4",
           "-o", "StrictHostKeyChecking=accept-new"]
    if config.GPU_SSH_KEY:
        pre += ["-i", config.GPU_SSH_KEY]
    if config.GPU_SSH_PORT and config.GPU_SSH_PORT != 22:
        pre += ["-p", str(config.GPU_SSH_PORT)]
    pre += ["--", config.GPU_SSH]      # '--' ends option parsing before the host
    return pre


def _fnum(v):
    try:
        return float(v)
    except (ValueError, TypeError):
        return None


def _parse_nvidia_csv(out: str) -> list[dict]:
    gpus = []
    for line in out.strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 5 or not parts[0]:
            continue
        # Every numeric field is parsed tolerantly — some GPUs report "[N/A]" for
        # columns they don't have (e.g. the GB10 unified-memory superchip has no
        # separate VRAM). A missing metric becomes None instead of dropping the
        # whole GPU, so util/temp/power still show.
        mu, mt = _fnum(parts[2]), _fnum(parts[3])
        gpus.append({
            "name": parts[0],
            "util": _fnum(parts[1]) or 0.0,
            "vram_used": int(mu * _MiB) if mu is not None else None,
            "vram_total": int(mt * _MiB) if mt is not None else None,
            "temp": _fnum(parts[4]),
            "power": _fnum(parts[5]) if len(parts) > 5 else None,
            "power_limit": _fnum(parts[6]) if len(parts) > 6 else None,
            "throttled": (parts[7].lower() == "active") if len(parts) > 7 else None,
        })
    return gpus


def _nvidia_local() -> dict | None:
    if not shutil.which("nvidia-smi"):
        return None
    out = _run(_NVIDIA_QUERY, timeout=4)
    gpus = _parse_nvidia_csv(out) if out else []
    return {"vendor": "nvidia", "gpus": gpus} if gpus else None


def _nvidia_file() -> dict | None:
    """Read nvidia-smi CSV that the host writes to a mounted file (read-only). A
    stale file (host stopped writing) is treated as no data so the panel doesn't
    show frozen numbers."""
    path = config.GPU_METRICS_FILE
    if not path:
        return None
    try:
        if time.time() - os.path.getmtime(path) > config.GPU_FILE_MAX_AGE:
            return None                  # stale
        with open(path, encoding="utf-8") as f:
            out = f.read()
    except Exception:
        return None
    gpus = _parse_nvidia_csv(out)
    return {"vendor": "nvidia", "gpus": gpus} if gpus else None


def _nvidia_ssh(pre: list[str]) -> dict | None:
    out = _run(pre + _NVIDIA_QUERY, timeout=8)
    if out is None:
        return None                      # ssh failed OR remote has no nvidia-smi
    gpus = _parse_nvidia_csv(out)
    return {"vendor": "nvidia", "gpus": gpus} if gpus else None


def _rocm_local() -> dict | None:
    if not shutil.which("rocm-smi"):
        return None
    out = _run(["rocm-smi", "--showuse", "--showmeminfo", "vram", "--json"])
    if not out:
        return None
    try:
        data = json.loads(out)
    except Exception:
        return None
    gpus = []
    for k, v in data.items():
        if not k.lower().startswith("card"):
            continue
        try:
            gpus.append({
                "name": k,
                "util": float(str(v.get("GPU use (%)", 0)).strip() or 0),
                "vram_used": int(v.get("VRAM Total Used Memory (B)", 0) or 0),
                "vram_total": int(v.get("VRAM Total Memory (B)", 0) or 0),
                "temp": None,
            })
        except (ValueError, TypeError):
            continue
    return {"vendor": "amd", "gpus": gpus} if gpus else None


def _http() -> dict | None:
    """Fetch GPU JSON from an agent. Accepts our own schema or {gpus:[...]}."""
    url = config.GPU_METRICS_URL or ""
    # only http(s): a misconfigured/injected file:// or gopher:// URL must not
    # turn this fetch into local-file exfiltration or an SSRF primitive.
    if not url.startswith(("http://", "https://")):
        return None
    try:
        # bypass any http_proxy/https_proxy env — the GPU agent is a local/LAN
        # endpoint and must not be routed through a corporate proxy. Redirects are
        # NOT followed (_NoRedirect): a 3xx to file://-via-http or an internal
        # metadata IP would otherwise turn this into an SSRF/exfil primitive.
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect())
        with opener.open(url, timeout=4) as r:  # noqa: S310 (scheme-checked)
            data = json.loads(r.read().decode())
    except Exception:
        return None
    gpus_in = data.get("gpus") if isinstance(data, dict) else None
    if not isinstance(gpus_in, list):
        return None
    gpus = []
    for g in gpus_in:
        try:
            gpus.append({
                "name": g.get("name", "gpu"),
                "util": float(g.get("util", g.get("utilization", 0)) or 0),
                "vram_used": int(g.get("vram_used", g.get("memory_used", 0)) or 0),
                "vram_total": int(g.get("vram_total", g.get("memory_total", 0)) or 0),
                "temp": g.get("temp", g.get("temperature")),
            })
        except (ValueError, TypeError):
            continue
    return {"vendor": data.get("vendor", "remote"), "gpus": gpus} if gpus else None


def sample() -> dict:
    """GPU snapshot from the configured target. Never raises."""
    ssh_pre = _ssh_prefix()
    if config.GPU_METRICS_FILE:
        res, mode, target = _nvidia_file(), "file", config.GPU_METRICS_FILE or ""
    elif ssh_pre is not None:
        res, mode, target = _nvidia_ssh(ssh_pre), "ssh", config.GPU_SSH or ""
    elif config.GPU_METRICS_URL:
        res, mode, target = _http(), "http", config.GPU_METRICS_URL or ""
    else:
        res, mode, target = (_nvidia_local() or _rocm_local()), "local", "local"

    if not res or not res.get("gpus"):
        # local mode with no GPU CLI = there is simply no GPU here → treat as
        # "unconfigured" (hidden panel, NO backend-down alert). file/ssh/http modes
        # were explicitly pointed at a GPU box, so a failure IS a real outage.
        errs = {
            "file": f"gpu file {target}: missing, empty, or stale (>{config.GPU_FILE_MAX_AGE:.0f}s)",
            "ssh": f"remote {target}: no GPU / nvidia-smi (or SSH failed)",
            "http": f"gpu agent {target} unreachable / no gpus",
            "local": "unconfigured",
        }
        return {"available": False, "mode": mode, "error": errs[mode]}

    gpus = res["gpus"]
    util_vals = [g["util"] for g in gpus if g.get("util") is not None]
    power_vals = [g["power"] for g in gpus if g.get("power") is not None]
    temp_vals = [g["temp"] for g in gpus if g.get("temp") is not None]
    return {
        "available": True,
        "mode": mode,
        "target": target,
        "vendor": res.get("vendor", "nvidia"),
        "count": len(gpus),
        "util": round(sum(util_vals) / len(util_vals), 1) if util_vals else 0.0,
        # None (not 0) when NO gpu reports VRAM — e.g. the GB10's unified memory.
        # Lets the dashboard hide the VRAM tiles instead of drawing a flat 0.
        "vram_used": (sum(vu) if (vu := [g["vram_used"] for g in gpus
                      if g.get("vram_used") is not None]) else None),
        "vram_total": (sum(vt) if (vt := [g["vram_total"] for g in gpus
                       if g.get("vram_total") is not None]) else None),
        "power": round(sum(power_vals), 1) if power_vals else None,
        "temp_max": max(temp_vals) if temp_vals else None,
        "throttled": any(g.get("throttled") for g in gpus),
        "gpus": gpus,
    }
