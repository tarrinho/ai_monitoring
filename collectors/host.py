# collectors/host.py — host resource sampling from /proc + statvfs.
#
# Design adapted from the GW service_metrics sampler. Pure stdlib, no deps.
# CPU % is delta-based across ticks; the collector holds the previous cpu
# snapshot between calls.
from __future__ import annotations

import os

_PROC = "/proc"
_prev_cpu: tuple[int, int] | None = None  # (total, idle) from last sample


def _read_cpu() -> tuple[int, int] | None:
    try:
        with open(f"{_PROC}/stat") as f:
            nums = [int(x) for x in f.readline().split()[1:]]
        idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
        return sum(nums), idle
    except Exception:
        return None


def _read_meminfo() -> dict[str, int]:
    out: dict[str, int] = {}
    try:
        with open(f"{_PROC}/meminfo") as f:
            for line in f:
                k, _, rest = line.partition(":")
                v = rest.strip().split()
                if v:
                    out[k.strip()] = int(v[0]) * 1024  # kB → bytes
    except Exception:
        pass
    return out


def _disk(path: str) -> dict[str, float]:
    try:
        s = os.statvfs(path)
        total = s.f_frsize * s.f_blocks
        avail = s.f_frsize * s.f_bavail
        used = total - avail
        return {"total": total, "used": used, "avail": avail,
                "pct": (used / total * 100) if total else 0.0}
    except Exception:
        return {}


def _loadavg() -> list[float]:
    try:
        return list(os.getloadavg())
    except (OSError, AttributeError):
        return [0.0, 0.0, 0.0]


def sample(disk_path: str = "/") -> dict:
    """Return a host snapshot. Never raises — degrades to partial data."""
    global _prev_cpu
    cpu_pct = 0.0
    cur = _read_cpu()
    if cur and _prev_cpu:
        d_total = cur[0] - _prev_cpu[0]
        d_idle = cur[1] - _prev_cpu[1]
        if d_total > 0:
            cpu_pct = max(0.0, min(100.0, (1 - d_idle / d_total) * 100))
    if cur:
        _prev_cpu = cur

    mem = _read_meminfo()
    mem_total = mem.get("MemTotal", 0)
    mem_avail = mem.get("MemAvailable", 0)
    mem_used = mem_total - mem_avail if mem_total else 0

    return {
        "available": True,
        "cpu_pct": round(cpu_pct, 1),
        "load": _loadavg(),
        "mem_total": mem_total,
        "mem_used": mem_used,
        "mem_avail": mem_avail,
        "mem_pct": round(mem_used / mem_total * 100, 1) if mem_total else 0.0,
        "disk": _disk(disk_path),
        "ncpu": os.cpu_count() or 0,
    }
