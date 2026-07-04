# collectors/procs.py — top processes ("apps") by CPU and RAM from /proc.
#
# CPU% is delta-based across ticks (jiffies used / wall jiffies elapsed × ncpu).
# Processes are aggregated by "app" = comm (the executable name), so multiple
# workers of the same app sum together. Reads only /proc — pure stdlib.
#
# NOTE: inside a container this sees only the container's PID namespace. Run the
# monitor with `pid: host` (compose) to observe host-wide apps.
from __future__ import annotations

import os

_PROC = "/proc"
_prev: dict[int, tuple[str, int]] = {}   # pid -> (comm, utime+stime jiffies)
_prev_wall: float | None = None
_CLK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
_PAGE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
_NCPU = os.cpu_count() or 1


def _read_stat(pid: int):
    """Return (comm, cpu_jiffies) for a pid, or None."""
    try:
        with open(f"{_PROC}/{pid}/stat") as f:
            data = f.read()
        # comm is in parens and may contain spaces/parens — split on last ')'
        rparen = data.rfind(")")
        comm = data[data.find("(") + 1:rparen]
        fields = data[rparen + 2:].split()
        # after comm: state(0) ppid(1) ... utime(11) stime(12) (0-indexed here)
        utime = int(fields[11])
        stime = int(fields[12])
        return comm, utime + stime
    except (OSError, ValueError, IndexError):
        return None


def _read_rss(pid: int) -> int:
    """Resident memory in bytes from /proc/pid/statm (field 2 = resident pages)."""
    try:
        with open(f"{_PROC}/{pid}/statm") as f:
            resident = int(f.read().split()[1])
        return resident * _PAGE
    except (OSError, ValueError, IndexError):
        return 0


def sample(top_n: int = 10) -> dict:
    """Return top-N apps by CPU% and by RAM, aggregated by executable name."""
    global _prev, _prev_wall
    now_wall = 0.0
    try:
        # monotonic-ish wall in jiffies via total cpu time isn't per-proc; use
        # boot-relative seconds from /proc/uptime for the elapsed interval.
        with open(f"{_PROC}/uptime") as f:
            now_wall = float(f.read().split()[0])
    except Exception:
        pass

    pids = []
    try:
        pids = [int(d) for d in os.listdir(_PROC) if d.isdigit()]
    except Exception:
        return {"available": False, "error": "cannot read /proc"}

    cur: dict[int, tuple[str, int]] = {}
    rss_by_app: dict[str, int] = {}
    cpu_by_app: dict[str, float] = {}
    elapsed = (now_wall - _prev_wall) if _prev_wall else 0.0

    for pid in pids:
        st = _read_stat(pid)
        if not st:
            continue
        comm, jiff = st
        cur[pid] = (comm, jiff)
        rss_by_app[comm] = rss_by_app.get(comm, 0) + _read_rss(pid)
        # CPU% only when we have a previous sample for this pid + elapsed time
        if elapsed > 0 and pid in _prev and _prev[pid][0] == comm:
            d = jiff - _prev[pid][1]
            if d > 0:
                pct = (d / _CLK) / elapsed * 100.0   # % of ONE core
                cpu_by_app[comm] = cpu_by_app.get(comm, 0.0) + pct

    _prev = cur
    _prev_wall = now_wall

    top_cpu = sorted(cpu_by_app.items(), key=lambda x: -x[1])[:top_n]
    top_ram = sorted(rss_by_app.items(), key=lambda x: -x[1])[:top_n]
    return {
        "available": True,
        "ncpu": _NCPU,
        "top_cpu": [{"app": a, "cpu": round(c, 1)} for a, c in top_cpu],
        "top_ram": [{"app": a, "ram": r} for a, r in top_ram],
    }
