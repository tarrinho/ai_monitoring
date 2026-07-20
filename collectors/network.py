# collectors/network.py — host network I/O from /proc/net/dev.
#
# Pure stdlib /proc read, same class as host.py: cheap, non-blocking, sampled
# inline on the main tick (never in a backend loop). /proc/net/dev gives
# CUMULATIVE byte + packet counters per interface since boot; we keep the
# previous sample to differentiate them into down/up RATES (bytes/sec), the same
# delta pattern host.py uses for CPU% and vllm.py for token/s.
from __future__ import annotations

import time

import config

_PROC = "/proc"

# Virtual / non-physical interfaces the "total" and default view skip — loopback,
# container veths, bridges, VPN/overlay taps. They double-count real traffic
# (a veth mirrors what eth0 already carried) and bury the physical NIC. A user
# can still force any set with NETWORK_IFACES.
_VIRTUAL_PREFIXES = ("lo", "veth", "docker", "br-", "virbr", "cni", "flannel",
                     "cali", "tunl", "tun", "tap", "kube", "nodelocal", "dummy",
                     "bond-slave",
                     # overlay VPNs mirror traffic the physical NIC already carried,
                     # so counting them again inflates the host total
                     "tailscale", "wg", "zt")

# Previous per-interface counters, for differentiating cumulative bytes into a rate.
# Module-level like host._prev_cpu: one monitored host per instance.
_prev: dict = {"ts": None, "ifaces": {}}


def _is_physical(name: str) -> bool:
    return not any(name == p or name.startswith(p) for p in _VIRTUAL_PREFIXES)


def _iface_filter() -> set[str] | None:
    """Explicit interface whitelist from NETWORK_IFACES (comma-separated), or None
    to auto-select physical interfaces. Lets an operator pin exactly the NIC(s)
    that matter (e.g. only `eth0`) on a host full of virtual devices."""
    raw = config.NETWORK_IFACES
    if not raw:
        return None
    names = {n.strip() for n in raw.split(",") if n.strip()}
    return names or None


def _read_net_dev() -> dict[str, dict[str, int]]:
    """Parse /proc/net/dev into {iface: {rx_bytes, rx_packets, rx_errs, rx_drop,
    tx_bytes, tx_packets, tx_errs, tx_drop}}. Returns {} on any error."""
    out: dict[str, dict[str, int]] = {}
    try:
        with open(f"{_PROC}/net/dev") as f:
            lines = f.readlines()
    except Exception:
        return {}
    # first two lines are headers; each data line is "  name: rx... tx..."
    for ln in lines[2:]:
        name, _, rest = ln.partition(":")
        name = name.strip()
        cols = rest.split()
        if not name or len(cols) < 16:
            continue
        try:
            nums = [int(c) for c in cols[:16]]
        except ValueError:
            continue
        out[name] = {
            "rx_bytes": nums[0], "rx_packets": nums[1],
            "rx_errs": nums[2], "rx_drop": nums[3],
            "tx_bytes": nums[8], "tx_packets": nums[9],
            "tx_errs": nums[10], "tx_drop": nums[11],
        }
    return out


def _rate(cur: int, prev: int | None, dt: float) -> float | None:
    """Bytes/sec between two cumulative readings, or None on the first sample or a
    counter RESET (reboot / iface re-created → cur < prev). A negative delta would
    render as a huge bogus spike, so a one-sample gap is preferred."""
    if prev is None or dt <= 0 or cur < prev:
        return None
    return round((cur - prev) / dt, 1)


def sample() -> dict:
    """Host network snapshot. Never raises — degrades to partial/empty data.

    Rates are None until a second sample exists (and across a counter reset); the
    dashboard charts them with empty-tile auto-hide, so a fresh start shows totals
    immediately and speeds fill in on the next tick."""
    now = time.time()
    dev = _read_net_dev()
    if not dev:
        return {"available": False, "error": "no /proc/net/dev"}

    whitelist = _iface_filter()
    prev_ifaces = _prev["ifaces"]
    dt = (now - _prev["ts"]) if _prev["ts"] is not None else 0.0

    ifaces: list[dict] = []
    rx_rate_total = tx_rate_total = 0.0
    rx_bytes_total = tx_bytes_total = 0
    have_rate = False
    for name, c in sorted(dev.items()):
        selected = (name in whitelist) if whitelist is not None else _is_physical(name)
        if not selected:
            continue
        p = prev_ifaces.get(name)
        rx_rate = _rate(c["rx_bytes"], p["rx_bytes"] if p else None, dt)
        tx_rate = _rate(c["tx_bytes"], p["tx_bytes"] if p else None, dt)
        if rx_rate is not None:
            rx_rate_total += rx_rate
            have_rate = True
        if tx_rate is not None:
            tx_rate_total += tx_rate
            have_rate = True
        rx_bytes_total += c["rx_bytes"]
        tx_bytes_total += c["tx_bytes"]
        ifaces.append({
            "name": name,
            "rx_bytes": c["rx_bytes"], "tx_bytes": c["tx_bytes"],
            "rx_rate": rx_rate, "tx_rate": tx_rate,
            "rx_packets": c["rx_packets"], "tx_packets": c["tx_packets"],
            "rx_errs": c["rx_errs"], "tx_errs": c["tx_errs"],
            "rx_drop": c["rx_drop"], "tx_drop": c["tx_drop"],
        })

    # remember EVERY interface's counters (not just the selected ones) so a filter
    # change between ticks still has a baseline to diff against.
    _prev["ts"] = now
    _prev["ifaces"] = {n: {"rx_bytes": c["rx_bytes"], "tx_bytes": c["tx_bytes"]}
                       for n, c in dev.items()}

    # "primary" = the busiest selected NIC by lifetime traffic — what the KPI strip
    # leads with when several are present.
    primary = None
    if ifaces:
        primary = max(ifaces, key=lambda i: i["rx_bytes"] + i["tx_bytes"])["name"]

    return {
        "available": True,
        "interfaces": ifaces,
        "primary": primary,
        "rx_rate_total": round(rx_rate_total, 1) if have_rate else None,
        "tx_rate_total": round(tx_rate_total, 1) if have_rate else None,
        "rx_bytes_total": rx_bytes_total,
        "tx_bytes_total": tx_bytes_total,
    }
