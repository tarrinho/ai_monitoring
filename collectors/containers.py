# collectors/containers.py — per-container liveness + alive-time via the Docker
# Engine API (read-only GETs). For each configured container name it reports
# whether it's running and, if so, how long it's been alive (now - State.StartedAt).
# No docker CLI needed; pure aiohttp.
#
# Two transports (see config F1): preferred is a read-only socket PROXY over TCP
# (MONITOR_DOCKER_API_URL) so the monitor never touches the host-root raw socket;
# the legacy fallback is the unix socket mounted into the monitor. Missing
# socket/proxy or perms → available:False with an error string; it never raises.
from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import datetime, timezone
from urllib.parse import quote

import aiohttp

import config

_session: aiohttp.ClientSession | None = None
_last_seen: dict = {}   # container name -> epoch when last observed in Docker


def _parse_started(s: str | None) -> float | None:
    """Docker State.StartedAt is RFC-3339 with nanoseconds
    (e.g. '2026-07-03T10:00:00.123456789Z'). datetime.fromisoformat wants ≤6
    fractional digits, so trim. Returns epoch seconds, or None."""
    if not s or s.startswith("0001-01-01"):   # zero value = never started
        return None
    txt: str = s.replace("Z", "+00:00")
    m = re.match(r"^(.*\.\d{6})\d*(\+\d{2}:\d{2}|)$", txt)
    if m:
        txt = str(m.group(1)) + str(m.group(2))
    try:
        dt = datetime.fromisoformat(txt)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


def _base() -> str:
    """Base URL for the Docker Engine API. With a socket proxy (F1) this is a real
    TCP URL; over the raw unix socket aiohttp needs a dummy host ('http://docker')."""
    if config.DOCKER_API_URL:
        return config.DOCKER_API_URL.rstrip("/")
    return "http://docker"


async def _sess() -> aiohttp.ClientSession:
    global _session
    if _session is None or _session.closed:
        if config.DOCKER_API_URL:
            # F1: talk to a read-only socket proxy over TCP — no raw socket mount,
            # so a monitor compromise can't reach the full host-root Docker API.
            _session = aiohttp.ClientSession()
        else:
            _session = aiohttp.ClientSession(
                connector=aiohttp.UnixConnector(path=config.DOCKER_SOCKET or "/var/run/docker.sock"))
    return _session


async def close() -> None:
    """Close the module-level unix-socket session (call on app shutdown)."""
    global _session
    if _session is not None and not _session.closed:
        await _session.close()
    _session = None


async def sample(_session: aiohttp.ClientSession | None = None) -> dict:
    """Return {available, containers:[{name, running, status, uptime_s}]}.
    The passed session (TCP) is ignored — we use a unix-socket session.
    MONITOR_CONTAINERS empty  -> auto-discover ALL host containers.
    MONITOR_CONTAINERS set     -> only those names (missing ones show 'not found')."""
    try:
        s = await _sess()
    except Exception as e:
        return {"available": False, "error": f"docker socket: {type(e).__name__}"}

    names = list(config.MONITOR_CONTAINERS)
    if not names:
        # discover every container on the host (running + stopped)
        try:
            async with s.get(f"{_base()}/containers/json?all=1",
                             allow_redirects=False,          # SSRF guard (T-24): a TCP socket-proxy
                             timeout=aiohttp.ClientTimeout(total=4)) as r:
                if r.status != 200:
                    return {"available": False, "error": f"list HTTP {r.status}"}
                # Byte-cap the list read (even a local docker can report a huge container set).
                # Read to the cap with iter_chunked — a single StreamReader.read(n) returns only
                # the first buffered chunk, NOT n bytes, so on a multi-chunk body it would parse
                # truncated JSON; accumulate like litellm._fetch_spend_raw does.
                buf = bytearray()
                async for chunk in r.content.iter_chunked(65536):
                    buf += chunk
                    if len(buf) > config.HTTP_MAX_BYTES:
                        return {"available": False, "error": "container list too large"}
                names = [(c.get("Names") or ["/?"])[0].lstrip("/")
                         for c in json.loads(bytes(buf) or b"[]")]
        except Exception as e:
            return {"available": False, "error": f"docker list: {type(e).__name__}"}

    now = time.time()

    async def _inspect(name: str) -> dict:
        entry = {"name": name, "running": False, "status": None,
                 "uptime_s": None, "down_s": None}
        try:
            async with s.get(f"{_base()}/containers/{quote(name, safe='')}/json",
                             allow_redirects=False,          # SSRF guard (T-24): no 3xx bounce
                             timeout=aiohttp.ClientTimeout(total=4)) as r:
                if r.status == 404:
                    # removed from Docker entirely — fall back to when WE last saw it
                    entry["status"] = "not found"
                    ls = _last_seen.get(name)
                    if ls:
                        entry["down_s"] = max(0, int(now - ls))
                elif r.status != 200:
                    entry["status"] = f"HTTP {r.status}"
                else:
                    # Byte-cap the inspect read too (T-23): a hostile/compromised socket-proxy could
                    # stream a huge inspect body — and this runs up to 50 concurrent. Accumulate to
                    # the cap like the list path, then parse.
                    ibuf = bytearray()
                    async for chunk in r.content.iter_chunked(65536):
                        ibuf += chunk
                        if len(ibuf) > config.HTTP_MAX_BYTES:
                            entry["status"] = "inspect too large"
                            return entry
                    st = json.loads(bytes(ibuf) or b"{}").get("State") or {}
                    _last_seen[name] = now          # observed (running or not)
                    entry["running"] = bool(st.get("Running"))
                    entry["status"] = st.get("Status")
                    if entry["running"]:
                        started = _parse_started(st.get("StartedAt"))
                        if started:
                            entry["uptime_s"] = max(0, int(now - started))
                    else:
                        # stopped — down since FinishedAt (persists across our restarts)
                        fin = _parse_started(st.get("FinishedAt"))
                        if fin:
                            entry["down_s"] = max(0, int(now - fin))
        except Exception as e:
            entry["status"] = f"err: {type(e).__name__}"
        return entry

    # Inspect concurrently (cap kept for card readability). Sequential inspects
    # would sum per-container timeouts and blow past the backend loop's wait_for
    # bound on a busy host, cancelling the whole sample every tick → permanent
    # stale panel. Concurrent → wall-time ≈ one timeout regardless of count.
    total = len(names)
    out = list(await asyncio.gather(*(_inspect(n) for n in names[:50])))
    # running first, then alphabetical — stable, readable ordering
    out.sort(key=lambda x: (not x["running"], x["name"]))
    # bound memory in auto-discover mode: forget containers not seen for a week
    # so ephemeral/CI container names don't accumulate for the process lifetime.
    if len(_last_seen) > 256:
        cutoff = now - 7 * 24 * 3600
        for stale in [k for k, t in _last_seen.items() if t < cutoff]:
            del _last_seen[stale]
    # Surface auto-discover truncation so the UI can say "showing 50 of N" instead of
    # silently dropping the rest (a busy host with >50 containers).
    res = {"available": True, "containers": out}
    if total > 50:
        res["truncated"] = True
        res["total"] = total
    return res
