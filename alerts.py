# alerts.py — threshold evaluation + webhook notification.
#
# evaluate(snap) returns the list of currently-breaching alert strings. The
# Notifier debounces: a given alert key re-fires only after ALERT_REPEAT_MIN,
# and a "recovered" note is sent once when a previously-firing key clears.
# Delivery is a single generic webhook (best-effort; a failure never breaks
# sampling).
from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

import aiohttp
from aiohttp.abc import AbstractResolver

import config
import db

# ── SSRF guard for USER-supplied webhooks ─────────────────────────────────────
# Per-user webhooks (set at /account) are attacker-influencable, so the server
# refuses a URL that resolves to a private/loopback/link-local/reserved address
# (cloud metadata, localhost, RFC1918, …) unless MONITOR_WEBHOOK_ALLOW_PRIVATE=1.
# The global ALERT_WEBHOOK_URL is operator config and is NOT checked here.
_BLOCKED_MSG = "URL resolves to a private/loopback/reserved address (blocked)"


# RFC 6598 carrier-grade-NAT / shared address space (100.64/10) is NOT flagged by
# is_private in Python < 3.13, but must never be a webhook target either.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _ip_blocked(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True                              # unparseable → fail closed
    # Collapse an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to its IPv4 form so an
    # internal v4 can't slip past the range checks by being mapped into v6.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified
            or (ip.version == 4 and ip in _CGNAT))


def _host_allowed(host: str) -> bool:
    hosts = [h.strip().lower() for h in config.WEBHOOK_ALLOW_HOSTS.split(",") if h.strip()]
    if not hosts:
        return True
    host = host.lower()
    return any(host == h or host.endswith("." + h) for h in hosts)


def _validate_sync(url: str) -> str | None:
    """None if the user webhook URL is safe to POST to, else a reason string."""
    if not url or len(url) > 2048:
        return "URL missing or too long"
    try:
        u = urlparse(url)
    except Exception:
        return "invalid URL"
    if u.scheme not in ("http", "https"):
        return "URL must be http or https"
    if config.WEBHOOK_HTTPS_ONLY and u.scheme != "https":
        return "URL must use https"
    host = u.hostname
    if not host:
        return "URL has no host"
    if not _host_allowed(host):
        return "host is not in the webhook allowlist"
    if config.WEBHOOK_ALLOW_PRIVATE:
        return None
    port = u.port or (443 if u.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except Exception:
        return "host does not resolve"
    for info in infos:                       # every resolved IP must be public
        if _ip_blocked(str(info[4][0])):
            return _BLOCKED_MSG
    return None


async def validate_webhook_url(url: str) -> str | None:
    """Async wrapper — DNS resolution (getaddrinfo) runs off the event loop."""
    return await asyncio.to_thread(_validate_sync, url)


class _SSRFResolver(AbstractResolver):
    """aiohttp resolver that drops any resolved address failing the SSRF IP check,
    so a connection can only be made to an address that was actually validated —
    the checked IP IS the connected IP. This closes the DNS-rebinding TOCTOU that a
    validate-then-reconnect-by-hostname flow leaves open (validator resolves a
    public IP, aiohttp re-resolves and connects to a rebound private IP).
    Honours WEBHOOK_ALLOW_PRIVATE so the operator opt-in still reaches a LAN host."""

    def __init__(self) -> None:
        self._base = aiohttp.ThreadedResolver()

    async def resolve(self, host: str, port: int = 0,
                      family: socket.AddressFamily = socket.AF_UNSPEC) -> list:
        infos = await self._base.resolve(host, port, family)
        if config.WEBHOOK_ALLOW_PRIVATE:
            return infos
        safe = [i for i in infos if not _ip_blocked(str(i["host"]))]
        if not safe:
            raise OSError(f"SSRF block: {host} resolves only to blocked addresses")
        return safe

    async def close(self) -> None:
        await self._base.close()


# Dedicated session for USER-supplied webhooks ONLY. Its SSRF resolver refuses to
# connect to a private/loopback/metadata address even if DNS rebinds after the
# save/tick validation, and ttl_dns_cache=0 forces a fresh resolution per connect.
# NOT used for backend collectors or the operator-set global ALERT_WEBHOOK_URL —
# those are operator config and legitimately point at LAN/private hosts.
_webhook_session: aiohttp.ClientSession | None = None


def _webhook_sender() -> aiohttp.ClientSession:
    global _webhook_session
    if _webhook_session is None or _webhook_session.closed:
        _webhook_session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(resolver=_SSRFResolver(),
                                           ttl_dns_cache=0))
    return _webhook_session


async def close_webhook_session() -> None:
    """Close the per-user webhook session (called from the app's on_cleanup)."""
    global _webhook_session
    if _webhook_session is not None and not _webhook_session.closed:
        await _webhook_session.close()
    _webhook_session = None


async def send_test(session: aiohttp.ClientSession) -> dict:
    """Fire a test message at the webhook; return its result (or 'not
    configured' when no webhook URL is set)."""
    text = "🔔 AI-Monitoring test alert — channel is working."
    n = Notifier()
    if config.ALERT_WEBHOOK_URL:
        res = await n._try_post(
            session, config.ALERT_WEBHOOK_URL,
            {"source": "AI-Monitoring", "text": text})
    else:
        res = "not configured"
    return {"webhook": res}


def channels_status() -> list[dict]:
    """Which alert channels are configured (for the alerts UI)."""
    return [
        {"id": "webhook", "name": "Webhook", "on": bool(config.ALERT_WEBHOOK_URL)},
    ]


def thresholds_status() -> dict:
    """Configured thresholds (0 = off) for the alerts UI summary."""
    return {
        "cpu_pct": config.ALERT_CPU_PCT, "mem_pct": config.ALERT_MEM_PCT,
        "disk_pct": config.ALERT_DISK_PCT, "gpu_pct": config.ALERT_GPU_PCT,
        "vram_pct": config.ALERT_VRAM_PCT, "llm_wait_ms": config.ALERT_LLM_WAIT_MS,
        "backlog": config.ALERT_BACKLOG, "backend_down": config.ALERT_ON_BACKEND_DOWN,
        "anomaly_factor": config.ANOMALY_FACTOR,
        "key_budget_hr": config.ANOMALY_KEY_BUDGET_HR,
        "repeat_min": config.ALERT_REPEAT_MIN,
    }


def _pct(used, total) -> float | None:
    try:
        if used is None or not total:
            return None
        return used / total * 100.0
    except Exception:
        return None


def evaluate(snap: dict) -> list[tuple[str, str]]:
    """Return list of (key, message) for every breaching condition."""
    out: list[tuple[str, str]] = []
    c = snap.get("collectors", {})
    h, g = c.get("host", {}), c.get("gpu", {})
    ll = c.get("litellm", {})

    if config.ALERT_CPU_PCT and h.get("available") and \
            (h.get("cpu_pct") or 0) >= config.ALERT_CPU_PCT:
        out.append(("cpu", f"CPU {h['cpu_pct']}% ≥ {config.ALERT_CPU_PCT}%"))
    if config.ALERT_MEM_PCT and h.get("available") and \
            (h.get("mem_pct") or 0) >= config.ALERT_MEM_PCT:
        out.append(("mem", f"Memory {h['mem_pct']}% ≥ {config.ALERT_MEM_PCT}%"))
    if config.ALERT_DISK_PCT and h.get("available"):
        dp = (h.get("disk") or {}).get("pct") or 0
        if dp >= config.ALERT_DISK_PCT:
            out.append(("disk", f"Disk {dp:.0f}% ≥ {config.ALERT_DISK_PCT}%"))
    if config.ALERT_GPU_PCT and g.get("available") and \
            (g.get("util") or 0) >= config.ALERT_GPU_PCT:
        out.append(("gpu", f"GPU {g['util']}% ≥ {config.ALERT_GPU_PCT}%"))
    if config.ALERT_VRAM_PCT and g.get("available"):
        vp = _pct(g.get("vram_used"), g.get("vram_total"))
        if vp is not None and vp >= config.ALERT_VRAM_PCT:
            out.append(("vram", f"VRAM {vp:.0f}% ≥ {config.ALERT_VRAM_PCT}%"))
    if config.ALERT_LLM_WAIT_MS and ll.get("available") and \
            (ll.get("wait_avg_ms") or 0) >= config.ALERT_LLM_WAIT_MS:
        out.append(("wait", f"LLM wait {ll['wait_avg_ms']}ms ≥ "
                            f"{config.ALERT_LLM_WAIT_MS}ms"))
    if config.ALERT_BACKLOG and ll.get("available") and \
            (ll.get("backlog") or 0) >= config.ALERT_BACKLOG:
        out.append(("backlog", f"LLM queue backlog {ll['backlog']} ≥ "
                              f"{config.ALERT_BACKLOG}"))
    if config.ALERT_ON_BACKEND_DOWN:
        for name in ("litellm", "ollama", "llamacpp", "gpu"):
            b = c.get(name, {})
            # "configured but down" = available False and not the unconfigured note
            if b and b.get("available") is False and \
                    b.get("error") not in (None, "unconfigured"):
                out.append((f"down:{name}", f"{name} DOWN: {b.get('error')}"))
    return out


class Notifier:
    """Debounced fan-out to every configured channel."""

    def __init__(self) -> None:
        self._last: dict[str, float] = {}   # key -> last-sent monotonic-ish ts
        self._active: set[str] = set()

    def _due(self, key: str, now: float) -> bool:
        last = self._last.get(key)
        if last is None:
            return True
        return (now - last) >= config.ALERT_REPEAT_MIN * 60

    async def process(self, session: aiohttp.ClientSession, snap: dict,
                      now: float,
                      extra_breaches: list[tuple[str, str]] | None = None
                      ) -> list[str]:
        """Diff current breaches vs active set, send new/repeat + recoveries.

        extra_breaches (e.g. per-key anomalies) participate in the same debounce
        + recovery + multi-channel fan-out as threshold breaches."""
        breaches = evaluate(snap) + list(extra_breaches or [])
        firing = {k for k, _ in breaches}
        sent: list[str] = []

        due = [(k, m) for k, m in breaches if self._due(k, now)]
        recoveries = list(self._active - firing)
        # Resolve the per-user recipient list ONCE per tick (SSRF-validate once),
        # not per alert key — cheap + observer-effect friendly.
        recipients = await self._recipients() if (due or recoveries) else []

        for key, msg in due:
            await self._fanout(session, f"🔴 {msg}", recipients)
            self._last[key] = now
            sent.append(msg)
            db.record_alert(now, key, "fire", msg)
        for key in recoveries:
            await self._fanout(session, f"🟢 recovered: {key}", recipients)
            self._last.pop(key, None)
            sent.append(f"recovered:{key}")
            db.record_alert(now, key, "recover", f"recovered: {key}")
        self._active = firing
        return sent

    def active_keys(self) -> list[str]:
        return sorted(self._active)

    async def _recipients(self) -> list[str]:
        """Validated per-user webhook URLs (enabled, non-disabled users). Bounded +
        concurrent + time-boxed so one slow-resolving host can't stall the alert tick
        (and, via the tick, the whole sampling loop): capped at WEBHOOK_MAX_RECIPIENTS
        and each validation runs under HTTP_TIMEOUT."""
        rows = list(db.user_webhooks_enabled())[:config.WEBHOOK_MAX_RECIPIENTS]

        async def _ok(url: str | None) -> str | None:
            if not url:
                return None
            try:
                if await asyncio.wait_for(validate_webhook_url(url),
                                          config.HTTP_TIMEOUT) is None:
                    return url
            except Exception:                 # timeout / resolver error → drop it
                return None
            return None

        checked = await asyncio.gather(*(_ok(r.get("url")) for r in rows))
        return [u for u in checked if u]

    async def _fanout(self, session: aiohttp.ClientSession, text: str,
                      recipients: list[str]) -> None:
        payload = {"source": "AI-Monitoring", "text": text}
        if config.ALERT_WEBHOOK_URL:                  # operator-set global (trusted)
            await self._post_json(session, config.ALERT_WEBHOOK_URL, payload)
        if recipients:                                 # per-user → SSRF-pinned sender
            wsess = _webhook_sender()                  # concurrent: each POST is
            await asyncio.gather(*(self._post_json(wsess, url, payload)  # HTTP_TIMEOUT-
                                   for url in recipients))               # bounded

    async def _post_json(self, session, url, payload) -> None:
        try:
            # `async with` so the response is released back to the pool immediately
            # (a bare post() leaks the connection/fd until GC).
            async with session.post(
                    url, json=payload, allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=config.HTTP_TIMEOUT)):
                pass
        except Exception:
            pass

    async def _try_post(self, session, url, payload) -> str:
        try:
            async with session.post(
                    url, json=payload, allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=config.HTTP_TIMEOUT)) as r:
                return "ok" if r.status < 400 else f"HTTP {r.status}"
        except Exception as e:
            return type(e).__name__


async def send_test_url(session: aiohttp.ClientSession, url: str) -> dict:
    """Validate + fire a test message at ONE user-supplied webhook URL."""
    err = await validate_webhook_url(url)
    if err:
        return {"ok": False, "error": err}
    # send via the SSRF-pinned session (not the passed shared one) so a rebind
    # between validation and connect can't reach an internal address.
    res = await Notifier()._try_post(
        _webhook_sender(), url,
        {"source": "AI-Monitoring", "text": "🔔 AI-Monitoring test alert — your webhook is working."})
    return {"ok": res == "ok", "result": res}
