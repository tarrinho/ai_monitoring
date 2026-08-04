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
import time
from urllib.parse import urlparse

import aiohttp
from aiohttp.abc import AbstractResolver

import config
import db
import obslog

_LOG = obslog.get("alerts")     # fire/recover edges (INFO recover, WARNING fire)


def _is_teams_url(url: str) -> bool:
    """An MS Teams incoming-webhook URL — Power Automate "Workflows" (…logic.azure.com/…/workflows/…)
    or a legacy O365 connector (…webhook.office.com…). Those need an Adaptive-Card envelope, not a
    bare {text}: without it Teams returns 202 (so the sender sees 'delivered') but the card never
    posts — the classic 'delivered but nothing shows' symptom."""
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    return (host.endswith("logic.azure.com") or host.endswith("logic.azure.us")
            or host.endswith("logic.azure.de") or host.endswith("webhook.office.com")
            or "/workflows/" in (url or ""))


# Human labels for the backends, so a message reads "vLLM is DOWN", not "vllm DOWN".
_SVC = {"litellm": "LiteLLM", "ollama": "Ollama", "llamacpp": "llama.cpp",
        "vllm": "vLLM", "gpu": "GPU"}
# Human labels for the threshold-alert keys, for a clean recovery line.
_METRIC = {"cpu": "CPU", "mem": "Memory", "disk": "Disk", "gpu": "GPU", "vram": "VRAM",
           "wait": "LLM wait", "vllm_queue": "vLLM queue", "backlog": "LLM backlog"}


def _machine(snap: dict) -> str:
    """Name of the monitored machine for the alert prefix: the operator override
    (MONITOR_INSTANCE_NAME) if set, else the host collector's own hostname."""
    if config.INSTANCE_NAME:
        return config.INSTANCE_NAME
    host = (snap.get("collectors", {}) or {}).get("host", {}) or {}
    return host.get("hostname") or "unknown-host"


def _alert_text(snap: dict, body: str, fired: bool) -> str:
    """One consistent, polished line for every channel: which machine, which tool, then the
    event — e.g. '🔴 [gpu-box-01] AI-Monitoring — vLLM is DOWN — connection refused'."""
    return f"{'🔴' if fired else '🟢'} [{_machine(snap)}] AI-Monitoring — {body}"


def _recover_msg(key: str) -> str:
    """Friendly recovery body from an alert key (on recovery only the key is known)."""
    if key.startswith("down:"):
        name = key.split(":", 1)[1]
        return f"{_SVC.get(name, name)} is back UP"
    return f"{_METRIC.get(key, key)} back to normal"


def _log_url(url: str) -> str:
    """Host (+port) only — the webhook URL's PATH/QUERY carries the secret (Teams `sig=`, Slack
    token in the path), so the full URL must never reach the log. Host alone identifies the target."""
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.hostname}" + (f":{p.port}" if p.port else "")
    except Exception:
        return "?"


def _webhook_payload(text: str, url: str) -> dict:
    """Shape the POST body for the destination (config.WEBHOOK_FORMAT; "auto" picks by URL):
      teams   -> Adaptive-Card message envelope the stock Teams flow renders with no flow edits
      slack   -> {"text": …}  (Slack incoming webhooks)
      generic -> {"source": "AI-Monitoring", "text": …}  (unchanged default for every other receiver)"""
    fmt = config.WEBHOOK_FORMAT
    if fmt == "auto":
        fmt = "teams" if _is_teams_url(url) else "generic"
    if fmt == "teams":
        return {"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {"type": "AdaptiveCard",
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "version": "1.4",
                        "body": [{"type": "TextBlock", "text": text, "wrap": True}]}}]}
    if fmt == "slack":
        return {"text": text}
    return {"source": "AI-Monitoring", "text": text}

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


def _priv_allowed() -> bool:
    """May a USER webhook resolve to a private/reserved address? Only when the operator has
    ALSO pinned the targets with an explicit allow-list (WEBHOOK_ALLOW_HOSTS). WEBHOOK_ALLOW_PRIVATE
    alone is NOT enough — on its own it would hand any viewer an unconstrained SSRF primitive
    (POST to cloud-metadata / internal services). The trusted operator-global ALERT_WEBHOOK_URL
    bypasses this whole path, so a LAN operator's own alert URL is unaffected either way."""
    return config.WEBHOOK_ALLOW_PRIVATE and bool(config.WEBHOOK_ALLOW_HOSTS.strip())


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
    if _priv_allowed():        # private targets only when explicitly allow-listed (see _priv_allowed)
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
        if _priv_allowed():        # private targets only when explicitly allow-listed
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
            _webhook_payload(text, config.ALERT_WEBHOOK_URL))
    else:
        res = "not configured"
    return {"webhook": res}


async def _record_send(channel: str, akey: str, status: int | None,
                       ok: bool, ms: float | None) -> None:
    """Persist ONE delivery outcome for the Channels card's recent-deliveries list.

    Runs OFF the event loop (§6 observer-effect) and swallows everything: this is bookkeeping
    about a notification, so a failure here must never propagate into the notifier and stop the
    next alert from being delivered."""
    try:
        await asyncio.to_thread(db.record_webhook_send, time.time(), channel,
                                akey, status, ok, ms)
    except Exception:
        pass


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
        "vllm_waiting": config.ALERT_VLLM_WAITING,
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
    vl = snap.get("collectors", {}).get("vllm", {}) or {}
    if config.ALERT_VLLM_WAITING and vl.get("available") and \
            (vl.get("waiting") or 0) >= config.ALERT_VLLM_WAITING:
        out.append(("vllm_queue", f"vLLM queue {vl['waiting']:.0f} waiting ≥ "
                                  f"{config.ALERT_VLLM_WAITING:.0f}"))
    if config.ALERT_BACKLOG and ll.get("available") and \
            (ll.get("backlog") or 0) >= config.ALERT_BACKLOG:
        out.append(("backlog", f"LLM queue backlog {ll['backlog']} ≥ "
                              f"{config.ALERT_BACKLOG}"))
    if config.ALERT_ON_BACKEND_DOWN:
        for name in ("litellm", "ollama", "llamacpp", "vllm", "gpu"):
            b = c.get(name, {})
            # "configured but down" = available False and not the unconfigured note
            if b and b.get("available") is False and \
                    b.get("error") not in (None, "unconfigured"):
                out.append((f"down:{name}",
                            f"{_SVC.get(name, name)} is DOWN — {b.get('error')}"))
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
            await self._fanout(session, _alert_text(snap, msg, fired=True), recipients, key)
            self._last[key] = now
            sent.append(msg)
            db.record_alert(now, key, "fire", msg)
            _LOG.warning("alert fired", extra={"key": key, "detail": msg,
                                               "machine": _machine(snap)})
        for key in recoveries:
            rmsg = _recover_msg(key)
            await self._fanout(session, _alert_text(snap, rmsg, fired=False), recipients, key)
            self._last.pop(key, None)
            sent.append(f"recovered:{key}")
            db.record_alert(now, key, "recover", rmsg)
            _LOG.info("alert recovered", extra={"key": key, "detail": rmsg,
                                                "machine": _machine(snap)})
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
                      recipients: list[str], akey: str = "") -> None:
        # Build the body PER URL: a Teams URL and a Slack URL need different shapes,
        # and a fan-out can mix destinations (global vs per-user).
        if config.ALERT_WEBHOOK_URL:                  # operator-set global (trusted)
            await self._post_json(session, config.ALERT_WEBHOOK_URL,
                                  _webhook_payload(text, config.ALERT_WEBHOOK_URL), akey)
        if recipients:                                 # per-user → SSRF-pinned sender
            wsess = _webhook_sender()                  # concurrent: each POST is
            await asyncio.gather(*(self._post_json(wsess, url, _webhook_payload(text, url), akey)
                                   for url in recipients))               # bounded

    async def _post_json(self, session, url, payload, akey: str = "") -> None:
        # Timed so the Channels card can show round-trip latency; `status`/`ms` stay None when
        # the POST never got a response, which is what distinguishes "rejected" from "never
        # arrived" in the delivery list.
        t0 = time.monotonic()
        status: int | None = None
        ok = False
        try:
            # `async with` so the response is released back to the pool immediately
            # (a bare post() leaks the connection/fd until GC).
            async with session.post(
                    url, json=payload, allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=config.HTTP_TIMEOUT)) as r:
                status, ok = r.status, r.status < 400
                if ok:
                    _LOG.info("webhook delivered", extra={"url": _log_url(url), "status": r.status})
                else:
                    _LOG.warning("webhook rejected", extra={"url": _log_url(url), "status": r.status})
        except Exception as e:                        # transport/timeout — was silently swallowed
            _LOG.warning("webhook failed", extra={"url": _log_url(url), "error": type(e).__name__})
        await _record_send("webhook", akey, status, ok,
                           (time.monotonic() - t0) * 1000.0 if status is not None else None)

    async def _try_post(self, session, url, payload) -> str:
        try:
            async with session.post(
                    url, json=payload, allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=config.HTTP_TIMEOUT)) as r:
                if r.status < 400:
                    _LOG.info("webhook test delivered",
                              extra={"url": _log_url(url), "status": r.status})
                    return "ok"
                _LOG.warning("webhook test rejected",
                             extra={"url": _log_url(url), "status": r.status})
                return f"HTTP {r.status}"
        except Exception as e:
            _LOG.warning("webhook test failed", extra={"url": _log_url(url), "error": type(e).__name__})
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
        _webhook_payload("🔔 AI-Monitoring test alert — your webhook is working.", url))
    return {"ok": res == "ok", "result": res}
