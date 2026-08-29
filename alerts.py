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
    (MONITOR_INSTANCE_NAME) if set, else the host collector's own hostname. "" when it
    genuinely cannot be resolved — the caller then omits the prefix entirely.

    The hostname lives at host['info']['hostname'] (collectors/host.py fills `info` from
    os.uname().nodename). This used to read host['hostname'], one level too high, so the
    lookup missed EVERY time and every alert read '[unknown-host]' even though the name was
    right there. The top-level key is still accepted so an older/flatter snapshot still works."""
    if config.INSTANCE_NAME:
        return config.INSTANCE_NAME
    host = (snap.get("collectors", {}) or {}).get("host", {}) or {}
    info = host.get("info") or {}
    return str(info.get("hostname") or host.get("hostname") or "")


def _alert_text(snap: dict, body: str, fired: bool) -> str:
    """One consistent, polished line for every channel: which machine, which tool, then the
    event — e.g. '🔴 [gpu-box-01] AI-Monitoring — vLLM is DOWN — connection refused'.

    When the machine name can't be resolved the bracket is DROPPED rather than filled with a
    placeholder: '🔴 AI-Monitoring — vLLM is DOWN — …'. A line that reads '[unknown-host]' tells
    the reader nothing and looks broken; the tool name alone is honest and already identifies
    the sender. (Set MONITOR_INSTANCE_NAME to label a specific box.)"""
    machine = _machine(snap)
    prefix = f"[{machine}] " if machine else ""
    return f"{'🔴' if fired else '🟢'} {prefix}AI-Monitoring — {body}"


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


def _egress_text(text: str) -> str:
    """Sanitize alert text BEFORE it leaves the box on a webhook: (1) run the same secret redactor
    the logs use (T-20 — the egress channel was previously un-scrubbed, so a secret/internal-host in
    a backend error string would ship verbatim to Teams/Slack), and (2) neutralize chat-platform
    markup so a backend-derived model/key string can't inject a Teams/Slack link (T-29). The emoji
    and em-dash we send intentionally are preserved."""
    try:
        text = obslog._redactor(config.log_redaction_values())(text)
    except Exception:            # redaction must never break delivery
        pass
    # Neutralize chat markup WITHOUT destroying our own format: a markdown/mrkdwn link needs the
    # parentheses (`[label](url)`), so stripping `()` + the emphasis/code/pipe chars defangs an
    # injected link while KEEPING the `[machine]` brackets and the em-dash we emit ourselves.
    for ch in "()`*_~<>|":
        text = text.replace(ch, " ")
    return text


def _webhook_payload(text: str, url: str) -> dict:
    """Shape the POST body for the destination (config.WEBHOOK_FORMAT; "auto" picks by URL):
      teams   -> Adaptive-Card message envelope the stock Teams flow renders with no flow edits
      slack   -> {"text": …}  (Slack incoming webhooks)
      generic -> {"source": "AI-Monitoring", "text": …}  (unchanged default for every other receiver)"""
    text = _egress_text(text)    # T-20 secret-scrub + T-29 markup-neutralize before it leaves the box
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
# NAT64 well-known prefix (RFC 6052) — embeds an IPv4 target in the low 32 bits.
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
# 6to4 (RFC 3056) — 2002:V4::/16 carries a routable IPv4 in bits 16-47; on a host with a 6to4
# relay it routes to that v4, so the embedded address must be re-checked like NAT64 (L5).
_6TO4 = ipaddress.ip_network("2002::/16")


def _ip_blocked(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True                              # unparseable → fail closed
    # Collapse an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to its IPv4 form so an
    # internal v4 can't slip past the range checks by being mapped into v6.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    # NAT64 well-known prefix 64:ff9b::/96 embeds an IPv4 target in the low 32 bits (T-33): on a
    # host with a NAT64 gateway this routes to that v4, and the address reads as global, so re-test
    # the embedded v4 rather than trusting it.
    if isinstance(ip, ipaddress.IPv6Address) and ip in _NAT64:
        return _ip_blocked(str(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)))
    # 6to4 (2002:V4::/16): the embedded v4 sits in bits 16-47 — extract and re-test it (L5).
    if isinstance(ip, ipaddress.IPv6Address) and ip in _6TO4:
        return _ip_blocked(str(ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)))
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


async def _record_sends(rows: list) -> None:
    """Persist a BATCH of delivery outcomes in one off-loop hop / one sqlite connection.

    Called once per fan-out, after every POST has returned — see the comment in _fanout for why
    per-POST recording inside the delivery path is unsafe. Swallows everything: bookkeeping about
    a notification must never break the notification."""
    if not rows:
        return
    try:
        await asyncio.to_thread(db.record_webhook_sends, rows)
    except Exception:
        pass


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
        "backend_down_after": config.ALERT_BACKEND_DOWN_AFTER,
        "backend_up_after": config.ALERT_BACKEND_UP_AFTER,
        "vllm_waiting": config.ALERT_VLLM_WAITING,
        "anomaly_factor": config.ANOMALY_FACTOR,
        "key_budget_hr": config.ANOMALY_KEY_BUDGET_HR,
        "repeat_min": config.ALERT_REPEAT_MIN,
        "maintenance_windows": {n: r for n, r in config.MAINTENANCE_RAW.items() if r},
    }


# Backend `error` values that are NOT an outage and must never page:
#   None           — no error recorded
#   'unconfigured' — the operator never set this backend up
#   'starting'     — the seed in app._backend_latest, meaning "not checked YET". The main sampler
#                    loop's first tick (pure /proc, sub-ms) beats every HTTP backend's first
#                    network round-trip, so it reads this seed on EVERY restart. Absence of a
#                    measurement is not evidence of failure, and a restart of the MONITOR says
#                    nothing about the monitored backend — alerting here paged on our own boot
#                    (plus a recovery moments later), which is how an alert channel gets ignored.
_NOT_AN_OUTAGE = (None, "unconfigured", "starting")

# Anti-flap hysteresis state per backend (evaluate() is otherwise a pure function of the snapshot;
# reset_down_streaks() clears it — used by tests; NOTE nothing in the app calls it on a live
# config change, so a lowered threshold arms an in-flight streak immediately and a raised one
# cannot un-latch a firing backend until it recovers normally):
#   _down_streak — consecutive failed polls, arms a DOWN alert at ALERT_BACKEND_DOWN_AFTER
#   _up_streak   — consecutive good polls, disarms it at ALERT_BACKEND_UP_AFTER
#   _firing      — backends currently LATCHED down: they keep alerting through a brief up-blip and
#                  only recover after a STABLE up run, so a flap can't spam down/recover pairs
#   _down_reason — last error seen while down, so the message keeps the real cause during the
#                  up-grace window (when b['error'] is momentarily None)
_down_streak: dict[str, int] = {}
_up_streak: dict[str, int] = {}
_firing: set[str] = set()
_down_reason: dict[str, str] = {}
# Rolling pass/fail history per backend (newest last), for the ALERT_BACKEND_DOWN_WINDOW
# majority-failure arm condition — the consecutive streak alone can never fire on a backend
# that fails most polls without ever failing N times in a row.
_down_hist: dict[str, list] = {}

# Why a key is ABSENT from evaluate()'s output, for the ONE tick just evaluated. Notifier.process
# infers recovery from `self._active - firing`, i.e. absence == recovered — true only when the
# backend actually came back. Two paths drop a key while it is STILL DOWN, and without these sets
# each emitted a triumphant "🟢 is back UP" for a backend that never recovered:
#   _held      — suppressed by a maintenance window. Still an outage; the message is withheld, the
#                latch is kept, and the key must stay ACTIVE so the window closing doesn't re-page.
#   _cancelled — no longer monitored (backend toggled off / absent from the snapshot). The alert
#                should CLOSE silently: not a recovery, and the key leaves the active set.
_held: set[str] = set()
_cancelled: set[str] = set()


def held_keys() -> set[str]:
    """Keys withheld this tick by a maintenance window (absence != recovery, still down)."""
    return set(_held)


def cancelled_keys() -> set[str]:
    """Keys closed this tick because the backend stopped being monitored (absence != recovery)."""
    return set(_cancelled)


def _note_poll(name: str, ok: bool) -> None:
    """Append one poll result to the backend's rolling history, capped at the window size."""
    w = max(0, config.ALERT_BACKEND_DOWN_WINDOW)
    if not w:
        _down_hist.pop(name, None)
        return
    h = _down_hist.setdefault(name, [])
    h.append(bool(ok))
    del h[:-w]


def _majority_failing(name: str) -> bool:
    """True when MORE THAN HALF of the last ALERT_BACKEND_DOWN_WINDOW samples failed.

    Consecutive-only arming can never fire on a backend that fails most of its polls without
    ever failing N times in a row — at a 2-in-3 error rate the streak resets forever, yet that
    is an outage by any user's definition. Strictly-more-than-half is deliberate: an exact 50/50
    alternation is the flap the hysteresis exists to damp, and must NOT page. Needs a full
    window before it can arm, so a couple of early failures can't trip it."""
    w = max(0, config.ALERT_BACKEND_DOWN_WINDOW)
    h = _down_hist.get(name) or []
    if not w or len(h) < w:
        return False
    fails = sum(1 for ok in h if not ok)
    # Must ALSO have seen at least ALERT_BACKEND_DOWN_AFTER failures. Without this the smaller
    # of the two knobs silently wins: N consecutive failures always satisfy "more than half of
    # the last N", so an operator who raised DOWN_AFTER above the window size had their setting
    # quietly ignored and got paged after `window` failures instead.
    return fails * 2 > len(h) and fails >= max(1, config.ALERT_BACKEND_DOWN_AFTER)


def reset_down_streaks() -> None:
    """Forget every backend's flap-hysteresis state."""
    _down_streak.clear()
    _up_streak.clear()
    _firing.clear()
    _down_reason.clear()
    _down_hist.clear()
    _held.clear()
    _cancelled.clear()


def _pct(used, total) -> float | None:
    try:
        if used is None or not total:
            return None
        return used / total * 100.0
    except Exception:
        return None


def evaluate(snap: dict) -> list[tuple[str, str]]:
    """Return list of (key, message) for every breaching condition.

    Also refreshes the per-tick `held_keys()` / `cancelled_keys()` sets, which tell the caller
    WHY a previously-firing key is absent from this result — absence alone must never be read
    as recovery (see the _held/_cancelled comment above)."""
    _held.clear()
    _cancelled.clear()
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
    if not config.ALERT_ON_BACKEND_DOWN:
        # Toggling backend-down alerting OFF must CLOSE any latched alert silently — the
        # same "absence != recovery" rule as _cancelled. Skipping the block entirely left
        # _firing populated and the keys simply vanished from the output, which Notifier
        # read as "🟢 back UP" for backends that were still down.
        for name in list(_firing):
            _cancelled.add(f"down:{name}")
        _firing.clear()
        _down_streak.clear()
        _up_streak.clear()
        _down_hist.clear()
        _down_reason.clear()
    if config.ALERT_ON_BACKEND_DOWN:
        for name in ("litellm", "ollama", "llamacpp", "vllm", "gpu"):
            b = c.get(name, {})
            if config.in_maintenance_window(name):
                # Known, expected outage (e.g. a daily model-reload restart) — the dashboard
                # still shows it down (collector data is untouched) and no alert can ARM during
                # the window. Streaks reset so the boundary can't count toward the
                # DOWN_AFTER/UP_AFTER hysteresis on either side.
                #
                # An ALREADY-LATCHED backend keeps its latch and is reported as HELD, not
                # dropped: suppression must be SILENT. Discarding the latch here made the key
                # vanish from evaluate()'s output, which Notifier reads as "recovered" — so a
                # window opening mid-outage sent "🟢 back UP" for a backend that was still down,
                # then re-paged when the window closed. Keeping the latch also means the window
                # closing on a still-down backend emits nothing new (it never stopped firing).
                _down_streak.pop(name, None)
                _down_hist.pop(name, None)
                # A GOOD poll inside the window still counts toward disarming. Skipping poll
                # data entirely meant a backend that recovered DURING its maintenance window
                # (the normal case — the restart is what fixes it) kept its latch, so the first
                # tick after the window emitted "🔴 is DOWN" with the stale pre-window reason for
                # a backend that had been healthy for the whole window. An always-open window
                # (two adjacent entries) also stranded the key in the active set forever.
                if b and b.get("available") is True:
                    _up_streak[name] = _up_streak.get(name, 0) + 1
                    if _up_streak[name] >= max(1, config.ALERT_BACKEND_UP_AFTER):
                        _firing.discard(name)
                        _up_streak.pop(name, None)
                        _down_reason.pop(name, None)
                else:
                    _up_streak.pop(name, None)   # still failing → no progress toward recovery
                if name in _firing:
                    _held.add(f"down:{name}")
                continue
            # "configured but down" = available False, and the error is a real failure — NOT
            # 'unconfigured' (operator never set it up) and NOT 'starting' (see _NOT_AN_OUTAGE).
            if b and b.get("available") is False and \
                    b.get("error") not in _NOT_AN_OUTAGE:
                # DOWN poll: arm after N consecutive failures (one blip is not an outage).
                _note_poll(name, False)
                _down_streak[name] = _down_streak.get(name, 0) + 1
                # DECAY the up-streak instead of zeroing it. A hard reset meant that if the
                # backend's blip period was shorter than ALERT_BACKEND_UP_AFTER ticks, the
                # up-streak could NEVER reach the threshold — so a mostly-healthy backend (e.g.
                # 85% good) stayed latched down forever and re-paged every ALERT_REPEAT_MIN.
                # That inverted the very flap-storm the hysteresis exists to prevent, and it bit
                # exactly the operator who RAISED the knob to damp flapping.
                _up_streak[name] = max(0, _up_streak.get(name, 0) - 1)
                _down_reason[name] = str(b.get("error"))
                if _down_streak[name] >= max(1, config.ALERT_BACKEND_DOWN_AFTER) \
                        or _majority_failing(name):
                    _firing.add(name)
            elif b and b.get("available") is True:
                # GOOD poll: only DISARM after M consecutive good polls (hysteresis). Until then a
                # latched backend stays DOWN — a single good poll can't emit a recovery + re-fire.
                _note_poll(name, True)
                _up_streak[name] = _up_streak.get(name, 0) + 1
                _down_streak.pop(name, None)
                if _up_streak[name] >= max(1, config.ALERT_BACKEND_UP_AFTER):
                    _firing.discard(name)
                    _up_streak.pop(name, None)
                    _down_reason.pop(name, None)
                    _down_hist.pop(name, None)
            else:                                 # unconfigured / starting / missing → not an outage
                # A LATCHED backend that stops being monitored (toggled off in Settings, or gone
                # from the snapshot) must have its alert CANCELLED, not "recovered": it did not
                # come back, we simply stopped watching. Reported so Notifier closes the key
                # silently instead of announcing "🟢 back UP" for a backend that is still down.
                if name in _firing:
                    _cancelled.add(f"down:{name}")
                _firing.discard(name)
                _down_streak.pop(name, None)
                _up_streak.pop(name, None)
                _down_reason.pop(name, None)
                _down_hist.pop(name, None)
            if name in _firing:                   # latched (armed, not yet stably recovered)
                out.append((f"down:{name}",
                            f"{_SVC.get(name, name)} is DOWN — "
                            f"{_down_reason.get(name) or 'no response'}"))
    return out


class Notifier:
    """Debounced fan-out to every configured channel."""

    def __init__(self) -> None:
        self._last: dict[str, float] = {}   # key -> last-sent monotonic-ish ts
        self._active: set[str] = set()
        # Keys whose FIRE we actually announced. Only these can produce a recovery: a breach
        # that was debounced away never told anyone, so its "🟢 back UP" would be an all-clear
        # for an alarm nobody heard — and that pairing is what let a flapping backend emit an
        # unbounded fire/recover storm.
        self._notified: set[str] = set()

    # Anomaly breach keys whose message carries per-key COST or attribution (alias/rates).
    # These are the surfaces SPEND_REQUIRE_ADMIN hides from non-admins in the UI (F-01).
    _COST_SENSITIVE_PREFIXES = ("budget:", "spike:")

    def _public_text(self, snap: dict, key: str, fired: bool) -> str | None:
        """Redacted alert line for NON-admin webhook recipients when SPEND_REQUIRE_ADMIN is on
        and the breach exposes per-key cost/attribution. Returns None when no redaction is
        needed (the fan-out then sends the full text to everyone)."""
        if not config.SPEND_REQUIRE_ADMIN:
            return None
        if key.startswith(self._COST_SENSITIVE_PREFIXES):
            body = ("a monitored key crossed an anomaly threshold"
                    if fired else "a key anomaly cleared")
            return _alert_text(snap, body, fired)
        return None

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
        # A key can leave `firing` for three different reasons, and only ONE is a recovery:
        #   held      — maintenance window: still down, message withheld → stay active, say nothing
        #   cancelled — no longer monitored: close the alert silently, drop it from active
        #   otherwise — genuinely recovered → send the 🟢
        held, cancelled = held_keys(), cancelled_keys()
        # ALERT_REPEAT_MIN rate-limits STATE CHANGES, not just fires. A recovery used to send
        # immediately AND clear the key's debounce, so the next failure counted as first-seen and
        # fired with no cooldown: a flapping backend produced fire→recover→fire→recover forever
        # (measured: 15 webhook posts in 5 minutes on defaults). A recovery that isn't due yet is
        # DEFERRED — held in `_active` and emitted once the cooldown passes — never dropped, or
        # the all-clear would be lost entirely.
        pending = self._active - firing - held - cancelled
        # Recover ONLY what we announced. A real fire still recovers immediately (an operator
        # who was paged learns it is over at once); a debounced-away breach leaves silently.
        # Combined with stamping `_last` on recovery, a flapping backend is bounded to one
        # fire + one recovery per ALERT_REPEAT_MIN instead of a fire/recover storm.
        recoveries = [k for k in pending if k in self._notified]
        # Resolve the per-user recipient list ONCE per tick (SSRF-validate once),
        # not per alert key — cheap + observer-effect friendly.
        recipients = await self._recipients() if (due or recoveries) else []

        for key, msg in due:
            ptext = self._public_text(snap, key, fired=True)
            await self._fanout(session, _alert_text(snap, msg, fired=True), recipients, key,
                               public_text=ptext)
            self._last[key] = now
            self._notified.add(key)
            sent.append(msg)
            await asyncio.to_thread(db.record_alert, now, key, "fire", msg)   # M2: off the event loop
            _LOG.warning("alert fired", extra={"key": key, "detail": msg,
                                               "machine": _machine(snap)})
        for key in recoveries:
            rmsg = _recover_msg(key)
            ptext = self._public_text(snap, key, fired=False)
            await self._fanout(session, _alert_text(snap, rmsg, fired=False), recipients, key,
                               public_text=ptext)
            self._last[key] = now          # stamp, don't clear: a re-fire waits out the cooldown
            self._notified.discard(key)
            sent.append(f"recovered:{key}")
            await asyncio.to_thread(db.record_alert, now, key, "recover", rmsg)   # M2: off the event loop
            _LOG.info("alert recovered", extra={"key": key, "detail": rmsg,
                                                "machine": _machine(snap)})
        # HELD keys stay active so the window closing on a still-down backend emits nothing new.
        # CANCELLED keys leave. Their debounce is deliberately NOT cleared: doing so was a
        # REPEAT_MIN bypass reachable by any backend alternating between a real error and an
        # 'unconfigured'/'starting' sample (a dying GPU driver does exactly that), which paged
        # once per alternation instead of once per cooldown.
        self._active = (firing | (self._active & held)) - cancelled
        # M3: bound `_last`. It is stamped for every fire/recover and (unlike `_active`/`_notified`)
        # was never pruned, so an unbounded anomaly-key space (spike:/budget:<rotating-alias>) grew
        # it forever on a months-long process. Once it exceeds a small ceiling, drop stamps for keys
        # that are no longer active and whose cooldown has elapsed (a still-relevant key keeps its
        # stamp so the debounce is unaffected).
        if len(self._last) > 512:
            _cut = now - config.ALERT_REPEAT_MIN * 60
            for _k in [k for k, t in self._last.items()
                       if k not in self._active and t < _cut]:
                self._last.pop(_k, None)
        self._notified -= cancelled
        return sent

    def active_keys(self) -> list[str]:
        return sorted(self._active)

    async def _recipients(self) -> list[dict]:
        """Validated per-user webhook recipients — each a {"url","role"} dict (enabled,
        non-disabled users). Bounded + concurrent + time-boxed so one slow-resolving host
        can't stall the alert tick (and, via the tick, the whole sampling loop): capped at
        WEBHOOK_MAX_RECIPIENTS and each validation runs under HTTP_TIMEOUT. The role rides
        along so the fan-out can withhold cost/attribution detail from non-admins when
        SPEND_REQUIRE_ADMIN is on (F-01)."""
        rows = list(db.user_webhooks_enabled())[:config.WEBHOOK_MAX_RECIPIENTS]

        async def _ok(row: dict) -> dict | None:
            url = row.get("url")
            if not url:
                return None
            try:
                if await asyncio.wait_for(validate_webhook_url(url),
                                          config.HTTP_TIMEOUT) is None:
                    return {"url": url, "role": row.get("role") or "viewer"}
            except Exception:                 # timeout / resolver error → drop it
                return None
            return None

        checked = await asyncio.gather(*(_ok(r) for r in rows))
        return [r for r in checked if r]

    async def _fanout(self, session: aiohttp.ClientSession, text: str,
                      recipients: list[dict], akey: str = "",
                      public_text: str | None = None) -> None:
        # `public_text` is the cost/attribution-redacted variant sent to NON-admin recipients
        # (F-01). None = no redaction needed → everyone gets `text`. The operator-global
        # webhook is operator-trusted and always receives the full `text`.
        public_text = text if public_text is None else public_text
        # Build the body PER URL: a Teams URL and a Slack URL need different shapes,
        # and a fan-out can mix destinations (global vs per-user).
        #
        # Delivery bookkeeping is collected here and written ONCE, AFTER every POST has
        # returned — never per-POST inside the fan-out. A fan-out can be 1 + WEBHOOK_MAX_RECIPIENTS
        # posts; recording each one inline meant that many separate sqlite connections queued on
        # the shared executor INSIDE the notifier's 15s budget. If they backed up behind a write
        # lock the budget expired and `process()` was CANCELLED mid-loop — and CancelledError is a
        # BaseException, so it sails straight through the recorder's `except Exception`, leaving
        # later `due` keys unsent and `_active` un-updated. Alerting is a security control, so a
        # LOGGING concern must never be able to delay it: batch after the sends, one hop, one
        # connection. (Channel: 'webhook' = operator-global, 'user' = a per-user recipient.)
        # Each row is stamped when ITS post completes (not at fan-out start): sharing one
        # timestamp made "Recent deliveries" ages off by up to HTTP_TIMEOUT per row, and
        # tied timestamps left the newest-first ordering to rowid luck.
        rows: list[tuple] = []
        if config.ALERT_WEBHOOK_URL:                  # operator-set global (trusted)
            out = await self._post_json(session, config.ALERT_WEBHOOK_URL,
                                        _webhook_payload(text, config.ALERT_WEBHOOK_URL), akey)
            if out:
                rows.append((out[0], "webhook", *out[1:]))
        if recipients:                                 # per-user → SSRF-pinned sender
            wsess = _webhook_sender()                  # concurrent: each POST is
            # An admin recipient gets the full text; a non-admin gets the redacted variant.
            def _rtext(r: dict) -> str:
                return text if (r.get("role") == "admin") else public_text
            outs = await asyncio.gather(
                *(self._post_json(wsess, r["url"], _webhook_payload(_rtext(r), r["url"]), akey)
                  for r in recipients))                                   # bounded
            rows.extend((o[0], "user", *o[1:]) for o in outs if o)
        await _record_sends(rows)

    async def _post_json(self, session, url, payload, akey: str = "") -> tuple | None:
        """POST one webhook. Returns (akey, status, ok, ms) for the caller to record in a batch —
        deliberately NOT recorded here (see _fanout). `status`/`ms` stay None when the POST never
        got a response, which is what distinguishes "rejected" from "never arrived" in the UI."""
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
        return (time.time(), akey, status, ok,
                (time.monotonic() - t0) * 1000.0 if status is not None else None)

    async def _try_post(self, session, url, payload) -> str:
        # Test sends are recorded too (channel='test'): an admin who clicks "Send test alert" and
        # then sees an EMPTY "Recent deliveries" list would read that as "delivery is broken" —
        # the exact confusion this feature exists to remove. One row, off the request path.
        t0 = time.monotonic()
        status: int | None = None
        ok = False
        try:
            async with session.post(
                    url, json=payload, allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=config.HTTP_TIMEOUT)) as r:
                status, ok = r.status, r.status < 400
                if ok:
                    _LOG.info("webhook test delivered",
                              extra={"url": _log_url(url), "status": r.status})
                    return "ok"
                _LOG.warning("webhook test rejected",
                             extra={"url": _log_url(url), "status": r.status})
                return f"HTTP {r.status}"
        except Exception as e:
            _LOG.warning("webhook test failed", extra={"url": _log_url(url), "error": type(e).__name__})
            return type(e).__name__
        finally:
            await _record_send("test", "test", status, ok,
                               (time.monotonic() - t0) * 1000.0 if status is not None else None)


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
