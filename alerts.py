# alerts.py — threshold evaluation + webhook notification.
#
# evaluate(snap) returns the list of currently-breaching alert strings. The
# Notifier debounces: a given alert key re-fires only after ALERT_REPEAT_MIN,
# and a "recovered" note is sent once when a previously-firing key clears.
# Delivery is a single generic webhook (best-effort; a failure never breaks
# sampling).
from __future__ import annotations

import aiohttp

import config
import db


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

        for key, msg in breaches:
            if self._due(key, now):
                await self._fanout(session, f"🔴 {msg}")
                self._last[key] = now
                sent.append(msg)
                db.record_alert(now, key, "fire", msg)
        # recovery: keys that were active but no longer firing
        for key in list(self._active - firing):
            await self._fanout(session, f"🟢 recovered: {key}")
            self._last.pop(key, None)
            sent.append(f"recovered:{key}")
            db.record_alert(now, key, "recover", f"recovered: {key}")
        self._active = firing
        return sent

    def active_keys(self) -> list[str]:
        return sorted(self._active)

    async def _fanout(self, session: aiohttp.ClientSession, text: str) -> None:
        if config.ALERT_WEBHOOK_URL:
            await self._post_json(session, config.ALERT_WEBHOOK_URL,
                                  {"source": "AI-Monitoring", "text": text})

    async def _post_json(self, session, url, payload) -> None:
        try:
            await session.post(url, json=payload,
                               timeout=aiohttp.ClientTimeout(total=config.HTTP_TIMEOUT))
        except Exception:
            pass

    async def _try_post(self, session, url, payload) -> str:
        try:
            async with session.post(
                    url, json=payload,
                    timeout=aiohttp.ClientTimeout(total=config.HTTP_TIMEOUT)) as r:
                return "ok" if r.status < 400 else f"HTTP {r.status}"
        except Exception as e:
            return type(e).__name__
