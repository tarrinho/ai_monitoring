# anomaly.py — per-key abuse / spike detection (idea #3).
#
# Two signals, both from data already collected:
#   spike  : a key's recent request rate >= ANOMALY_FACTOR × its hourly baseline
#            (catches a runaway loop, a leaked key being hammered).
#   budget : a key's spend rate exceeds ANOMALY_KEY_BUDGET_HR $/hour.
# Returns (key, message) breaches — fed to the same debounced multi-channel
# notifier as threshold alerts, and recorded for the dashboard panel.
from __future__ import annotations

import config


def detect(litellm_snap: dict, baselines: dict[str, dict]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if not litellm_snap or not litellm_snap.get("available"):
        return out

    # --- rate spikes (need history) -----------------------------------------
    if config.ANOMALY_FACTOR and config.ANOMALY_FACTOR > 0:
        for label, b in baselines.items():
            recent = b.get("recent") or 0.0
            base = b.get("baseline") or 0.0
            if recent < config.ANOMALY_MIN_REQS:
                continue                      # ignore low-volume keys
            # baseline near zero → treat any burst above the floor as a spike
            factor = recent / base if base > 0 else float("inf")
            if factor >= config.ANOMALY_FACTOR:
                fx = "∞" if base <= 0 else f"{factor:.1f}×"
                out.append((f"spike:{label}",
                            f"key {_short(label)} spike: {recent:.0f} reqs vs "
                            f"baseline {base:.0f} ({fx})"))

    # --- per-key budget (snapshot only) -------------------------------------
    if config.ANOMALY_KEY_BUDGET_HR and config.ANOMALY_KEY_BUDGET_HR > 0:
        win_min = litellm_snap.get("spend_window_min") or \
            config.LITELLM_SPEND_WINDOW_MIN
        hours = max(win_min / 60.0, 1e-6)
        for k in litellm_snap.get("top_keys", []) or []:
            rate = (k.get("cost") or 0.0) / hours     # $/hour for this key
            if rate >= config.ANOMALY_KEY_BUDGET_HR:
                label = k.get("alias") or k.get("key") or "?"
                out.append((f"budget:{label}",
                            f"key {_short(label)} spend ${rate:.2f}/h ≥ "
                            f"${config.ANOMALY_KEY_BUDGET_HR}/h"))
    return out


def _short(label: str) -> str:
    s = str(label or "?")
    return s if len(s) <= 18 else s[:8] + "…" + s[-4:]
