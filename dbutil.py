"""Pure window + label utilities (review D-4).

Extracted from db.py so the time-window math and the shared per-key hide predicate — which
have NO database or mutable-state coupling — no longer sit inside the 2000-line data-access
module. db.py re-exports every name here, so `db.window_secs`, `db.norm_window`, `db.WINDOWS`,
`db.month_start`, `db._pos_step`, `db._label_hidden`, … keep resolving unchanged.

Imports only `time` and `config` (config does not import db/dbutil, so there is no cycle).
"""
from __future__ import annotations

import time

import config

# Named windows -> seconds.
WINDOWS = {"15m": 900, "1h": 3600, "24h": 86400, "30d": 2592000,
           "12mo": 31536000}


def month_start(ref: float | None = None) -> float:
    """UTC epoch of 00:00 on the 1st of `ref`'s month (default: now)."""
    ref = time.time() if ref is None else ref
    lt = time.gmtime(ref)
    return ref - ((lt.tm_mday - 1) * 86400 + lt.tm_hour * 3600
                  + lt.tm_min * 60 + lt.tm_sec)


# Bounds for a drag-selected custom window (chart drag-to-zoom). Min 60s so a bucket
# grid is meaningful; max = 1 year (matches the rollup retention).
CUSTOM_WIN_MIN = 60
CUSTOM_WIN_MAX = 366 * 86400


def _custom_secs(window: str) -> int | None:
    """If `window` is a drag-selected 'custom:<secs>' token, return the clamped seconds;
    else None. Lets an arbitrary time range flow through the same named-window plumbing."""
    if not isinstance(window, str) or not window.startswith("custom:"):
        return None
    try:
        # OverflowError: int(float("inf")) / int(float("1e400")) — a crafted 'custom:inf'
        # would otherwise raise uncaught here and 500 the request (window is caller-supplied).
        return max(CUSTOM_WIN_MIN, min(CUSTOM_WIN_MAX, int(float(window[7:]))))
    except (TypeError, ValueError, OverflowError):
        return None


def window_secs(window: str, ref: float | None = None) -> float:
    """Seconds spanned by a window. Fixed durations come from WINDOWS; the special
    'month' window is MONTH-TO-DATE (from the 1st of the current UTC month), so its
    length grows through the month — used to reconcile against a provider's monthly bill.
    A 'custom:<secs>' token (chart drag-to-zoom) spans that many seconds, clamped."""
    cs = _custom_secs(window)
    if cs is not None:
        return float(cs)
    if window == "month":
        ref = time.time() if ref is None else ref
        return max(60.0, ref - month_start(ref))
    return float(WINDOWS.get(window, WINDOWS["1h"]))


def norm_window(window: str, default: str = "1h") -> str:
    """Validate an incoming window: a named window, or a clamped 'custom:<secs>' token.
    Anything else falls back to `default`. Used by every windowed API handler so drag-zoom
    ranges pass through while junk is rejected."""
    cs = _custom_secs(window)
    if cs is not None:
        return "custom:%d" % cs
    return window if window in VALID_WINDOWS else default


# Every window the API/series layer accepts (WINDOWS + the dynamic 'month').
VALID_WINDOWS = frozenset(WINDOWS) | {"month"}


def _pos_step(cur: float, prev: float | None) -> float:
    """Reset-safe positive step of a cumulative counter: the increase since the previous
    reading. Returns 0 on the FIRST reading (prev is None) or when the counter moved
    BACKWARDS — a re-based key / rolled budget / a replica with a different view. Crediting a
    backwards move would manufacture activity, and 0 is the only honest answer across a
    baseline change; the climb after it is picked up by the next positive step.

    THE single definition of the delta semantics every per-key chart shares
    (`key_series_window_delta`, `key_delta_series`, `concurrency_by_key`). It lived inline in
    all three, and getting it wrong in lockstep is exactly what silently broke zoom
    attribution — one place now, so the three cannot drift apart again."""
    return max(0.0, cur - prev) if prev is not None else 0.0


def _label_hidden(label: str, known: set[str], hidden: set[str],
                  require_known: bool = True) -> bool:
    """Whether a per-key `label` must be dropped from a NAMED band — folded into 'Other' on
    the aggregate/cost charts, simply omitted from a top-N ranking. True for an operator
    -excluded key (`MONITOR_EXCLUDE_KEYS`), a label LiteLLM's /key/list never confirmed (an
    unexpanded `${...}` bearer, a garbage/revoked hash — but only once a known-keys baseline
    exists, so cold start stays permissive), or a hidden 'Unassigned' key. THE one predicate
    every per-key chart applies, so a new chart can't silently skip a class — the two
    spend_model_user_daily-backed charts (`key_cumulative`, `key_cost_window`) did exactly
    that and surfaced excluded/garbage/ownerless keys the sibling charts already dropped.

    `require_known=False` for the spend-rollup-backed charts: a label that appears in
    spend_model_user_daily is SELF-EVIDENCE of a real key — a row only lands there after a
    request actually COMPLETED and was billed, which a garbage/`${...}` or revoked-hash bearer
    never does. Gating those charts on /key/list too would WRONGLY fold real, attributable spend
    into 'Other' (or drop it) for a key /key/list doesn't currently list: the LiteLLM master key,
    an ephemeral virtual key created+used+deleted between heavy polls, or an alias-vs-hash
    representation mismatch between /spend/logs and /key/list. Exclusion + hide-unassigned still
    apply (an operator can still MONITOR_EXCLUDE_KEYS the master key)."""
    if config.key_excluded(label) or label in hidden:
        return True
    return require_known and not config.key_known(label, known)
