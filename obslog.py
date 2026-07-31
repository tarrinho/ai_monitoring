"""obslog.py — structured operational logging for AI-Monitoring (stdlib `logging` ONLY).

Replaces the ad-hoc print()-to-stderr scattered across the app with ONE configured pipeline:
a single stderr handler, a human 'text' (default) or machine 'json' formatter, real levels, a
per-component logger hierarchy (aimon.*), automatic secret redaction, and duplicate collapsing.

Synchronous by design — NO background thread/queue. It costs the same as the print()s it
replaces (a formatted stderr write), so it never adds an off-loop worker; formatting only runs
for records at/above the effective level, so quieting the level makes it genuinely free.

SECURITY-audit events stay in SQLite (db.audit_*) — this module is OPERATIONAL logging only.
No third-party deps (keeps the runtime image = aiohttp + python-dotenv).
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
import time

import config

# Every component logger descends from "aimon", so one root config governs them and a
# per-component floor works: logging.getLogger("aimon.litellm").setLevel(DEBUG).
ROOT = "aimon"


def get(component: str = "") -> logging.Logger:
    """Logger for a component: get("litellm") -> "aimon.litellm"; get() -> "aimon"."""
    return logging.getLogger(ROOT + ("." + component if component else ""))


_LEVELS = {"DEBUG": logging.DEBUG, "INFO": logging.INFO, "WARN": logging.WARNING,
           "WARNING": logging.WARNING, "ERROR": logging.ERROR, "CRITICAL": logging.CRITICAL}


def _lvl(name: str, default: int = logging.INFO) -> int:
    return _LEVELS.get((name or "").strip().upper(), default)


# ---- redaction ---------------------------------------------------------------
# Generic secret SHAPES, scrubbed from every formatted line regardless of where it came from.
_GENERIC = [
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{6,}"), "Bearer «redacted»"),
    (re.compile(r"\bsk-[A-Za-z0-9._-]{6,}"), "«redacted-key»"),
    (re.compile(r"(?i)([?&](?:token|api[_-]?key|key)=)[^&\s\"']+"), r"\1«redacted»"),
]


def _redactor(values):
    """Return a scrub(text) that removes known secret VALUES + the generic shapes above."""
    vals = [re.escape(v) for v in values if v]
    exact = re.compile("|".join(vals)) if vals else None

    def scrub(text: str) -> str:
        if exact is not None:
            text = exact.sub("«redacted»", text)
        for pat, repl in _GENERIC:
            text = pat.sub(repl, text)
        return text
    return scrub


# ---- formatters --------------------------------------------------------------
# Standard LogRecord attrs we must NOT treat as caller 'extra' fields.
_STD = set(vars(logging.makeLogRecord({})).keys()) | {"message", "asctime", "taskName"}


def _extras(record: logging.LogRecord) -> dict:
    return {k: v for k, v in record.__dict__.items()
            if k not in _STD and not k.startswith("_")}


def _component(record: logging.LogRecord) -> str:
    c = record.__dict__.get("component")            # explicit extra wins
    if c:
        return str(c)
    n = record.name                                 # else derive from the logger name
    if n.startswith(ROOT + "."):
        return n[len(ROOT) + 1:]
    return "app" if n == ROOT else n


def _ts(created: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(created))


class TextFormatter(logging.Formatter):
    """`2026-07-31T09:14:02Z WARN  litellm: message key=val` — readable in `docker logs`."""

    def __init__(self, scrub):
        super().__init__()
        self._scrub = scrub

    def format(self, record: logging.LogRecord) -> str:
        line = f"{_ts(record.created)} {record.levelname:<5} {_component(record)}: {record.getMessage()}"
        extras = _extras(record)
        if extras:
            line += " " + " ".join(f"{k}={v}" for k, v in extras.items())
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return self._scrub(line)


def _jsonable(v):
    return v if isinstance(v, (str, int, float, bool)) or v is None else str(v)


class JsonFormatter(logging.Formatter):
    """One JSON object per line — for a fleet log aggregator (LOG_FORMAT=json)."""

    def __init__(self, scrub):
        super().__init__()
        self._scrub = scrub

    def format(self, record: logging.LogRecord) -> str:
        obj = {"ts": _ts(record.created), "level": record.levelname,
               "component": _component(record), "msg": record.getMessage()}
        obj.update({k: _jsonable(v) for k, v in _extras(record).items()})
        if record.exc_info:
            obj["exc"] = self.formatException(record.exc_info)
        return self._scrub(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))


# ---- dedupe filter -----------------------------------------------------------
class _DedupeFilter(logging.Filter):
    """Drop a record identical (name + level + message + extras + exception) to one EMITTED within
    `window` seconds, so a backend flapping every SAMPLE_INTERVAL can't repeat the same line forever.
    window<=0 off. The window measures from the last EMISSION (not the last attempt), so it re-surfaces
    once per window while the condition persists. The key includes the structured `extra` fields and
    the exception, so per-backend lines that share a message text (extra={"backend": ...}) are NOT
    collapsed into one — only truly identical lines are."""

    def __init__(self, window: float):
        super().__init__()
        self.window = window
        self._seen: dict = {}
        self._lock = threading.Lock()  # filters run OUTSIDE the handler lock; guard concurrent emits

    def _key(self, record: logging.LogRecord):
        extras = tuple(sorted((k, str(v)) for k, v in _extras(record).items()))
        exc = repr(record.exc_info[1]) if record.exc_info else None
        return (record.name, record.levelno, record.getMessage(), extras, exc)

    def filter(self, record: logging.LogRecord) -> bool:
        if self.window <= 0:
            return True
        # Fail OPEN: a bad %-format or a race must never crash the emitting caller (filters run
        # outside emit()'s handleError guard) — emit the line rather than raise.
        try:
            key = self._key(record)
            now = time.time()
            with self._lock:
                last = self._seen.get(key)
                emit = last is None or (now - last) >= self.window
                if emit:
                    if len(self._seen) > 2048:       # bound the dict on high-cardinality messages
                        self._seen = {k: t for k, t in self._seen.items() if now - t < self.window}
                    self._seen[key] = now
            return emit
        except Exception:
            return True


# ---- setup -------------------------------------------------------------------
_configured = False
_our_handler: logging.Handler | None = None


def setup(force: bool = False) -> None:
    """Configure the root + aiohttp loggers ONCE from `config`. Idempotent (safe in tests).
    Replaces only OUR handler on re-setup, leaving pytest's caplog handler intact."""
    global _configured, _our_handler
    if _configured and not force:
        return
    scrub = _redactor(config.log_redaction_values())
    fmt = JsonFormatter(scrub) if str(config.LOG_FORMAT).lower() == "json" else TextFormatter(scrub)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(fmt)
    handler.addFilter(_DedupeFilter(config.LOG_DEDUPE_S))

    root = logging.getLogger()
    if _our_handler is not None and _our_handler in root.handlers:
        root.removeHandler(_our_handler)            # replace just our own handler on re-setup
    root.addHandler(handler)
    _our_handler = handler

    level = logging.DEBUG if config.MONITOR_DEBUG else _lvl(config.LOG_LEVEL)
    root.setLevel(level)
    get().setLevel(level)

    # per-component floors: MONITOR_LOG_LEVEL_<logger>=<level> + the legacy LITELLM_DEBUG alias
    for env, val in os.environ.items():
        if env.startswith("MONITOR_LOG_LEVEL_"):
            logging.getLogger(env[len("MONITOR_LOG_LEVEL_"):]).setLevel(_lvl(val))
    if getattr(config, "LITELLM_DEBUG", False):
        get("litellm").setLevel(logging.DEBUG)

    # Fold aiohttp's own loggers into the SAME pipeline (they were a second logging system).
    # aiohttp.access logs every request at INFO — the app's own _log_mw already logs the
    # errors/denials it cares about, so keep aiohttp at WARNING+ to honour "never log the 200s".
    for n in ("aiohttp.access", "aiohttp.server", "aiohttp.web"):
        logging.getLogger(n).setLevel(max(level, logging.WARNING))
    _configured = True
