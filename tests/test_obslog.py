"""QA for obslog.py — the structured operational-logging pipeline (1.8.15).

Covers: text + json formatting, component derivation, secret REDACTION, DEDUPE, level
resolution (incl. the MONITOR_DEBUG legacy alias), per-component env overrides, idempotent
setup, and the aiohttp-access mute. Formatter/filter tests build LogRecords directly (no global
state); setup() tests save+restore the root logger so they can't leak into the rest of the suite.
"""
import io
import json
import logging

import pytest

import config
import obslog


def _rec(name="aimon.spend", level=logging.WARNING, msg="hi", **extra):
    r = logging.makeLogRecord({"name": name, "levelno": level,
                               "levelname": logging.getLevelName(level), "msg": msg})
    for k, v in extra.items():
        setattr(r, k, v)
    return r


# ---- formatters --------------------------------------------------------------
def test_text_formatter_shape_and_extras():
    line = obslog.TextFormatter(lambda s: s).format(_rec(msg="cost failed", err="TimeoutError"))
    assert " WARNING spend: cost failed" in line and line.endswith("err=TimeoutError")
    assert line[:4].isdigit() and line[4] == "-" and "T" in line[:20]      # ISO-8601 UTC prefix


def test_json_formatter_is_valid_and_structured():
    obj = json.loads(obslog.JsonFormatter(lambda s: s).format(
        _rec(name="aimon.collector", level=logging.INFO, msg="host: OK", backend="host")))
    assert obj["level"] == "INFO" and obj["component"] == "collector"
    assert obj["msg"] == "host: OK" and obj["backend"] == "host" and obj["ts"].endswith("Z")


def test_component_from_name_and_explicit_extra():
    f = obslog.TextFormatter(lambda s: s)
    assert " app: " in f.format(_rec(name="aimon", msg="x"))               # bare root -> "app"
    assert " litellm: " in f.format(_rec(name="aimon.litellm", msg="x"))   # strip aimon. prefix
    assert " custom: " in f.format(_rec(msg="x", component="custom"))      # explicit extra wins


# ---- redaction ---------------------------------------------------------------
def test_redaction_scrubs_secrets_and_generic_shapes():
    scrub = obslog._redactor(["SUPERSECRETVALUE"])
    out = scrub("v=SUPERSECRETVALUE Bearer abcdef123456 sk-deadbeef0011 ?token=zzz&x=1")
    for leaked in ("SUPERSECRETVALUE", "abcdef123456", "sk-deadbeef0011", "token=zzz"):
        assert leaked not in out, f"leaked {leaked!r}: {out!r}"
    assert "«redacted»" in out and "«redacted-key»" in out


def test_redaction_applies_through_the_formatter():
    f = obslog.TextFormatter(obslog._redactor(["HUNTER2"]))
    line = f.format(_rec(msg="login for HUNTER2 via Bearer tok_abc123def"))
    assert "HUNTER2" not in line and "tok_abc123def" not in line and "«redacted»" in line


# ---- dedupe ------------------------------------------------------------------
def test_dedupe_collapses_repeats_within_window(monkeypatch):
    clock = iter([100.0, 101.0, 102.0, 200.0])          # deterministic time
    monkeypatch.setattr(obslog.time, "time", lambda: next(clock))
    filt = obslog._DedupeFilter(60.0)
    r = _rec(msg="backend flapping")
    assert filt.filter(r) is True      # t=100 first → emit
    assert filt.filter(r) is False     # t=101 within window → drop
    assert filt.filter(r) is False     # t=102 window measured from last EMIT (100) → drop
    assert filt.filter(r) is True      # t=200 (>60 since 100) → emit again


def test_dedupe_lets_distinct_messages_through():
    filt = obslog._DedupeFilter(60.0)
    assert filt.filter(_rec(msg="a")) and filt.filter(_rec(msg="b"))       # different msgs


def test_dedupe_disabled_when_window_zero():
    filt = obslog._DedupeFilter(0)
    r = _rec(msg="x")
    assert filt.filter(r) and filt.filter(r)            # window<=0 → never suppress


# ---- setup / levels ----------------------------------------------------------
@pytest.fixture
def restore_logging():
    root = logging.getLogger()
    saved_h, saved_lvl = root.handlers[:], root.level
    names = ("aimon", "aimon.litellm", "aimon.spend", "aiohttp.access")
    saved = {n: logging.getLogger(n).level for n in names}
    obslog._configured = False
    yield
    root.handlers[:] = saved_h
    root.setLevel(saved_lvl)
    for n, lv in saved.items():
        logging.getLogger(n).setLevel(lv)
    obslog._configured = False
    obslog._our_handler = None


def _cfg(monkeypatch, level="INFO", debug=False, fmt="text", dedupe=0.0):
    monkeypatch.setattr(config, "LOG_LEVEL", level)
    monkeypatch.setattr(config, "MONITOR_DEBUG", debug)
    monkeypatch.setattr(config, "LOG_FORMAT", fmt)
    monkeypatch.setattr(config, "LOG_DEDUPE_S", dedupe)


def test_setup_level_from_config(monkeypatch, restore_logging):
    _cfg(monkeypatch, level="WARNING")
    obslog.setup(force=True)
    assert obslog.get().getEffectiveLevel() == logging.WARNING


def test_monitor_debug_is_a_debug_alias(monkeypatch, restore_logging):
    _cfg(monkeypatch, level="INFO", debug=True)          # legacy MONITOR_DEBUG=1
    obslog.setup(force=True)
    assert obslog.get().getEffectiveLevel() == logging.DEBUG


def test_per_component_env_override(monkeypatch, restore_logging):
    _cfg(monkeypatch, level="WARNING")
    monkeypatch.setenv("MONITOR_LOG_LEVEL_aimon.litellm", "debug")
    obslog.setup(force=True)
    assert obslog.get("litellm").getEffectiveLevel() == logging.DEBUG
    assert obslog.get("spend").getEffectiveLevel() == logging.WARNING     # others unaffected


def test_setup_end_to_end_levels_and_redaction(monkeypatch, restore_logging):
    _cfg(monkeypatch, level="INFO")
    monkeypatch.setattr(config, "log_redaction_values", lambda: ["TOPSECRET"])
    obslog.setup(force=True)
    buf = io.StringIO()
    obslog._our_handler.setStream(buf)                   # capture our handler's output
    obslog.get("spend").debug("hidden at INFO")
    obslog.get("spend").warning("leak TOPSECRET via Bearer abcdef123456")
    out = buf.getvalue()
    assert "hidden at INFO" not in out                   # DEBUG < INFO floor
    assert "TOPSECRET" not in out and "abcdef123456" not in out and "«redacted»" in out
    assert "WARNING spend:" in out


def test_json_setup_emits_one_object_per_line(monkeypatch, restore_logging):
    _cfg(monkeypatch, level="INFO", fmt="json")
    monkeypatch.setattr(config, "log_redaction_values", lambda: [])
    obslog.setup(force=True)
    buf = io.StringIO()
    obslog._our_handler.setStream(buf)
    obslog.get("spend").warning("cost failed", extra={"err": "Timeout"})
    obj = json.loads(buf.getvalue().strip())
    assert obj["component"] == "spend" and obj["level"] == "WARNING" and obj["err"] == "Timeout"


def test_setup_is_idempotent_no_duplicate_handlers(monkeypatch, restore_logging):
    _cfg(monkeypatch)
    obslog.setup(force=True)
    n = len(logging.getLogger().handlers)
    obslog.setup(force=True)                             # replaces OUR handler, doesn't stack
    assert len(logging.getLogger().handlers) == n


def test_aiohttp_access_muted_to_warning(monkeypatch, restore_logging):
    _cfg(monkeypatch, level="INFO")
    obslog.setup(force=True)
    assert logging.getLogger("aiohttp.access").level >= logging.WARNING   # never log the 200s
