"""Negative / error-path matrix — every LiteLLM call must DEGRADE (not raise) on the full
set of upstream failure modes. Most of this project's real bugs lived on these paths
(401/403 scope, the 422 page-size, timeouts, partial/empty data), not the happy path."""
import pytest

import config
from collectors import litellm

ERRORS = ["HTTP 401", "HTTP 403", "HTTP 422", "HTTP 429", "HTTP 500", "HTTP 502",
          "Timeout", "conn: refused", "decode error"]
# non-error but MALFORMED bodies (fetch_json returns data, no err)
JUNK = [None, [], {}, "not-json", 123, {"unexpected": "shape"}, [{"no": "fields"}]]


def _cfg(monkeypatch):
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")


@pytest.mark.parametrize("err", ERRORS)
async def test_key_budgets_degrades_on_error(monkeypatch, err):
    async def f(s, u, headers=None, timeout_s=None):
        return (None, err)
    monkeypatch.setattr(litellm, "fetch_json", f)
    _cfg(monkeypatch)
    litellm._KEY_BUDGETS_CACHE = None
    out = await litellm.key_budgets(None)
    assert out is None or isinstance(out, dict)          # never raises


@pytest.mark.parametrize("body", JUNK)
async def test_key_budgets_degrades_on_malformed_body(monkeypatch, body):
    async def f(s, u, headers=None, timeout_s=None):
        return (body, None)
    monkeypatch.setattr(litellm, "fetch_json", f)
    _cfg(monkeypatch)
    litellm._KEY_BUDGETS_CACHE = None
    litellm._TEAM_DIR_CACHE = ({}, {}, {})
    out = await litellm.key_budgets(None)
    assert out is None or isinstance(out, dict)


@pytest.mark.parametrize("err", ERRORS)
async def test_per_model_range_degrades(monkeypatch, err):
    async def f(s, u, headers=None, timeout_s=None):
        return (None, err)
    monkeypatch.setattr(litellm, "fetch_json", f)
    _cfg(monkeypatch)
    out = await litellm.per_model_range(None, "2026-07-01", "2026-07-02")
    assert out is None or isinstance(out, list)


@pytest.mark.parametrize("err", ERRORS)
async def test_model_prices_and_spend_activity_degrade(monkeypatch, err):
    async def f(s, u, headers=None, timeout_s=None):
        return (None, err)
    monkeypatch.setattr(litellm, "fetch_json", f)
    _cfg(monkeypatch)
    assert isinstance(await litellm.model_prices(None), dict)
    sa = await litellm.spend_activity(None, "2026-07-01", "2026-07-11")
    assert sa is None or isinstance(sa, list)


@pytest.mark.parametrize("err", ERRORS)
async def test_per_model_daily_cost_degrades(monkeypatch, err):
    async def f(s, u, headers=None, timeout_s=None):
        return (None, err)
    monkeypatch.setattr(litellm, "fetch_json", f)
    _cfg(monkeypatch)
    out = await litellm.per_model_daily_cost(None, "2026-07-01", "2026-07-10", {"m": 0.1})
    assert out is None or isinstance(out, dict)
