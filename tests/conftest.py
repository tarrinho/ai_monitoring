import os
import sys

# Project root on path so tests import app/config/db/collectors.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Isolate the test DB from any real /data path.
os.environ.setdefault("MONITOR_DB_PATH", "/tmp/ai-monitoring-test.db")

# Neutralize the production .env: config.py calls load_dotenv(), which would
# otherwise pull the real dashboard token / backend URLs into the test process
# (load_dotenv does not override an already-set env var, so setting these here
# wins). Auth tests opt back in via monkeypatch on config.DASHBOARD_TOKEN.
os.environ["MONITOR_DASHBOARD_TOKEN"] = ""
for _k in ("LITELLM_BASE_URL", "LITELLM_MASTER_KEY",
           "OLLAMA_BASE_URL", "LLAMACPP_BASE_URL", "LLAMACPP_API_KEY",
           "GPU_SSH", "GPU_METRICS_URL", "ALERT_WEBHOOK_URL"):
    os.environ[_k] = ""

import pytest  # noqa: E402
from collectors import litellm as _litellm  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_litellm_heavy_cache():
    """The LiteLLM collector throttles /health + /spend/logs behind a module-level
    cache (LITELLM_HEAVY_INTERVAL). Reset it before every test so each test's stub
    is parsed fresh instead of reusing a prior test's cached heavy result."""
    _litellm._HEAVY = {}
    _litellm._HEAVY_TS = 0.0
    _litellm._CB = {}
    yield
