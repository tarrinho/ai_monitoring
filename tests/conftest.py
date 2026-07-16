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
    _litellm._PRICES_CACHE = {}   # last-good /model/info prices — isolate per test
    yield


@pytest.fixture(autouse=True)
def _reset_auth_state():
    """Isolate the multi-user auth state between tests: the test DB is shared, so a
    user created by one test would otherwise make `_any_users()` True and flip auth
    on for every later test. Clear the users table + in-memory sessions/lockouts +
    the user-presence cache before each test, so the default is 'no users → open'."""
    import app as _app
    import auth as _auth
    import db as _db
    try:
        _db.init()
        with _db._connect() as conn:
            conn.execute("DELETE FROM users")
            conn.execute("DELETE FROM audit_log")
            # api_tokens are per-user and capped (20/user); the shared on-disk
            # test DB persists across runs, so without this a user's tokens pile
            # up until create hits the cap (400). Reset them like users/sessions.
            conn.execute("DELETE FROM api_tokens")
    except Exception:
        pass
    _app._users_seen["checked"] = 0.0
    _app._users_seen["any"] = False
    _auth._sessions.clear()
    _app._auth_fails.clear()
    _app._auth_locked_until.clear()
    yield
