import os
import sys

# Project root on path so tests import app/config/db/collectors.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Isolate the test DB from any real /data path — and from ANOTHER pytest run on the
# same machine. The path used to be fixed, so two concurrent runs shared one SQLite
# file while the autouse reset fixture DELETEs users/tokens/sessions before every
# test: each run wiped the other's fixtures mid-test, surfacing as unrelated 401s and
# `KeyError: 'csrf'` far from the real cause. Per-PID makes concurrent runs disjoint.
os.environ.setdefault("MONITOR_DB_PATH", f"/tmp/ai-monitoring-test-{os.getpid()}.db")

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
            # The per-(day,model,key) spend rollup is shared too: rows written by one
            # test would otherwise inflate another's model×user series. Reset it (+ its
            # one-time backfill marker) like the other shared tables.
            conn.execute("DELETE FROM spend_model_user_daily")
            conn.execute("DELETE FROM settings WHERE key = 'spend_mu_backfill'")
            # Same for the per-day usage/cost history: the spend-series write-through
            # persists each call's live days, and db.spend_daily_range is merged into the
            # Spend "cost over time" series, so rows a prior test upserts would otherwise
            # inflate another test's lifetime/window real_cost totals.
            conn.execute("DELETE FROM spend_daily")
    except Exception:
        pass
    _app._users_seen["checked"] = 0.0
    _app._users_seen["any"] = False
    _app._MU_SERIES_CACHE.clear()          # module-level series cache — isolate per test
    _auth._sessions.clear()
    _app._auth_fails.clear()
    _app._auth_locked_until.clear()
    # Per-ACCOUNT lockout + token sessions. These maps were added after this fixture
    # was written and were never cleared, so a test that failed logins for a user left
    # that account LOCKED for every later test — the suite then passed or failed
    # depending purely on collection order (a locked account answers 401 with no csrf
    # in the body, which surfaced as `KeyError: 'csrf'` far from the real cause).
    _app._user_fails.clear()
    _app._user_locked_until.clear()
    _app._token_sessions.clear()
    yield
