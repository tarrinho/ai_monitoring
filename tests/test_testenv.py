# QA for the test environment (test-env/): real Ollama + LiteLLM + Postgres.
#
# Static tests validate the compose + config files and always run.
# Dynamic tests exercise the real collectors against the live backends and
# SKIP automatically when the stack isn't reachable (e.g. inside the Docker
# build test stage), so they never break the build gate.
import os
import urllib.request
from pathlib import Path

import aiohttp
import pytest

import config
from collectors import litellm, ollama

ROOT = Path(__file__).resolve().parent.parent
TE = ROOT / "test-env"

LITELLM = os.environ.get("TESTENV_LITELLM", "http://127.0.0.1:4000")
OLLAMA = os.environ.get("TESTENV_OLLAMA", "http://127.0.0.1:11434")


def _key_from_env_file() -> str:
    """Read the master key from the git-ignored test-env/.env (source of truth)
    so the integration tests authenticate without a key committed anywhere."""
    f = TE / ".env"
    if f.exists():
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.startswith("LITELLM_MASTER_KEY="):
                return line.split("=", 1)[1].strip()
    return ""


KEY = os.environ.get("TESTENV_KEY") or _key_from_env_file()


# ------------------------------------------------------------- static ---------
def test_compose_file_defines_three_services():
    f = TE / "docker-compose.yml"
    assert f.exists(), "test-env compose missing"
    txt = f.read_text(encoding="utf-8")
    for svc in ("ollama:", "litellm:", "db:"):
        assert svc in txt, f"service {svc} missing"
    assert "ollama/ollama" in txt
    assert "ghcr.io/berriai/litellm" in txt
    assert "postgres" in txt
    assert "127.0.0.1:11434:11434" in txt and "127.0.0.1:4000:4000" in txt
    assert "LITELLM_MASTER_KEY" in txt
    assert "DATABASE_URL" in txt   # spend logs need the DB
    # F1/F2 remediation: no plaintext secrets committed — creds come from ${...}
    import re as _re
    assert not _re.search(r'sk-[A-Za-z0-9]{12}', txt), "plaintext key in compose"
    assert "POSTGRES_PASSWORD: litellm" not in txt, "weak/plaintext pg password"
    assert "${LITELLM_MASTER_KEY" in txt and "${POSTGRES_PASSWORD" in txt


def test_testenv_env_is_gitignored():
    # the real secrets live in test-env/.env which must never be committed
    gi = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in gi


def test_litellm_config_points_at_ollama():
    f = TE / "litellm-config.yaml"
    assert f.exists(), "litellm-config.yaml missing"
    txt = f.read_text(encoding="utf-8")
    assert "model_list" in txt
    assert "api_base: http://ollama:11434" in txt
    assert "ollama/qwen2.5" in txt
    assert "store_model_in_db: true" in txt


# ----------------------------------------------------- reachability probe -----
def _up(url: str, timeout: float = 2.0) -> bool:
    try:
        # bypass proxy env — the test-env backends are on localhost
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url, timeout=timeout):
            return True
    except Exception:
        return False


_TESTENV_UP = _up(f"{OLLAMA}/api/version") and _up(f"{LITELLM}/health/liveliness")
skip_if_down = pytest.mark.skipif(
    not _TESTENV_UP, reason="test-env backends not reachable")


# ------------------------------------------------------------- dynamic --------
@skip_if_down
async def test_live_ollama_collector(monkeypatch):
    monkeypatch.setattr(config, "OLLAMA_BASE_URL", OLLAMA)
    async with aiohttp.ClientSession() as s:
        out = await ollama.sample(s)
    assert out["available"] is True
    assert out.get("version")                    # real version string
    assert out["models_installed"] >= 1
    # if a model is loaded, per-model detail must parse
    for m in out.get("models", []):
        assert "gpu_pct" in m and "size" in m


@skip_if_down
async def test_live_litellm_collector(monkeypatch):
    monkeypatch.setattr(config, "LITELLM_BASE_URL", LITELLM)
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", KEY)
    monkeypatch.setattr(config, "LITELLM_SPEND_WINDOW_MIN", 60 * 24)  # wide
    # Live LiteLLM under concurrent load can transiently time out individual
    # sub-requests (/health/backlog, /v1/models). Retry a few times so the test
    # asserts the steady state, not a momentary blip.
    out = {}
    async with aiohttp.ClientSession() as s:
        for _ in range(5):
            out = await litellm.sample(s)
            if out.get("backlog") is not None and out.get("models"):
                break
            await _asleep(1)
    assert out["available"] is True
    assert out.get("backlog") is not None                 # real /health/backlog
    assert "qwen2.5-0.5b" in (out.get("models") or [])     # served + key-authed


@skip_if_down
async def test_live_traffic_reflected_in_collector(monkeypatch):
    # send one real completion, then confirm the collector sees the request in
    # its rolling window (end-to-end: request -> spend log -> monitor read).
    monkeypatch.setattr(config, "LITELLM_BASE_URL", LITELLM)
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", KEY)
    monkeypatch.setattr(config, "LITELLM_SPEND_WINDOW_MIN", 60 * 24)
    # heavy calls are throttled/cached in production; disable the throttle here so
    # the retry loop re-fetches /spend/logs each pass and can observe the async
    # spend-log flush (otherwise every poll returns the first cached empty result).
    monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 0)
    # the test-env runs a traffic generator, so /spend/logs (whole-day query) is
    # slow — give it the heavy-call timeout, not the 4s default, or it times out.
    monkeypatch.setattr(config, "LITELLM_SPEND_TIMEOUT", 30.0)
    # the traffic gen accumulates a big daily log (can exceed the 64 MiB default
    # size cap, which would refuse it) — lift the cap so the window is parsed.
    monkeypatch.setattr(config, "LITELLM_SPEND_MAX_BYTES", 512 * 1024 * 1024)
    hdr = {"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"}
    body = {"model": "qwen2.5-0.5b",
            "messages": [{"role": "user", "content": "ping"}], "max_tokens": 8}
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{LITELLM}/v1/chat/completions", json=body,
                          headers=hdr, timeout=aiohttp.ClientTimeout(total=60)) as r:
            assert r.status == 200
        # spend logs flush in batches; poll briefly for the window to be non-zero
        seen = 0
        for _ in range(10):
            out = await litellm.sample(s)
            seen = out.get("requests_window") or 0
            if seen > 0:
                break
            await _asleep(2)
    assert seen > 0, "completion not reflected in collector window"


async def _asleep(sec):
    import asyncio
    await asyncio.sleep(sec)
