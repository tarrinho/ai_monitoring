"""Contract tests — pin the collector against the RECORDED SHAPE of LiteLLM's real
responses (fixtures), not the inline stubs elsewhere in the suite that encode our own
assumptions. These capture the quirks that caused live bugs:
  * the key row carries user_id / created_by as UUIDs and a NULL user_email — the email
    lives on the /user/list `user_email` field, joined via user_id;
  * the team is a team_id UUID on the key, resolved to an alias via /team/list.
Refresh the fixtures when LiteLLM changes shape; a diff here is an early warning.
"""
import json
import pathlib

import config
from collectors import litellm

FIX = pathlib.Path(__file__).parent / "fixtures"

# Internal-infra names must never be hardcoded (rules.md §7a) — they live in
# tests/_internal_markers.py, which is NOT in the publish ALLOW-list. A public
# checkout has no such file, so the fixture guard falls back to the generic
# leak patterns below (there is nothing internal to leak there anyway).
try:
    from _internal_markers import MARKERS as _INTERNAL_MARKERS
except ImportError:
    _INTERNAL_MARKERS = ()
# Generic credential/PII shapes — safe to name inline, not tied to any client.
_GENERIC_LEAK_MARKERS = ("@gmail", "sk-live")


def _load(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


async def test_contract_key_budgets_joins_email_and_resolves_team(monkeypatch):
    kl, ul, tl = (_load("litellm_key_list.json"),
                  _load("litellm_user_list.json"),
                  _load("litellm_team_list.json"))

    async def fake_fetch(session, url, headers=None, timeout_s=None):
        if "/key/list" in url:
            return (kl, None)
        if "/user/list" in url:
            return (ul, None)
        if "/team/list" in url:
            return (tl, None)
        return (None, "HTTP 404")
    monkeypatch.setattr(litellm, "fetch_json", fake_fetch)
    monkeypatch.setattr(config, "LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-x")
    litellm._KEY_BUDGETS_CACHE = None
    litellm._TEAM_DIR_CACHE = ({}, {}, {})

    out = await litellm.key_budgets(None)
    # email comes from the /user/list join (key row's user_email is null)
    assert out["alpha-key"]["user_name"] == "dev1@example.com"
    assert out["beta-key"]["user_name"] == "dev2@example.com"
    # team_id UUID on the key → alias via /team/list, never a raw UUID
    assert out["alpha-key"]["team"] == "Platform"
    assert out["beta-key"]["team"] == "Platform"
    # budget + spend read straight off the key row
    assert out["alpha-key"]["budget"] == 100 and out["alpha-key"]["spend"] == 42.5
    litellm._KEY_BUDGETS_CACHE = None
    litellm._TEAM_DIR_CACHE = ({}, {}, {})


def test_contract_fixtures_carry_no_real_data():
    """The recorded fixtures must stay synthetic — placeholder emails only, no internal
    markers (so they never leak into the public repo)."""
    blob = "".join((FIX / n).read_text(encoding="utf-8")
                   for n in ("litellm_key_list.json", "litellm_user_list.json",
                             "litellm_team_list.json")).lower()
    for marker in tuple(_INTERNAL_MARKERS) + _GENERIC_LEAK_MARKERS:
        assert marker.lower() not in blob, f"fixture leaks {marker!r}"
    assert "@example.com" in blob
