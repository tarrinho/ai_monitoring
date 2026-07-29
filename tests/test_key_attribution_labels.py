"""Per-key attribution must not invent activity, and must not mislabel what it plots.

Four live-observed defects are pinned here:

  1. LiteLLM's internal health-check pseudo-key reached the per-key charts in LITE mode.
     The full-mode /spend/logs parser had always dropped it, but the lite-mode
     /global/spend/keys path had no equivalent test, so LiteLLM probing its own
     deployments occupied a slot in every per-key ranking.

  2. Lite mode's `requests_window` is the UTC DAY-TO-DATE total (/global/activity is
     queried today->tomorrow), not a rolling LITELLM_SPEND_WINDOW_MIN window. It was
     rendered under a "last 15m" badge, so an idle proxy read as permanently busy —
     the day counter simply sits at its total until UTC midnight. The collector now
     declares `requests_basis` so the dashboard can label it honestly.

  3. In lite mode there are no per-key REQUEST counts, so db.insert_key_series stores
     per-key SPEND in the same column. The "…requests in window" charts were therefore
     drawing currency under a requests heading.

  4. The by-key charts gave a real but INVALID auth attempt (an unexpanded
     '${ENV_VAR}' bearer token, a made-up/revoked key hash that 404s on /key/info) its
     own named chart band. `config.key_known()` + the `known_keys` table (populated
     from LiteLLM's own /key/list) now gate which labels may claim a band, the same
     way `config.key_excluded()` already gates operator-excluded labels.
"""
import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

import config
import db
from collectors import litellm


def _lite_app(keys_payload, *, activity=None):
    """Minimal LiteLLM stub serving only the aggregate endpoints lite mode uses."""
    async def _live(_r): return web.json_response({"status": "healthy"})
    async def _models(_r): return web.json_response({"data": []})
    async def _b(_r): return web.json_response({"in_flight_requests": 0})
    async def _act(_r): return web.json_response(
        activity or {"daily_data": [], "sum_api_requests": 52, "sum_total_tokens": 1353436})
    async def _actm(_r): return web.json_response([])
    async def _keys(_r): return web.json_response(keys_payload)
    async def _spend_logs(_r): return web.json_response([])

    app = web.Application()
    for p, fn in (("/health/liveliness", _live), ("/v1/models", _models),
                  ("/health/backlog", _b), ("/spend/logs", _spend_logs),
                  ("/global/activity", _act), ("/global/activity/model", _actm),
                  ("/global/spend/keys", _keys)):
        app.router.add_get(p, fn)
    return app


async def _sample_lite(monkeypatch, app):
    srv = TestServer(app)
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LITELLM_BASE_URL",
                            str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 0)
        monkeypatch.setattr(config, "LITELLM_SPEND_ENABLED", True)
        monkeypatch.setattr(config, "LITELLM_SPEND_MODE", "lite")
        async with aiohttp.ClientSession() as s:
            return await litellm.sample(s)
    finally:
        await srv.close()


# --- 1. health-check pseudo-key ---------------------------------------------------

@pytest.mark.parametrize("row", [
    {"api_key": "litellm-internal-health-check", "key_alias": None, "total_spend": 0.0},
    {"api_key": "hashZ", "key_alias": "litellm-internal-health-check", "total_spend": 3.0},
    {"api_key": "HEALTH-CHECK-abc", "key_alias": None, "total_spend": 0.0},
])
async def test_lite_mode_drops_litellm_health_check_key(monkeypatch, row):
    """LiteLLM probing its own deployments is not user traffic — drop it whether the
    marker sits on the hash or the alias, and case-insensitively."""
    out = await _sample_lite(monkeypatch, _lite_app([
        row,
        {"api_key": "hash1", "key_alias": "team-a", "total_spend": 1.25},
    ]))
    labels = {str(k.get("key")) + "|" + str(k.get("alias")) for k in out["top_keys"]}
    assert not any("health-check" in lb.lower() for lb in labels), labels
    assert len(out["top_keys"]) == 1
    assert out["top_keys"][0]["alias"] == "team-a"


async def test_health_check_filter_does_not_eat_ordinary_keys(monkeypatch):
    """The substring test must not swallow a legitimate key that merely mentions
    'health' (a real product/team name) — only the health-check marker is excluded."""
    out = await _sample_lite(monkeypatch, _lite_app([
        {"api_key": "hash1", "key_alias": "health-platform-team", "total_spend": 2.0},
        {"api_key": "hash2", "key_alias": "checkout-service", "total_spend": 1.0},
    ]))
    assert {k["alias"] for k in out["top_keys"]} == {"health-platform-team",
                                                    "checkout-service"}


def test_is_health_check_key_helper():
    """Shared helper backing both the lite and full paths."""
    assert litellm._is_health_check_key("litellm-internal-health-check")
    assert litellm._is_health_check_key(None, "Health-Check")
    assert not litellm._is_health_check_key(None, None)
    assert not litellm._is_health_check_key("hash1", "team-a")
    assert not litellm._is_health_check_key("healthcheck")   # no hyphen != the marker


# --- 2. requests_window basis -----------------------------------------------------

async def test_lite_requests_window_declares_day_basis(monkeypatch):
    """Lite's count comes from /global/activity today->tomorrow: a UTC day-to-date
    total. It must say so, or the dashboard renders it as a rolling window."""
    out = await _sample_lite(monkeypatch, _lite_app([]))
    assert out["requests_window"] == 52
    assert out["requests_basis"] == "today_utc"


_ROWS = [
    {"startTime": "2026-07-24T10:00:00", "endTime": "2026-07-24T10:00:01",
     "api_key": "litellm-internal-health-check", "model": "m",
     "total_tokens": 5, "response_cost": 0.5},
    {"startTime": "2026-07-24T10:00:00", "endTime": "2026-07-24T10:00:01",
     "api_key": "hash1", "model": "m", "total_tokens": 10, "response_cost": 0.1},
]


def test_full_mode_requests_window_is_a_real_window():
    """Full mode counts per-request rows inside LITELLM_SPEND_WINDOW_MIN — a genuine
    rolling window, so it keeps the 'window' basis (never 'today_utc')."""
    import json
    d, *_ = litellm._parse_spend_bytes(json.dumps(_ROWS).encode(), 0.0, 1000)
    assert d.get("requests_basis") == "window"


def test_health_check_rows_excluded_from_full_mode_per_key():
    """Regression guard on the refactor: routing full mode through the shared helper
    must keep dropping health-check rows from the per-key breakdown."""
    import json
    d, *_ = litellm._parse_spend_bytes(json.dumps(_ROWS).encode(), 0.0, 1000)
    keys = {k["key"] for k in (d.get("top_keys") or [])}
    assert "litellm-internal-health-check" not in keys
    assert "hash1" in keys


def test_health_check_rows_excluded_from_the_persisted_spend_rollup():
    """`_fold_model_user` feeds the on-disk per-(day, model, key) rollup that the Spend
    page reads. A health-check row leaking in there would persist fake usage/cost
    history, which no later filter can undo."""
    rollup = litellm._fold_model_user(_ROWS)
    assert rollup, "rollup should still contain the real row"
    assert all("health-check" not in str(r.get("key", "")).lower() for r in rollup)
    assert {r["key"] for r in rollup} == {"hash1"}


# --- 3. exclusion interacts correctly with the health-check filter -----------------

async def test_excluded_key_and_health_check_key_are_both_dropped(monkeypatch):
    """The two filters are independent and must compose: MONITOR_EXCLUDE_KEYS removes
    the operator's own monitoring key, the automatic filter removes LiteLLM's
    health-check probe, and only real user keys survive. Mirrors the live payload
    shape that prompted this work."""
    monkeypatch.setattr(config, "EXCLUDE_KEYS", {"svc-monitoring"})
    out = await _sample_lite(monkeypatch, _lite_app([
        {"api_key": "litellm-internal-health-check", "key_alias": None, "total_spend": 0.0},
        {"api_key": "hashSvc", "key_alias": "svc-monitoring", "total_spend": 1.0256},
        {"api_key": "hashA", "key_alias": "user-one", "total_spend": 9.2627},
        {"api_key": "hashB", "key_alias": "user-two", "total_spend": 2.7192},
    ]))
    assert [k["alias"] for k in out["top_keys"]] == ["user-one", "user-two"]


async def test_top_keys_can_end_up_empty_when_everything_is_filtered(monkeypatch):
    """A proxy whose only traffic is LiteLLM's own health checks must report NO keys —
    not a lone health-check band. Empty is the honest answer and the chart hides."""
    out = await _sample_lite(monkeypatch, _lite_app([
        {"api_key": "litellm-internal-health-check", "key_alias": None, "total_spend": 0.0},
    ]))
    assert out["top_keys"] == []


# --- 4. the basis reaches the dashboard through the API ---------------------------

async def test_requests_basis_survives_to_the_snapshot_api(monkeypatch):
    """The KPI label is driven by `requests_basis` on the client, so the field has to
    survive the collector -> snapshot -> /api/data hop. Asserting on the collector
    alone would still pass if the API layer dropped or renamed it, so go through the
    real handler and read the served JSON."""
    import app as appmod
    from aiohttp.test_utils import TestClient

    out = await _sample_lite(monkeypatch, _lite_app([]))
    assert out["requests_basis"] == "today_utc"      # precondition

    db.init()
    c = TestClient(TestServer(appmod.build_app()))
    await c.start_server()
    try:
        # stop the samplers so they can't overwrite the snapshot mid-assertion
        for _t in c.app.get(appmod._BACKENDS, []) or []:
            _t.cancel()
        for _key in (appmod._SAMPLER, appmod._MU_BACKFILL):
            _t = c.app.get(_key)
            if _t is not None:
                _t.cancel()
        monkeypatch.setattr(appmod, "_latest",
                            {"ts": 1.0, "collectors": {"litellm": out}})
        r = await c.get("/api/data")
        assert r.status == 200
        served = (await r.json())["latest"]["collectors"]["litellm"]
        assert served["requests_basis"] == "today_utc", \
            "requests_basis must reach the dashboard — the Reqs KPI label depends on it"
        assert served["requests_window"] == 52
    finally:
        await c.close()


async def test_off_mode_top_keys_also_filters_health_check(monkeypatch):
    """`_fetch_top_keys` is shared by lite AND the 'off'/load-shed path (so the per-key
    charts survive with the heavy pull disabled) — the filter must hold there too."""
    monkeypatch.setattr(config, "LITELLM_SPEND_ENABLED", False)
    srv = TestServer(_lite_app([
        {"api_key": "litellm-internal-health-check", "key_alias": None, "total_spend": 0.0},
        {"api_key": "hashA", "key_alias": "user-one", "total_spend": 5.0},
    ]))
    await srv.start_server()
    try:
        monkeypatch.setattr(config, "LITELLM_BASE_URL",
                            str(srv.make_url("")).rstrip("/"))
        monkeypatch.setattr(config, "LITELLM_MASTER_KEY", "sk-test")
        monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 0)
        async with aiohttp.ClientSession() as s:
            out = await litellm.sample(s)
    finally:
        await srv.close()
    aliases = [k["alias"] for k in (out.get("top_keys") or [])]
    assert "user-one" in aliases
    assert not any("health-check" in str(a).lower() for a in aliases)


# --- 5. lite mode stores SPEND in the reqs column (why the charts say "spend") -----

def test_insert_key_series_stores_spend_when_requests_unavailable(tmp_path, monkeypatch):
    """The chart relabel is only correct because db.insert_key_series falls back to
    cost when the collector reports reqs=None. Pin that fallback so the label and the
    stored metric can never drift apart."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    db.insert_key_series(1000.0, [
        {"key": "hashA", "alias": "user-one", "reqs": None, "cost": 9.26},
        {"key": "hashB", "alias": "user-two", "reqs": 4, "cost": 1.0},
    ])
    with db._connect() as conn:
        rows = dict(conn.execute(
            "SELECT label, reqs FROM key_series WHERE ts=1000.0").fetchall())
    assert rows["user-one"] == 9.26     # lite: spend stands in for the missing count
    assert rows["user-two"] == 4.0      # full: the real request count wins


# --- 6. known_keys / key_known — real but INVALID auth attempts ------------------
#
# Moved here (from tests/test_dynamic_qa.py) because this is the same class of bug
# as sections 1/3 above: a label that reaches the by-key charts must not get its own
# named band unless it's actually attributable, whether the reason is "it's LiteLLM's
# own health-check probe" (sections 1/3) or "it's not a real, currently-or-formerly
# registered LiteLLM key" (this section). key_known()'s cold-start permissiveness
# mirrors key_excluded()'s always-on behaviour: both fold a label into 'Other'
# instead of dropping the underlying activity.

def test_key_known_permissive_when_no_baseline(monkeypatch):
    """config.key_known(): a non-empty known set gates strictly (label must be a member),
    but an EMPTY known set (no /key/list poll has ever succeeded — e.g. right after a
    fresh start) must be permissive, or every by-key chart would blank out before the
    first poll completes — worse than the garbage-label bug being fixed."""
    assert config.key_known("anything", set()) is True             # no baseline -> permissive
    known = {"alex-batista", "claude-code"}
    assert config.key_known("alex-batista", known) is True         # a real, known key
    assert config.key_known("${LITELLM_API_KEY}", known) is False  # never a registered key
    assert config.key_known("a" * 64, known) is False              # made-up/revoked hash


def test_key_known_is_case_sensitive_unlike_key_excluded(monkeypatch):
    """Latent asymmetry worth pinning down: key_excluded() normalizes both sides to
    lower-case (case-insensitive, exact-match on the whole value — see its docstring),
    but key_known() does a bare `str(label) in known_keys` with NO case-folding. In
    practice both known_keys (from /key/list key_alias) and the label recorded on
    usage rows come from the same LiteLLM field, so casing should already agree — but
    if a caller/config ever compares differently-cased forms, key_known() will NOT
    match the way key_excluded() would. This test locks in the CURRENT (case-sensitive)
    behaviour so a change to it is deliberate, not accidental."""
    known = {"Alex-Batista"}
    assert config.key_known("Alex-Batista", known) is True
    assert config.key_known("alex-batista", known) is False   # differs only by case -> NOT known
    # key_excluded(), by contrast, treats differing case as the SAME identifier:
    monkeypatch.setattr(config, "EXCLUDE_KEYS", {"alex-batista"})
    assert config.key_excluded("Alex-Batista") is True


def test_key_series_hides_unknown_label(tmp_path, monkeypatch):
    """The persisted per-key over-time chart (key_series) drops a label that LiteLLM's
    own /key/list has never confirmed valid (a real but INVALID auth attempt — an
    unexpanded '${ENV_VAR}' string, a made-up/revoked hash), same as it already drops an
    operator-excluded label — and a full top-N is still returned (the unknown label
    doesn't eat a slot)."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "ks_known.db"))
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    db.known_keys_upsert(["pedro"], now)                # only "pedro" is a REAL LiteLLM key
    for i in range(30):
        db.insert_key_series(now - 1800 + i * 60, [
            {"key": "hA", "alias": "pedro", "reqs": 100 + i},
            {"key": "hZ", "alias": "${LITELLM_API_KEY}", "reqs": 99999},  # would rank #1
        ])
    out = db.key_series("1h", top_n=10)
    assert "pedro" in out["labels"]
    assert "${LITELLM_API_KEY}" not in out["labels"]    # never confirmed valid -> hidden
    dl = db.key_series_window_delta("1h", top_n=10)
    assert "${LITELLM_API_KEY}" not in dl["labels"]
    assert "pedro" in dl["labels"]


def test_key_series_keeps_all_labels_with_no_known_keys_baseline(tmp_path, monkeypatch):
    """Before the FIRST successful /key/list poll, db.known_keys_set() is empty — the
    validity filter must be a no-op in that state (permissive), not hide every key, so a
    fresh deployment isn't blank on the by-key charts while the baseline is still warming
    up."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "ks_nobaseline.db"))
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)
    for i in range(5):
        db.insert_key_series(now - 240 + i * 60, [{"key": "hA", "alias": "pedro", "reqs": 10}])
    out = db.key_series("1h", top_n=10)
    assert "pedro" in out["labels"]                     # not hidden despite no baseline yet


def test_key_series_keeps_label_after_it_vanishes_from_a_later_key_list_poll(
        tmp_path, monkeypatch):
    """known_keys rows are NEVER deleted (see the schema comment): a key that was
    confirmed valid and later rotated/deleted off LiteLLM must keep showing in
    HISTORY. Unlike the roundtrip test (which only checks known_keys_set() itself),
    this exercises the actual read path — key_series() over data recorded both before
    AND after the key disappeared from /key/list — to confirm it still gets its own
    band rather than silently folding into 'Other' the moment a later poll stops
    re-confirming it."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "ks_rotated.db"))
    db.init()
    t0 = 9_000_000.0
    db.known_keys_upsert(["old-team", "pedro"], t0)     # poll #1: both confirmed
    # poll #2 (later): /key/list no longer lists "old-team" (rotated/deleted) — the
    # sampler only ever re-confirms what IS present, it never removes a stale label.
    db.known_keys_upsert(["pedro"], t0 + 3600)
    assert db.known_keys_set() == {"old-team", "pedro"}  # history preserved, not wiped
    monkeypatch.setattr(db.time, "time", lambda: t0 + 7200)
    for i in range(30):
        db.insert_key_series(t0 + 7200 - 1800 + i * 60, [
            {"key": "hA", "alias": "pedro", "reqs": 50 + i},
            {"key": "hB", "alias": "old-team", "reqs": 30 + i},
        ])
    out = db.key_series("1h", top_n=10)
    assert "old-team" in out["labels"]                  # still its own band, not "Other"
    assert "pedro" in out["labels"]


def test_concurrency_by_key_folds_unknown_label_into_other(tmp_path, monkeypatch):
    """Same class of bug as the excluded-label regression, but for a label that's real
    ACTIVITY yet was never a currently-or-formerly registered LiteLLM key (per
    db.known_keys_set()) — e.g. a client sending the literal string '${LITELLM_API_KEY}'
    as its bearer token, or a made-up/revoked 64-char hash that 404s on /key/info. That's
    real backlog/concurrency load, so its weight must still count in the split
    denominator (real keys' shares aren't inflated), but it must fold into 'Other'
    instead of claiming its own named band."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "cbk_known.db"))
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)   # align wall-clock so age-aware _pick_tier reads raw
    db.known_keys_upsert(["alice"], now)                # only "alice" is LiteLLM-confirmed
    for i in range(10):
        t = now - 600 + i * 60
        with db._connect() as c:
            c.execute("INSERT INTO metrics(ts,conc,backlog) VALUES (?,?,?)", (t, 10.0, 4.0))
        db.insert_key_series(t, [
            {"key": "hA", "alias": "alice", "reqs": 3},
            {"key": "hZ", "alias": "${LITELLM_API_KEY}", "reqs": 9999},  # would rank #1
        ])
    out = db.concurrency_by_key("1h", "conc", end=now)
    labels = {s["label"] for s in out["series"]}
    assert "${LITELLM_API_KEY}" not in labels           # never its own band
    assert "alice" in labels and "Other" in labels
    last = {s["label"]: s["data"][-1] for s in out["series"]}
    assert round(sum(last.values()), 2) == 10.0         # bands still sum to the real total
    # alice's tiny real share (3 reqs) vs the garbage label's 9999 must NOT inflate
    # alice's band to the whole aggregate — the unknown weight still counts in the
    # split denominator, so alice gets only her true (small) proportional share.
    assert last["alice"] < 1.0


def test_concurrency_by_key_composes_excluded_and_known_filters(tmp_path, monkeypatch):
    """The two independent gates (config.key_excluded() / MONITOR_EXCLUDE_KEYS and
    config.key_known() / known_keys) must compose cleanly on the SAME chart: a label
    can be excluded-but-known, known-but-not-excluded, excluded-AND-unknown, or
    neither — only the last gets its own band, but every one of them keeps its
    weight in the split denominator (no double-counting, nothing silently dropped
    from the total)."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "cbk_compose.db"))
    monkeypatch.setattr(config, "EXCLUDE_KEYS", {"monitor-self", "rogue-excluded"})
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now)   # align wall-clock so age-aware _pick_tier reads raw
    # "monitor-self" and "pedro" are the only two LiteLLM-confirmed keys; "rogue-excluded"
    # and "${LITELLM_API_KEY}" were never confirmed by /key/list.
    db.known_keys_upsert(["monitor-self", "pedro"], now)
    for i in range(10):
        t = now - 600 + i * 60
        with db._connect() as c:
            c.execute("INSERT INTO metrics(ts,conc,backlog) VALUES (?,?,?)", (t, 20.0, 4.0))
        db.insert_key_series(t, [
            {"key": "h1", "alias": "pedro", "reqs": 5},              # known, not excluded
            {"key": "h2", "alias": "monitor-self", "reqs": 4000},    # known, BUT excluded
            {"key": "h3", "alias": "rogue-excluded", "reqs": 3000},  # excluded AND unknown
            {"key": "h4", "alias": "${LITELLM_API_KEY}", "reqs": 2000},  # unknown, not excluded
        ])
    out = db.concurrency_by_key("1h", "conc", end=now)
    labels = {s["label"] for s in out["series"]}
    assert labels == {"pedro", "Other"}                 # the only label allowed a named band
    last = {s["label"]: s["data"][-1] for s in out["series"]}
    assert round(sum(last.values()), 2) == 20.0         # every key's weight still counted once
    assert last["pedro"] < 1.0                          # pedro's true (tiny) share, not inflated


def test_concurrency_by_key_bridges_isolated_request_to_nearest_key_sample(tmp_path, monkeypatch):
    """A single, isolated request: its backlog blip (fast, SAMPLE_INTERVAL-polled) and its
    key_series sample (slow, LITELLM_HEAVY_INTERVAL-polled) almost never land in the exact
    same bucket. Observed live: two one-off test requests billed correctly to a known key,
    yet the by-key chart showed the whole aggregate as 'Other' because no key_series row
    fell in the aggregate's own bucket. The nearest key_series sample, within one heavy-poll
    interval, must now be borrowed instead of defaulting straight to 'Other'."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "cbk_bridge.db"))
    monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 60.0)
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now + 40)   # align wall-clock (end=now+40) so _pick_tier reads raw
    db.known_keys_upsert(["pedro"], now)
    # a single backlog blip — the ONLY metrics row, so it's the only bucket in the window
    with db._connect() as c:
        c.execute("INSERT INTO metrics(ts,conc,backlog) VALUES (?,?,?)", (now, 5.0, 1.0))
    # the matching key_series sample lands 40s later — a different bucket, but well within
    # one LITELLM_HEAVY_INTERVAL (60s)
    db.insert_key_series(now + 40, [{"key": "h1", "alias": "pedro", "reqs": 7}])
    out = db.concurrency_by_key("1h", "conc", end=now + 40)
    labels = {s["label"] for s in out["series"]}
    assert "pedro" in labels
    data = {s["label"]: s["data"] for s in out["series"]}
    assert sum(data["pedro"]) > 0                       # attributed to pedro, not lost
    assert sum(data.get("Other", [0])) == 0              # not dumped into "Other"


def test_concurrency_by_key_does_not_bridge_across_a_stale_gap(tmp_path, monkeypatch):
    """The bridge is bounded to one LITELLM_HEAVY_INTERVAL — a key_series sample far outside
    that window is stale enough that attributing an unrelated blip to it would be a guess,
    not an inference. Beyond the bound, 'Other' is still the honest answer."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "cbk_no_bridge.db"))
    monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 60.0)
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now + 600)   # align wall-clock (end=now+600) so _pick_tier reads raw
    db.known_keys_upsert(["pedro"], now)
    with db._connect() as c:
        c.execute("INSERT INTO metrics(ts,conc,backlog) VALUES (?,?,?)", (now, 5.0, 1.0))
    # far outside the bridge window (well beyond one heavy interval)
    db.insert_key_series(now + 600, [{"key": "h1", "alias": "pedro", "reqs": 7}])
    out = db.concurrency_by_key("1h", "conc", end=now + 600)
    data = {s["label"]: s["data"] for s in out["series"]}
    # pedro's own bucket (their real sample) may show activity; the ORIGINAL blip bucket
    # (index 0, sorted by time) must still have gone to "Other", not been guessed at
    assert data["Other"][0] > 0


def test_concurrency_by_key_blends_equidistant_donor_buckets(tmp_path, monkeypatch):
    """When a gap bucket sits exactly between two donor buckets (one before, one after, same
    distance), neither is more likely to represent the isolated request than the other —
    picking one arbitrarily would bias attribution toward whichever side happens to come
    first. Both keys' activity must be blended into the gap bucket's split instead."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "cbk_tie.db"))
    monkeypatch.setattr(config, "LITELLM_HEAVY_INTERVAL", 60.0)
    db.init()
    now = 9_000_000.0
    monkeypatch.setattr(db.time, "time", lambda: now + 100)   # align wall-clock (end=now+100) so _pick_tier reads raw
    db.known_keys_upsert(["alice", "bob"], now)
    with db._connect() as c:
        c.execute("INSERT INTO metrics(ts,conc,backlog) VALUES (?,?,?)", (now, 6.0, 1.0))
    # symmetric donors, exactly 2 bucket-widths either side of the blip (an offset that
    # isn't an exact multiple of bsize can floor to different bucket-distances on each
    # side, so this uses 2*bsize precisely rather than an arbitrary round-seconds value)
    bsize = 3600 / 200
    db.insert_key_series(now - 2 * bsize, [{"key": "hA", "alias": "alice", "reqs": 5}])
    db.insert_key_series(now + 2 * bsize, [{"key": "hB", "alias": "bob", "reqs": 5}])
    out = db.concurrency_by_key("1h", "conc", end=now + 100)
    data = {s["label"]: s["data"] for s in out["series"]}
    blip_idx = out["labels"].index(now)
    assert data["alice"][blip_idx] > 0                  # both donors contribute...
    assert data["bob"][blip_idx] > 0
    assert round(data["alice"][blip_idx], 3) == round(data["bob"][blip_idx], 3)  # ...equally
    assert data.get("Other", [0] * len(out["labels"]))[blip_idx] == 0


# --- 5. a counter that runs BACKWARDS must not manufacture activity ---------------

def _seed_flat_then_drop(tmp_path, monkeypatch):
    """Reproduce the exact live series that produced a phantom band: a key's stored
    CUMULATIVE value sits flat at 2.72, re-bases down to 0.86, then sits flat again.
    No traffic at any point — every sample is one of two constant plateaus."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    now = 1_800_000_000.0
    rows = []
    for i in range(40):
        rows.append((now - 3000 + i * 30, "quiet-key", 2.72))
    for i in range(20):
        rows.append((now - 1800 + i * 30, "quiet-key", 0.86))
    with db._connect() as conn:
        conn.executemany("INSERT INTO key_series(ts,label,reqs) VALUES (?,?,?)", rows)
    return now


def test_backwards_counter_does_not_invent_a_band(tmp_path, monkeypatch):
    """A key whose cumulative total is re-based DOWNWARD (LiteLLM re-issuing the key,
    a budget period rolling, a replica with a different view) previously had its whole
    new total charged to the bucket where the drop landed, then carried as a flat
    plateau for the rest of the window — a visible band on a proxy that served nothing.
    The window must report zero activity for a series that only ever plateaus."""
    now = _seed_flat_then_drop(tmp_path, monkeypatch)
    series = db.key_delta_series("1h", 200, end=now)
    vals = [p.get("quiet-key") for p in series["points"] if p.get("quiet-key") is not None]
    assert vals, "the key should still be plotted, just flat"
    assert max(vals) == 0.0, f"idle key drew a phantom band: peaked at {max(vals)}"


def test_backwards_counter_does_not_rank_into_top_n(tmp_path, monkeypatch):
    """The ranking function must agree with the plot: an idle key must not win a
    top-N slot off a downward re-base, or it ranks in here and draws flat there."""
    now = _seed_flat_then_drop(tmp_path, monkeypatch)
    ranked = db.key_series_window_delta("1h", 10, end=now)
    d = dict(zip(ranked["labels"], ranked["deltas"]))
    assert d.get("quiet-key", 0.0) == 0.0, f"idle key ranked with delta {d.get('quiet-key')}"


def test_genuine_reset_to_zero_still_counts_the_climb_after_it(tmp_path, monkeypatch):
    """Guard the case the old 'reset-safe' branch existed for: a counter that really
    resets to 0 and then climbs must still report the post-reset activity, so this fix
    cannot be accused of hiding real traffic."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    now = 1_800_000_000.0
    seq = [100.0, 100.0, 0.0, 3.0, 7.0]
    with db._connect() as conn:
        conn.executemany("INSERT INTO key_series(ts,label,reqs) VALUES (?,?,?)",
                         [(now - 600 + i * 60, "busy-key", v) for i, v in enumerate(seq)])
    series = db.key_delta_series("1h", 200, end=now)
    vals = [p.get("busy-key") for p in series["points"] if p.get("busy-key") is not None]
    assert max(vals) == 7.0, f"post-reset climb lost: {vals}"
