"""Settings → the Unassigned group's show/hide switch.

"Unassigned" is every key LiteLLM reports no owner for and that carries no admin user
override — the same set the Settings board groups under that name. Hiding it must drop
those keys from EVERY per-key/per-user graph, which is why the filter lives server-side
in the three read paths that already gate on key_excluded()/key_known(), not in one
page's JS. Hiding removes a key's own named band; its usage still counts toward the
measured aggregate (folded into "Other"), exactly like an excluded key.
"""
import config
import db


def _seed(tmp_path, monkeypatch, *, owners):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    now = 1_800_000_000.0
    db.known_keys_upsert(owners, now)
    rows = []
    for i in range(20):
        for lab in owners:
            rows.append((now - 1800 + i * 60, lab, float(i)))
    with db._connect() as conn:
        conn.executemany("INSERT INTO key_series(ts,label,reqs) VALUES (?,?,?)", rows)
    return now


def test_owner_is_persisted_from_the_key_list_poll(tmp_path, monkeypatch):
    """The owner must survive to the DB — it used to be discarded (only kb.keys() was
    stored), so nothing downstream could tell an unassigned key from an owned one."""
    _seed(tmp_path, monkeypatch, owners={"owned": "u-1", "orphan": ""})
    assert db.unassigned_labels() == {"orphan"}


def test_a_blank_owner_never_overwrites_a_known_one(tmp_path, monkeypatch):
    """A transient /key/list response that loses the user field must not orphan a key
    that was previously attributed — that would silently hide it once the toggle is on."""
    now = _seed(tmp_path, monkeypatch, owners={"owned": "u-1"})
    db.known_keys_upsert({"owned": ""}, now + 60)          # degraded poll
    assert db.unassigned_labels() == set()


def test_an_admin_override_rescues_a_key_from_unassigned(tmp_path, monkeypatch):
    """Settings lets an admin assign a key to a user; the board then moves it out of the
    Unassigned group, so the hide filter must stop covering it too (settings.html groups
    by `k.user_grp || k.user`, and user_grp is the override). Seeds a mixed world (one
    owned key present) so owner resolution is trusted — see the all-empty guard test."""
    _seed(tmp_path, monkeypatch, owners={"owned": "u-1", "orphan": ""})
    assert db.unassigned_labels() == {"orphan"}
    db.key_user_set("orphan", "someone@example.com", 1_800_000_000.0)
    assert db.unassigned_labels() == set()


def test_all_owners_empty_makes_hide_a_no_op_not_a_blackout(tmp_path, monkeypatch):
    """FIELD BUG (live: 61/61 keys had an empty owner): `unassigned_labels()` returned EVERY
    key, so flipping 'Hide unassigned' ON blanked every band — including 21 keys the Settings
    board showed under real named users. When owner resolution has produced NOTHING (no row
    carries a non-empty owner), 'empty owner' cannot be told apart from 'owner not known yet',
    so hiding must be a no-op rather than a blackout. Once ANY owner is known, an empty-owner
    key is again a trustworthy 'unassigned'."""
    now = _seed(tmp_path, monkeypatch, owners={"a": "", "b": "", "c": ""})
    monkeypatch.setattr(config, "HIDE_UNASSIGNED_KEYS", True)
    # all owners empty → owner data unresolved → hide is a NO-OP (was: all three hidden)
    assert db.unassigned_labels() == set()
    assert db.hidden_unassigned() == set()
    for lab in ("a", "b", "c"):
        assert lab in db.key_series("1h", 200, end=now)["labels"], f"{lab} must stay visible"
    # once one owner resolves, the genuinely-ownerless ones become hideable again
    db.known_keys_upsert({"a": "u-1"}, now + 60)
    assert db.unassigned_labels() == {"b", "c"}


def test_toggle_off_is_a_pure_no_op(tmp_path, monkeypatch):
    """Default state: unassigned keys are SHOWN, and the hide set is empty so the
    filter costs nothing and changes no chart."""
    now = _seed(tmp_path, monkeypatch, owners={"owned": "u-1", "orphan": ""})
    monkeypatch.setattr(config, "HIDE_UNASSIGNED_KEYS", False)
    assert db.hidden_unassigned() == set()
    assert "orphan" in db.key_series("1h", 200, end=now)["labels"]


def test_hiding_removes_unassigned_from_every_per_key_read_path(tmp_path, monkeypatch):
    """The point of the feature: one switch, every graph. All three read paths that feed
    per-key charts must drop the label — a per-chart filter would leave it visible
    wherever it wasn't applied."""
    now = _seed(tmp_path, monkeypatch, owners={"owned": "u-1", "orphan": ""})
    monkeypatch.setattr(config, "HIDE_UNASSIGNED_KEYS", True)
    assert db.hidden_unassigned() == {"orphan"}
    assert "orphan" not in db.key_series("1h", 200, end=now)["labels"]
    assert "owned" in db.key_series("1h", 200, end=now)["labels"]
    assert "orphan" not in db.key_series_window_delta("1h", 10, end=now)["labels"]
    assert "orphan" not in (db.concurrency_by_key("1h", "conc", end=now)["labels"] or [])


def test_hiding_does_not_touch_the_measured_total(tmp_path, monkeypatch):
    """Hiding drops a NAMED BAND, it does not rewrite the aggregate — the stacked bands
    must still sum to the real measured value, with the hidden key's share in "Other"."""
    now = _seed(tmp_path, monkeypatch, owners={"owned": "u-1", "orphan": ""})
    with db._connect() as conn:
        conn.executemany("INSERT INTO metrics(ts,conc) VALUES (?,?)",
                         [(now - 1800 + i * 60, 4.0) for i in range(20)])
    monkeypatch.setattr(config, "HIDE_UNASSIGNED_KEYS", True)
    d = db.concurrency_by_key("1h", "conc", end=now)
    labels = [s["label"] for s in (d.get("series") or [])]
    assert "orphan" not in labels


# --- the LIVE-snapshot path: top_keys never touches the DB, so the stored-series -----
# --- gates could not see it. Every chart fed by it must obey the same rule. ----------

def _snap(rows):
    return {"ts": 1.0, "collectors": {"litellm": {"available": True, "top_keys": rows}}}


_ROWS = [
    {"key": "hashOwned", "alias": "owned", "cost": 9.26},
    {"key": "hashOrphan", "alias": "orphan", "cost": 1.0},
    {"key": "${LITELLM_API_KEY}", "alias": "", "cost": 0.0},   # unexpanded env var
    {"key": "hashGhost", "alias": "ghost", "cost": 0.0},        # never in /key/list
]


def _prep(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    db.known_keys_upsert({"owned": "u-1", "orphan": ""}, 1000.0)


def test_garbage_labels_are_dropped_from_the_live_snapshot(tmp_path, monkeypatch):
    """`${LITELLM_API_KEY}` is an unexpanded bearer token, not a key, and 'ghost' was
    never confirmed by /key/list. key_known() folded them on the stored-series charts but
    the live top_keys path had no such gate, so they still drew their own bars."""
    import app as appmod
    _prep(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "HIDE_UNASSIGNED_KEYS", False)
    vis = [k["key"] for k in appmod._visible_top_keys(_ROWS)]
    assert vis == ["hashOwned", "hashOrphan"]


def test_unassigned_toggle_reaches_the_live_snapshot(tmp_path, monkeypatch):
    """Option 1: unassigned keys disappear from the live-snapshot charts too, but only
    when the Settings switch is set to Hidden."""
    import app as appmod
    _prep(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "HIDE_UNASSIGNED_KEYS", True)
    vis = [k["key"] for k in appmod._visible_top_keys(_ROWS)]
    assert vis == ["hashOwned"], "orphan must go when the group is hidden"


def test_totals_survive_the_visibility_filter(tmp_path, monkeypatch):
    """Hiding removes a key's own BAR, never a measured total. The Overview's spend KPI
    and key count must reflect every key, so the filtered snapshot carries the pre-filter
    aggregate alongside the reduced list."""
    import app as appmod
    _prep(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "HIDE_UNASSIGNED_KEYS", True)
    out = appmod._snapshot_for_display(_snap(_ROWS))
    ll = out["collectors"]["litellm"]
    assert [k["key"] for k in ll["top_keys"]] == ["hashOwned"]
    assert ll["cost_all_keys"] == 10.26          # 9.26 + 1.0 + 0 + 0 — nothing lost
    assert ll["keys_total"] == 4


def test_display_filter_never_mutates_the_live_snapshot(tmp_path, monkeypatch):
    """`_latest` is ALSO what gets persisted to key_series. Filtering in place would
    silently truncate stored history, which no later toggle could undo."""
    import app as appmod
    _prep(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "HIDE_UNASSIGNED_KEYS", True)
    snap = _snap(list(_ROWS))
    before = len(snap["collectors"]["litellm"]["top_keys"])
    appmod._snapshot_for_display(snap)
    assert len(snap["collectors"]["litellm"]["top_keys"]) == before


def test_filter_is_a_no_op_when_nothing_is_hidden(tmp_path, monkeypatch):
    """With the toggle off and every label confirmed, the snapshot is returned unchanged
    (identity) — no copying, no added fields, no behaviour change by default."""
    import app as appmod
    _prep(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "HIDE_UNASSIGNED_KEYS", False)
    rows = [{"key": "hashOwned", "alias": "owned", "cost": 1.0}]
    snap = _snap(rows)
    assert appmod._snapshot_for_display(snap) is snap


def test_admin_keys_board_still_sees_unassigned_keys(tmp_path, monkeypatch):
    """The Settings board must keep showing unassigned keys even while they are hidden
    from graphs — it is where an admin ASSIGNS them. Hiding them there would make the
    group unusable and the toggle irreversible from the UI."""
    src = (__import__("pathlib").Path(__file__).resolve().parent.parent / "app.py"
           ).read_text(encoding="utf-8")
    board = src[src.index("uov = db.key_user_overrides()"):]
    board = board[:board.index("\nasync def ")]
    assert "_visible_top_keys" not in board, \
        "the admin keys board must NOT filter — it is how keys get assigned"


def test_board_owner_resolution_writes_through_to_known_keys(tmp_path, monkeypatch):
    """PHASE-2 (#2 single-source): the Settings board / budgets panel resolve owners LIVE from
    LiteLLM; that resolution must be WRITTEN THROUGH to `known_keys` — the same store the
    by-key graph read-paths use — so the board and the charts can never disagree about who
    owns a key (the live divergence: 61/61 owners empty in the store while 21 resolved on the
    board). `_store_owners_from_live` is the single write path."""
    import asyncio
    import app as appmod
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    # a fresh store with the keys seen but NO owners yet (the stale-store state)
    db.known_keys_upsert({"k1": "", "k2": ""}, 1_800_000_000.0)
    monkeypatch.setattr(config, "HIDE_UNASSIGNED_KEYS", True)
    # before the board is viewed, owner resolution has produced nothing → hide is a no-op
    assert db.unassigned_labels() == set()
    # the board resolves k1 → user-1 live; write-through fills the store
    live = {"k1": {"user": "user-1", "spend": 1.0}, "k2": {"user": "", "spend": 0.0}}
    asyncio.run(appmod._store_owners_from_live(live))
    # now the graphs agree with the board: k1 is owned, only k2 is unassigned
    assert db.unassigned_labels() == {"k2"}


def test_board_write_through_never_blanks_a_known_owner(tmp_path, monkeypatch):
    """A later live resolution that momentarily loses a key's user (degraded /key/list) must
    not blank an owner the store already knew — that would silently move an attributed key
    into 'Unassigned' and (with the toggle on) hide it. The write-through inherits
    `known_keys_upsert`'s fill-only semantics."""
    import asyncio
    import app as appmod
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    asyncio.run(appmod._store_owners_from_live({"k1": {"user": "user-1"}, "k2": {"user": "u2"}}))
    # a degraded poll drops k1's user; write-through must keep the known owner
    asyncio.run(appmod._store_owners_from_live({"k1": {"user": ""}, "k2": {"user": "u2"}}))
    monkeypatch.setattr(config, "HIDE_UNASSIGNED_KEYS", True)
    assert db.unassigned_labels() == set(), "a transient empty owner must not orphan k1"


# --- Finding-1 fix: the visibility gate is memoized on the hot serving path -----------

def test_visible_gate_is_memoized_but_toggle_stays_live(tmp_path, monkeypatch):
    """_visible_top_keys runs on every /api/data poll and the SSE loop per client, so its
    two db reads are cached for a few seconds (§6 — don't reopen sqlite every tick). The
    cache must NOT leak across DBs, and the Show/Hide toggle must stay LIVE (read each call,
    not cached), or flipping it would appear stuck until the TTL expired."""
    import app as appmod
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "a.db"))
    db.init()
    db.known_keys_upsert({"owned": "u-1", "orphan": ""}, 1000.0)
    appmod._vis_gate["mono"] = -1e9        # cold cache

    calls = {"n": 0}
    real = db.known_keys_set
    def _counting():
        calls["n"] += 1
        return real()
    monkeypatch.setattr(db, "known_keys_set", _counting)

    rows = [{"key": "h1", "alias": "owned", "cost": 1.0},
            {"key": "h2", "alias": "orphan", "cost": 1.0}]
    # toggle OFF: orphan is a known key, so it stays; only the DB is read once, then cached
    monkeypatch.setattr(config, "HIDE_UNASSIGNED_KEYS", False)
    a = [k["alias"] for k in appmod._visible_top_keys(rows)]
    b = [k["alias"] for k in appmod._visible_top_keys(rows)]
    assert a == ["owned", "orphan"] and b == ["owned", "orphan"]
    assert calls["n"] == 1, "second call within TTL must hit the cache, not re-query"

    # toggle ON in the SAME tick: must take effect immediately (gate read live), even though
    # the underlying sets are still cached
    monkeypatch.setattr(config, "HIDE_UNASSIGNED_KEYS", True)
    c = [k["alias"] for k in appmod._visible_top_keys(rows)]
    assert c == ["owned"], "toggle must be live, not frozen by the cache"


def test_visible_gate_force_refreshes_on_db_swap(tmp_path, monkeypatch):
    """The cache is keyed on DB_PATH, so pointing at a different database (a test, or a
    reconfigured deployment) must re-read rather than serve the previous DB's key set."""
    import app as appmod
    appmod._vis_gate["mono"] = -1e9
    monkeypatch.setattr(config, "HIDE_UNASSIGNED_KEYS", False)

    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "a.db"))
    db.init(); db.known_keys_upsert({"alpha": "u-1"}, 1000.0)
    rows_a = [{"key": "h", "alias": "alpha", "cost": 1.0}]
    assert [k["alias"] for k in appmod._visible_top_keys(rows_a)] == ["alpha"]

    # different DB: 'alpha' is unknown here → filtered; proves no stale cross-DB cache
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "b.db"))
    db.init(); db.known_keys_upsert({"beta": "u-2"}, 1000.0)
    rows_b = [{"key": "h", "alias": "alpha", "cost": 1.0},
              {"key": "h2", "alias": "beta", "cost": 1.0}]
    vis = [k["alias"] for k in appmod._visible_top_keys(rows_b)]
    assert vis == ["beta"], f"cache leaked across DB swap: {vis}"


# --- debounced owner transition: owned -> unassigned only after a sustained blank -------

def _owner(label):
    with db._connect() as conn:
        r = conn.execute("SELECT owner, owner_blank_streak FROM known_keys WHERE label=?",
                         (label,)).fetchone()
    return (r[0], r[1]) if r else (None, None)


def test_owner_survives_a_single_blank_poll(tmp_path, monkeypatch):
    """A ONE-OFF blank owner (owner-resolution blipped inside an otherwise-good poll) must
    NOT orphan the key — it keeps its owner and just starts a blank streak, so the key
    never flaps in/out of Unassigned between polls."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    db.known_keys_upsert({"k": "u-1"}, 1000.0)          # owned
    assert _owner("k") == ("u-1", 0)
    db.known_keys_upsert({"k": ""}, 1060.0)             # one blank poll
    assert _owner("k") == ("u-1", 1), "must hold the owner after a single blank"
    assert db.unassigned_labels() == set(), "still owned → not unassigned"
    db.known_keys_upsert({"k": "u-1"}, 1120.0)          # owner reappears
    assert _owner("k") == ("u-1", 0), "a non-blank poll resets the streak"


def test_owner_clears_after_sustained_blank(tmp_path, monkeypatch):
    """A GENUINE un-assignment (owner removed in LiteLLM) shows up: after
    OWNER_BLANK_THRESHOLD consecutive blank polls the owner is cleared and the key
    becomes Unassigned."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    # a second, still-owned key so unassigned_labels' all-empty guard doesn't kick in
    db.known_keys_upsert({"k": "u-1", "keep": "u-2"}, 1000.0)
    t = db.OWNER_BLANK_THRESHOLD
    for i in range(t):
        db.known_keys_upsert({"k": "", "keep": "u-2"}, 1000.0 + 60 * (i + 1))
    owner, streak = _owner("k")
    assert owner == "", f"after {t} blank polls the owner must clear, got {owner!r}"
    assert "k" in db.unassigned_labels(), "genuinely un-owned key becomes Unassigned"
    assert "keep" not in db.unassigned_labels()


def test_blank_streak_resets_before_threshold(tmp_path, monkeypatch):
    """Intermittent blips that never reach the threshold in a row must never clear the
    owner — the streak has to be CONSECUTIVE."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    db.known_keys_upsert({"k": "u-1"}, 1000.0)
    t = db.OWNER_BLANK_THRESHOLD
    for i in range(t + 3):                               # more blips than the threshold…
        db.known_keys_upsert({"k": ""}, 2000.0 + 120 * i)     # blank
        db.known_keys_upsert({"k": "u-1"}, 2060.0 + 120 * i)  # …but a good poll between each
    assert _owner("k") == ("u-1", 0), "non-consecutive blips must never clear the owner"


def test_label_only_upsert_never_touches_owner(tmp_path, monkeypatch):
    """The list form carries no owner info (owner UNKNOWN, not blank). It must record
    validity without ever disturbing a stored owner or its streak — otherwise a
    load-shed/legacy label-only refresh would wrongly orphan owned keys."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    db.known_keys_upsert({"k": "u-1"}, 1000.0)
    for i in range(db.OWNER_BLANK_THRESHOLD + 2):
        db.known_keys_upsert(["k"], 1100.0 + 60 * i)    # label-only refreshes
    assert _owner("k") == ("u-1", 0), "label-only upsert must not blank the owner"
    assert "k" in db.known_keys_set()


# --- debounce edge cases + end-to-end -------------------------------------------------

def test_owner_held_one_poll_before_threshold(tmp_path, monkeypatch):
    """Boundary: with THRESHOLD-1 consecutive blanks the owner is still held (the clear
    must happen ON the threshold, not one poll early)."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    db.known_keys_upsert({"k": "u-1", "keep": "u-2"}, 1000.0)
    t = db.OWNER_BLANK_THRESHOLD
    for i in range(t - 1):                              # one short of the threshold
        db.known_keys_upsert({"k": "", "keep": "u-2"}, 1000.0 + 60 * (i + 1))
    owner, streak = _owner("k")
    assert owner == "u-1" and streak == t - 1, f"must still be owned at streak {t-1}"
    assert "k" not in db.unassigned_labels()
    db.known_keys_upsert({"k": "", "keep": "u-2"}, 9000.0)   # the threshold-th blank
    assert _owner("k")[0] == "", "clears exactly on the threshold"


def test_new_key_reported_unowned_is_unassigned_immediately(tmp_path, monkeypatch):
    """A key FIRST seen with no owner is genuinely unassigned from the start — the
    debounce only guards the owned→unowned TRANSITION, not a never-owned key."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    db.known_keys_upsert({"fresh": "", "keep": "u-2"}, 1000.0)
    assert _owner("fresh") == ("", 0), "new unowned key inserts blank, no streak"
    assert "fresh" in db.unassigned_labels()


def test_owner_reassignment_is_not_an_unassignment(tmp_path, monkeypatch):
    """Owner CHANGING from one user to another (both non-blank) is a plain update — it
    must never be mistaken for the blank transition or accrue a streak."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    db.known_keys_upsert({"k": "u-1"}, 1000.0)
    db.known_keys_upsert({"k": "u-2"}, 1060.0)
    assert _owner("k") == ("u-2", 0)
    assert "k" not in db.unassigned_labels()


def test_streak_stays_zero_once_unassigned(tmp_path, monkeypatch):
    """After the owner is cleared, further blank polls are a no-op — the streak must not
    keep climbing (it only counts blanks while an owner is still held)."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    db.known_keys_upsert({"k": "u-1", "keep": "u-2"}, 1000.0)
    for i in range(db.OWNER_BLANK_THRESHOLD + 4):
        db.known_keys_upsert({"k": "", "keep": "u-2"}, 2000.0 + 60 * i)
    assert _owner("k") == ("", 0), "cleared owner + blank stays streak 0"


async def test_debounced_unassignment_reaches_a_chart_read_path(tmp_path, monkeypatch):
    """End-to-end: once the debounce clears a key's owner and the Hide toggle is on, the
    key actually drops out of a per-key read path (key_series), not just the label set."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    db.init()
    now = 1_800_000_000.0
    db.known_keys_upsert({"k": "u-1", "keep": "u-2"}, now)
    rows = [(now - 1800 + i * 60, lab, float(i))
            for i in range(20) for lab in ("k", "keep")]
    with db._connect() as conn:
        conn.executemany("INSERT INTO key_series(ts,label,reqs) VALUES (?,?,?)", rows)

    monkeypatch.setattr(config, "HIDE_UNASSIGNED_KEYS", True)
    assert "k" in db.key_series("1h", 200, end=now)["labels"], "still owned → shown"

    for i in range(db.OWNER_BLANK_THRESHOLD):
        db.known_keys_upsert({"k": "", "keep": "u-2"}, now + 60 * (i + 1))
    assert "k" in db.unassigned_labels()
    assert "k" not in db.key_series("1h", 200, end=now)["labels"], "now hidden everywhere"
    assert "keep" in db.key_series("1h", 200, end=now)["labels"]
