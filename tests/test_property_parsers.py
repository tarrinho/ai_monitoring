"""Property-based / fuzz tests (Hypothesis) — the pure parsers and money/date math run on
UNTRUSTED upstream data, so they must never crash and must hold simple invariants for any
input, not just the handful of cases we hand-picked."""
import re

from hypothesis import given, settings
from hypothesis import strategies as st

import app as appmod
from collectors import litellm

# deadline=None: emulated/loaded CI must not flake on per-example timing.
SETTINGS = settings(max_examples=200, deadline=None)

# year is normally 4 digits; out-of-range epochs can overflow to 5+ — still canonical shape
_DATE_RE = re.compile(r"^\d{4,}-\d{2}-\d{2}$")


@given(st.text())
@SETTINGS
def test_norm_date_never_crashes_and_is_canonical_or_empty(s):
    r = litellm._norm_date(s)
    assert r == "" or _DATE_RE.match(r)


# plausible epoch range only (0 .. year 2100); huge epochs legitimately yield 5-digit years
@given(st.one_of(st.integers(min_value=0, max_value=4102444800),
                 st.floats(min_value=0, max_value=4102444800,
                           allow_nan=False, allow_infinity=False)))
@SETTINGS
def test_norm_date_epochs_normalize(n):
    r = litellm._norm_date(n)
    assert r == "" or _DATE_RE.match(r)


_money = st.floats(min_value=0, max_value=1e7, allow_nan=False, allow_infinity=False)
_keys = st.lists(st.fixed_dictionaries({
    "alias": st.text(min_size=1, max_size=12),
    "cost": _money}), max_size=40)


@given(_keys)
@SETTINGS
def test_budget_rows_returns_a_row_per_key_never_drops(keys):
    rows = litellm.budget_rows(keys, {}, 15, 30)
    assert len(rows) == len(keys)                 # no silent drop, no top-N cap
    for r in rows:
        # projected/days_to_cap are None for keys whose spend never resets (there is
        # no period to project to); when present they must be non-negative
        assert r["spent"] >= 0
        assert r["projected"] is None or r["projected"] >= 0
        assert r["status"] in ("bad", "warn", "ok", "none")


@given(st.dictionaries(st.text(min_size=1, max_size=8),
                       st.fixed_dictionaries({"spend": _money, "team": st.text(max_size=8),
                                              "budget": _money}), max_size=20),
       _keys)
@SETTINGS
def test_merge_key_budgets_unions_and_dedupes(live, snap_keys):
    merged = appmod.merge_key_budgets(live or None, snap_keys, {})
    ids = [(k.get("alias") or k.get("key_alias") or k.get("key")) for k in merged]
    assert len(ids) == len(set(ids))              # every alias appears at most once
    for a in live:                                # every live key survives
        assert a in ids


@given(st.lists(st.fixed_dictionaries({
    "model": st.text(max_size=20),
    "tokens": st.integers(min_value=0, max_value=10**12),
    "cost_kind": st.sampled_from(["real", "reference", "unknown", ""])}), max_size=30))
@SETTINGS
def test_cost_model_split_only_buckets_real_and_reference(rows):
    split = appmod.cost_model_split(rows)
    assert set(split) == {"real", "reference"}
    assert len(split["real"]) + len(split["reference"]) <= len(rows)
