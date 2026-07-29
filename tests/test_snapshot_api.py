"""Golden / snapshot tests — freeze the SHAPE (key set) of the structures the dashboard
JS reads. The frontend indexes these fields by name; a silent rename or dropped field is
a contract break the browser can't compile-check. Update the golden set on purpose."""
import app as appmod
from collectors import litellm

# Every field web/spend.html + web/settings.html read off a budget row. Adding a field is
# fine (superset check); RENAMING or DROPPING one breaks the UI → must update this set.
BUDGET_ROW_KEYS = {
    "key", "role", "team", "spent", "reference", "total", "budget",
    "pct", "burn", "days_to_cap", "projected", "status",
    "email", "user",     # resolved owner — Spend "Per-key budgets" click-for-details
}


def test_budget_row_shape_is_stable():
    row = litellm.budget_rows([{"alias": "k1", "cost": 12.5}], {"k1": 100}, 15, 30)[0]
    missing = BUDGET_ROW_KEYS - set(row)
    assert not missing, f"budget row lost fields the UI depends on: {missing}"


def test_cost_model_split_shape_is_stable():
    split = appmod.cost_model_split([
        {"model": "gpt-4o", "tokens": 10, "cost_kind": "real"},
        {"model": "llama3", "tokens": 20, "cost_kind": "reference"},
    ])
    assert set(split) == {"real", "reference"}
    assert isinstance(split["real"], list) and isinstance(split["reference"], list)


def test_budget_rows_status_vocabulary_is_closed():
    # the CSS pill classes are keyed on exactly these status strings
    rows = litellm.budget_rows(
        [{"alias": "a", "cost": 0}, {"alias": "b", "cost": 200}], {"b": 100}, 15, 30)
    assert {r["status"] for r in rows} <= {"bad", "warn", "ok", "none"}
