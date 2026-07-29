"""Time-frozen tests (freezegun) — date logic that depends on 'now' must be deterministic,
not "works on the day you ran it". _norm_date infers the year for LiteLLM's year-less
display dates (`Jul 02`) from the current date, so it is clock-dependent."""
from freezegun import freeze_time

from collectors import litellm


@freeze_time("2026-08-15")
def test_display_date_year_is_current_when_month_already_passed():
    # today = Aug 2026; July has passed this year → "Jul 02" belongs to 2026
    assert litellm._norm_date("Jul 02") == "2026-07-02"
    assert litellm._norm_date("July 2") == "2026-07-02"


@freeze_time("2026-03-15")
def test_display_date_year_rolls_back_when_month_is_still_future():
    # today = Mar 2026; July 2026 is in the FUTURE → most-recent-past July = 2025
    assert litellm._norm_date("Jul 02") == "2025-07-02"


@freeze_time("2026-07-11")
def test_explicit_year_dates_ignore_the_clock():
    assert litellm._norm_date("2024-07-02") == "2024-07-02"
    assert litellm._norm_date("2024/07/02") == "2024-07-02"
    assert litellm._norm_date("2024-07-02T00:00:00Z") == "2024-07-02"
