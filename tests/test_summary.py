from datetime import datetime, timezone

import pytest

from baaz.summary import period_start

# 01:30 on 24 November in the UAE (GST, UTC+4) is still 23 November in UTC.
NOW = datetime(2026, 11, 23, 21, 30, tzinfo=timezone.utc)


@pytest.mark.parametrize("period, start", [
    ("today", datetime(2026, 11, 23, 20, 0, tzinfo=timezone.utc)),
    ("24h", datetime(2026, 11, 22, 21, 30, tzinfo=timezone.utc)),
    ("7d", datetime(2026, 11, 17, 20, 0, tzinfo=timezone.utc)),
    ("all", None),
])
def test_summary_periods_follow_uae_days(period, start):
    assert period_start(period, NOW) == start
