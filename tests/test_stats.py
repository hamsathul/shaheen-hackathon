import sqlite3
from datetime import datetime, timezone

import pytest

from baaz.store import Store
from baaz.web import charts, stats


def test_scans_per_hour_fall_in_whole_hours_of_the_last_day(tmp_path):
    path = tmp_path / "baaz.db"
    Store(path)
    scans = [
        ("a", "fraud", "2026-11-23T11:59:59Z"),  # before the window
        ("b", "fraud", "2026-11-23T12:00:00Z"),  # first second of the first hour
        ("c", "suspicious", "2026-11-23T12:59:59+00:00"),
        ("d", "legitimate", "2026-11-24T11:00:00Z"),  # the hour under way
        ("e", "legitimate", "2026-11-24T11:30:00Z"),
    ]
    db = sqlite3.connect(path)
    db.executemany("INSERT INTO scans (id, url, domain, verdict, risk_score, scanned_at, result_json)"
                   " VALUES (?, '', '', ?, 0, ?, '{}')", scans)
    db.commit()
    db.close()

    now = datetime(2026, 11, 24, 11, 40, tzinfo=timezone.utc)
    with stats.connect(path) as db:
        hours = stats.hourly(db, now)

    assert len(hours) == 24
    assert hours[0]["start"] == datetime(2026, 11, 23, 12, tzinfo=timezone.utc)
    assert (hours[0]["fraud"], hours[0]["suspicious"], hours[0]["legitimate"]) == (1, 1, 0)
    assert hours[-1]["legitimate"] == 2
    assert sum(h[v] for h in hours for v in stats.VERDICTS) == 4
    columns = charts.columns(hours, rtl=False)
    assert columns["cols"][0]["hour"] == "16:00"  # 12:00 UTC is 16:00 GST
    assert charts.columns(hours, rtl=True)["cols"][0]["centre"] == pytest.approx(100 - columns["cols"][0]["centre"])
