import sqlite3
from datetime import datetime, timezone

import pytest

from shaheen.store import Store
from shaheen.web import charts, stats


def test_scans_per_hour_fall_in_whole_hours_of_the_last_day(tmp_path):
    path = tmp_path / "shaheen.db"
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


def test_headline_counts_windows_and_operator_links(tmp_path):
    path = tmp_path / "shaheen.db"
    Store(path)
    db = sqlite3.connect(path)
    db.executemany("INSERT INTO scans (id, url, domain, verdict, risk_score, impersonated_brand, analyst_confirmed,"
                   " scanned_at, result_json) VALUES (?, '', ?, ?, 0, ?, ?, ?, '{}')", [
                       ("a", "a.test", "fraud", "Bose", 1, "2026-11-24T11:30:00Z"),  # the last hour
                       ("b", "b.test", "fraud", "JBL", 0, "2026-11-24T01:00:00Z"),  # the last day
                       ("c", "c.test", "suspicious", "Bose", 0, "2026-11-22T09:00:00Z"),  # older
                       ("d", "a.test", "legitimate", "", 0, "2026-11-22T08:00:00Z"),
                   ])
    db.executemany("INSERT INTO fingerprints (scan_id, domain, kind, value) VALUES (?, ?, ?, ?)", [
        ("a", "a.test", "gateway", "sankee"), ("b", "b.test", "gateway", "sankee"),  # a private skimmer gateway
        ("a", "a.test", "gateway", "stripe"), ("c", "c.test", "gateway", "stripe"),  # a public one links no one
        ("b", "b.test", "admin", "h1"), ("c", "c.test", "admin", "h1"),
    ])
    db.execute("INSERT INTO candidates (url, domain, source, added_at) VALUES ('https://a.test/', 'a.test', 'manual', '')")
    db.commit()
    db.close()

    with stats.connect(path) as db:
        h = stats.headline(db, datetime(2026, 11, 24, 12, tzinfo=timezone.utc), ["sankee"])

    assert (h["checked"], h["domains"], h["fraud"], h["suspicious"], h["legitimate"]) == (4, 3, 2, 1, 1)
    assert (h["last_hour"], h["last_day"], h["fraud_day"], h["brands"], h["confirmed"]) == (1, 2, 2, 2, 1)
    assert (h["links"], h["linked_domains"], h["candidates"], h["maps_leads"]) == (2, 3, 1, 0)
