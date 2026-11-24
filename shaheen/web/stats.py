"""Read-only queries for the dashboard's statistics page and its Simple view:
one function per chart, each a few grouped counts over the scans, candidates
and investigations tables. The counts by verdict and hour read the
(verdict, scanned_at) index alone, so they stay cheap as the store grows."""

from __future__ import annotations

import sqlite3
import statistics
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

HOURS = 24
VERDICTS = ("fraud", "suspicious", "legitimate")
SOURCES = ("lookalikes", "storefronts", "newdomains", "ctlogs", "maps", "investigator", "manual")
INVESTIGATION_STATES = ("done", "running", "queued", "failed")
TOP_BRANDS = 10


@contextmanager
def connect(path: Path) -> Iterator[sqlite3.Connection]:
    db = sqlite3.connect(path, timeout=30)
    db.row_factory = sqlite3.Row
    try:
        yield db
    finally:
        db.close()


def _split(rows: list[sqlite3.Row], key: str) -> dict[str, dict[str, int]]:
    """Counts grouped by `key` and verdict, as {key: {verdict: n}}."""
    found: dict[str, dict[str, int]] = {}
    for row in rows:
        found.setdefault(row[key], {})[row["verdict"]] = row["n"]
    return found


def _flagged(name: str, counts: dict[str, int], **extra: Any) -> dict[str, Any]:
    fraud, suspicious = counts.get("fraud", 0), counts.get("suspicious", 0)
    return {"name": name, "fraud": fraud, "suspicious": suspicious, "flagged": fraud + suspicious, **extra}


def hourly(db: sqlite3.Connection, now: datetime) -> list[dict[str, Any]]:
    """Scans per hour by verdict over the 24 hours up to `now`, oldest first. Each
    bucket is a whole UTC hour (a whole GST hour too); the last is the hour under way."""
    last = now.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
    first = last - timedelta(hours=HOURS - 1)
    rows = db.execute(
        "SELECT substr(scanned_at, 1, 13) AS hour, verdict, COUNT(*) AS n FROM scans"
        " WHERE verdict IN ('fraud', 'suspicious', 'legitimate') AND scanned_at >= ? GROUP BY hour, verdict",
        (first.strftime("%Y-%m-%dT%H"),),
    ).fetchall()
    counts = _split(rows, "hour")
    buckets = []
    for i in range(HOURS):
        start = first + timedelta(hours=i)
        found = counts.get(start.strftime("%Y-%m-%dT%H"), {})
        buckets.append({"start": start, **{v: found.get(v, 0) for v in VERDICTS}})
    return buckets


def verdicts(db: sqlite3.Connection) -> dict[str, int]:
    """Every scan so far by verdict."""
    rows = db.execute("SELECT verdict, COUNT(*) AS n FROM scans GROUP BY verdict").fetchall()
    found = {r["verdict"]: r["n"] for r in rows}
    return {v: found.get(v, 0) for v in VERDICTS}


def brands(db: sqlite3.Connection) -> list[dict[str, Any]]:
    """The brands flagged scans impersonate most, with their fraud and suspicious counts."""
    rows = db.execute(
        "SELECT impersonated_brand AS brand, verdict, COUNT(*) AS n FROM scans"
        " WHERE verdict IN ('fraud', 'suspicious') AND impersonated_brand <> '' GROUP BY brand, verdict"
    ).fetchall()
    found = [_flagged(name, counts) for name, counts in _split(rows, "brand").items()]
    found.sort(key=lambda b: (-b["flagged"], -b["fraud"], b["name"]))
    return found[:TOP_BRANDS]


def sources(db: sqlite3.Connection) -> list[dict[str, Any]]:
    """Scans by the collector that queued them, with the flagged and fraud among them.
    A scan no collector queued is a link pasted by hand, or a saved capture."""
    queued = _split(db.execute(
        "SELECT c.source, s.verdict, COUNT(*) AS n FROM candidates c JOIN scans s ON s.id = c.scan_id"
        " GROUP BY c.source, s.verdict"
    ).fetchall(), "source")
    direct = db.execute(
        "SELECT CASE WHEN json_extract(result_json, '$.signals.captured_from') IS NULL"
        " THEN 'manual' ELSE 'capture' END AS source, verdict, COUNT(*) AS n FROM scans"
        " WHERE id NOT IN (SELECT scan_id FROM candidates WHERE scan_id IS NOT NULL) GROUP BY source, verdict"
    ).fetchall()
    for source, counts in _split(direct, "source").items():
        queued[source] = counts
    names = [*SOURCES, *sorted(set(queued) - set(SOURCES))]
    found = [_flagged(name, queued.get(name, {}), scanned=sum(queued.get(name, {}).values())) for name in names]
    found.sort(key=lambda s: (-s["flagged"], -s["scanned"]))
    return found


def fraud_types(db: sqlite3.Connection) -> list[dict[str, Any]]:
    """Flagged scans by fraud type."""
    rows = db.execute(
        "SELECT fraud_type, verdict, COUNT(*) AS n FROM scans"
        " WHERE verdict IN ('fraud', 'suspicious') AND fraud_type <> '' GROUP BY fraud_type, verdict"
    ).fetchall()
    found = [_flagged(name, counts) for name, counts in _split(rows, "fraud_type").items()]
    found.sort(key=lambda f: (-f["flagged"], f["name"]))
    return found


def investigations(db: sqlite3.Connection, alive: bool) -> dict[str, Any]:
    """Investigations by status, and the median minutes and tool calls of the finished
    runs that kept a run record. A run counts as running only while the investigator
    is alive: a stopped one leaves its last cases marked running until it restarts."""
    rows = db.execute("SELECT status, COUNT(*) AS n FROM investigations GROUP BY status").fetchall()
    counts = {r["status"]: r["n"] for r in rows}
    if not alive:
        counts["queued"] = counts.get("queued", 0) + counts.pop("running", 0)
    runs = db.execute(
        "SELECT json_extract(report_json, '$.run.wall_s') AS wall_s,"
        " COALESCE(json_array_length(report_json, '$.run.pi.tool_calls'), 0) AS calls"
        " FROM investigations WHERE status = 'done' AND json_extract(report_json, '$.run.wall_s') IS NOT NULL"
    ).fetchall()
    return {
        "counts": {s: counts.get(s, 0) for s in INVESTIGATION_STATES},
        "runs": len(runs),
        "minutes": round(statistics.median(r["wall_s"] for r in runs) / 60, 1) if runs else None,
        "calls": round(statistics.median(r["calls"] for r in runs)) if runs else None,
    }


def summaries(db: sqlite3.Connection, scan_ids: list[str]) -> dict[str, tuple[str, str]]:
    """The English and Arabic summaries of these cases' finished investigations, for those that have both."""
    if not scan_ids:
        return {}
    rows = db.execute(
        "SELECT scan_id, json_extract(report_json, '$.summary_en') AS en,"
        " json_extract(report_json, '$.summary_ar') AS ar"
        f" FROM investigations WHERE status = 'done' AND scan_id IN ({','.join('?' * len(scan_ids))})",
        scan_ids,
    ).fetchall()
    return {r["scan_id"]: (str(r["en"]), str(r["ar"])) for r in rows if r["en"] and r["ar"]}
