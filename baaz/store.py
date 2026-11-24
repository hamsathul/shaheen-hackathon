"""SQLite storage: scan results, the candidate queue, investigations,
fingerprints for linking cases, and an intel cache."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from baaz.models import ScanResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    final_url TEXT,
    domain TEXT NOT NULL,
    verdict TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    fraud_type TEXT,
    impersonated_brand TEXT,
    cluster_id TEXT,
    analyst_confirmed INTEGER NOT NULL DEFAULT 0,
    scanned_at TEXT NOT NULL,
    result_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_domain ON scans(domain);
CREATE INDEX IF NOT EXISTS scans_verdict ON scans(verdict, scanned_at);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    domain TEXT NOT NULL,
    source TEXT NOT NULL,
    note TEXT,
    status TEXT NOT NULL DEFAULT 'queued',
    added_at TEXT NOT NULL,
    scanned_at TEXT,
    scan_id TEXT
);
CREATE INDEX IF NOT EXISTS candidates_status ON candidates(status, id);

CREATE TABLE IF NOT EXISTS investigations (
    scan_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    mode TEXT,
    queued_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    report_json TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS fingerprints (
    scan_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (scan_id, kind, value)
);
CREATE INDEX IF NOT EXISTS fingerprints_value ON fingerprints(kind, value);

CREATE TABLE IF NOT EXISTS intel_cache (
    domain TEXT NOT NULL,
    kind TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    data_json TEXT NOT NULL,
    PRIMARY KEY (domain, kind)
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        try:
            yield db
            db.commit()
        finally:
            db.close()

    # scans

    def save_scan(self, result: ScanResult, domain: str) -> None:
        with self._conn() as db:
            db.execute(
                "INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    result.id, result.url, result.final_url, domain, result.verdict,
                    result.risk_score, result.fraud_type, result.impersonated_brand,
                    result.cluster_id, int(result.analyst_confirmed), result.scanned_at,
                    json.dumps(result.to_dict(), ensure_ascii=False),
                ),
            )

    def get_scan(self, scan_id: str) -> ScanResult | None:
        with self._conn() as db:
            row = db.execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return ScanResult.from_dict(json.loads(row["result_json"])) if row else None

    def list_scans(self, verdicts: tuple[str, ...] = (), limit: int = 100) -> list[ScanResult]:
        sql = "SELECT result_json FROM scans"
        args: list[Any] = []
        if verdicts:
            sql += f" WHERE verdict IN ({','.join('?' * len(verdicts))})"
            args.extend(verdicts)
        sql += " ORDER BY scanned_at DESC, rowid DESC LIMIT ?"
        args.append(limit)
        with self._conn() as db:
            rows = db.execute(sql, args).fetchall()
        return [ScanResult.from_dict(json.loads(r["result_json"])) for r in rows]

    def latest_scan_for(self, domain: str) -> ScanResult | None:
        with self._conn() as db:
            row = db.execute(
                "SELECT result_json FROM scans WHERE domain = ? ORDER BY scanned_at DESC LIMIT 1",
                (domain,),
            ).fetchone()
        return ScanResult.from_dict(json.loads(row["result_json"])) if row else None

    def set_confirmed(self, scan_id: str) -> ScanResult | None:
        result = self.get_scan(scan_id)
        if result is None:
            return None
        result.analyst_confirmed = True
        with self._conn() as db:
            db.execute(
                "UPDATE scans SET analyst_confirmed = 1, result_json = ? WHERE id = ?",
                (json.dumps(result.to_dict(), ensure_ascii=False), scan_id),
            )
        return result

    def update_scan(self, result: ScanResult) -> None:
        with self._conn() as db:
            db.execute(
                "UPDATE scans SET verdict = ?, risk_score = ?, cluster_id = ?, result_json = ? WHERE id = ?",
                (result.verdict, result.risk_score, result.cluster_id,
                 json.dumps(result.to_dict(), ensure_ascii=False), result.id),
            )

    # candidate queue

    def enqueue(self, url: str, domain: str, source: str, note: str = "") -> bool:
        """Queue a URL once; returns False when it was already queued or scanned."""
        with self._conn() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO candidates (url, domain, source, note, added_at) VALUES (?,?,?,?,?)",
                (url, domain, source, note, utcnow()),
            )
        return cur.rowcount == 1

    def claim_candidate(self) -> sqlite3.Row | None:
        with self._conn() as db:
            row = db.execute(
                "SELECT * FROM candidates WHERE status = 'queued' ORDER BY id LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            db.execute("UPDATE candidates SET status = 'scanning' WHERE id = ?", (row["id"],))
        return row

    def finish_candidate(self, candidate_id: int, status: str, scan_id: str | None = None) -> None:
        with self._conn() as db:
            db.execute(
                "UPDATE candidates SET status = ?, scan_id = ?, scanned_at = ? WHERE id = ?",
                (status, scan_id, utcnow(), candidate_id),
            )

    def requeue_stale(self) -> int:
        """Return candidates left 'scanning' by a crashed run to the queue."""
        with self._conn() as db:
            cur = db.execute("UPDATE candidates SET status = 'queued' WHERE status = 'scanning'")
        return cur.rowcount

    def scan_sources(self, scan_ids: list[str]) -> dict[str, str]:
        """The collector that queued each of these scans, for those that came through the queue."""
        if not scan_ids:
            return {}
        with self._conn() as db:
            rows = db.execute(
                f"SELECT scan_id, source FROM candidates WHERE scan_id IN ({','.join('?' * len(scan_ids))})",
                scan_ids,
            ).fetchall()
        return {r["scan_id"]: r["source"] for r in rows}

    def domain_seen_since(self, domain: str, hours: float) -> bool:
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
        with self._conn() as db:
            row = db.execute(
                "SELECT 1 FROM candidates WHERE domain = ? AND added_at >= ? LIMIT 1", (domain, since)
            ).fetchone()
        return row is not None

    def first_seen(self, domain: str) -> str | None:
        """When Baaz first met `domain`: as a queued candidate or a scan's landing domain."""
        with self._conn() as db:
            row = db.execute(
                "SELECT MIN(seen) FROM (SELECT MIN(added_at) AS seen FROM candidates WHERE domain = ?"
                " UNION ALL SELECT MIN(scanned_at) FROM scans WHERE domain = ?)",
                (domain, domain),
            ).fetchone()
        return row[0]

    # fingerprints (raw values stay in this local database only)

    def add_fingerprints(self, scan_id: str, domain: str, items: list[tuple[str, str]]) -> None:
        with self._conn() as db:
            db.executemany(
                "INSERT OR IGNORE INTO fingerprints VALUES (?,?,?,?)",
                [(scan_id, domain, kind, value) for kind, value in items if value],
            )

    def fingerprints_of(self, scan_id: str) -> list[tuple[str, str]]:
        with self._conn() as db:
            rows = db.execute(
                "SELECT kind, value FROM fingerprints WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        return [(r["kind"], r["value"]) for r in rows]

    def domains_sharing(self, kind: str, value: str, exclude_domain: str = "") -> list[str]:
        with self._conn() as db:
            rows = db.execute(
                "SELECT DISTINCT domain FROM fingerprints WHERE kind = ? AND value = ? AND domain != ?",
                (kind, value, exclude_domain),
            ).fetchall()
        return [r["domain"] for r in rows]

    # intel cache

    def cache_get(self, domain: str, kind: str, max_age_hours: float = 24) -> Any | None:
        with self._conn() as db:
            row = db.execute(
                "SELECT fetched_at, data_json FROM intel_cache WHERE domain = ? AND kind = ?",
                (domain, kind),
            ).fetchone()
        if row is None:
            return None
        age = datetime.now(timezone.utc) - datetime.fromisoformat(row["fetched_at"])
        return json.loads(row["data_json"]) if age <= timedelta(hours=max_age_hours) else None

    def cache_put(self, domain: str, kind: str, data: Any) -> None:
        with self._conn() as db:
            db.execute(
                "INSERT OR REPLACE INTO intel_cache VALUES (?,?,?,?)",
                (domain, kind, utcnow(), json.dumps(data, ensure_ascii=False, default=str)),
            )

    # investigations

    def queue_investigation(self, scan_id: str) -> bool:
        with self._conn() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO investigations (scan_id, status, queued_at) VALUES (?, 'queued', ?)",
                (scan_id, utcnow()),
            )
        return cur.rowcount == 1

    def domain_investigated(self, domain: str) -> bool:
        """Whether a case on this domain is already queued, under way or investigated."""
        with self._conn() as db:
            row = db.execute(
                "SELECT 1 FROM investigations i JOIN scans s ON s.id = i.scan_id WHERE s.domain = ? LIMIT 1",
                (domain,),
            ).fetchone()
        return row is not None

    def next_investigation(self) -> str | None:
        """Fraud before suspicious, oldest first."""
        with self._conn() as db:
            row = db.execute(
                """SELECT i.scan_id FROM investigations i JOIN scans s ON s.id = i.scan_id
                   WHERE i.status = 'queued'
                   ORDER BY CASE s.verdict WHEN 'fraud' THEN 0 ELSE 1 END, i.queued_at LIMIT 1"""
            ).fetchone()
        return row["scan_id"] if row else None

    def set_investigation(self, scan_id: str, status: str, **fields: Any) -> None:
        cols = {"status": status, **fields}
        if status == "running":
            cols.setdefault("started_at", utcnow())
        if status in ("done", "failed"):
            cols.setdefault("finished_at", utcnow())
        if "report_json" in cols and not isinstance(cols["report_json"], str):
            cols["report_json"] = json.dumps(cols["report_json"], ensure_ascii=False)
        sets = ", ".join(f"{k} = ?" for k in cols)
        with self._conn() as db:
            db.execute(
                "INSERT OR IGNORE INTO investigations (scan_id, status, queued_at) VALUES (?, ?, ?)",
                (scan_id, status, utcnow()),
            )
            db.execute(f"UPDATE investigations SET {sets} WHERE scan_id = ?", [*cols.values(), scan_id])

    def get_investigation(self, scan_id: str) -> dict[str, Any] | None:
        with self._conn() as db:
            row = db.execute("SELECT * FROM investigations WHERE scan_id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["report"] = json.loads(data.pop("report_json")) if data.get("report_json") else None
        return data

    # counters and metadata

    def counters(self) -> dict[str, int]:
        with self._conn() as db:
            one = lambda sql: db.execute(sql).fetchone()[0]  # noqa: E731
            return {
                "candidates_seen": one("SELECT COUNT(*) FROM candidates"),
                "queued": one("SELECT COUNT(*) FROM candidates WHERE status = 'queued'"),
                "scanned": one("SELECT COUNT(*) FROM scans"),
                "flagged": one("SELECT COUNT(*) FROM scans WHERE verdict IN ('fraud','suspicious')"),
                "fraud": one("SELECT COUNT(*) FROM scans WHERE verdict = 'fraud'"),
                "investigated": one("SELECT COUNT(*) FROM investigations WHERE status = 'done'"),
                "confirmed": one("SELECT COUNT(*) FROM scans WHERE analyst_confirmed = 1"),
            }

    def get_meta(self, key: str) -> str | None:
        with self._conn() as db:
            row = db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._conn() as db:
            db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, value))
