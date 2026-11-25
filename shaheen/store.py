"""SQLite storage: scan results, the candidate queue, investigations, the
contacts read from flagged pages, AI hunts with the domains each one found,
fingerprints for linking cases, an intel cache, and the Google Maps listings
seen with the leads among them."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from shaheen.models import ScanResult

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
CREATE INDEX IF NOT EXISTS scans_time ON scans(scanned_at);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    domain TEXT NOT NULL,
    source TEXT NOT NULL,
    note TEXT,
    status TEXT NOT NULL DEFAULT 'queued',
    added_at TEXT NOT NULL,
    scanned_at TEXT,
    scan_id TEXT,
    priority INTEGER NOT NULL DEFAULT 0
);

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

CREATE TABLE IF NOT EXISTS contact_reads (
    scan_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    queued_at TEXT NOT NULL,
    finished_at TEXT,
    result_json TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS hunts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mission TEXT NOT NULL,
    theme TEXT,
    status TEXT NOT NULL,
    queued_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    report_json TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS hunt_finds (
    hunt_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    reason TEXT NOT NULL,
    scan_id TEXT,
    found_at TEXT NOT NULL,
    PRIMARY KEY (hunt_id, url)
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

CREATE TABLE IF NOT EXISTS maps_places (
    place_id TEXT PRIMARY KEY,
    seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS maps_leads (
    place_id TEXT PRIMARY KEY,
    found_at TEXT NOT NULL,
    query TEXT NOT NULL,
    brand TEXT NOT NULL,
    reasons TEXT NOT NULL,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    phone TEXT NOT NULL,
    official_phones TEXT NOT NULL,
    website TEXT NOT NULL,
    maps_url TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS maps_leads_website ON maps_leads(website);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


# The order the AI workers take queued cases in: fraud before suspicious, oldest first.
NEXT_CASE = "ORDER BY CASE s.verdict WHEN 'fraud' THEN 0 ELSE 1 END, i.queued_at"

# How long after its last check a URL may be queued again, by the verdict of
# that check (None: the check failed). Fraud and analyst-confirmed cases are
# never re-queued.
RECHECK_AFTER: dict[str | None, timedelta] = {
    "suspicious": timedelta(days=1), "legitimate": timedelta(days=7), None: timedelta(days=1),
}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as db:
            db.executescript(SCHEMA)
            self._migrate(db)

    @staticmethod
    def _migrate(db: sqlite3.Connection) -> None:
        """Bring a store made by an earlier version up to this schema: candidates gained
        a priority, and the watcher claims them by status, priority and age."""
        if "priority" not in {row["name"] for row in db.execute("PRAGMA table_info(candidates)")}:
            db.execute("ALTER TABLE candidates ADD COLUMN priority INTEGER NOT NULL DEFAULT 0")
        db.execute("DROP INDEX IF EXISTS candidates_status")
        db.execute("CREATE INDEX IF NOT EXISTS candidates_claim ON candidates(status, priority, id)")

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

    def enqueue(self, url: str, domain: str, source: str, note: str = "", priority: int = 0) -> bool:
        """Queue a URL, to be scanned after every queued URL of a lower `priority`
        (`focus.priority`); returns False when it is already queued, or was checked
        too recently to check again (`RECHECK_AFTER`), or was found fraud or confirmed."""
        now = datetime.now(timezone.utc)
        with self._conn() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO candidates (url, domain, source, note, added_at, priority) VALUES (?,?,?,?,?,?)",
                (url, domain, source, note, now.isoformat(timespec="seconds"), priority),
            )
            if cur.rowcount == 1:
                return True
            row = db.execute(
                """SELECT c.id, c.status, c.scanned_at, s.verdict, s.analyst_confirmed
                   FROM candidates c LEFT JOIN scans s ON s.id = c.scan_id WHERE c.url = ?""",
                (url,),
            ).fetchone()
            if (row["status"] not in ("done", "error") or row["analyst_confirmed"] or row["verdict"] == "fraud"
                    or not row["scanned_at"]
                    or now - datetime.fromisoformat(row["scanned_at"]) < RECHECK_AFTER[row["verdict"]]):
                return False
            db.execute(
                "UPDATE candidates SET status = 'queued', source = ?, note = ?, added_at = ?, priority = ?"
                " WHERE id = ?",
                (source, note, now.isoformat(timespec="seconds"), priority, row["id"]),
            )
        return True

    def claim_candidate(self) -> sqlite3.Row | None:
        with self._conn() as db:
            row = db.execute(
                "SELECT * FROM candidates WHERE status = 'queued' ORDER BY priority, id LIMIT 1"
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

    def queued_candidates(self) -> list[sqlite3.Row]:
        with self._conn() as db:
            return db.execute("SELECT id, url, source, priority FROM candidates WHERE status = 'queued'").fetchall()

    def set_priorities(self, priorities: dict[int, int]) -> None:
        """Change the priority of these candidates (by id) that are still queued."""
        with self._conn() as db:
            db.executemany("UPDATE candidates SET priority = ? WHERE id = ? AND status = 'queued'",
                           [(p, i) for i, p in priorities.items()])

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
        """When Shaheen first met `domain`: as a queued candidate or a scan's landing domain."""
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

    def queue_investigation(self, scan_id: str, parked: bool = False) -> bool:
        """Queue a case for the investigator, or park it (outside the UAE focus) until
        an analyst sends it on from the case page."""
        with self._conn() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO investigations (scan_id, status, queued_at) VALUES (?, ?, ?)",
                (scan_id, "parked" if parked else "queued", utcnow()),
            )
        return cur.rowcount == 1

    def waiting_investigations(self) -> dict[str, str]:
        """The status, queued or parked, of each investigation not started yet."""
        with self._conn() as db:
            rows = db.execute(
                "SELECT scan_id, status FROM investigations WHERE status IN ('queued', 'parked')").fetchall()
        return {r["scan_id"]: r["status"] for r in rows}

    def move_investigations(self, states: dict[str, str]) -> None:
        """Queue or park these investigations (scan id to status) that are still waiting."""
        with self._conn() as db:
            db.executemany(
                "UPDATE investigations SET status = ? WHERE scan_id = ? AND status IN ('queued', 'parked')",
                [(s, i) for i, s in states.items()])

    def needs_investigation(self, domain: str, verdict: str) -> bool:
        """Whether a new case on this domain should be investigated: when no case on
        it was, or when this one is fraud and every earlier investigation of the
        domain is finished or parked and was of a case that was not fraud."""
        with self._conn() as db:
            rows = db.execute(
                "SELECT i.status, s.verdict FROM investigations i JOIN scans s ON s.id = i.scan_id WHERE s.domain = ?",
                (domain,),
            ).fetchall()
        return not rows or (verdict == "fraud" and all(
            r["status"] in ("done", "failed", "parked") and r["verdict"] != "fraud" for r in rows))

    def claim_investigation(self) -> str | None:
        """Take the next queued case, fraud before suspicious, oldest first, and mark
        it running. One UPDATE takes the write lock for the pick and the change, so
        parallel investigators never take the same case."""
        with self._conn() as db:
            rows = db.execute(
                f"""UPDATE investigations SET status = 'running', started_at = ?, finished_at = NULL, error = NULL
                    WHERE scan_id = (SELECT i.scan_id FROM investigations i JOIN scans s ON s.id = i.scan_id
                                     WHERE i.status = 'queued' {NEXT_CASE} LIMIT 1)
                    RETURNING scan_id""",
                (utcnow(),),
            ).fetchall()
        return rows[0]["scan_id"] if rows else None

    def requeue_running_investigations(self) -> int:
        """Return investigations left 'running' by a stopped or crashed run to the queue."""
        with self._conn() as db:
            cur = db.execute("UPDATE investigations SET status = 'queued' WHERE status = 'running'")
        return cur.rowcount

    def requeue_failed_investigations(self, error_prefixes: tuple[str, ...]) -> int:
        """Return failed investigations whose error starts with one of these prefixes to the queue."""
        matches = " OR ".join("substr(error, 1, ?) = ?" for _ in error_prefixes)
        args = [x for prefix in error_prefixes for x in (len(prefix), prefix)]
        with self._conn() as db:
            cur = db.execute(
                f"UPDATE investigations SET status = 'queued', error = NULL WHERE status = 'failed' AND ({matches})",
                args,
            )
        return cur.rowcount

    def running_investigations(self) -> list[dict[str, Any]]:
        """The investigations under way, oldest first, with their case's address, verdict and score."""
        with self._conn() as db:
            rows = db.execute(
                """SELECT i.scan_id, i.mode, i.started_at, s.url, s.final_url, s.verdict, s.risk_score
                   FROM investigations i JOIN scans s ON s.id = i.scan_id
                   WHERE i.status = 'running' ORDER BY i.started_at, i.scan_id"""
            ).fetchall()
        return [dict(r) for r in rows]

    def investigation_queue(self) -> dict[str, int]:
        """Queued investigations by verdict."""
        with self._conn() as db:
            rows = db.execute(
                """SELECT s.verdict, COUNT(*) AS n FROM investigations i JOIN scans s ON s.id = i.scan_id
                   WHERE i.status = 'queued' GROUP BY s.verdict"""
            ).fetchall()
        return {r["verdict"]: r["n"] for r in rows}

    def next_investigations(self, limit: int) -> list[dict[str, Any]]:
        """The queued cases the AI workers take next, in the order they take them."""
        with self._conn() as db:
            rows = db.execute(
                f"""SELECT i.scan_id, i.queued_at, s.url, s.final_url, s.verdict, s.risk_score, s.impersonated_brand
                    FROM investigations i JOIN scans s ON s.id = i.scan_id
                    WHERE i.status = 'queued' {NEXT_CASE} LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def finished_investigations(self, limit: int) -> list[dict[str, Any]]:
        """The latest finished investigations, newest first, with their report."""
        with self._conn() as db:
            rows = db.execute(
                """SELECT i.scan_id, i.finished_at, i.report_json, s.url, s.final_url, s.verdict, s.risk_score,
                          s.fraud_type
                   FROM investigations i JOIN scans s ON s.id = i.scan_id
                   WHERE i.status = 'done' ORDER BY i.finished_at DESC, i.rowid DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        found = []
        for row in rows:
            data = dict(row)
            data["report"] = json.loads(data.pop("report_json")) if data.get("report_json") else {}
            found.append(data)
        return found

    def investigation_states(self, scan_ids: list[str]) -> dict[str, str]:
        """The investigation status of each of these cases that has one."""
        if not scan_ids:
            return {}
        with self._conn() as db:
            rows = db.execute(
                f"SELECT scan_id, status FROM investigations WHERE scan_id IN ({','.join('?' * len(scan_ids))})",
                scan_ids,
            ).fetchall()
        return {r["scan_id"]: r["status"] for r in rows}

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

    # contacts read from flagged pages (shaheen.contacts)

    def queue_contacts(self, scan_id: str) -> bool:
        with self._conn() as db:
            cur = db.execute("INSERT OR IGNORE INTO contact_reads (scan_id, status, queued_at) VALUES (?, 'queued', ?)",
                             (scan_id, utcnow()))
        return cur.rowcount == 1

    def queue_missing_contacts(self) -> int:
        """Queue a contacts read for every case sent to the investigator (queued, running
        or done) that has none yet."""
        with self._conn() as db:
            cur = db.execute(
                """INSERT OR IGNORE INTO contact_reads (scan_id, status, queued_at)
                   SELECT scan_id, 'queued', ? FROM investigations WHERE status IN ('queued', 'running', 'done')""",
                (utcnow(),))
        return cur.rowcount

    def claim_contacts(self) -> str | None:
        """Take the oldest queued contacts read, fraud first, and mark it running."""
        with self._conn() as db:
            rows = db.execute(
                """UPDATE contact_reads SET status = 'running'
                   WHERE scan_id = (SELECT c.scan_id FROM contact_reads c JOIN scans s ON s.id = c.scan_id
                                    WHERE c.status = 'queued'
                                    ORDER BY CASE s.verdict WHEN 'fraud' THEN 0 ELSE 1 END, c.queued_at LIMIT 1)
                   RETURNING scan_id""").fetchall()
        return rows[0]["scan_id"] if rows else None

    def set_contacts(self, scan_id: str, status: str, result_json: Any = None, error: str | None = None) -> None:
        with self._conn() as db:
            db.execute(
                "UPDATE contact_reads SET status = ?, finished_at = ?, result_json = ?, error = ? WHERE scan_id = ?",
                (status, utcnow() if status != "queued" else None,
                 json.dumps(result_json, ensure_ascii=False) if result_json is not None else None, error, scan_id))

    def get_contacts(self, scan_id: str) -> dict[str, Any] | None:
        with self._conn() as db:
            row = db.execute("SELECT * FROM contact_reads WHERE scan_id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["result"] = json.loads(data.pop("result_json")) if data.get("result_json") else None
        return data

    def contacts_activity(self) -> tuple[int, list[dict[str, Any]]]:
        """How many contacts reads are queued, and the ones being read with their case."""
        with self._conn() as db:
            waiting = db.execute("SELECT COUNT(*) FROM contact_reads WHERE status = 'queued'").fetchone()[0]
            reading = db.execute(
                """SELECT c.scan_id, s.url, s.final_url, s.verdict, s.risk_score
                   FROM contact_reads c JOIN scans s ON s.id = c.scan_id WHERE c.status = 'running'""").fetchall()
        return waiting, [dict(r) for r in reading]

    def recent_contacts(self, limit: int) -> list[dict[str, Any]]:
        """The latest finished contacts reads, newest first, with their case and result."""
        with self._conn() as db:
            rows = db.execute(
                """SELECT c.scan_id, c.status, c.finished_at, c.result_json, s.url, s.final_url, s.verdict, s.risk_score
                   FROM contact_reads c JOIN scans s ON s.id = c.scan_id
                   WHERE c.status IN ('done', 'skipped', 'failed') ORDER BY c.finished_at DESC, c.rowid DESC LIMIT ?""",
                (limit,)).fetchall()
        found = []
        for row in rows:
            data = dict(row)
            data["result"] = json.loads(data.pop("result_json")) if data.get("result_json") else {}
            found.append(data)
        return found

    def requeue_running_contacts(self) -> int:
        """Return contacts reads left 'running' by a stopped run to the queue."""
        with self._conn() as db:
            cur = db.execute("UPDATE contact_reads SET status = 'queued' WHERE status = 'running'")
        return cur.rowcount

    # AI hunts

    def add_hunt(self, mission: str, theme: str | None, status: str = "queued") -> int:
        """Store a hunt: queued for the workers, or 'running' for one run in the foreground."""
        with self._conn() as db:
            cur = db.execute("INSERT INTO hunts (mission, theme, status, queued_at) VALUES (?, ?, ?, ?)",
                             (mission, theme, status, utcnow()))
        return int(cur.lastrowid)

    def claim_hunt(self) -> int | None:
        """Take the oldest queued hunt and mark it running, in one UPDATE (as `claim_investigation`)."""
        with self._conn() as db:
            rows = db.execute(
                """UPDATE hunts SET status = 'running', started_at = ?, finished_at = NULL, error = NULL
                   WHERE id = (SELECT id FROM hunts WHERE status = 'queued' ORDER BY id LIMIT 1)
                   RETURNING id""",
                (utcnow(),),
            ).fetchall()
        return rows[0]["id"] if rows else None

    def set_hunt(self, hunt_id: int, **fields: Any) -> None:
        if fields.get("status") in ("done", "failed"):
            fields.setdefault("finished_at", utcnow())
        if fields.get("report_json") is not None and not isinstance(fields["report_json"], str):
            fields["report_json"] = json.dumps(fields["report_json"], ensure_ascii=False)
        sets = ", ".join(f"{k} = ?" for k in fields)
        with self._conn() as db:
            db.execute(f"UPDATE hunts SET {sets} WHERE id = ?", [*fields.values(), hunt_id])

    def get_hunt(self, hunt_id: int) -> dict[str, Any] | None:
        with self._conn() as db:
            row = db.execute("SELECT * FROM hunts WHERE id = ?", (hunt_id,)).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["report"] = json.loads(data.pop("report_json")) if data.get("report_json") else None
        return data

    def list_hunts(self, limit: int = 50) -> list[dict[str, Any]]:
        """The latest hunts, newest first, with how many domains each one found."""
        with self._conn() as db:
            rows = db.execute(
                """SELECT h.id, h.mission, h.theme, h.status, h.queued_at, h.finished_at,
                          (SELECT COUNT(*) FROM hunt_finds f WHERE f.hunt_id = h.id) AS finds
                   FROM hunts h ORDER BY h.id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def hunts_with_status(self, status: str) -> list[dict[str, Any]]:
        """The hunts in one state, oldest first (the order the workers take queued
        ones), with how many domains each one has found so far."""
        with self._conn() as db:
            rows = db.execute(
                """SELECT h.id, h.mission, h.theme, h.queued_at, h.started_at, h.finished_at,
                          (SELECT COUNT(*) FROM hunt_finds f WHERE f.hunt_id = h.id) AS finds
                   FROM hunts h WHERE h.status = ? ORDER BY h.id""",
                (status,),
            ).fetchall()
        return [dict(r) for r in rows]

    def requeue_running_hunts(self) -> int:
        """Return hunts left 'running' by a stopped or crashed run to the queue."""
        with self._conn() as db:
            cur = db.execute("UPDATE hunts SET status = 'queued' WHERE status = 'running'")
        return cur.rowcount

    def add_hunt_find(self, hunt_id: int, url: str, domain: str, reason: str, scan_id: str | None = None) -> None:
        with self._conn() as db:
            db.execute(
                """INSERT INTO hunt_finds (hunt_id, url, domain, reason, scan_id, found_at) VALUES (?,?,?,?,?,?)
                   ON CONFLICT (hunt_id, url) DO UPDATE SET scan_id = COALESCE(excluded.scan_id, scan_id)""",
                (hunt_id, url, domain, reason, scan_id, utcnow()),
            )

    def hunt_finds(self, hunt_id: int) -> list[dict[str, Any]]:
        """The domains a hunt found, in the order found, each with its latest check:
        the hunter's own scan, else the watcher's scan of the queued URL."""
        with self._conn() as db:
            rows = db.execute(
                """SELECT f.url, f.domain, f.reason, f.found_at, c.status AS queue_status,
                          s.id AS scan_id, s.verdict, s.risk_score
                   FROM hunt_finds f LEFT JOIN candidates c ON c.url = f.url
                   LEFT JOIN scans s ON s.id = COALESCE(f.scan_id, c.scan_id)
                   WHERE f.hunt_id = ? ORDER BY f.found_at, f.rowid""",
                (hunt_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def known_domains(self, words: list[str], limit: int = 50) -> list[dict[str, Any]]:
        """Domains already in the store whose name contains one of `words`, with the
        latest verdict of each, or the queue status of those not scanned yet."""
        found: dict[str, dict[str, Any]] = {}
        with self._conn() as db:
            for word in words:
                for row in db.execute(
                    """SELECT domain, id, verdict, risk_score FROM scans WHERE instr(domain, ?) > 0
                       ORDER BY scanned_at DESC LIMIT ?""",
                    (word, limit),
                ):
                    found.setdefault(row["domain"], {"domain": row["domain"], "case_id": row["id"],
                                                     "verdict": row["verdict"], "risk_score": row["risk_score"]})
                for row in db.execute(
                    "SELECT domain, status FROM candidates WHERE instr(domain, ?) > 0 AND scan_id IS NULL LIMIT ?",
                    (word, limit),
                ):
                    found.setdefault(row["domain"], {"domain": row["domain"], "queue_status": row["status"]})
        return list(found.values())[:limit]

    # Google Maps listings: the place IDs seen, and the leads among them

    def maps_place_seen(self, place_id: str) -> bool:
        with self._conn() as db:
            row = db.execute("SELECT 1 FROM maps_places WHERE place_id = ?", (place_id,)).fetchone()
        return row is not None

    def mark_maps_place(self, place_id: str) -> None:
        with self._conn() as db:
            db.execute("INSERT OR IGNORE INTO maps_places VALUES (?, ?)", (place_id, utcnow()))

    def add_maps_lead(self, lead: dict[str, str]) -> bool:
        """Record a lead once per listing; returns False when the listing already has one."""
        with self._conn() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO maps_leads (place_id, found_at, query, brand, reasons, name, address, phone,"
                " official_phones, website, maps_url) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (lead["place_id"], utcnow(), lead["query"], lead["brand"], lead["reasons"], lead["name"],
                 lead["address"], lead["phone"], lead["official_phones"], lead["website"], lead["maps_url"]),
            )
        return cur.rowcount == 1

    def maps_leads(self) -> list[dict[str, Any]]:
        """Every lead (one per listing, so they stay few), newest first, each with
        its website's place in the queue and its scan."""
        with self._conn() as db:
            rows = db.execute(
                """SELECT l.*, c.status AS candidate_status, s.id AS scan_id, s.verdict, s.risk_score
                   FROM maps_leads l LEFT JOIN candidates c ON c.url = l.website
                   LEFT JOIN scans s ON s.id = c.scan_id
                   ORDER BY l.found_at DESC, l.rowid DESC"""
            ).fetchall()
        return [dict(r) for r in rows]

    def maps_leads_for_scans(self, scan_ids: list[str]) -> dict[str, list[dict[str, Any]]]:
        """The Maps leads whose website became each of these scans, oldest first."""
        if not scan_ids:
            return {}
        with self._conn() as db:
            rows = db.execute(
                f"""SELECT c.scan_id, l.* FROM maps_leads l JOIN candidates c ON c.url = l.website
                    WHERE c.scan_id IN ({','.join('?' * len(scan_ids))}) ORDER BY l.found_at, l.rowid""",
                scan_ids,
            ).fetchall()
        found: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            found.setdefault(row["scan_id"], []).append(dict(row))
        return found

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
                "maps_leads": one("SELECT COUNT(*) FROM maps_leads"),
            }

    def get_meta(self, key: str) -> str | None:
        with self._conn() as db:
            row = db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._conn() as db:
            db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, value))

    # reports

    def select(self, sql: str, args: list[Any] | tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        """The rows of a read-only query, for the reports library and the threat summary."""
        with self._conn() as db:
            return [dict(r) for r in db.execute(sql, args).fetchall()]
