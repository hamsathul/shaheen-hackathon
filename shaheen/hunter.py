"""AI hunts: an officer gives the local model a mission, such as "fake visa
services aimed at UAE residents", and the model looks for suspect domains with
Shaheen's own search tools: certificate logs, yesterday's newly registered
domains and the store. It checks the likeliest few with the deterministic
scanner, queues the rest for the watcher, and files a hunt report.

A hunt runs pi as an investigation does, but without the browser: every tool
is Shaheen's (`shaheen mcp` with SHAHEEN_HUNT_ID). Hunts wait in the store
until a queue worker takes one (before any case) or `shaheen hunt` runs one in
the foreground. A hunt's trace is kept in var/hunts/<id>/. The model only
finds and queues; every verdict still comes from the deterministic scorer.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from shaheen import investigator, themes
from shaheen.config import REPO_DIR, Settings, load_settings
from shaheen.domains import host_of, normalize_url
from shaheen.investigator import PiJob, Stopped
from shaheen.store import Store, utcnow

log = logging.getLogger("shaheen.hunter")

PROMPT_PATH = REPO_DIR / "agent" / "hunter.md"
MISSION_MAX = 500
TIMEOUT_S = 900.0


class Suspect(BaseModel):
    domain: str
    reason: str


class HuntReport(BaseModel):
    """The report the model files through submit_hunt_report."""

    model_config = ConfigDict(extra="ignore")

    summary_en: str
    summary_ar: str
    searches: list[str] = []
    suspects: list[Suspect] = []
    next_steps: list[str] = []


def clean_mission(text: str) -> str:
    """A mission on one line, at most 500 characters."""
    return " ".join(str(text).split())[:MISSION_MAX]


def hunt_folder(settings: Settings, hunt_id: int) -> Path:
    return settings.db_path.parent / "hunts" / str(hunt_id)


def hunt_job(settings: Settings, hunt: dict[str, Any]) -> PiJob:
    """The pi run of a hunt. The task starts with a fixed word, so a mission can
    never be read as one of pi's own options."""
    theme = themes.get(hunt["theme"]) if hunt["theme"] else None
    task = f"Hunt {hunt['id']}. Mission: {hunt['mission']}"
    if theme:
        task += f" Theme: {theme.id} ({theme.name_en})."
    return PiJob(f"hunt-{hunt['id']}", hunt_folder(settings, hunt["id"]), {"SHAHEEN_HUNT_ID": str(hunt["id"])},
                 PROMPT_PATH, task, browser=False)


def verify_suspects(report: HuntReport, tool_text: str) -> list[str]:
    """Drop suspects that no tool result of the run mentions; returns their domains."""
    haystack = tool_text.lower()
    kept, dropped = [], []
    for suspect in report.suspects:
        host = host_of(normalize_url(suspect.domain)) if suspect.domain.strip() else ""
        (kept if host and (host in haystack or host.replace(".", "[.]") in haystack) else dropped).append(suspect)
    report.suspects = kept
    return [s.domain for s in dropped]


def hunt(hunt_id: int, timeout_s: float = TIMEOUT_S, settings: Settings | None = None,
         store: Store | None = None, stop: threading.Event | None = None) -> dict[str, Any]:
    """Run one stored hunt; returns the record kept in the store."""
    settings = settings or load_settings()
    store = store or Store(settings.db_path)
    if not settings.llm_enabled:
        raise RuntimeError("set LLM_BASE_URL and LLM_MODEL to run a hunt")
    row = store.get_hunt(hunt_id)
    if row is None:
        raise LookupError(f"no hunt {hunt_id}")
    store.set_hunt(hunt_id, status="running", started_at=utcnow(), finished_at=None, report_json=None, error=None)
    try:
        return _hunt(settings, store, row, timeout_s, stop)
    except Stopped:
        store.set_hunt(hunt_id, status="queued")
        raise
    except Exception as exc:
        store.set_hunt(hunt_id, status="failed", error=f"{type(exc).__name__}: {exc}"[:500])
        raise


def _hunt(settings: Settings, store: Store, row: dict[str, Any], timeout_s: float,
          stop: threading.Event | None) -> dict[str, Any]:
    job = hunt_job(settings, row)
    job.folder.mkdir(parents=True, exist_ok=True)
    (job.folder / "agent_trace.jsonl").write_bytes(b"")
    started = time.monotonic()
    pi = investigator.run_pi(settings, job, timeout_s, stop)
    declared = pi.pop("declared_tools")
    tool_text = pi.pop("tool_text")
    stray = [name for name in declared if not str(name).startswith(investigator.TOOL_PREFIX)]
    submitted = (store.get_hunt(row["id"]) or {}).get("report")
    report = None
    if stray:
        error = f"tools outside the allowlist were declared to the model: {stray}"
    elif submitted:
        report, error = HuntReport.model_validate(submitted), None
    else:
        error = ("timed out" if pi["timed_out"] else "no Shaheen tools were declared" if not declared
                 else "pi finished without submitting a hunt report")
    run = {"hunt_id": row["id"], "model": settings.llm_model, "endpoint": settings.llm_base_url, "pi": pi,
           "unverified_suspects": verify_suspects(report, tool_text) if report else [],
           "status": "failed" if error else "done", "error": error, "finished_at": utcnow(),
           "wall_s": round(time.monotonic() - started, 1)}
    record = {**(report.model_dump() if report else {}), "declared_tools": declared, "run": run}
    store.set_hunt(row["id"], status=run["status"], report_json=record, error=error)
    return record


def submit(store: Store, hunt_id: int, report: HuntReport) -> None:
    """Keep a report the model submitted; `hunt` adds the run record when pi ends."""
    store.set_hunt(hunt_id, report_json=report.model_dump())
