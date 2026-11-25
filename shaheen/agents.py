"""The AI agents' queue: parallel workers that take a queued hunt first
(`shaheen.hunter`), else a queued contacts read (`shaheen.contacts`, one quick
model call), else the next flagged case (`shaheen.investigator`), fraud before
suspicious. All of them share one view of the model endpoint and claim nothing
while it does not answer.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

from shaheen import contacts, evidence, hunter
from shaheen.config import Settings, load_settings
from shaheen.domains import host_of
from shaheen.investigator import POLL, Stopped, first_sentence, investigate, model_answers
from shaheen.store import Store, utcnow

log = logging.getLogger("shaheen.agents")

IDLE_S = 10.0  # seconds an idle queue worker waits before looking for new work
# While the queue runs, it writes the time to this meta key every HEARTBEAT_S seconds,
# so the dashboard can tell an idle investigator from one that is not running.
HEARTBEAT_KEY = "investigator_seen_at"
HEARTBEAT_S = 15.0
# While the model endpoint does not answer, the queue claims nothing, waits (10 s,
# doubling up to 60 s) and keeps the time it went down in this meta key.
MODEL_DOWN_KEY = "investigator_model_down_since"
BACKOFF_S = (10.0, 60.0)
# A run that failed with one of these errors never reached the model: its case goes
# back to the queue instead of staying failed.
CONNECTION_ERRORS = ("ConnectError", "ConnectTimeout", "ReadError", "RemoteProtocolError")


class ModelGate:
    """The queue workers' shared view of the model endpoint: one log line when it
    stops answering and one when it is back, with a growing wait in between."""

    def __init__(self, settings: Settings, store: Store):
        self.settings, self.store = settings, store
        self.lock = threading.Lock()
        self.down = False
        self.wait_s = BACKOFF_S[0]

    def ready(self, stop: threading.Event) -> bool:
        """True when the model answers; otherwise waits out the back-off and returns False."""
        with self.lock:
            answers = model_answers(self.settings)
            if answers and self.down:
                log.info("the model endpoint answers again: investigating")
                self.store.set_meta(MODEL_DOWN_KEY, "")
                self.down, self.wait_s = False, BACKOFF_S[0]
            elif not answers and not self.down:
                log.warning("the model endpoint %s does not answer: no case is claimed until it does",
                            self.settings.llm_base_url)
                self.store.set_meta(MODEL_DOWN_KEY, utcnow())
                self.down = True
            wait = self.wait_s
            if not answers:
                self.wait_s = min(self.wait_s * 2, BACKOFF_S[1])
        if not answers:
            stop.wait(wait)
        return answers


def _work_hunt(settings: Settings, store: Store, hunt_id: int, timeout_s: float, stop: threading.Event) -> None:
    row = store.get_hunt(hunt_id) or {}
    log.info("hunting %d: %s", hunt_id, row.get("mission", ""))
    try:
        record = hunter.hunt(hunt_id, timeout_s, settings, store, stop)
    except Stopped:
        raise
    except Exception as exc:  # noqa: BLE001 - one bad hunt must not stop the queue
        log.warning("hunt %d failed: %s", hunt_id, f"{type(exc).__name__}: {exc}"[:200])
        return
    run = record["run"]
    outcome = first_sentence(record["summary_en"]) if record.get("summary_en") else run.get("error") or ""
    log.info("%s hunt %d in %s s, %d tool calls, %d finds: %s", run["status"], hunt_id, run.get("wall_s", "?"),
             len(run["pi"].get("tool_calls") or []), len(store.hunt_finds(hunt_id)), evidence.defang_text(outcome))


def _work_contacts(settings: Settings, store: Store, scan_id: str) -> None:
    try:
        record = contacts.read(scan_id, settings, store)
    except Exception as exc:  # noqa: BLE001 - one bad page must not stop the queue
        store.set_contacts(scan_id, "failed", error=f"{type(exc).__name__}: {exc}"[:300])
        log.warning("contacts of %s failed: %s", scan_id, f"{type(exc).__name__}: {exc}"[:200])
        return
    if record["status"] == "failed" and str(record.get("error") or "").startswith(CONNECTION_ERRORS):
        store.set_contacts(scan_id, "queued")
        log.warning("contacts of %s did not reach the model: back in the queue", scan_id)
        return
    found = sum(len(record.get(field) or []) for field in contacts.IDENTIFIERS)
    log.info("contacts %s %s: %d numbers, addresses or accounts", record["status"], scan_id, found)


def _queue_worker(settings: Settings, store: Store, gate: ModelGate, loop: bool, timeout_s: float, mode: str,
                  stop: threading.Event, on_record: Callable[[dict[str, Any]], None]) -> None:
    while not stop.is_set():
        if not gate.ready(stop):
            continue
        hunt_id = store.claim_hunt()
        if hunt_id is not None:
            try:
                _work_hunt(settings, store, hunt_id, timeout_s, stop)
            except Stopped:
                log.info("stopped hunt %d: its run was ended and the hunt is back in the queue", hunt_id)
                return
            continue
        read_id = store.claim_contacts()
        if read_id is not None:
            _work_contacts(settings, store, read_id)
            continue
        scan_id = store.claim_investigation()
        if scan_id is None:
            if not loop:
                return
            stop.wait(IDLE_S)
            continue
        case = store.get_scan(scan_id)
        if case is not None:
            log.info("investigating %s  %s %d  %s", scan_id, case.verdict, case.risk_score,
                     evidence.defang_text(host_of(case.final_url or case.url)))
        try:
            record = investigate(scan_id, mode, timeout_s, settings, store, stop)
        except Stopped:
            store.set_investigation(scan_id, "queued")
            log.info("stopped %s: its run was ended and the case is back in the queue", scan_id)
            return
        except Exception as exc:  # noqa: BLE001 - one bad case must not stop the queue
            record = {"declared_tools": [], "run": {"case_id": scan_id, "status": "failed",
                                                    "error": f"{type(exc).__name__}: {exc}"[:500]}}
        run = record["run"]
        if run["status"] == "failed" and str(run.get("error") or "").startswith(CONNECTION_ERRORS):
            store.set_investigation(scan_id, "queued")
            log.warning("%s did not reach the model (%s): the case is back in the queue", scan_id,
                        str(run["error"])[:160])
            stop.wait(BACKOFF_S[0])
            continue
        calls = len((run.get("pi") or {}).get("tool_calls") or [])
        outcome = first_sentence(record["summary_en"]) if record.get("summary_en") else run.get("error") or ""
        log.info("%s %s in %s s, %d tool calls: %s", run["status"], scan_id, run.get("wall_s", "?"), calls,
                 evidence.defang_text(outcome))
        on_record(record)


def work_queue(loop: bool = False, timeout_s: float = 900, mode: str = "auto", workers: int = 1,
               stop: threading.Event | None = None,
               on_record: Callable[[dict[str, Any]], None] | None = None) -> None:
    """Work queued hunts, then queued cases (fraud before suspicious), with `workers`
    parallel runs until the queues are empty or, with `loop`, until stopped. Each
    filed case record goes to `on_record`. Ctrl-C (in the main thread) or `stop`
    ends the pi runs in flight and puts their hunts and cases back in the queue."""
    settings = load_settings()
    store = Store(settings.db_path)
    if not settings.llm_enabled:
        raise RuntimeError("set LLM_BASE_URL and LLM_MODEL to run the investigator")
    stop = stop or threading.Event()
    if requeued := store.requeue_running_investigations():
        log.info("requeued %d investigations left running by an earlier run", requeued)
    if requeued := store.requeue_failed_investigations(CONNECTION_ERRORS):
        log.info("requeued %d investigations that failed because the model did not answer", requeued)
    if requeued := store.requeue_running_hunts():
        log.info("requeued %d hunts left running by an earlier run", requeued)
    if requeued := store.requeue_running_contacts():
        log.info("requeued %d contacts reads left running by an earlier run", requeued)
    store.set_meta(MODEL_DOWN_KEY, "")
    gate = ModelGate(settings, store)
    lock = threading.Lock()

    def report(record: dict[str, Any]) -> None:
        if on_record is not None:
            with lock:
                on_record(record)

    threads = [threading.Thread(target=_queue_worker, name=f"agent-{n}", daemon=True,
                                args=(settings, store, gate, loop, timeout_s, mode, stop, report))
               for n in range(1, max(1, workers) + 1)]
    for thread in threads:
        thread.start()
    beat = 0.0
    try:
        while any(t.is_alive() for t in threads):
            if time.monotonic() - beat >= HEARTBEAT_S:
                store.set_meta(HEARTBEAT_KEY, utcnow())
                beat = time.monotonic()
            time.sleep(POLL)
    except KeyboardInterrupt:
        stop.set()
        for thread in threads:
            thread.join()
        raise
