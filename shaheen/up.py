"""`shaheen up`: the autonomous mode. One process runs the watcher (collectors
and scanning workers) and the investigator's queue (parallel pi runs) in
background threads and serves the dashboard in the main thread, so
monitoring, scoring and investigating go on by themselves while the feed and
the live investigator panel update.

Ctrl-C stops the dashboard, then the investigator (it ends the pi runs in
flight and puts their cases back in the queue), then the watcher (it lets
the scans in flight finish).
"""

from __future__ import annotations

import logging
import sys
import threading

import uvicorn

from shaheen import agents, investigator, watch
from shaheen.config import load_settings
from shaheen.store import Store
from shaheen.web.app import create_app

log = logging.getLogger("shaheen.up")

# Log prefix of each component, by logger name.
COMPONENTS = {"shaheen.watch": "watch", "shaheen.collectors": "watch", "shaheen.investigator": "agent",
              "shaheen.agents": "agent", "shaheen.hunter": "agent", "uvicorn": "web", "shaheen.up": "up"}
INVESTIGATOR_STOP_S = 30.0  # killing the pi runs takes a second or two; a one-shot request may not stop
WATCHER_STOP_S = 120.0  # a rendered scan in flight can take a minute


class _Component(logging.Filter):
    """Adds `component`: a short prefix per part of Shaheen; an investigator line names its worker."""

    def filter(self, record: logging.LogRecord) -> bool:
        short = next((p for name, p in COMPONENTS.items()
                      if record.name == name or record.name.startswith(name + ".")), record.name)
        record.component = record.threadName if short == "agent" and record.threadName.startswith("agent-") \
            else short
        return True


def _setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(_Component())
    handler.setFormatter(logging.Formatter("%(asctime)s %(component)-7s %(message)s", "%H:%M:%S"))
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def _investigate(stop: threading.Event, workers: int) -> None:
    try:
        agents.work_queue(loop=True, workers=workers, stop=stop)
    except Exception:  # noqa: BLE001 - the watcher and the dashboard go on
        log.exception("the investigator stopped")


def run(host: str, port: int, workers: int, render: bool, investigate: bool, investigators: int | None,
        collectors: list[str] | None) -> None:
    """Watch, investigate and serve the dashboard until Ctrl-C."""
    if collectors:
        watch.check_collectors(collectors)
    _setup_logging()
    settings = load_settings()
    # Create the database and switch it to WAL before any thread opens it: SQLite cannot
    # switch a new file to WAL while another connection is using it.
    Store(settings.db_path)
    stop = threading.Event()
    threads = []
    if investigate and settings.llm_enabled:
        count = investigators or settings.investigators
        log.info("investigator: %d worker%s, %s mode, model %s at %s%s", count, "" if count == 1 else "s",
                 investigator.choose_mode(settings), settings.llm_model, settings.llm_base_url,
                 "" if investigator.model_answers(settings) else " (not answering yet)")
        threads.append(threading.Thread(target=_investigate, args=(stop, count), name="investigator", daemon=True))
    elif investigate:
        log.info("investigator off: set LLM_BASE_URL and LLM_MODEL (in .env) to investigate flagged cases")
    else:
        log.info("investigator off (--no-investigate)")
    threads.append(threading.Thread(
        target=watch.run, name="watcher", daemon=True,
        kwargs={"settings": settings, "workers": workers, "render": render, "collectors": collectors, "stop": stop},
    ))
    for thread in threads:
        thread.start()
    log.info("dashboard: http://%s:%d/", host, port)
    try:
        uvicorn.run(create_app(settings), host=host, port=port, log_config=None, access_log=False,
                    timeout_graceful_shutdown=5)
    except KeyboardInterrupt:
        pass
    finally:
        _stop(stop, threads)


def _stop(stop: threading.Event, threads: list[threading.Thread]) -> None:
    stop.set()
    log.info("stopping: ending the investigations in flight, then letting the scans in flight finish")
    try:
        for thread in threads:
            thread.join(INVESTIGATOR_STOP_S if thread.name == "investigator" else WATCHER_STOP_S)
            if thread.is_alive():
                log.warning("%s did not stop in time; exiting anyway", thread.name)
    except KeyboardInterrupt:
        log.warning("second Ctrl-C: exiting without waiting")
    log.info("stopped")
