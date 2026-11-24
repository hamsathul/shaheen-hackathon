"""`baaz watch`: the 24/7 loop. Collectors push candidate URLs into the
SQLite queue; a pool of workers drains it through the same `scan()` as every
other entry point.

Each round runs the collectors that are due (each has its own interval,
recorded in meta `collector:<name>:last_run`) in a thread of their own while
the workers scan what they queue, so the first scans start within seconds
even on a fresh store. The workers stop when the collectors are done and the
queue is empty or the round's time slice has ended; the round then logs the
counters and sleeps until the next collector is due. A failing collector or
scan is logged and the loop goes on. Ctrl-C (or SIGTERM where the platform
has it) lets the in-flight scans finish, then exits.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from baaz.collectors import Limits, ctlogs, lookalikes, newdomains, storefronts
from baaz.config import Settings, load_settings
from baaz.domains import host_of
from baaz.evidence import defang_text
from baaz.models import ScanOptions
from baaz.pipeline import Scanner
from baaz.store import Store, utcnow

log = logging.getLogger("baaz.watch")

COUNTERS_EVERY = 60.0  # seconds between counter lines while draining
POLL = 1.0  # seconds; short waits keep Ctrl-C responsive on Windows


@dataclass(frozen=True)
class Collector:
    collect: Callable[[Store, Limits], int]
    interval: float  # seconds between runs; 0 runs it every round
    max_per_run: int  # default cap on DNS lookups or HTTP requests per run
    rate: float  # requests per second


# Run in this order: the storefront sweep takes about a minute and finds skimmers,
# the lookalike sweep takes about ten minutes on a fresh store.
COLLECTORS: dict[str, Collector] = {
    "storefronts": Collector(storefronts.collect, 0, 300, 10.0),
    "ctlogs": Collector(ctlogs.collect, 3600, 3, 0.2),
    "newdomains": Collector(newdomains.collect, 24 * 3600, 500, 1.0),
    "lookalikes": Collector(lookalikes.collect, 6 * 3600, 3000, 20.0),
}


def check_collectors(names: list[str]) -> None:
    unknown = set(names) - set(COLLECTORS)
    if unknown:
        raise ValueError(f"unknown collector(s): {', '.join(sorted(unknown))}; choose from {', '.join(COLLECTORS)}")


def _last_run_key(name: str) -> str:
    return f"collector:{name}:last_run"


def _seconds_until_due(store: Store, name: str, now: datetime) -> float:
    last = store.get_meta(_last_run_key(name))
    if last is None:
        return 0.0
    elapsed = (now - datetime.fromisoformat(last)).total_seconds()
    return max(0.0, COLLECTORS[name].interval - elapsed)


def run_collectors(store: Store, names: list[str], max_per_run: int | None, stop: threading.Event) -> int:
    """Run every collector that is due; returns the number of new candidates."""
    total = 0
    for name in names:
        if stop.is_set():
            break
        if _seconds_until_due(store, name, datetime.now(timezone.utc)) > 0:
            continue
        spec = COLLECTORS[name]
        started = time.monotonic()
        try:
            added = spec.collect(store, Limits(max_per_run or spec.max_per_run, spec.rate, stop))
        except Exception:  # noqa: BLE001 - one collector never stops the loop
            log.exception("collector %s failed", name)
            added = 0
        store.set_meta(_last_run_key(name), utcnow())
        log.info("collector %s: %d new candidates in %.0fs", name, added, time.monotonic() - started)
        total += added
    return total


def _scan_one(scanner: Scanner, store: Store, row: Any, options: ScanOptions) -> None:
    try:
        result = scanner.scan(row["url"], options)
    except Exception:  # noqa: BLE001 - one scan never stops the loop
        log.exception("scan failed: %s [%s]", defang_text(row["url"]), row["source"])
        store.finish_candidate(row["id"], "error")
        return
    store.finish_candidate(row["id"], "done", result.id)
    log.info("%-10s %3d  %s  [%s] %s", result.verdict, result.risk_score,
             defang_text(host_of(result.final_url or result.url)), row["source"], result.id)


def _worker(settings: Settings, store: Store, options: ScanOptions, deadline: float,
            stop: threading.Event, claim_lock: threading.Lock, collecting: Callable[[], bool]) -> int:
    scanned = 0
    try:
        with Scanner(settings, store) as scanner:
            while not stop.is_set() and (collecting() or time.monotonic() < deadline):
                with claim_lock:
                    row = store.claim_candidate()
                if row is None:
                    if not collecting():
                        break
                    stop.wait(POLL)
                    continue
                _scan_one(scanner, store, row, options)
                scanned += 1
    except Exception:  # noqa: BLE001 - a broken worker ends; the others go on
        log.exception("scan worker stopped")
    return scanned


def _wait_all(futures: list[Future[int]], store: Store) -> None:
    pending = set(futures)
    last_counters = time.monotonic()
    while pending:
        _, pending = wait(pending, timeout=POLL, return_when=FIRST_COMPLETED)
        if time.monotonic() - last_counters >= COUNTERS_EVERY:
            log_counters(store)
            last_counters = time.monotonic()


def drain(settings: Settings, store: Store, options: ScanOptions, workers: int, deadline: float,
          stop: threading.Event, collecting: Callable[[], bool]) -> int:
    """Scan queued candidates with `workers` threads until `stop` is set or, once
    `collecting()` is false, until the queue is empty or `deadline` (monotonic
    time) has passed; returns the scans done."""
    claim_lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="baaz-scan") as pool:
        futures = [pool.submit(_worker, settings, store, options, deadline, stop, claim_lock, collecting)
                   for _ in range(workers)]
        try:
            _wait_all(futures, store)
        except KeyboardInterrupt:
            stop.set()
            log.info("stopping: finishing the scans in flight")
            _wait_all(futures, store)
            raise
    return sum(f.result() for f in futures)


def log_counters(store: Store) -> None:
    counters = store.counters()
    log.info("counters: %s", " ".join(f"{k}={v}" for k, v in counters.items()))


def _sleep(seconds: float, stop: threading.Event) -> None:
    end = time.monotonic() + seconds
    while not stop.is_set() and (left := end - time.monotonic()) > 0:
        time.sleep(min(POLL, left))


def _idle_seconds(store: Store, names: list[str], interval: float) -> float:
    if store.counters()["queued"]:
        return 0.0
    now = datetime.now(timezone.utc)
    return min([interval, *(_seconds_until_due(store, n, now) for n in names
                            if COLLECTORS[n].interval > 0)])


def run(*, settings: Settings | None = None, once: bool = False, workers: int = 4,
        collectors: list[str] | None = None, interval: float = 300, max_per_run: int | None = None,
        render: bool = True, reset_clock: bool = False, stop: threading.Event | None = None) -> dict[str, int]:
    """Watch until stopped (Ctrl-C, SIGTERM or `stop`), or for one round with
    `once`. `interval` is the longest a round's drain lasts once its
    collectors are done, and the longest sleep between rounds. Returns the
    store's counters at exit."""
    settings = settings or load_settings()
    names = collectors or list(COLLECTORS)
    check_collectors(names)
    store = Store(settings.db_path)
    stop = stop or threading.Event()
    options = ScanOptions(render=render)

    if requeued := store.requeue_stale():
        log.info("requeued %d candidates left mid-scan by an earlier run", requeued)
    if reset_clock or store.get_meta("watch_started_at") is None:
        store.set_meta("watch_started_at", utcnow())
    log.info("watching since %s: collectors %s, %d workers, render %s",
             store.get_meta("watch_started_at"), ",".join(names), workers, "on" if render else "off")

    previous = _on_sigterm_raise_interrupt()
    try:
        while not stop.is_set():
            deadline = float("inf") if once else time.monotonic() + interval
            with ThreadPoolExecutor(max_workers=1, thread_name_prefix="baaz-collect") as pool:
                collected = pool.submit(run_collectors, store, names, max_per_run, stop)
                scanned = drain(settings, store, options, workers, deadline, stop,
                                lambda job=collected: not job.done())
            added = collected.result()
            log.info("round done: %d new candidates, %d scans", added, scanned)
            log_counters(store)
            if once:
                break
            _sleep(_idle_seconds(store, names, interval), stop)
    except KeyboardInterrupt:
        stop.set()
        log.info("stopped")
    finally:
        if previous is not None:
            signal.signal(signal.SIGTERM, previous)
    return store.counters()


def _on_sigterm_raise_interrupt() -> Any:
    """Treat SIGTERM like Ctrl-C, where the platform has SIGTERM and this is
    the main thread (the dashboard may run the watcher in a thread). Returns
    the previous handler, or None when nothing was installed."""
    if not hasattr(signal, "SIGTERM") or threading.current_thread() is not threading.main_thread():
        return None
    return signal.signal(signal.SIGTERM, signal.default_int_handler)
