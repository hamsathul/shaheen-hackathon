"""`shaheen demo`: load a fixed set of saved captures into the store by offline
re-analysis, then serve the dashboard (optionally with the watcher), so the
proof video records the same way every time.

Each case folder is an evidence pack. It is re-analysed with
`--from-capture` (no network) under a new scan ID; an `investigation.json`
and `agent_trace.jsonl` shipped with it are copied into the new pack, added
to its manifest and recorded as the case's investigation. A case already
loaded is not loaded twice.
"""

from __future__ import annotations

import json
import logging
import shutil
import sys
import threading
from pathlib import Path

import uvicorn

from shaheen import evidence, watch
from shaheen.capture import Capture
from shaheen.config import Settings, load_settings
from shaheen.models import ScanResult
from shaheen.pipeline import Scanner
from shaheen.store import Store
from shaheen.web.app import create_app

INVESTIGATION = "investigation.json"
TRACE = "agent_trace.jsonl"


def _meta_key(capture: Capture) -> str:
    return f"demo_case:{capture.id}"


def load_cases(cases_dir: Path, settings: Settings | None = None) -> list[tuple[str, ScanResult, bool]]:
    """(folder name, result, loaded now) for every case folder in `cases_dir`."""
    settings = settings or load_settings()
    store = Store(settings.db_path)
    loaded = []
    with Scanner(settings, store) as scanner:
        for folder in sorted(p for p in Path(cases_dir).iterdir() if (p / "report.json").is_file()):
            capture = Capture(folder)
            known = store.get_meta(_meta_key(capture))
            if known and (result := store.get_scan(known)):
                loaded.append((folder.name, result, False))
                continue
            result = scanner.rescan(folder)
            _import_investigation(folder, result.id, settings, store)
            store.set_meta(_meta_key(capture), result.id)
            loaded.append((folder.name, result, True))
    return loaded


def _import_investigation(source: Path, scan_id: str, settings: Settings, store: Store) -> None:
    names = [name for name in (INVESTIGATION, TRACE) if (source / name).is_file()]
    if INVESTIGATION not in names:
        return
    pack = settings.evidence_dir / scan_id
    for name in names:
        shutil.copyfile(source / name, pack / name)
    evidence.add_to_manifest(pack, names)
    report = json.loads((pack / INVESTIGATION).read_text(encoding="utf-8"))
    store.set_investigation(scan_id, "done", mode=report.get("mode"), report_json=report)


def print_cases(loaded: list[tuple[str, ScanResult, bool]]) -> None:
    for name, result, fresh in loaded:
        state = "loaded" if fresh else "already loaded"
        print(f"{result.id}  {result.verdict:<10} {result.risk_score:>3}  {name} ({state})")


def run(cases_dir: Path, host: str, port: int, with_watcher: bool) -> None:
    """Load the demo cases, then serve the dashboard until Ctrl-C."""
    settings = load_settings()
    print_cases(load_cases(cases_dir, settings))
    stop = threading.Event()
    watcher = None
    if with_watcher:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S",
                            stream=sys.stdout)
        logging.getLogger("httpx").setLevel(logging.WARNING)
        watcher = threading.Thread(target=watch.run, kwargs={"settings": settings, "stop": stop},
                                   name="shaheen-watch", daemon=True)
        watcher.start()
    try:
        uvicorn.run(create_app(settings), host=host, port=port)
    finally:
        stop.set()
        if watcher is not None:
            watcher.join(timeout=60)
