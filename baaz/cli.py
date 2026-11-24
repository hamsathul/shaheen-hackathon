"""Command-line entry point: `baaz <command>`."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from pathlib import Path

import uvicorn

from baaz import __version__, batch, demo, evidence, investigator, mcp_server, summary, up, watch
from baaz.capture import CaptureError
from baaz.config import load_settings
from baaz.domains import normalize_url, registrable_domain
from baaz.models import ScanOptions, ScanResult
from baaz.pipeline import Scanner
from baaz.store import Store
from baaz.web.app import create_app


def _print_result(result: ScanResult, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result.to_dict(), ensure_ascii=False))
        return
    print(f"{result.verdict.upper()}  risk {result.risk_score}/100  confidence {result.confidence}")
    print(f"  {result.url} -> {result.final_url}  [{result.fetch_status}]")
    for r in result.reasons:
        print(f"  {r.weight:+4d}  {r.en}")
    print(f"  evidence: {result.evidence_path}")


def cmd_scan(args: argparse.Namespace) -> int:
    if (args.url is None) == (args.from_capture is None):
        print("error: give either a URL or --from-capture <evidence_dir>", file=sys.stderr)
        return 2
    options = ScanOptions(render=not args.no_render, storefront=not args.no_storefront)
    with Scanner() as scanner:
        if args.from_capture is None:
            result = scanner.scan(args.url, options)
        else:
            try:
                result = scanner.rescan(args.from_capture, options)
            except CaptureError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
    _print_result(result, args.json)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    folder = evidence.pack_folder(args.case)
    problems = evidence.verify(folder)
    for problem in problems:
        print(f"FAIL  {problem}")
    if problems:
        print(f"{folder}: {len(problems)} problem(s)")
        return 1
    print(f"OK  {folder}: every file matches manifest.json (manifest sha256 {evidence.manifest_sha256(folder)})")
    return 0


def cmd_confirm(args: argparse.Namespace) -> int:
    settings = load_settings()
    try:
        takedown = evidence.confirm_case(args.id, args.analyst or settings.reporter_name, args.note,
                                         settings=settings)
    except evidence.EvidenceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"confirmed {args.id}; takedown request: {takedown}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    settings = load_settings()
    try:
        out = evidence.export_pack(args.id, args.out, settings)
    except evidence.EvidenceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if problems := evidence.verify(settings.evidence_dir / args.id):
        print(f"warning: the pack fails verification: {'; '.join(problems)}", file=sys.stderr)
    print(out)
    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    print(summary.write(load_settings(), args.period, args.lang, args.out))
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S",
                        stream=sys.stdout)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    collectors = [c.strip() for c in args.collectors.split(",") if c.strip()] if args.collectors else None
    try:
        watch.run(once=args.once, workers=args.workers, collectors=collectors, interval=args.interval,
                  max_per_run=args.max_per_run, render=not args.no_render, reset_clock=args.reset_clock)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def _targets(path: Path) -> list[str]:
    """URLs from a text file (one per line) or a CSV file with a `url` column."""
    rows = [line.strip() for line in path.read_text(encoding="utf-8-sig").splitlines()]
    rows = [row for row in rows if row and not row.startswith("#")]
    if rows and "," in rows[0]:
        reader = csv.DictReader(rows)
        column = next((f for f in reader.fieldnames or [] if f.strip().lower() == "url"), None)
        if column:
            return [r[column].strip() for r in reader if (r.get(column) or "").strip()]
    return [row.split(",")[0].strip() for row in rows]


def cmd_enqueue(args: argparse.Namespace) -> int:
    store = Store(load_settings().db_path)
    path = Path(args.target)
    targets = _targets(path) if path.is_file() else [args.target]
    added = 0
    for target in targets:
        url = normalize_url(target)
        added += store.enqueue(url, registrable_domain(url), args.source)
    known = len(targets) - added
    print(f"queued {added} of {len(targets)}" + (f" ({known} already queued or scanned)" if known else ""))
    return 0


def cmd_batch(args: argparse.Namespace) -> int:
    targets = batch.read_targets(Path(args.file))
    options = ScanOptions(render=not args.no_render, storefront=not args.no_storefront)
    results = batch.run_batch(targets, args.workers, options, args.timeout)
    batch.write_results(Path(args.out), targets, results)
    flagged = sum(batch.call(r) == "fraud" for r in results)
    print(f"scanned {len(results)}, flagged {flagged}; wrote {args.out}")
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    options = ScanOptions(render=not args.no_render, storefront=not args.no_storefront)
    rows = []
    for name in args.files:
        path = Path(name)
        targets = batch.read_targets(path)
        results = batch.run_batch(targets, args.workers, options, args.timeout)
        batch.write_eval_rows(Path(args.out_dir) / f"{path.stem}.csv", targets, results)
        print(batch.file_report(name, targets, results), end="\n\n", flush=True)
        rows.append((path.name, targets, results))
    if len(rows) > 1:
        print(batch.combined_table(rows))
    return 0


def add_batch_commands(sub: argparse._SubParsersAction) -> None:
    for name, func, about in (("batch", cmd_batch, "scan a list of links and write a results CSV"),
                              ("eval", cmd_eval, "scan labelled lists and print accuracy metrics")):
        p = sub.add_parser(name, help=about)
        if name == "batch":
            p.add_argument("file", help="text file (one link per line) or CSV with a url column")
            p.add_argument("--out", required=True, help="results CSV: url,label,risk_score,verdict,top_reason")
        else:
            p.add_argument("files", nargs="+", help="labelled text or CSV files")
            p.add_argument("--out-dir", default="eval/results", help="per-URL rows, one CSV per input file")
        p.add_argument("--workers", type=int, default=8)
        p.add_argument("--timeout", type=float, default=90.0, help="seconds before a link is scored from its URL alone")
        p.add_argument("--no-render", action="store_true", help="skip the headless browser")
        p.add_argument("--no-storefront", action="store_true", help="skip WooCommerce storefront checks")
        p.set_defaults(func=func)


def _print_investigation(record: dict) -> None:
    run = record["run"]
    print(f"{run['status'].upper()}  case {run['case_id']}  mode {run.get('mode', '?')}  "
          f"{run.get('wall_s', '?')} s")
    if run.get("fallback_from"):
        print(f"  fell back from {run['fallback_from']}: {run['fallback_reason']}")
    if run.get("error"):
        print(f"  error: {run['error']}")
    if record["declared_tools"]:
        print(f"  tools declared to the model: {', '.join(record['declared_tools'])}")
    calls = (run.get("pi") or {}).get("tool_calls") or []
    if calls:
        print(f"  tool calls: {', '.join(c['tool'] for c in calls)}")
    for action in record.get("browser_actions") or []:
        print(f"  browser: {action['tool']} {action['target']} -> {action['page_url'] or '-'}")
    if record.get("policy_violation"):
        print("  POLICY VIOLATION: a browser action may have put input into a page "
              "(see policy_violations)")
    applied = run.get("applied")
    if applied:
        before, after = applied["before"], applied["after"]
        print(f"  verdict {before['verdict']} {before['risk_score']} -> {after['verdict']} "
              f"{after['risk_score']} (model asked {applied['requested_adjustment']:+d}; {applied['note']})")
    if record.get("summary_en"):
        print(f"  {record['summary_en']}")


def cmd_investigate(args: argparse.Namespace) -> int:
    try:
        if args.bench:
            print(json.dumps(investigator.bench(), ensure_ascii=False))
            return 0
        if args.queue:
            logging.basicConfig(level=logging.INFO, format="%(asctime)s %(threadName)s %(message)s",
                                datefmt="%Y-%m-%d %H:%M:%S", stream=sys.stdout)
            logging.getLogger("httpx").setLevel(logging.WARNING)
            investigator.work_queue(args.loop, args.timeout, args.mode,
                                    args.workers or load_settings().investigators, on_record=_print_investigation)
            return 0
        if not args.id:
            print("baaz investigate: give a case id, --queue or --bench", file=sys.stderr)
            return 2
        record = investigator.investigate(args.id, args.mode, args.timeout)
    except (LookupError, RuntimeError) as exc:
        print(f"baaz investigate: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("baaz investigate: stopped; the runs in flight were ended", file=sys.stderr)
        return 130
    _print_investigation(record)
    return 0 if record["run"]["status"] == "done" else 1


def cmd_mcp(args: argparse.Namespace) -> int:
    mcp_server.main()
    return 0


def _add_agent_commands(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("investigate", help="have the local model investigate a flagged case")
    p.add_argument("id", nargs="?", help="case (scan) id")
    p.add_argument("--mode", choices=("auto", "pi", "oneshot"), default="auto")
    p.add_argument("--timeout", type=float, default=900, help="seconds per case (default 900)")
    p.add_argument("--queue", action="store_true", help="work the investigation queue")
    p.add_argument("--loop", action="store_true", help="with --queue: keep waiting for new cases")
    p.add_argument("--workers", type=int,
                   help="with --queue: parallel investigations (default: BAAZ_INVESTIGATORS, else 2)")
    p.add_argument("--bench", action="store_true", help="measure the model's tokens per second")
    p.set_defaults(func=cmd_investigate)

    p = sub.add_parser("mcp", help="serve the investigator's tools over stdio (used by pi)")
    p.set_defaults(func=cmd_mcp)


def cmd_dashboard(args: argparse.Namespace) -> int:
    uvicorn.run(create_app(), host=args.host, port=args.port)
    return 0


def cmd_demo_load(args: argparse.Namespace) -> int:
    try:
        demo.print_cases(demo.load_cases(args.cases))
    except (CaptureError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    try:
        demo.run(args.cases, args.host, args.port, args.watch)
    except (CaptureError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def cmd_up(args: argparse.Namespace) -> int:
    collectors = [c.strip() for c in args.collectors.split(",") if c.strip()] if args.collectors else None
    try:
        up.run(args.host, args.port, args.workers, not args.no_render, not args.no_investigate, args.investigators,
               collectors)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def add_dashboard_commands(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("up", help="autonomous mode: watcher, investigator and dashboard in one process")
    p.add_argument("--host", default="127.0.0.1", help="interface to listen on (0.0.0.0 for the LAN)")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--workers", type=int, default=4, help="parallel scans (default 4)")
    p.add_argument("--no-render", action="store_true", help="skip the headless browser in scans (faster)")
    p.add_argument("--no-investigate", action="store_true", help="watch and serve only; no AI investigator")
    p.add_argument("--investigators", type=int,
                   help="parallel investigations (default: BAAZ_INVESTIGATORS, else 2)")
    p.add_argument("--collectors", help=f"comma-separated subset of: {','.join(watch.COLLECTORS)}")
    p.set_defaults(func=cmd_up)

    p = sub.add_parser("dashboard", help="serve the dashboard (live feed, cases, confirm, export)")
    p.add_argument("--host", default="127.0.0.1", help="interface to listen on (0.0.0.0 for the LAN)")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(func=cmd_dashboard)

    p = sub.add_parser("demo-load", help="re-analyse saved capture folders offline into the store")
    p.add_argument("cases", type=Path, nargs="?", default=Path("demo/cases"), help="default: demo/cases")
    p.set_defaults(func=cmd_demo_load)

    p = sub.add_parser("demo", help="load demo/cases, then serve the dashboard")
    p.add_argument("--cases", type=Path, default=Path("demo/cases"))
    p.add_argument("--watch", action="store_true", help="also run the watcher in the background")
    p.add_argument("--host", default="127.0.0.1", help="interface to listen on (0.0.0.0 for the LAN)")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(func=cmd_demo)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="baaz", description=__doc__)
    parser.add_argument("--version", action="version", version=f"baaz {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="score one link 0-100 with reasons and an evidence pack")
    p.add_argument("url", nargs="?")
    p.add_argument("--from-capture", type=Path, metavar="EVIDENCE_DIR",
                   help="re-analyse a saved evidence folder offline (no network) under a new scan ID")
    p.add_argument("--json", action="store_true", help="print exactly one JSON object")
    p.add_argument("--no-render", action="store_true", help="skip the headless browser")
    p.add_argument("--no-storefront", action="store_true", help="skip WooCommerce storefront checks")
    p.set_defaults(func=cmd_scan)
    add_batch_commands(sub)

    p = sub.add_parser("verify", help="recompute an evidence pack's hashes against its manifest")
    p.add_argument("case", help="scan ID or evidence folder path")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("confirm", help="mark a case analyst-confirmed and draft its takedown request")
    p.add_argument("id")
    p.add_argument("--analyst", help="the confirming analyst (default: BAAZ_REPORTER_NAME)")
    p.add_argument("--note", default="", help="a note kept with the confirmation")
    p.set_defaults(func=cmd_confirm)

    p = sub.add_parser("export", help="zip a case's evidence pack")
    p.add_argument("id")
    p.add_argument("--out", type=Path, help="zip path (default: evidence/<id>.zip)")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("summary", help="write the threat summary for the police as one self-contained HTML file")
    p.add_argument("--period", choices=summary.PERIODS, default="7d",
                   help="today or the last 7 days in UAE time, the last 24 hours, or all (default 7d)")
    p.add_argument("--lang", choices=("en", "ar"), default="en")
    p.add_argument("--out", type=Path,
                   help="HTML path (default: evidence/reports/threat-summary-<period>-<lang>-<time>.html)")
    p.set_defaults(func=cmd_summary)

    p = sub.add_parser("watch", help="run the collectors and scan what they find, 24/7")
    p.add_argument("--once", action="store_true", help="one collector round, drain the queue, exit")
    p.add_argument("--workers", type=int, default=4, help="parallel scans (default 4)")
    p.add_argument("--collectors", help=f"comma-separated subset of: {','.join(watch.COLLECTORS)}")
    p.add_argument("--interval", type=float, default=300,
                   help="longest drain per round and longest idle sleep, in seconds (default 300)")
    p.add_argument("--max-per-run", type=int, help="cap on DNS lookups or requests per collector run")
    p.add_argument("--no-render", action="store_true", help="skip the headless browser (faster)")
    p.add_argument("--reset-clock", action="store_true", help="restart the 'running since' clock")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("enqueue", help="queue a URL, or every URL in a file, for the watcher")
    p.add_argument("target", help="a URL, or a text file (one per line) or CSV with a url column")
    p.add_argument("--source", default="manual", help="source label (default: manual)")
    p.set_defaults(func=cmd_enqueue)
    add_dashboard_commands(sub)

    _add_agent_commands(sub)

    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
