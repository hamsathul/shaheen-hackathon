"""Command-line entry point: `baaz <command>`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from baaz import __version__, evidence
from baaz.config import load_settings
from baaz.models import ScanOptions, ScanResult
from baaz.pipeline import Scanner


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
    options = ScanOptions(render=not args.no_render, storefront=not args.no_storefront)
    with Scanner() as scanner:
        result = scanner.scan(args.url, options)
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="baaz", description=__doc__)
    parser.add_argument("--version", action="version", version=f"baaz {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="score one link 0-100 with reasons and an evidence pack")
    p.add_argument("url")
    p.add_argument("--json", action="store_true", help="print exactly one JSON object")
    p.add_argument("--no-render", action="store_true", help="skip the headless browser")
    p.add_argument("--no-storefront", action="store_true", help="skip WooCommerce storefront checks")
    p.set_defaults(func=cmd_scan)

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

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
