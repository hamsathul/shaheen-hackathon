"""Command-line entry point: `baaz <command>`."""

from __future__ import annotations

import argparse
import json
import sys

from baaz import __version__
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

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
