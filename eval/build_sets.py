"""Build the labelled evaluation sets in eval/.

    uv run python eval/build_sets.py woo  --tranco top-1m.csv --want 250
    uv run python eval/build_sets.py top  --tranco top-1m.csv --sample 300
    uv run python eval/build_sets.py uae
    uv run python eval/build_sets.py phish --want 300

Every request is an unauthenticated GET of a public page or endpoint.
"""

from __future__ import annotations

import argparse
import csv
import random
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from pathlib import Path

import httpx
import yaml

from shaheen.config import DATA_DIR, DESKTOP_UA
from shaheen.domains import defang, refang, registrable_domain

EVAL_DIR = Path(__file__).resolve().parent
OPENPHISH_FEED = "https://openphish.com/feed.txt"


def read_tranco(path: Path, limit: int, match: str = "", cap: int = 0) -> list[str]:
    """Tranco domains in rank order: the top `limit`, optionally only those matching `match`, at most `cap`."""
    pattern = re.compile(match) if match else None
    out: list[str] = []
    with path.open(newline="", encoding="utf-8") as fh:
        for _, row in zip(range(limit), csv.reader(fh)):
            if pattern is None or pattern.search(row[1]):
                out.append(row[1])
                if cap and len(out) >= cap:
                    break
    return out


def ground_truth_domains() -> set[str]:
    lines = (EVAL_DIR / "ground_truth_skimmers.txt").read_text(encoding="utf-8").splitlines()
    return {registrable_domain(refang(x)) for x in lines if x and not x.startswith("#")}


def write_set(path: Path, label: str, header: list[str], urls: list[str], fang: bool) -> None:
    lines = [f"# {h}" for h in header] + [f"# label: {label}"]
    lines += [defang(u) if fang else u for u in urls]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(urls)} urls to {path}")


def is_woocommerce(client: httpx.Client, domain: str) -> bool:
    try:
        resp = client.get(f"https://{domain}/wp-json/")
        namespaces = resp.json().get("namespaces", []) if resp.status_code == 200 else []
    except (httpx.HTTPError, ValueError, AttributeError):
        return False
    return "wc/store" in namespaces or "wc/store/v1" in namespaces


def build_woo(args: argparse.Namespace) -> None:
    excluded = ground_truth_domains()
    domains = [d for d in read_tranco(args.tranco, args.ranks, args.match, args.cap) if d not in excluded]
    found: list[tuple[int, str]] = []
    headers = {"User-Agent": DESKTOP_UA}
    with httpx.Client(timeout=6, follow_redirects=True, headers=headers) as client, \
            ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(is_woocommerce, client, d): (rank, d) for rank, d in enumerate(domains, 1)}
        for fut in as_completed(futures):
            if fut.result():
                found.append(futures[fut])
                if len(found) % 25 == 0:
                    print(f"{len(found)} WooCommerce stores so far")
    found.sort()
    urls = [f"https://{d}/" for _, d in found[: args.want]]
    write_set(
        EVAL_DIR / "legit_woocommerce.txt", "legitimate",
        [f"Legitimate WooCommerce stores: Tranco top-{args.ranks} domains matching /{args.match}/ (first {args.cap}),",
         "whose /wp-json/ lists the wc/store namespace; skimmer ground-truth domains excluded.",
         f"Built {date.today().isoformat()} with: eval/build_sets.py woo --ranks {args.ranks} --match '{args.match}' --cap {args.cap}"],
        urls, fang=False,
    )


def build_top(args: argparse.Namespace) -> None:
    domains = read_tranco(args.tranco, args.ranks)
    rng = random.Random(args.seed)
    sample = sorted(rng.sample(domains, args.sample), key=domains.index)
    write_set(
        EVAL_DIR / "legit_top_sites.txt", "legitimate",
        [f"Random sample (seed {args.seed}) of {args.sample} Tranco top-{args.ranks} domains.",
         f"Built {date.today().isoformat()} with eval/build_sets.py top."],
        [f"https://{d}/" for d in sample], fang=False,
    )


def build_uae(_: argparse.Namespace) -> None:
    data = yaml.safe_load((DATA_DIR / "brands_uae.yaml").read_text(encoding="utf-8"))
    urls = sorted({f"https://{d}/" for b in data["brands"] for d in b["official_domains"]})
    write_set(
        EVAL_DIR / "legit_uae_official.txt", "legitimate",
        ["Official domains of UAE government entities, banks and services, from data/brands_uae.yaml."],
        urls, fang=False,
    )


def build_phish(args: argparse.Namespace) -> None:
    resp = httpx.get(OPENPHISH_FEED, timeout=20, headers={"User-Agent": DESKTOP_UA}, follow_redirects=True)
    resp.raise_for_status()
    seen: set[str] = set()
    urls: list[str] = []
    for line in resp.text.splitlines():
        url = line.strip()
        domain = registrable_domain(url) if url else ""
        if url and domain not in seen:
            seen.add(domain)
            urls.append(url)
    write_set(
        EVAL_DIR / "phish_openphish.txt", "fraud",
        [f"OpenPhish community feed ({OPENPHISH_FEED}), one URL per registrable domain.",
         f"Captured {date.today().isoformat()}; phishing pages die within hours, so scan soon after capture."],
        urls[: args.want], fang=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="set", required=True)
    p = sub.add_parser("woo")
    p.add_argument("--tranco", type=Path, required=True)
    p.add_argument("--ranks", type=int, default=1_000_000)
    p.add_argument("--match", default=r"(\.ae$|shop|store|boutique|mall|market)")
    p.add_argument("--cap", type=int, default=25_000)
    p.add_argument("--want", type=int, default=250)
    p.add_argument("--workers", type=int, default=48)
    p.set_defaults(func=build_woo)
    p = sub.add_parser("top")
    p.add_argument("--tranco", type=Path, required=True)
    p.add_argument("--ranks", type=int, default=10_000)
    p.add_argument("--sample", type=int, default=300)
    p.add_argument("--seed", type=int, default=42)
    p.set_defaults(func=build_top)
    sub.add_parser("uae").set_defaults(func=build_uae)
    p = sub.add_parser("phish")
    p.add_argument("--want", type=int, default=300)
    p.set_defaults(func=build_phish)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
