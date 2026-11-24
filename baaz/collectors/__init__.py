"""Collectors: sources of candidate URLs for the watcher's queue.

Each module exposes `collect(store, limits) -> int`, the number of new
candidates it queued. Collectors are rate-limited, cap their work per run,
respect their source's terms and fail soft: an unreachable source is logged
and yields 0, never an exception the watcher has to survive.

They watch the UAE brands and the storefront brands (`data/brands_uae.yaml`,
`data/brands_storefront.yaml`); the global brands are left to the scorer.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from typing import TypeVar

import dns.exception
import dns.resolver
import yaml

from baaz import brands, signals
from baaz.brands import Brand
from baaz.config import DATA_DIR
from baaz.domains import registrable_domain
from baaz.store import Store

WATCHED_FILES = ("brands_uae.yaml", "brands_storefront.yaml")
STOREFRONT_FILE = "brands_storefront.yaml"
DNS_LIFETIME = 3.0

T = TypeVar("T")


@dataclass(frozen=True)
class Limits:
    max_per_run: int  # DNS lookups or HTTP requests one run may make
    rate: float  # requests per second
    stop: threading.Event = field(default_factory=threading.Event)


class Throttle:
    """Spaces calls so there are at most `rate` per second."""

    def __init__(self, rate: float):
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self.next_at = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        if self.next_at > now:
            time.sleep(self.next_at - now)
        self.next_at = max(now, self.next_at) + self.interval


def _brand_ids(*files: str) -> frozenset[str]:
    return frozenset(b["id"] for name in files
                     for b in yaml.safe_load((DATA_DIR / name).read_text(encoding="utf-8"))["brands"])


@lru_cache(maxsize=1)
def watched_brands() -> tuple[Brand, ...]:
    ids = _brand_ids(*WATCHED_FILES)
    return tuple(b for b in brands.load_brands() if b.id in ids)


@lru_cache(maxsize=1)
def storefront_brands() -> tuple[Brand, ...]:
    ids = _brand_ids(STOREFRONT_FILE)
    return tuple(b for b in brands.load_brands() if b.id in ids)


def excluded(domain: str) -> bool:
    """Official domains, government namespaces and popular sites are never candidates."""
    return bool(brands.official_brand(domain) or brands.gov_namespace(domain)
                or signals.top_site_rank(registrable_domain(domain)))


def make_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_LIFETIME
    return resolver


def is_registered(domain: str, resolver: dns.resolver.Resolver) -> bool | None:
    """Whether `domain` is delegated in DNS (it has NS records); None when DNS fails."""
    try:
        resolver.resolve(domain, "NS")
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return True
    except dns.exception.DNSException:
        return None
    return True


def enqueue_host(store: Store, host: str, source: str, note: str = "") -> bool:
    """Queue `https://<host>/` once; False when it was already queued or scanned."""
    return store.enqueue(f"https://{host}/", registrable_domain(host), source, note)


def rotation(store: Store, key: str, items: Sequence[T], limits: Limits) -> Iterator[T]:
    """Up to `limits.max_per_run` items, starting where the previous run stopped
    and wrapping round at the end. The position is kept in meta `key`, so a
    sweep continues across restarts."""
    if not items:
        return
    position = int(store.get_meta(key) or 0) % len(items)
    try:
        for _ in range(min(limits.max_per_run, len(items))):
            if limits.stop.is_set():
                return
            item = items[position]
            position = (position + 1) % len(items)
            yield item
    finally:
        store.set_meta(key, str(position))
