"""The brand x place x pattern sweep for fake storefronts (bose-uae.com,
jblkuwait.shop, sharkninjasa.com): each storefront brand's keywords and
tokens joined to every country name, short form and ISO code
(`data/countries.yaml`) and the Gulf cities, as `{brand}{place}`,
`{brand}s{place}`, `{brand}-{place}`, `{brand}{cc}` and `{brand}-{cc}`.

The Gulf comes first, then the rest of the world; .com first, then the other
TLDs in `SHAHEEN_STOREFRONT_TLDS`. A name is checked in DNS first (an NS
record), so an unregistered name costs no HTTP request, and a registered
domain is queued at most once a day. The position in the sweep is kept in
meta, so it continues across restarts.
"""

from __future__ import annotations

import logging
from functools import lru_cache

import yaml

from shaheen.collectors import (Limits, Throttle, brand_terms, enqueue_host, excluded, is_registered, make_resolver,
                             rotation, storefront_brands)
from shaheen.config import DATA_DIR, load_settings
from shaheen.store import Store

SOURCE = "storefronts"
CURSOR = "storefronts:cursor"
GULF_CODES = ("ae", "sa", "qa", "kw", "bh", "om")
RECHECK_HOURS = 24

log = logging.getLogger(__name__)


def places() -> list[tuple[str, bool]]:
    """(place, is_code): the Gulf states' names and codes, the Gulf cities,
    then every other country's names and codes."""
    data = yaml.safe_load((DATA_DIR / "countries.yaml").read_text(encoding="utf-8"))
    countries = data["countries"]
    gulf = [c for code in GULF_CODES for c in countries if code in c["codes"]]
    others = [c for c in countries if c not in gulf]

    def of(group: list[dict]) -> list[tuple[str, bool]]:
        return [(p, False) for c in group for p in c["names"]] + [(p, True) for c in group for p in c["codes"]]

    return list(dict.fromkeys([*of(gulf), *((city, False) for city in data["cities"]), *of(others)]))


def names_for(term: str, place: str, is_code: bool) -> list[str]:
    """The domain labels for one brand term and one place."""
    if is_code:
        return [f"{term}{place}", f"{term}-{place}"]
    return [f"{term}{place}", f"{term}s{place}", f"{term}-{place}"]


def terms() -> list[tuple[str, str]]:
    """(term, brand id) for every string naming a storefront brand."""
    pairs = {(t, b.id) for b in storefront_brands() for t in brand_terms(b)}
    return sorted(pairs, key=lambda pair: (pair[1], pair[0]))


@lru_cache(maxsize=4)
def sweep_list(tlds: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    """(domain, brand id) in sweep order: TLD, then place, then brand, then pattern."""
    out: dict[str, str] = {}
    for tld in tlds:
        for place, is_code in places():
            for term, brand_id in terms():
                for label in names_for(term, place, is_code):
                    out.setdefault(f"{label}.{tld}", brand_id)
    return tuple(out.items())


def collect(store: Store, limits: Limits) -> int:
    added = 0
    try:
        resolver, throttle = make_resolver(), Throttle(limits.rate)
        for domain, brand_id in rotation(store, CURSOR, sweep_list(load_settings().storefront_tlds), limits):
            if excluded(domain):
                continue
            throttle.wait()
            if not is_registered(domain, resolver) or store.domain_seen_since(domain, RECHECK_HOURS):
                continue
            if enqueue_host(store, domain, SOURCE, f"{brand_id} brand and place pattern"):
                added += 1
    except Exception:  # noqa: BLE001 - a collector fails soft
        log.exception("storefronts: sweep failed")
    return added
