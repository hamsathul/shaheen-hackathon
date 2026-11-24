"""Lookalike domains of the watched brands' official domains: typos,
homoglyphs, added keywords and other TLDs, generated with dnstwist. Only
registered names (delegated in DNS) are queued.

Every permutation of every official domain forms one ordered list: the
common typo, keyword and TLD forms of all brands first, brand by brand,
then the homoglyph and bit-flip forms. Each run checks the next
`max_per_run` names and saves its place, so successive runs rotate through
the brands.
"""

from __future__ import annotations

import logging
from functools import lru_cache

import dnstwist

from baaz import brands
from baaz.brands import Brand
from baaz.collectors import (Limits, Throttle, enqueue_host, excluded, is_registered, make_resolver, rotation,
                             watched_brands)
from baaz.domains import registrable_domain, split_host
from baaz.store import Store

SOURCE = "lookalikes"
CURSOR = "lookalikes:cursor"
# Words scam domains add to a brand name (dnstwist's "dictionary" fuzzer).
DICTIONARY = ("login", "verify", "secure", "pay", "payment", "online", "portal", "account", "update",
              "refund", "fines", "support", "service", "app", "uae", "ae", "dubai", "shop", "store", "offer")
# Other TLDs tried for each official name (dnstwist's "tld-swap" fuzzer).
TLDS = ("com", "net", "org", "info", "online", "site", "top", "xyz", "shop", "store", "live", "app",
        "vip", "cc", "icu", "co", "ae")
# dnstwist fuzzers, most often registered by scammers first. "subdomain" is
# left out: its names belong to another registrable domain.
FUZZERS = ("tld-swap", "dictionary", "omission", "addition", "hyphenation", "transposition", "replacement",
           "repetition", "insertion", "vowel-swap", "plural", "various", "homoglyph", "bitsquatting", "cyrillic")
LATE_FUZZERS = frozenset({"homoglyph", "bitsquatting", "cyrillic"})

log = logging.getLogger(__name__)


def targets(brand: Brand) -> list[str]:
    """The official domains to permute. Nobody else can register under a
    government namespace, so for `adpolice.gov.ae` the label is tried as
    `adpolice.com` and `adpolice.ae` instead."""
    out: list[str] = []
    for official in brand.official_domains:
        if brands.gov_namespace(official):
            label = split_host(official)[1]
            out += [f"{label}.com", f"{label}.ae"]
        else:
            out.append(official)
    return list(dict.fromkeys(out))


def permutations(domain: str) -> list[tuple[str, str]]:
    """(fuzzer, name) for the permutations of `domain` that are registrable
    domains themselves and neither official nor popular sites. Homoglyphs
    are kept in ASCII only (rn for m, 1 for l): the Unicode ones run to
    hundreds of thousands of names and are seldom registered."""
    fuzzer = dnstwist.Fuzzer(domain, dictionary=DICTIONARY, tld_dictionary=TLDS)
    fuzzer.generate(fuzzers=list(FUZZERS))
    names = {(p["fuzzer"], p["domain"]) for p in fuzzer.domains
             if p["domain"] and not (p["fuzzer"] == "homoglyph" and "xn--" in p["domain"])}
    return sorted((f, name) for f, name in names if registrable_domain(name) == name and not excluded(name))


@lru_cache(maxsize=1)
def sweep_list() -> tuple[tuple[str, str, str], ...]:
    """(name, brand id, fuzzer) for every watched brand, in sweep order."""
    rank = {f: i for i, f in enumerate(FUZZERS)}
    rows = sorted(
        (fuzzer in LATE_FUZZERS, i, rank[fuzzer], name, brand.id, fuzzer)
        for i, brand in enumerate(watched_brands())
        for target in targets(brand)
        for fuzzer, name in permutations(target)
    )
    seen: set[str] = set()
    out = []
    for *_, name, brand_id, fuzzer in rows:
        if name not in seen:
            seen.add(name)
            out.append((name, brand_id, fuzzer))
    return tuple(out)


def collect(store: Store, limits: Limits) -> int:
    added = 0
    try:
        resolver, throttle = make_resolver(), Throttle(limits.rate)
        for name, brand_id, fuzzer in rotation(store, CURSOR, sweep_list(), limits):
            throttle.wait()
            if is_registered(name, resolver) and enqueue_host(store, name, SOURCE, f"{fuzzer} of {brand_id}"):
                added += 1
    except Exception:  # noqa: BLE001 - a collector fails soft
        log.exception("lookalikes: sweep failed")
    return added
