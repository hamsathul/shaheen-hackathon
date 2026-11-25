"""The UAE focus: which links and cases Shaheen works on first.

A host is in focus when it carries a UAE marker (a UAE place name, a name
ending in -ae, or the .ae suffix) or names or imitates a UAE brand or
government body. A link is in focus when its host is, or when it did not come
from a sweep that finds names by pattern alone: an officer's scan, a Google
Maps lead or an AI hunt. A case is in focus when its link or any address in
its redirect chain is, or when the page imitates a UAE brand.

The watcher scans the queued links in focus first. A case out of focus is not
sent to the AI investigator: its investigation is parked, and the case page
sends it on by hand. `refocus` applies the rule to what is already waiting.
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

from shaheen import brands, themes
from shaheen.domains import host_of
from shaheen.models import ScanResult

if TYPE_CHECKING:
    from shaheen.store import Store

# Sources that queue names found by pattern alone, wherever they point.
SWEEPS = frozenset({"storefronts", "lookalikes", "ctlogs", "newdomains", "investigator"})
IN_FOCUS, OUT_OF_FOCUS = 0, 1  # candidate priorities: the watcher scans the lower first


@lru_cache(maxsize=1)
def _uae_brand_names() -> frozenset[str]:
    return frozenset(b.name_en for b in brands.load_brands() if b.scope == "uae")


def host_in_focus(host: str) -> bool:
    return themes.uae_marker(host) is not None or any(m.brand.scope == "uae" for m in brands.match_domain(host))


def priority(host: str, source: str) -> int:
    return IN_FOCUS if source not in SWEEPS or host_in_focus(host) else OUT_OF_FOCUS


def case_in_focus(result: ScanResult, source: str | None) -> bool:
    """`source` is the collector that queued the link, None for a link scanned by hand."""
    return (source not in SWEEPS or result.impersonated_brand in _uae_brand_names()
            or any(host_in_focus(host_of(url)) for url in (result.url, *result.redirect_chain)))


def refocus(store: Store) -> dict[str, int]:
    """Apply the focus to the queued links and the waiting investigations: queued
    ones out of focus are parked and parked ones in focus are queued again."""
    links = store.queued_candidates()
    wanted = {row["id"]: priority(host_of(row["url"]), row["source"]) for row in links}
    store.set_priorities({row["id"]: wanted[row["id"]] for row in links if wanted[row["id"]] != row["priority"]})
    waiting = store.waiting_investigations()
    sources = store.scan_sources(list(waiting))
    states = {}
    for scan_id in waiting:
        result = store.get_scan(scan_id)
        states[scan_id] = "queued" if result is None or case_in_focus(result, sources.get(scan_id)) else "parked"
    store.move_investigations({i: s for i, s in states.items() if s != waiting[i]})
    found = list(states.values())
    return {"links_first": sum(p == IN_FOCUS for p in wanted.values()),
            "links_later": sum(p == OUT_OF_FOCUS for p in wanted.values()),
            "cases_queued": found.count("queued"), "cases_parked": found.count("parked")}
