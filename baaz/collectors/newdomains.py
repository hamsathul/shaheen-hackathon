"""Newly registered domains: WhoisDS's free daily list (one zip per day of
gTLD registrations), filtered for the watched brands and UAE place names.

One download a day: the list of the previous UTC day, fetched once (the date
done is kept in meta). WhoisDS allows the free download and forbids only
redistributing the data; Baaz keeps the list in memory and queues matches.
"""

from __future__ import annotations

import base64
import io
import logging
import re
import zipfile
from collections.abc import Iterable
from datetime import date, datetime, timedelta, timezone

import httpx

from baaz import brands
from baaz.collectors import Limits, enqueue_host, excluded, watched_brands
from baaz.store import Store

SOURCE = "newdomains"
DONE_KEY = "newdomains:last_date"
LIST_URL = "https://www.whoisds.com/whois-database/newly-registered-domains/{}/nrd"
TIMEOUT = 60.0
MAX_ZIP_BYTES = 20_000_000
UAE_TERMS = ("uae", "dubai", "abudhabi", "emirates", "sharjah", "ajman")
_UAE_SUFFIX = re.compile(r"(?:-ae|\.ae)$")

log = logging.getLogger(__name__)


def list_url(day: date) -> str:
    return LIST_URL.format(base64.b64encode(f"{day.isoformat()}.zip".encode("ascii")).decode("ascii"))


def domains_in(zip_bytes: bytes) -> list[str]:
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        text = zf.read(zf.namelist()[0]).decode("utf-8", errors="replace")
    return [line.strip().lower() for line in text.splitlines() if line.strip()]


def matches(domains: Iterable[str]) -> list[tuple[str, str]]:
    """(domain, why) for domains imitating a watched brand or pairing it with a
    place (as the scorer reads host names; a bare mention of a short brand
    token such as `du` is too common to count), then for domains carrying a
    UAE place name or an `ae` ending."""
    watched = {b.id for b in watched_brands()}
    terms = {t for b in watched_brands() for t in (*b.keywords, *b.tokens)}
    branded, local = [], []
    for domain in domains:
        if excluded(domain):
            continue
        if any(t in domain for t in terms):
            found = [m.brand for m in brands.match_domain(domain) if m.brand.id in watched and m.method != "mention"]
            if found:
                branded.append((domain, f"new domain naming {found[0].name_en}"))
                continue
        name = domain.rsplit(".", 1)[0]
        if any(t in name for t in UAE_TERMS) or _UAE_SUFFIX.search(name) or domain.endswith(".ae"):
            local.append((domain, "new domain with a UAE name"))
    return branded + local


def collect(store: Store, limits: Limits) -> int:
    day = datetime.now(timezone.utc).date() - timedelta(days=1)
    if store.get_meta(DONE_KEY) == day.isoformat():
        return 0
    added = 0
    try:
        resp = httpx.get(list_url(day), timeout=TIMEOUT, follow_redirects=True,
                         headers={"User-Agent": "baaz-watch"})
        if resp.status_code != 200 or len(resp.content) > MAX_ZIP_BYTES:
            log.info("newdomains: no list for %s (HTTP %s)", day, resp.status_code)
            return 0
        domains = domains_in(resp.content)
        found = matches(domains)
        for domain, why in found:
            if added >= limits.max_per_run:
                break
            if enqueue_host(store, domain, SOURCE, why):
                added += 1
        store.set_meta(DONE_KEY, day.isoformat())
        log.info("newdomains: %s: %d domains, %d matches", day, len(domains), len(found))
    except (httpx.HTTPError, zipfile.BadZipFile, IndexError) as exc:
        log.info("newdomains: list for %s unavailable: %s", day, type(exc).__name__)
    except Exception:  # noqa: BLE001 - a collector fails soft
        log.exception("newdomains: run failed")
    return added
