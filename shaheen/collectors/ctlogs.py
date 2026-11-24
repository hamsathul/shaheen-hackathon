"""Certificate Transparency: recently issued certificates whose names contain
a watched brand keyword, found through crt.sh.

crt.sh is a free public service and often slow or overloaded, so each run
sends at most a few searches (one keyword each, rotating through the
keywords), with a long timeout and exponential backoff between retries, and
stops for the run when a search gets no answer.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from shaheen.collectors import Limits, Throttle, enqueue_host, excluded, rotation, watched_brands
from shaheen.domains import registrable_domain, split_host
from shaheen.store import Store

SOURCE = "ctlogs"
CURSOR = "ctlogs:cursor"
CRT_URL = "https://crt.sh/"
SEARCHES_PER_RUN = 3
MIN_KEYWORD = 4  # shorter keywords match far too many unrelated names
MAX_AGE = timedelta(days=30)
TIMEOUT = 60.0
ATTEMPTS = 3
BACKOFF = 5.0  # seconds before the first retry; doubles each time

log = logging.getLogger(__name__)


def keywords() -> list[str]:
    return sorted({k for b in watched_brands() for k in b.keywords if len(k) >= MIN_KEYWORD})


def _issued(entry: dict[str, Any]) -> datetime | None:
    try:
        moment = datetime.fromisoformat(str(entry.get("not_before")).replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def recent_hosts(entries: Iterable[dict[str, Any]], keyword: str, now: datetime) -> list[str]:
    """Host names containing `keyword` on certificates issued in the last 30
    days, without wildcards, official domains or popular sites."""
    hosts: set[str] = set()
    for entry in entries:
        issued = _issued(entry)
        if issued is None or now - issued > MAX_AGE:
            continue
        names = f"{entry.get('common_name') or ''}\n{entry.get('name_value') or ''}".lower().split()
        for name in names:
            host = name.removeprefix("*.").rstrip(".")
            if keyword in host and "." in host and "@" not in host and not excluded(host):
                hosts.add(host)
    return sorted(hosts)


def candidate_host(host: str, keyword: str) -> str:
    """The registrable domain to scan, or the full host when only its
    subdomain carries the keyword (`adcb.login-check.example`)."""
    _, label, _ = split_host(host)
    return registrable_domain(host) if keyword in label else host


def search(keyword: str, client: httpx.Client, throttle: Throttle) -> list[dict[str, Any]] | None:
    """crt.sh's answer for names containing `keyword`; None when it never answered."""
    delay = BACKOFF
    for attempt in range(1, ATTEMPTS + 1):
        throttle.wait()
        try:
            resp = client.get(CRT_URL, params={"q": f"%{keyword}%", "output": "json", "exclude": "expired"})
            if resp.status_code == 200:
                data = resp.json()
                return data if isinstance(data, list) else []
            log.info("ctlogs: crt.sh answered %s for %r (attempt %d)", resp.status_code, keyword, attempt)
        except (httpx.HTTPError, ValueError) as exc:
            log.info("ctlogs: crt.sh failed for %r (attempt %d): %s", keyword, attempt, type(exc).__name__)
        if attempt < ATTEMPTS:
            time.sleep(delay)
            delay *= 2
    return None


def collect(store: Store, limits: Limits) -> int:
    added = 0
    try:
        throttle = Throttle(limits.rate)
        searches = Limits(min(SEARCHES_PER_RUN, limits.max_per_run), limits.rate, limits.stop)
        with httpx.Client(timeout=TIMEOUT, headers={"User-Agent": "shaheen-watch"}) as client:
            for keyword in rotation(store, CURSOR, keywords(), searches):
                entries = search(keyword, client, throttle)
                if entries is None:
                    log.info("ctlogs: crt.sh is not answering; trying again next run")
                    break
                hosts = recent_hosts(entries, keyword, datetime.now(timezone.utc))
                for host in dict.fromkeys(candidate_host(h, keyword) for h in hosts):
                    if added >= limits.max_per_run:
                        break
                    if enqueue_host(store, host, SOURCE, f"certificate names {keyword}"):
                        added += 1
                log.info("ctlogs: %r: %d certificates, %d recent names", keyword, len(entries), len(hosts))
    except Exception:  # noqa: BLE001 - a collector fails soft
        log.exception("ctlogs: run failed")
    return added
