"""Google Maps: listings that name a watched brand, found with the Places API
(New) Text Search, checked for the two ways a Maps listing serves a scam.

- **Website.** The listing gives a website that is not on the brand's
  official domains (or any allowlisted domain). The website is queued for the
  scorer with source `maps`, which decides its verdict like any other
  candidate's: Maps adds a lead, never a verdict.
- **Helpline.** The listing presents itself as the brand's helpline (customer
  care, call centre, خدمة العملاء: `helpline_claims` in `data/wording.yaml`),
  the brand has verified numbers (`phones` in the brand data) and the
  listing's number, in E.164 form, is not one of them. Branches, resellers and
  service centres keep local numbers, so only this claim is flagged on the
  phone alone, and only for an analyst to review.

Both are recorded as leads (store table `maps_leads`) with the listing's name,
address, phone and Google Maps link. Every place ID seen is kept, so a listing
is checked once.

Searches are restricted to the emirate of Abu Dhabi (Abu Dhabi city, Al Ain and
Al Dhafra). Each round sends at most `QUERIES_PER_RUN` searches, `PACE_S` seconds apart,
one request each for the first page of up to 20 listings (no further pages),
rotating through victim-style queries built from the brand data after a few
fixed government-service searches. The watcher runs a round every
`BAAZ_MAPS_INTERVAL_HOURS` (6 by default), and the dashboard's "Search Maps
now" button can start one sooner. The request asks for the fields used here
only; the website and phone fields put it in Google's Text Search Enterprise
SKU.

The searches of the last round and the one under way, with every listing's
name, location and outcome, are kept in memory only (`live`), for the
dashboard's live panel: Google's terms allow storing place IDs, and
coordinates for up to 30 days, but no other listing content.

It needs `GOOGLE_MAPS_API_KEY`; without one the watcher leaves it out.
`GOOGLE_MAPS_API_BASE` points it at another server speaking the same API,
such as a local stub.
"""

from __future__ import annotations

import logging
import re
import threading
from collections import deque
from dataclasses import dataclass, replace
from datetime import datetime
from functools import lru_cache
from typing import Any

import httpx
import yaml

from baaz import brands, signals
from baaz.brands import Brand
from baaz.collectors import WATCHED_SCOPES, Limits, Throttle, rotation, watched_brands
from baaz.config import DATA_DIR, load_settings
from baaz.domains import normalize_url, registrable_domain
from baaz.evidence import GST, defang_text
from baaz.store import Store, utcnow

SOURCE = "maps"
CURSOR = "maps:cursor"
CALLS = "maps:calls"  # meta: "<GST date> <searches sent that day>"
QUERIES_PER_RUN = 6
PACE_S = 6.0  # seconds between the searches of a round, so a viewer can follow them one by one
SEARCH_PATH = "/v1/places:searchText"
FIELD_MASK = ",".join(f"places.{field}" for field in (
    "id", "displayName", "formattedAddress", "addressComponents", "location", "websiteUri",
    "nationalPhoneNumber", "internationalPhoneNumber", "googleMapsUri", "businessStatus",
))
PAGE_SIZE = 20
# The emirate of Abu Dhabi (Abu Dhabi city, Al Ain and Al Dhafra), the area Abu Dhabi
# Police covers: south-west and north-east corners of the rectangle the search is
# restricted to. It also reaches into southern Dubai and Al Buraimi (Oman), so a listing
# counts only when Google gives Abu Dhabi as its emirate, in English or Arabic.
ABU_DHABI_VIEWPORT = {"low": {"latitude": 22.6, "longitude": 51.5}, "high": {"latitude": 25.25, "longitude": 56.05}}
ABU_DHABI_NAMES = frozenset({"Abu Dhabi", "أبو ظبي", "أبوظبي"})
TIMEOUT = 30.0
UAE_CODE = "971"
_PAREN = re.compile(r"\s*\(([^)]*)\)")
_ARABIC_FOLD = str.maketrans({"أ": "ا", "إ": "ا", "آ": "ا", "ة": "ه", "ى": "ي", "ـ": None})
_HARAKAT = re.compile("[ً-ْ]")

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Query:
    text: str
    language: str  # en or ar, the language listing names come back in


GOVERNMENT_QUERIES = (
    Query("pay traffic fine Abu Dhabi", "en"),
    Query("دفع المخالفات المرورية أبوظبي", "ar"),
    Query("pay traffic fine Al Ain", "en"),
    Query("دفع المخالفات المرورية العين", "ar"),
    Query("pay traffic fine Al Dhafra", "en"),
    Query("دفع المخالفات المرورية الظفرة", "ar"),
)


@dataclass(frozen=True)
class Lead:
    place_id: str
    brand: str  # the brand's English name
    reasons: tuple[str, ...]  # "website", "helpline"
    name: str
    address: str
    phone: str  # E.164
    official_phones: tuple[str, ...]  # the brand's verified numbers, E.164
    website: str  # normalised
    maps_url: str

    def row(self, query: Query) -> dict[str, str]:
        return {"place_id": self.place_id, "query": query.text, "brand": self.brand,
                "reasons": ",".join(self.reasons), "name": self.name, "address": self.address,
                "phone": self.phone, "official_phones": ",".join(self.official_phones),
                "website": self.website, "maps_url": self.maps_url}


def e164(raw: str) -> str:
    """A phone number in E.164 form (+97141234567), read in any digit script.
    A number without a country code is a UAE one: a national 04 ..., or a short,
    toll-free or unified number as brands publish them (999, 800 ..., 600 ...).
    Empty when there is no digit."""
    text = raw.strip().lstrip("(")
    digits = "".join(str(int(c)) for c in text if c.isdecimal())
    if not digits:
        return ""
    if text.startswith("+"):
        return "+" + digits
    if digits.startswith("00"):
        return "+" + digits[2:]
    if digits.startswith(UAE_CODE) and len(digits) >= 11:
        return "+" + digits
    return "+" + UAE_CODE + digits.removeprefix("0")


def _fold(text: str) -> str:
    """Lower case, Arabic letter variants and diacritics folded, single spaces."""
    return " ".join(_HARAKAT.sub("", text.lower()).translate(_ARABIC_FOLD).split())


@lru_cache(maxsize=1)
def _helpline_patterns() -> tuple[re.Pattern[str], ...]:
    words = yaml.safe_load((DATA_DIR / "wording.yaml").read_text(encoding="utf-8"))["helpline_claims"]
    english = [re.compile(rf"(?<!\w){re.escape(_fold(w))}(?!\w)") for w in words["en"]]
    arabic = [re.compile(re.escape(_fold(w))) for w in words["ar"]]
    return (*english, *arabic)


def claims_helpline(name: str) -> bool:
    """Whether a listing's name presents it as a helpline, in English or Arabic."""
    folded = _fold(name)
    return any(p.search(folded) for p in _helpline_patterns())


def named_brands(text: str) -> list[Brand]:
    """The watched brands named in a listing's name."""
    return [brand for brand, _ in signals.find_brands(text, WATCHED_SCOPES)]


def search_name(brand: Brand) -> str | None:
    """The name to search for: the short name in brackets (ADCB, Dubai RTA,
    Etisalat), else the full name, whichever the listing check finds in a name;
    None when it finds neither (noon and du are everyday words)."""
    short = _PAREN.search(brand.name_en)
    names = ([short.group(1)] if short else []) + [_PAREN.sub("", brand.name_en)]
    return next((n for n in names if brand in named_brands(n)), None)


@lru_cache(maxsize=1)
def queries() -> tuple[Query, ...]:
    """Every search, in rotation order: the government services, each watched
    brand's customer service in English, then in Arabic, then its service centre."""
    names = [(brand, search_name(brand)) for brand in watched_brands()]
    return (
        *GOVERNMENT_QUERIES,
        *(Query(f"{name} customer service", "en") for _, name in names if name),
        *(Query(f"{brand.name_ar} خدمة العملاء", "ar") for brand, _ in names if brand.name_ar),
        *(Query(f"{name} service center", "en") for _, name in names if name),
    )


def _name(place: dict[str, Any]) -> str:
    display = place.get("displayName")
    return str(display.get("text") or "") if isinstance(display, dict) else ""


def classify(place: dict[str, Any]) -> Lead | None:
    """The lead in one Text Search listing; None when it names no watched brand,
    is permanently closed, or gives only the brand's own website and numbers."""
    name = _name(place)
    named = named_brands(name)
    if not named or place.get("businessStatus") == "CLOSED_PERMANENTLY":
        return None
    website = normalize_url(str(place["websiteUri"])) if place.get("websiteUri") else ""
    phone = e164(str(place.get("internationalPhoneNumber") or place.get("nationalPhoneNumber") or ""))
    with_phones = [b for b in named if b.phones]
    official = tuple(sorted({e164(p) for b in with_phones for p in b.phones}))
    reasons = []
    if website and brands.allowlist([website]) is None:
        reasons.append("website")
    if phone and official and phone not in official and claims_helpline(name):
        reasons.append("helpline")
    if not reasons:
        return None
    brand = with_phones[0] if "helpline" in reasons else named[0]
    return Lead(str(place["id"]), brand.name_en, tuple(reasons), name, str(place.get("formattedAddress") or ""),
                phone, official, website, str(place.get("googleMapsUri") or ""))


@dataclass(frozen=True)
class Listing:
    """A listing as the live panel shows it. In memory only, never stored."""
    name: str
    lat: float | None
    lng: float | None
    outcome: str  # lead, brand_ok or other
    lead: Lead | None

    @classmethod
    def of(cls, place: dict[str, Any], lead: Lead | None) -> Listing:
        """`lead` is `classify(place)`. A listing that names a watched brand and is no
        lead (its website and number check out) is `brand_ok`."""
        name = _name(place)
        location = place.get("location")
        lat, lng = (location.get("latitude"), location.get("longitude")) if isinstance(location, dict) else (None, None)
        located = all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in (lat, lng))
        return cls(name, float(lat) if located else None, float(lng) if located else None,
                   "lead" if lead else "brand_ok" if named_brands(name) else "other", lead)


@dataclass(frozen=True)
class Search:
    query: Query
    sent_at: str  # ISO-8601 UTC
    listings: tuple[Listing, ...] | None = None  # None while the request is in flight
    failed: bool = False  # the API gave no usable answer


class LiveSearches:
    """The searches of the last round and the one under way, for the dashboard of
    the same process (`baaz up`). Held in memory only: Google's terms do not let
    Baaz store listing names. One round runs at a time, whoever starts it."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._round = threading.Lock()  # held while a round runs
        self._searches: deque[Search] = deque(maxlen=QUERIES_PER_RUN + 1)
        self.stop: threading.Event | None = None  # the watcher's, when it runs Maps in this process
        self.ended_at: str | None = None  # when the last round in this process ended, ISO-8601 UTC

    def attach(self, stop: threading.Event) -> None:
        """Called by the watcher that runs the Maps collector in this process."""
        self.stop = stop

    @property
    def attached(self) -> bool:
        return self.stop is not None and not self.stop.is_set()

    def begin(self) -> bool:
        """Claim the round; False when one is under way."""
        return self._round.acquire(blocking=False)

    def end(self) -> None:
        """Release the round when it has run."""
        self.ended_at = utcnow()
        self._round.release()

    def cancel(self) -> None:
        """Release a round claimed but not run."""
        self._round.release()

    def sent(self, query: Query) -> None:
        with self._lock:
            self._searches.append(Search(query, utcnow()))

    def answered(self, listings: tuple[Listing, ...] | None) -> None:
        """The answer to the search in flight, if any; None when there was no usable one."""
        with self._lock:
            if self._searches and self._searches[-1].listings is None:
                last = self._searches.pop()
                self._searches.append(replace(last, listings=listings or (), failed=listings is None))

    def snapshot(self) -> tuple[bool, list[Search]]:
        """Whether a round is under way, and the searches kept, oldest first."""
        with self._lock:
            return self._round.locked(), list(self._searches)


live = LiveSearches()


def _today() -> str:
    return datetime.now(GST).date().isoformat()


def calls_today(store: Store) -> int:
    """Searches sent today (GST), by every process using this store."""
    day, _, count = (store.get_meta(CALLS) or "").partition(" ")
    return int(count) if day == _today() and count.isdigit() else 0


def _count_call(store: Store) -> None:
    store.set_meta(CALLS, f"{_today()} {calls_today(store) + 1}")


def _error_message(data: Any) -> str:
    error = data.get("error") if isinstance(data, dict) else None
    return str(error.get("message") or "") if isinstance(error, dict) else ""


def search(client: httpx.Client, query: Query) -> list[dict[str, Any]] | None:
    """The listings on the first result page; None when the API gave no usable answer."""
    body = {"textQuery": query.text, "languageCode": query.language, "regionCode": "AE",
            "pageSize": PAGE_SIZE, "locationRestriction": {"rectangle": ABU_DHABI_VIEWPORT}}
    try:
        resp = client.post(SEARCH_PATH, json=body)
    except httpx.HTTPError as exc:
        log.info("maps: the Places API did not answer %r (%s); no more searches this run",
                 query.text, type(exc).__name__)
        return None
    try:
        data = resp.json()
    except ValueError:
        data = None
    if resp.status_code != 200 or not isinstance(data, dict):
        log.info("maps: the Places API answered HTTP %s to %r: %s; no more searches this run",
                 resp.status_code, query.text, _error_message(data) or "no error message")
        return None
    places = data.get("places")
    return [p for p in places if isinstance(p, dict) and p.get("id") and in_abu_dhabi(p)] \
        if isinstance(places, list) else []


def in_abu_dhabi(place: dict[str, Any]) -> bool:
    """Whether Google gives the emirate of Abu Dhabi as the listing's first-level area."""
    return any(isinstance(part, dict) and "administrative_area_level_1" in (part.get("types") or [])
               and part.get("longText") in ABU_DHABI_NAMES for part in place.get("addressComponents") or [])


def _log_lead(lead: Lead) -> None:
    why = []
    if "website" in lead.reasons:
        why.append(f"website {defang_text(lead.website)} is not on its official domains")
    if "helpline" in lead.reasons:
        why.append(f"claims a helpline on {lead.phone}, not one of its verified numbers "
                   f"({', '.join(lead.official_phones)})")
    log.info("maps lead: %s names %s: %s", defang_text(lead.name), lead.brand, "; ".join(why))


def collect(store: Store, limits: Limits) -> int:
    """The watcher's Maps round; skipped while a round started from the dashboard runs."""
    if not live.begin():
        log.info("maps: a round started from the dashboard is under way; this one is skipped")
        return 0
    try:
        return run_round(store, limits)
    finally:
        live.end()


def run_round(store: Store, limits: Limits) -> int:
    """One round of searches, for a caller holding `live.begin()`; returns the
    number of lead websites queued for the scorer."""
    settings = load_settings()
    added = 0
    try:
        throttle = Throttle(limits.rate)
        searches = Limits(min(QUERIES_PER_RUN, limits.max_per_run), limits.rate, limits.stop)
        headers = {"X-Goog-Api-Key": settings.google_maps_api_key, "X-Goog-FieldMask": FIELD_MASK,
                   "User-Agent": "baaz-watch"}
        with httpx.Client(base_url=settings.google_maps_api_base, timeout=TIMEOUT, headers=headers) as client:
            for query in rotation(store, CURSOR, queries(), searches):
                throttle.wait()
                live.sent(query)
                _count_call(store)
                places = search(client, query)
                if places is None:
                    live.answered(None)
                    break
                listings, new, leads = [], 0, 0
                for place in places:
                    lead = classify(place)
                    listings.append(Listing.of(place, lead))
                    if store.maps_place_seen(str(place["id"])):
                        continue
                    new += 1
                    if lead and store.add_maps_lead(lead.row(query)):
                        leads += 1
                        _log_lead(lead)
                        if "website" in lead.reasons and store.enqueue(
                                lead.website, registrable_domain(lead.website), SOURCE,
                                f"Google Maps listing: {lead.name}"):
                            added += 1
                    store.mark_maps_place(str(place["id"]))
                live.answered(tuple(listings))
                log.info("maps: %r: %d listings, %d new, %d leads", query.text, len(places), new, leads)
    except Exception:  # noqa: BLE001 - a collector fails soft
        log.exception("maps: run failed")
        live.answered(None)
    return added
