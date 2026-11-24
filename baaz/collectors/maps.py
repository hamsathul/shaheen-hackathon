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

Each run sends at most `QUERIES_PER_RUN` searches, one request each for the
first page of up to 20 listings (no further pages), rotating through
victim-style queries built from the brand data after a few fixed
government-service searches. The watcher runs it every
`BAAZ_MAPS_INTERVAL_HOURS` (6 by default). The request asks for the fields
used here only; the website and phone fields put it in Google's Text Search
Enterprise SKU.

It needs `GOOGLE_MAPS_API_KEY`; without one the watcher leaves it out.
`GOOGLE_MAPS_API_BASE` points it at another server speaking the same API,
such as a local stub.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import httpx
import yaml

from baaz import brands, signals
from baaz.brands import Brand
from baaz.collectors import WATCHED_SCOPES, Limits, Throttle, rotation, watched_brands
from baaz.config import DATA_DIR, load_settings
from baaz.domains import normalize_url, registrable_domain
from baaz.evidence import defang_text
from baaz.store import Store

SOURCE = "maps"
CURSOR = "maps:cursor"
QUERIES_PER_RUN = 6
SEARCH_PATH = "/v1/places:searchText"
FIELD_MASK = ",".join(f"places.{field}" for field in (
    "id", "displayName", "formattedAddress", "websiteUri", "nationalPhoneNumber", "internationalPhoneNumber",
    "googleMapsUri", "businessStatus",
))
PAGE_SIZE = 20
# The UAE's bounding box, south-west and north-east corners. A bias: Text Search
# restricts results to an area only for categorical queries, and these name a business.
UAE_VIEWPORT = {"low": {"latitude": 22.6, "longitude": 51.5}, "high": {"latitude": 26.1, "longitude": 56.4}}
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
    Query("pay traffic fine Dubai", "en"),
    Query("دفع المخالفات المرورية دبي", "ar"),
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


def classify(place: dict[str, Any]) -> Lead | None:
    """The lead in one Text Search listing; None when it names no watched brand,
    is permanently closed, or gives only the brand's own website and numbers."""
    display = place.get("displayName")
    name = str(display.get("text") or "") if isinstance(display, dict) else ""
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


def _error_message(data: Any) -> str:
    error = data.get("error") if isinstance(data, dict) else None
    return str(error.get("message") or "") if isinstance(error, dict) else ""


def search(client: httpx.Client, query: Query) -> list[dict[str, Any]] | None:
    """The listings on the first result page; None when the API gave no usable answer."""
    body = {"textQuery": query.text, "languageCode": query.language, "regionCode": "AE",
            "pageSize": PAGE_SIZE, "locationBias": {"rectangle": UAE_VIEWPORT}}
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
    return [p for p in places if isinstance(p, dict) and p.get("id")] if isinstance(places, list) else []


def _log_lead(lead: Lead) -> None:
    why = []
    if "website" in lead.reasons:
        why.append(f"website {defang_text(lead.website)} is not on its official domains")
    if "helpline" in lead.reasons:
        why.append(f"claims a helpline on {lead.phone}, not one of its verified numbers "
                   f"({', '.join(lead.official_phones)})")
    log.info("maps lead: %s names %s: %s", defang_text(lead.name), lead.brand, "; ".join(why))


def collect(store: Store, limits: Limits) -> int:
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
                places = search(client, query)
                if places is None:
                    break
                new = [p for p in places if not store.maps_place_seen(str(p["id"]))]
                leads = 0
                for place in new:
                    lead = classify(place)
                    if lead and store.add_maps_lead(lead.row(query)):
                        leads += 1
                        _log_lead(lead)
                        if "website" in lead.reasons and store.enqueue(
                                lead.website, registrable_domain(lead.website), SOURCE,
                                f"Google Maps listing: {lead.name}"):
                            added += 1
                    store.mark_maps_place(str(place["id"]))
                log.info("maps: %r: %d listings, %d new, %d leads", query.text, len(places), len(new), leads)
    except Exception:  # noqa: BLE001 - a collector fails soft
        log.exception("maps: run failed")
    return added
