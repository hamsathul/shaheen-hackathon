"""Brand data and domain matching: the official-domain allowlist, restricted
government namespaces, hosting platforms, and lookalike detection of a host
against every brand's official domains, keywords and tokens.

Each brand in `data/brands_*.yaml` lists `official_domains`, `keywords`
(distinctive strings, matched anywhere inside a domain label) and `tokens`
(short or common words, matched only as a whole token, or glued to a place
name for BRAND_GEO_DOMAIN).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

import yaml
from rapidfuzz.distance import OSA

from baaz.config import DATA_DIR
from baaz.domains import is_ip, registrable_domain, split_host
from baaz.resolve import SHORTENERS

BRAND_FILES = ("brands_uae.yaml", "brands_global.yaml", "brands_storefront.yaml")

# Lookalike methods (LOOKALIKE_DOMAIN), most specific first. Other match
# methods: "mention" (BRAND_IN_DOMAIN) and "geo" (BRAND_GEO_DOMAIN).
LOOKALIKE_METHODS = ("punycode", "homoglyph", "subdomain_spoof", "tld_swap", "typo", "combo")

# Characters that render like an ASCII letter, mapped to that letter.
_CONFUSABLES = str.maketrans({
    # Cyrillic
    "а": "a", "в": "b", "ь": "b", "с": "c", "ԁ": "d", "е": "e", "ё": "e", "һ": "h", "н": "h",
    "і": "i", "ї": "i", "ј": "j", "к": "k", "ӏ": "l", "м": "m", "о": "o", "р": "p", "ԛ": "q",
    "г": "r", "ѕ": "s", "т": "t", "ԝ": "w", "х": "x", "у": "y", "ү": "y",
    # Greek
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "γ": "y", "ω": "w",
    # Latin look-alikes and digits
    "ı": "i", "ł": "l", "ɑ": "a", "ɡ": "g", "0": "o", "1": "l",
})
_TOKEN_SPLIT = re.compile(r"[-.\d]+")
# Keywords this long also match across hyphens (dubai-police for dubaipolice);
# shorter ones would match by accident (code-wars for dewa).
HYPHENATED_KEYWORD_MIN = 6


@dataclass(frozen=True)
class Brand:
    id: str
    name_en: str
    name_ar: str
    category: str
    official_domains: tuple[str, ...]
    keywords: tuple[str, ...]
    tokens: tuple[str, ...]


@dataclass(frozen=True)
class BrandMatch:
    method: str  # one of LOOKALIKE_METHODS, "mention" or "geo"
    brand: Brand
    official: str  # the official domain imitated; the brand's main domain for mention and geo
    matched: str  # the brand text found in the host
    place: str | None = None  # the country or city, for geo


@dataclass(frozen=True)
class Allowed:
    code: str  # OFFICIAL_DOMAIN or GOV_NAMESPACE
    owner: str  # the brand name, or the domain for a government namespace
    params: dict[str, Any]


@dataclass(frozen=True)
class _Places:
    names: tuple[str, ...]  # longest first, so "saudiarabia" wins over "saudi"
    codes: frozenset[str]  # two-letter codes that count as whole tokens
    glued_codes: frozenset[str]  # two-letter codes that also count glued after a brand


def _read(name: str) -> Any:
    return yaml.safe_load((DATA_DIR / name).read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_brands() -> tuple[Brand, ...]:
    brands = []
    for name in BRAND_FILES:
        for b in _read(name)["brands"]:
            brands.append(Brand(
                id=b["id"],
                name_en=b["name_en"],
                name_ar=b.get("name_ar") or "",
                category=b["category"],
                official_domains=tuple(dict.fromkeys(registrable_domain(d) for d in b["official_domains"])),
                keywords=tuple(k.lower() for k in b.get("keywords") or ()),
                tokens=tuple(t.lower() for t in b.get("tokens") or ()),
            ))
    return tuple(brands)


@lru_cache(maxsize=1)
def _official_index() -> dict[str, Brand]:
    index: dict[str, Brand] = {}
    for brand in load_brands():
        for domain in brand.official_domains:
            index.setdefault(domain, brand)
    return index


@lru_cache(maxsize=1)
def _namespaces() -> tuple[str, ...]:
    return tuple(sorted(_read("namespaces.yaml")["namespaces"], key=len, reverse=True))


@lru_cache(maxsize=1)
def _hosting() -> tuple[tuple[str, ...], tuple[tuple[str, str], ...]]:
    data = _read("hosting_platforms.yaml")
    urls = []
    for entry in data["urls"]:
        host, slash, path = entry.partition("/")
        urls.append((host, slash + path))
    return tuple(data["suffixes"]), tuple(urls)


@lru_cache(maxsize=1)
def _places() -> _Places:
    data = _read("countries.yaml")
    names = {n for country in data["countries"] for n in country["names"]} | set(data["cities"])
    codes = {c for country in data["countries"] for c in country["codes"]} - set(data["ambiguous_codes"])
    return _Places(tuple(sorted(names, key=len, reverse=True)), frozenset(codes), frozenset(data["glued_codes"]))


def official_brand(domain: str) -> Brand | None:
    """The brand owning this URL, host or domain's registrable domain."""
    return _official_index().get(registrable_domain(domain))


def gov_namespace(domain: str) -> str | None:
    """The restricted government namespace (`gov.ae`) this domain sits in."""
    registrable = registrable_domain(domain)
    return next((ns for ns in _namespaces() if registrable.endswith("." + ns)), None)


def hosting_platform(url: str) -> str | None:
    """The free-hosting, site-builder, form or file-sharing platform serving `url`."""
    parts = urlsplit(url)
    host = (parts.hostname or "").rstrip(".")
    suffixes, urls = _hosting()
    for suffix in suffixes:
        if host.endswith("." + suffix):
            return suffix
    bare = host.removeprefix("www.")
    path = parts.path or "/"
    for platform_host, prefix in urls:
        if bare == platform_host and (not prefix or path == prefix or path.startswith(prefix + "/")):
            return platform_host + prefix
    return None


def allowlist(chain: list[str]) -> Allowed | None:
    """Whether a redirect chain (its last URL is where the link landed) is official.

    The landing domain must be official or in a government namespace, and every
    domain on the way must be official (any brand), in a government namespace,
    a URL shortener, or the landing brand's own name under another suffix (a
    defensive registration). A URL on a hosting platform is never allowlisted.
    """
    if any(hosting_platform(url) for url in chain):
        return None
    final = registrable_domain(chain[-1])
    brand = official_brand(final)
    namespace = None if brand else gov_namespace(final)
    if brand is None and namespace is None:
        return None
    own_labels = {split_host(d)[1] for d in brand.official_domains} if brand else set()
    for url in chain:
        domain = registrable_domain(url)
        if not (official_brand(domain) or gov_namespace(domain) or domain in SHORTENERS
                or split_host(domain)[1] in own_labels):
            return None
    if brand:
        return Allowed("OFFICIAL_DOMAIN", brand.name_en, {"domain": final, "brand": brand.name_en})
    return Allowed("GOV_NAMESPACE", final, {"domain": final, "suffix": namespace})


def skeleton(text: str) -> str:
    """Map look-alike characters to the ASCII letters they imitate."""
    text = unicodedata.normalize("NFKD", text.lower())
    text = "".join(c for c in text if not unicodedata.combining(c)).translate(_CONFUSABLES)
    return text.replace("rn", "m").replace("vv", "w")


def _unicode_label(label: str) -> str:
    if not label.startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except UnicodeError:
        return label


def _tokens(text: str) -> list[str]:
    return [t for t in _TOKEN_SPLIT.split(text) if t]


@dataclass(frozen=True)
class _Host:
    """A host name cut into the pieces the matchers need."""

    host: str
    sub: str
    label: str
    suffix: str
    skeleton: str  # skeleton of the registrable label, decoded from punycode
    token_runs: tuple[tuple[str, ...], ...]  # tokens of subdomain + label, raw and skeleton

    @classmethod
    def of(cls, host: str) -> _Host:
        sub, label, suffix = split_host(host)
        name = f"{sub}.{label}" if sub else label
        runs = (tuple(_tokens(name)), tuple(_tokens(skeleton(name))))
        return cls(host, sub, label, suffix, skeleton(_unicode_label(label)), tuple(dict.fromkeys(runs)))

    @property
    def prefix(self) -> str:
        """The host without its public suffix."""
        return self.host[: -len(self.suffix) - 1] if self.suffix else self.host

    @property
    def token_set(self) -> set[str]:
        return {t for run in self.token_runs for t in run}

    def homoglyph_skeletons(self) -> set[str]:
        return {self.skeleton, skeleton(self.label.replace("1", "i"))}


@lru_cache(maxsize=1024)
def _official_parts(official: str) -> tuple[str, str, str, re.Pattern[str]]:
    """(label, suffix, skeleton of label, pattern finding the domain inside another host)."""
    _, label, suffix = split_host(official)
    spoof = re.compile(rf"(?:^|[.-]){re.escape(official)}(?:[.-]|$)")
    return label, suffix, skeleton(label), spoof


def is_typo(label: str, official: str) -> bool:
    """One edit away (two for official labels of 8+ characters), transpositions
    counting as one. Never below 5 characters; the first letter must match and
    the lengths differ by at most one, which keeps unrelated words out."""
    n = len(official)
    if n < 5 or len(label) < 5 or label[0] != official[0] or abs(len(label) - n) > 1:
        return False
    limit = 1 if n <= 7 else 2
    return 0 < OSA.distance(label, official, score_cutoff=limit) <= limit


def _lookalike(brand: Brand, h: _Host) -> BrandMatch | None:
    for official in brand.official_domains:
        label, suffix, official_skeleton, spoof = _official_parts(official)
        if h.label.startswith("xn--") and h.skeleton == official_skeleton:
            return BrandMatch("punycode", brand, official, h.label)
        if h.label != label and official_skeleton in h.homoglyph_skeletons():
            return BrandMatch("homoglyph", brand, official, h.label)
        if spoof.search(h.prefix):
            return BrandMatch("subdomain_spoof", brand, official, official)
        if h.label == label and h.suffix != suffix and any(k in label for k in brand.keywords):
            return BrandMatch("tld_swap", brand, official, h.label)
        if label not in brand.tokens and is_typo(h.label, label):
            return BrandMatch("typo", brand, official, h.label)
    for keyword in brand.keywords:
        if any(_contains(text, keyword) for text in (h.label, h.skeleton)):
            return BrandMatch("combo", brand, brand.official_domains[0], keyword)
    return None


def _contains(label: str, keyword: str) -> bool:
    if keyword in label:
        return True
    return len(keyword) >= HYPHENATED_KEYWORD_MIN and keyword in label.replace("-", "")


def _place_among(tokens: tuple[str, ...]) -> str | None:
    """A country or city written as whole tokens, possibly split by hyphens."""
    places = _places()
    for size in (3, 2, 1):
        for i in range(len(tokens) - size + 1):
            joined = "".join(tokens[i:i + size])
            if joined in places.names or (size == 1 and joined in places.codes):
                return joined
    return None


def _glued_place(before: str, after: str, term: str, exact: bool) -> str | None:
    """The place written straight before or after a brand term inside one token."""
    places = _places()
    if after and len(term) >= 3 and after in places.glued_codes:
        return after
    for name in places.names:
        if after and (after == name or (not exact and after.startswith(name))):
            return name
        if before and (before == name or (not exact and before.endswith(name))):
            return name
    return None


def _geo(brand: Brand, h: _Host) -> BrandMatch | None:
    """A brand keyword or token together with a country or city."""
    for run in h.token_runs:
        whole_place = _place_among(run)
        for term in brand.keywords + brand.tokens:
            is_keyword = term in brand.keywords
            for token in run:
                at = token.find(term)
                if at < 0:
                    continue
                before, after = token[:at], token[at + len(term):]
                if not is_keyword and before and after:
                    continue
                place = _glued_place(before, after, term, exact=not is_keyword)
                if place is None and (token == term or is_keyword):
                    place = whole_place
                if place:
                    return BrandMatch("geo", brand, brand.official_domains[0], term, place)
    return None


def _mention(brand: Brand, h: _Host, geo: BrandMatch | None) -> BrandMatch | None:
    """The brand named in the host without imitating an official domain."""
    main = brand.official_domains[0]
    tokens = h.token_set
    for token in brand.tokens:
        if token in tokens:
            return BrandMatch("mention", brand, main, token)
    for keyword in brand.keywords:
        if keyword in h.sub:
            return BrandMatch("mention", brand, main, keyword)
    if geo:
        return BrandMatch("mention", brand, main, geo.matched)
    return None


def match_domain(host: str) -> list[BrandMatch]:
    """Every brand this host imitates (lookalike), names (mention) or pairs with a place (geo).

    Official domains and government namespaces never match.
    """
    host = host.lower().rstrip(".")
    if not host or is_ip(host) or official_brand(host) or gov_namespace(host):
        return []
    h = _Host.of(host)
    if not h.label:
        return []
    matches = []
    for brand in load_brands():
        geo = _geo(brand, h)
        found = _lookalike(brand, h) or _mention(brand, h, geo)
        matches.extend(m for m in (found, geo) if m)
    return matches
