"""URL and domain signals: lexical checks on every hop of the redirect chain,
brand and lookalike matching, risky TLDs and hosting platforms, plus the
registration, certificate and popularity facts of the landing domain. Page
signals: brands the page presents itself as, the sensitive fields it asks
for, where its forms send data, urgency wording, doorways and cloaking.

Each `*_findings` function is pure and returns the findings it would add;
`url_signals` runs them over a scan and records the results on the context.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

import yaml

from shaheen import brands
from shaheen.config import DATA_DIR
from shaheen.domains import host_of, is_ip, registrable_domain, split_host
from shaheen.models import Finding, ScanContext
from shaheen.page import PageFacts
from shaheen.resolve import SHORTENERS
from shaheen.score import COMMON_TOKEN_WEIGHTS, TELEGRAM_EXFIL_WEIGHT, TLD_SWAP_WEIGHT, weight_of

# Deceptive words (data/domain_words.yaml) of this many letters also count
# inside a longer token (adcblogin); shorter ones only as a whole token.
SUBSTRING_MIN = 5
MANY_SUBDOMAINS = 4
LONG_URL = 100
NEW_DOMAIN_7D_DAYS = 7
NEW_DOMAIN_30D_DAYS = 30
OLD_DOMAIN_DAYS = 2 * 365
NEW_CERT_DAYS = 14


@lru_cache(maxsize=1)
def _risky_tlds() -> frozenset[str]:
    return frozenset(yaml.safe_load((DATA_DIR / "tlds.yaml").read_text(encoding="utf-8"))["tlds"])


@lru_cache(maxsize=1)
def _top_sites() -> dict[str, int]:
    lines = (DATA_DIR / "top_sites.txt").read_text(encoding="utf-8").splitlines()
    domains = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
    return {domain: rank for rank, domain in enumerate(domains, start=1)}


def top_site_rank(domain: str) -> int | None:
    return _top_sites().get(domain)


def deceptive_words(host: str) -> list[str]:
    """Official- or urgent-sounding words in the host, outside its public suffix.
    Never reported for an official domain or a government namespace."""
    if is_ip(host) or brands.official_brand(host) or brands.gov_namespace(host):
        return []
    sub, label, _ = split_host(host)
    name = f"{sub}.{label}" if sub else label
    tokens = set(brands.split_tokens(name))
    return [w for w in brands.deceptive_terms() if w in tokens or (len(w) >= SUBSTRING_MIN and w in name)]


def lexical_findings(url: str, evidence: str) -> list[Finding]:
    """RAW_IP_HOST, AT_IN_URL, MANY_SUBDOMAINS, LONG_URL and DECEPTIVE_DOMAIN_WORDS for one URL."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    found = []
    if is_ip(host):
        found.append(Finding("RAW_IP_HOST", evidence, {"host": host}))
    if "@" in parts.netloc:
        found.append(Finding("AT_IN_URL", evidence))
    levels = 0 if is_ip(host) else len([p for p in split_host(host)[0].split(".") if p])
    if levels >= MANY_SUBDOMAINS:
        found.append(Finding("MANY_SUBDOMAINS", evidence, {"count": levels}))
    length = len(f"{parts.scheme}://{host}{parts.path}")
    if length > LONG_URL:
        found.append(Finding("LONG_URL", evidence, {"length": length}))
    words = deceptive_words(host)
    if words:
        found.append(Finding("DECEPTIVE_DOMAIN_WORDS", evidence, {"words": words}))
    return found


def domain_findings(url: str, evidence: str) -> list[Finding]:
    """RISKY_TLD and FREE_HOSTING for one URL."""
    host = host_of(url)
    found = []
    tld = host.rsplit(".", 1)[-1]
    if not is_ip(host) and tld in _risky_tlds():
        found.append(Finding("RISKY_TLD", evidence, {"tld": tld}))
    platform = brands.hosting_platform(url)
    if platform:
        found.append(Finding("FREE_HOSTING", evidence, {"platform": platform}))
    return found


def brand_findings(host: str, evidence: str) -> list[tuple[Finding, str | None]]:
    """LOOKALIKE_DOMAIN, BRAND_IN_DOMAIN and BRAND_GEO_DOMAIN for one host,
    each paired with the name of the brand behind it. A match on a common-word
    token counts at its reduced weight (COMMON_TOKEN_WEIGHTS); a common-word
    BRAND_IN_DOMAIN alone is too weak to name the impersonated brand, so it is
    paired with None."""
    found = []
    for m in brands.match_domain(host):
        if m.method in brands.LOOKALIKE_METHODS:
            code, params = "LOOKALIKE_DOMAIN", {"domain": host, "official": m.official, "method": m.method}
        elif m.method == "geo":
            code, params = "BRAND_GEO_DOMAIN", {"domain": host, "brand": m.brand.name_en, "place": m.place}
        else:
            code, params = "BRAND_IN_DOMAIN", {"domain": host, "brand": m.brand.name_en}
        weight = COMMON_TOKEN_WEIGHTS[code] if m.common else TLD_SWAP_WEIGHT if m.method == "tld_swap" else None
        name = None if m.common and code == "BRAND_IN_DOMAIN" else m.brand.name_en
        found.append((Finding(code, evidence, params, weight), name))
    return found


def _date(value: str | None) -> date | None:
    try:
        return date.fromisoformat(value[:10]) if value else None
    except ValueError:
        return None


def _datetime(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


def _created(whois: dict[str, Any], today: date) -> date | None:
    """The registration date; a date in the future is a bad record, so unknown."""
    created = _date(whois.get("created"))
    return created if created and created <= today else None


def age_findings(whois: dict[str, Any], today: date) -> list[Finding]:
    """NEW_DOMAIN_7D, NEW_DOMAIN_30D or DOMAIN_OLD from the registration date."""
    created = _created(whois, today)
    if created is None:
        return []
    days = (today - created).days
    evidence = "whois.json#created"
    if days < NEW_DOMAIN_7D_DAYS:
        return [Finding("NEW_DOMAIN_7D", evidence, {"days": days, "created": created.isoformat()})]
    if days < NEW_DOMAIN_30D_DAYS:
        return [Finding("NEW_DOMAIN_30D", evidence, {"days": days, "created": created.isoformat()})]
    if days > OLD_DOMAIN_DAYS:
        return [Finding("DOMAIN_OLD", evidence, {"years": days // 365})]
    return []


def cert_findings(cert: dict[str, Any], now: datetime) -> list[Finding]:
    """NEW_TLS_CERT when the certificate was issued under NEW_CERT_DAYS ago."""
    issued = _datetime(cert.get("not_before"))
    if issued is None:
        return []
    days = max((now - issued).days, 0)
    if days < NEW_CERT_DAYS:
        return [Finding("NEW_TLS_CERT", "cert.json#not_before", {"days": days})]
    return []


def intel_features(facts: dict[str, Any], now: datetime) -> dict[str, Any]:
    whois, dns, cert = facts.get("whois") or {}, facts.get("dns") or {}, facts.get("cert") or {}
    created, issued = _created(whois, now.date()), _datetime(cert.get("not_before"))
    return {
        "domain_age_days": (now.date() - created).days if created else None,
        "registrar": whois.get("registrar"),
        "asn": dns.get("asn"),
        "hosting_country": dns.get("country"),
        "cert_age_days": (now - issued).days if issued else None,
        "nxdomain": dns.get("nxdomain"),
    }


def _lands_without_detour(chain: list[str], final: str) -> bool:
    """True when every hop that is not a URL shortener is on the landing domain."""
    domains = {registrable_domain(url) for url in chain} - SHORTENERS
    return domains <= {final}


def url_signals(ctx: ScanContext, intel_by_domain: dict[str, dict[str, Any]]) -> None:
    """Add the URL and domain findings of a scan to `ctx`, with raw features.

    Lexical and brand signals look at every hop (brand and domain signals skip
    URL shorteners); registration, certificate and popularity signals look at
    the landing domain, aged from when the facts were collected
    (`ctx.as_of`). The landing domain only vouches for the link (TOP_SITE,
    DOMAIN_OLD) when it is not a URL shortener, no hop is on a hosting
    platform or carries another site's address (`?url=`), and the link reached
    it without passing through another domain.
    """
    chain = ctx.redirect_chain or [ctx.final_url]
    found: list[tuple[Finding, str | None]] = []
    for i, url in enumerate(chain):
        evidence = f"redirects.json#chain[{i}]"
        found += [(f, None) for f in lexical_findings(url, evidence)]
        if registrable_domain(url) in SHORTENERS:
            continue
        found += [(f, None) for f in domain_findings(url, evidence)]
        found += brand_findings(host_of(url), evidence)

    final = registrable_domain(ctx.final_url)
    platform = next((p for p in map(brands.hosting_platform, chain) if p), None)
    embedded = list(dict.fromkeys(target for url in chain for target in brands.embedded_targets(url)))
    vouched = (platform is None and not embedded and final not in SHORTENERS
               and _lands_without_detour(chain, final))
    facts = intel_by_domain.get(final) or {}
    if facts:
        found += [(f, None) for f in age_findings(facts["whois"], ctx.as_of.date())
                  if vouched or f.code != "DOMAIN_OLD"]
        found += [(f, None) for f in cert_findings(facts["cert"], ctx.as_of)]
    rank = top_site_rank(final)
    if rank and vouched:
        found.append((Finding("TOP_SITE", "redirects.json#final_url", {"domain": final, "rank": rank}), None))

    seen: set[tuple[str, str]] = set()
    for finding, _ in found:
        key = (finding.code, repr(sorted(finding.params.items())))
        if key not in seen:
            seen.add(key)
            ctx.findings.append(finding)
    branded = [(weight_of(f), name) for f, name in found if name]
    if branded:
        ctx.impersonated_brand = max(branded, key=lambda pair: pair[0])[1]
    ctx.features.update(intel_features(facts, ctx.as_of))
    ctx.features.update(top_site_rank=rank, hosting_platform=platform, embedded_targets=embedded)


# Page signals: what the page itself shows and asks for.

DOORWAY_TEXT = 200
CLOAK_FULL_TEXT = 500
CLOAK_EMPTY_TEXT = 100
CLOAK_EMPTY_HTML = 512
MAX_PAGE_BRANDS = 2  # a page naming more brands than this is a shop or a directory, not an impersonation
MAX_TERMS = 3
_PAREN = re.compile(r"\(([^)]*)\)")
_REDIRECT_CODE = re.compile(
    r"""location(?:\.href)?\s*=(?!=)|location\.(?:replace|assign)\s*\(|http-equiv\s*=\s*["']?refresh""", re.I)
_CHALLENGE_TEXT = re.compile(
    r"just a moment|attention required|checking your browser|verify you are (a )?human|are you a robot"
    r"|captcha|ddos protection|access denied|request blocked|security check|enable javascript and cookies",
    re.I,
)
_CHALLENGE_HTML = re.compile(r"_cf_chl_opt|cf-chl-|_incapsula_resource|sgcaptcha|px-captcha", re.I)
_TELEGRAM_BOT = re.compile(r"api\.telegram\.org/bot", re.I)


@dataclass(frozen=True)
class BrandOnPage:
    brand: brands.Brand
    where: str  # title, site_name, h1, logo or text
    term: str


def _name_parts(brand: brands.Brand) -> list[str]:
    """Display names of a brand worth finding on a page: `Abu Dhabi Commercial
    Bank (ADCB)` gives both names, `Meta / Facebook` both halves. A name that is
    an ordinary word (one of the brand's common tokens: Emirates, Visa, noon)
    or a place (the UAE in `Ministry of Interior (UAE)`) is left out, since it
    turns up in ordinary text."""
    inner = [p for group in _PAREN.findall(brand.name_en) for p in group.split(",")]
    outer = _PAREN.sub("", brand.name_en).split("/")
    parts = [p.strip() for p in outer + inner]
    return [p for p in parts if len(p) >= 3 and p.lower() not in brand.common_tokens
            and p.lower().replace(" ", "") not in _place_names()]


@lru_cache(maxsize=1)
def _place_names() -> frozenset[str]:
    data = yaml.safe_load((DATA_DIR / "countries.yaml").read_text(encoding="utf-8"))
    return frozenset({n for country in data["countries"] for n in country["names"]} | set(data["cities"]))


def _term_pattern(term: str) -> re.Pattern[str]:
    if re.search(r"[؀-ۿ]", term):
        return re.compile(re.escape(term))
    body = r"\s+".join(map(re.escape, term.split()))
    return re.compile(rf"(?<![\w&]){body}(?!\w)", re.I)


@lru_cache(maxsize=1)
def _wording() -> dict[str, Any]:
    return yaml.safe_load((DATA_DIR / "wording.yaml").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _page_terms() -> tuple[tuple[brands.Brand, tuple[tuple[str, re.Pattern[str]], ...]], ...]:
    ordinary = set(_wording()["ordinary_words"])
    out = []
    for brand in brands.load_brands():
        terms = _name_parts(brand) + [brand.name_ar] + list(brand.keywords) + list(brand.tokens)
        terms = [t for t in dict.fromkeys(terms) if len(t) >= 3 and t.lower() not in ordinary]
        out.append((brand, tuple((t, _term_pattern(t)) for t in terms)))
    return tuple(out)


def find_brands(text: str, scopes: tuple[str, ...] = ()) -> list[tuple[brands.Brand, str]]:
    """Brands named in `text`, each with the term as written; only brands of `scopes` when given."""
    found = []
    for brand, terms in _page_terms():
        if scopes and brand.scope not in scopes:
            continue
        for _, pattern in terms:
            m = pattern.search(text)
            if m:
                found.append((brand, m.group(0)))
                break
    return found


def _own_name_shown(facts: PageFacts, domain: str) -> bool:
    """Whether the page's title, site name, h1 or logo names its own domain (`GitHub` on github.com)."""
    label = split_host(domain)[1].replace("-", "")
    shown = re.sub(r"[\s\-]", "", " ".join([facts.title, facts.site_name, *facts.h1, *facts.logos]).lower())
    return len(label) >= 4 and label in shown


def brands_on_page(facts: PageFacts, domain: str) -> list[BrandOnPage]:
    """Brands the page presents itself as: named in its title, `og:site_name`,
    h1 or logo, or in the first 1,500 characters of its own text (links,
    buttons, menus and footers aside). The text only counts when the page
    names no site of its own (neither its domain's name nor an `og:site_name`),
    so a shop that mentions WhatsApp or Instagram in passing is not taken for
    them."""
    places = [("title", facts.title), ("site_name", facts.site_name),
              ("h1", " | ".join(facts.h1)), ("logo", " | ".join(facts.logos))]
    if not facts.site_name and not _own_name_shown(facts, domain):
        places.append(("text", facts.lead))
    found: dict[str, BrandOnPage] = {}
    for where, text in places:
        for brand, term in find_brands(text) if text else []:
            found.setdefault(brand.id, BrandOnPage(brand, where, term))
    return list(found.values())


def fields_for(brand: brands.Brand, sensitive: set[str]) -> set[str]:
    """The sensitive fields worth stealing under this brand's name. A login on
    a product-brand page is the shop's own account, so product brands count
    card fields only; card-network and wallet logos sit next to every card
    form, so payment brands count everything but card fields."""
    if brand.scope == "storefront":
        return sensitive & {"card"}
    if brand.category == "payments":
        return sensitive - {"card"}
    return set(sensitive)


def _form_index(facts: PageFacts, fields: set[str]) -> int:
    return next((i for i, f in enumerate(facts.forms) if f.sensitive() & fields), 0)


@lru_cache(maxsize=1)
def _urgency_patterns() -> tuple[re.Pattern[str], ...]:
    data = _wording()["urgency"]
    return tuple(_term_pattern(p) for p in data["en"] + data["ar"])


def urgency_terms(text: str) -> list[str]:
    """Distinct urgency phrases (data/wording.yaml) in `text`, as written there."""
    return [m.group(0) for m in (p.search(text) for p in _urgency_patterns()) if m]


def exfiltration_targets(html: str) -> list[str]:
    """Data drops named in the page source: a Telegram bot API call."""
    return ["api.telegram.org"] if _TELEGRAM_BOT.search(html or "") else []


def page_findings(facts: PageFacts, final_url: str, html: str) -> tuple[list[Finding], str | None]:
    """SENSITIVE_FORM_BRAND, FORM_OFFSITE_POST and URGENCY_WORDING for a page,
    with the brand it impersonates."""
    domain = registrable_domain(final_url)
    sensitive = facts.sensitive_fields()
    found: list[Finding] = []
    impersonated = None
    named = brands_on_page(facts, domain)
    if sensitive and len(named) <= MAX_PAGE_BRANDS:
        for hit in named:
            fields = fields_for(hit.brand, sensitive)
            if fields and domain not in hit.brand.official_domains:
                found.append(Finding("SENSITIVE_FORM_BRAND", f"page.json#forms[{_form_index(facts, fields)}]",
                                     {"brand": hit.brand.name_en, "fields": sorted(fields)}))
                impersonated = hit.brand.name_en
                break
    for i, form in enumerate(facts.forms):
        target = registrable_domain(form.action) if form.action.startswith("http") else domain
        if (form.sensitive() and target != domain
                and not (brands.official_brand(target) or brands.gov_namespace(target))):
            found.append(Finding("FORM_OFFSITE_POST", f"page.json#forms[{i}]", {"target": target}))
            break
    for target in exfiltration_targets(html):
        found.append(Finding("FORM_OFFSITE_POST", "page.json#exfiltration", {"target": target}, TELEGRAM_EXFIL_WEIGHT))
    terms = urgency_terms(facts.text)
    if len(terms) >= 2 or (terms and sensitive):
        found.append(Finding("URGENCY_WORDING", "page.json#urgency_terms", {"terms": terms[:MAX_TERMS]}))
    return found, impersonated


def doorway_findings(chain: list[dict[str, Any]]) -> list[Finding]:
    """DOORWAY: a near-empty page whose meta refresh or script (seen by the HTTP
    fetch or the browser) sends the visitor to another registrable domain.
    `chain` is the `redirects.json` chain; plain HTTP redirects never count."""
    for i in range(1, len(chain)):
        prev, hop = chain[i - 1], chain[i]
        source, target = registrable_domain(prev["url"]), registrable_domain(hop["url"])
        if (hop["via"] in ("meta", "script", "browser") and prev.get("text_len") is not None
                and prev["text_len"] < DOORWAY_TEXT and source != target and source not in SHORTENERS):
            return [Finding("DOORWAY", f"redirects.json#chain[{i}]", {"target": target})]
    return []


def is_challenge(title: str, text: str, html: str) -> bool:
    """A bot check or block page instead of the site (Cloudflare, Incapsula and the like)."""
    return bool(_CHALLENGE_TEXT.search(f"{title} {text[:500]}") or _CHALLENGE_HTML.search(html[:200_000]))


def profile_view(res: Any, facts: PageFacts) -> dict[str, Any]:
    """The `profiles.json` entry for one visitor profile's fetch (a `resolve.Resolution`)."""
    html = res.html or ""
    return {
        "final_url": res.final_url,
        "domain": registrable_domain(res.final_url),
        "status": res.status_code,
        "fetch_status": res.fetch_status,
        "text_len": facts.text_len,
        "title": facts.title[:200],
        "redirected": any(h.via in ("meta", "script") for h in res.hops),
        "redirect_code": bool(_REDIRECT_CODE.search(html)),
        "empty_html": len(html.strip()) < CLOAK_EMPTY_HTML,
        "challenge": is_challenge(facts.title, facts.text, html),
    }


def cloaking_findings(profiles: dict[str, dict[str, Any]]) -> list[Finding]:
    """CLOAKING: visitor profiles land on different sites, or one gets a full
    page while another gets an empty or redirecting one. Profiles that were
    blocked or shown a bot check do not count (Cloudflare blocks fake crawlers
    on real sites), and the same name under another suffix (a language or
    country site) is not a different site."""
    usable = {k: p for k, p in profiles.items()
              if p["fetch_status"] == "ok" and not p["challenge"] and p["domain"] not in SHORTENERS}
    if len(usable) < 2:
        return []
    label = {k: split_host(p["domain"])[1] or p["domain"] for k, p in usable.items()}
    if len(set(label.values())) > 1:
        ref = next(k for k in ("crawler", "desktop", "mobile_ar") if k in usable)
        odd = [k for k in usable if label[k] != label[ref]]
        return [Finding("CLOAKING", f"profiles.json#{odd[0]}", {"profiles": odd})]
    full = [k for k, p in usable.items() if p["status"] == 200 and p["text_len"] >= CLOAK_FULL_TEXT]
    empty = [k for k, p in usable.items()
             if p["status"] and 200 <= p["status"] < 300 and p["text_len"] < CLOAK_EMPTY_TEXT
             and (p["redirected"] or p["redirect_code"] or p["empty_html"])]
    if full and empty:
        return [Finding("CLOAKING", f"profiles.json#{empty[0]}", {"profiles": empty})]
    return []
