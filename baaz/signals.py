"""URL and domain signals: lexical checks on every hop of the redirect chain,
brand and lookalike matching, risky TLDs and hosting platforms, plus the
registration, certificate and popularity facts of the landing domain.

Each `*_findings` function is pure and returns the findings it would add;
`url_signals` runs them over a scan and records the results on the context.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

import yaml

from baaz import brands
from baaz.config import DATA_DIR
from baaz.domains import host_of, is_ip, registrable_domain, split_host
from baaz.models import Finding, ScanContext
from baaz.resolve import SHORTENERS
from baaz.score import weight_of

# Words that make a host look official or urgent. Words of 5+ letters also
# count inside a longer token (adcblogin); shorter ones only as a whole token.
DECEPTIVE_WORDS = (
    "login", "signin", "verify", "secure", "account", "update", "confirm", "wallet", "refund",
    "fine", "fines", "gov", "portal", "reward", "claim", "unlock", "support", "payment",
    "pay", "otp", "kyc",
)
SUBSTRING_MIN = 5
MANY_SUBDOMAINS = 4
LONG_URL = 100
NEW_DOMAIN_7D_DAYS = 7
NEW_DOMAIN_30D_DAYS = 30
OLD_DOMAIN_DAYS = 2 * 365
NEW_CERT_DAYS = 14

_TOKEN_SPLIT = re.compile(r"[-.\d]+")


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
    tokens = set(_TOKEN_SPLIT.split(name))
    return [w for w in DECEPTIVE_WORDS if w in tokens or (len(w) >= SUBSTRING_MIN and w in name)]


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


def brand_findings(host: str, evidence: str) -> list[tuple[Finding, str]]:
    """LOOKALIKE_DOMAIN, BRAND_IN_DOMAIN and BRAND_GEO_DOMAIN for one host,
    each paired with the name of the brand behind it."""
    found = []
    for m in brands.match_domain(host):
        if m.method in brands.LOOKALIKE_METHODS:
            finding = Finding("LOOKALIKE_DOMAIN", evidence,
                              {"domain": host, "official": m.official, "method": m.method})
        elif m.method == "geo":
            finding = Finding("BRAND_GEO_DOMAIN", evidence,
                              {"domain": host, "brand": m.brand.name_en, "place": m.place})
        else:
            finding = Finding("BRAND_IN_DOMAIN", evidence, {"domain": host, "brand": m.brand.name_en})
        found.append((finding, m.brand.name_en))
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


def age_findings(whois: dict[str, Any], today: date) -> list[Finding]:
    """NEW_DOMAIN_7D, NEW_DOMAIN_30D or DOMAIN_OLD from the registration date."""
    created = _date(whois.get("created"))
    if created is None:
        return []
    days = max((today - created).days, 0)
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
    created, issued = _date(whois.get("created")), _datetime(cert.get("not_before"))
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
    the landing domain. The landing domain only vouches for the link (TOP_SITE,
    DOMAIN_OLD) when it is not a URL shortener, no hop is on a hosting
    platform, and the link reached it without passing through another domain.
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
    vouched = platform is None and final not in SHORTENERS and _lands_without_detour(chain, final)
    facts = intel_by_domain.get(final) or {}
    if facts:
        found += [(f, None) for f in age_findings(facts["whois"], ctx.scanned_at.date())
                  if vouched or f.code != "DOMAIN_OLD"]
        found += [(f, None) for f in cert_findings(facts["cert"], ctx.scanned_at)]
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
    ctx.features.update(intel_features(facts, ctx.scanned_at))
    ctx.features.update(top_site_rank=rank, hosting_platform=platform)
