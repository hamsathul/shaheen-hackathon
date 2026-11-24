from datetime import date, datetime, timedelta, timezone

import pytest

from baaz.models import ScanContext, ScanOptions
from baaz.signals import (
    age_findings,
    cert_findings,
    deceptive_words,
    domain_findings,
    lexical_findings,
    top_site_rank,
    url_signals,
)

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
TODAY = NOW.date()
EV = "redirects.json#chain[0]"


def codes(findings) -> dict[str, dict]:
    return {f.code: f.params for f in findings}


def context(chain: list[str]) -> ScanContext:
    return ScanContext(id="t", url=chain[0], scanned_at=NOW, options=ScanOptions(),
                       final_url=chain[-1], redirect_chain=chain)


def facts(created: str | None = None, not_before: str | None = None) -> dict:
    return {"whois": {"created": created, "registrar": None},
            "dns": {"asn": None, "country": None, "nxdomain": None},
            "cert": {"not_before": not_before}}


def test_raw_ip_host():
    assert codes(lexical_findings("http://192.168.1.10/login", EV))["RAW_IP_HOST"] == {"host": "192.168.1.10"}
    assert "RAW_IP_HOST" not in codes(lexical_findings("https://example.com/", EV))


def test_at_sign_only_counts_in_the_authority():
    assert "AT_IN_URL" in codes(lexical_findings("https://www.adcb.com@evil.example/", EV))
    assert "AT_IN_URL" not in codes(lexical_findings("https://example.com/contact?to=a@b.com", EV))


def test_many_subdomains_from_four_levels():
    assert codes(lexical_findings("https://a.b.c.d.example.com/", EV))["MANY_SUBDOMAINS"] == {"count": 4}
    assert "MANY_SUBDOMAINS" not in codes(lexical_findings("https://a.b.c.example.com/", EV))


def test_long_url_ignores_the_query():
    path = "/" + "p" * 90
    long_one = lexical_findings(f"https://example.com{path}", EV)
    assert codes(long_one)["LONG_URL"] == {"length": len("https://example.com") + len(path)}
    assert "LONG_URL" not in codes(lexical_findings("https://example.com/?" + "q" * 200, EV))


def test_deceptive_words():
    assert deceptive_words("secure-login.example.com") == ["login", "secure"]
    assert deceptive_words("adcbsignin.test") == ["signin"]
    assert deceptive_words("rta-fine-pay.test") == ["fine", "pay"]
    assert deceptive_words("payroll-gov-portal.test") == ["gov", "portal"]  # pay inside payroll is too short
    assert deceptive_words("refinery.com") == []
    assert deceptive_words("login.microsoftonline.com") == []  # official domain
    assert deceptive_words("portal.example.gov.ae") == []  # government namespace
    assert deceptive_words("shop.support") == []  # the public suffix is ignored
    found = codes(lexical_findings("https://verify-account.example.com/", EV))
    assert found["DECEPTIVE_DOMAIN_WORDS"] == {"words": ["verify", "account"]}


def test_risky_tld_and_hosting():
    assert codes(domain_findings("https://cheap-deals-example.top/", EV)) == {"RISKY_TLD": {"tld": "top"}}
    assert codes(domain_findings("https://shop.ae/", EV)) == {}
    assert codes(domain_findings("https://x.github.io/", EV)) == {"FREE_HOSTING": {"platform": "github.io"}}


@pytest.mark.parametrize("age, code", [
    (3, "NEW_DOMAIN_7D"), (6, "NEW_DOMAIN_7D"), (7, "NEW_DOMAIN_30D"), (29, "NEW_DOMAIN_30D"),
    (30, None), (730, None), (731, "DOMAIN_OLD"),
])
def test_domain_age_thresholds(age, code):
    created = (TODAY - timedelta(days=age)).isoformat()
    found = age_findings({"created": created}, TODAY)
    assert [f.code for f in found] == ([code] if code else [])
    if code in ("NEW_DOMAIN_7D", "NEW_DOMAIN_30D"):
        assert found[0].params == {"days": age, "created": created}
        assert found[0].evidence == "whois.json#created"


def test_old_domain_years_and_unknown_age():
    assert age_findings({"created": "2003-06-25"}, TODAY)[0].params == {"years": 23}
    assert age_findings({"created": None}, TODAY) == []


def test_new_tls_certificate():
    found = cert_findings({"not_before": "2026-11-20T00:00:00Z"}, NOW)
    assert codes(found) == {"NEW_TLS_CERT": {"days": 4}}
    assert found[0].evidence == "cert.json#not_before"
    assert cert_findings({"not_before": "2026-11-01T00:00:00Z"}, NOW) == []
    assert cert_findings({"not_before": None}, NOW) == []


def test_top_site_list_ranks():
    assert top_site_rank("google.com") == 1
    assert top_site_rank("never-a-top-site.example") is None


def test_top_site_vouches_for_a_link_that_lands_directly():
    ctx = context(["http://google.com/", "https://www.google.com/"])
    url_signals(ctx, {"google.com": facts(created="1997-09-15")})
    found = codes(ctx.findings)
    assert found["TOP_SITE"] == {"domain": "google.com", "rank": 1}
    assert found["DOMAIN_OLD"] == {"years": 29}
    assert ctx.features["domain_age_days"] == (TODAY - date(1997, 9, 15)).days


def test_hosting_platform_never_gets_top_site():
    ctx = context(["https://sites.google.com/view/x"])
    url_signals(ctx, {"google.com": facts(created="1997-09-15")})
    found = codes(ctx.findings)
    assert found == {"FREE_HOSTING": {"platform": "sites.google.com"}}
    assert ctx.features["hosting_platform"] == "sites.google.com"


def test_popular_landing_domain_does_not_vouch_for_the_domain_before_it():
    ctx = context(["https://adcb-verify.test/", "https://www.zendesk.com/"])
    url_signals(ctx, {"zendesk.com": facts(created="2007-01-01")})
    found = codes(ctx.findings)
    assert "TOP_SITE" not in found and "DOMAIN_OLD" not in found
    assert found["LOOKALIKE_DOMAIN"]["method"] == "combo"
    assert ctx.features["top_site_rank"] == top_site_rank("zendesk.com")


def test_signals_cover_every_hop_and_name_the_brand():
    ctx = context(["https://bit.ly/x", "https://track.example.net/r", "https://adcb.com.verify-now-example.xyz/"])
    url_signals(ctx, {})
    by_code = {f.code: f for f in ctx.findings}
    assert by_code["LOOKALIKE_DOMAIN"].evidence == "redirects.json#chain[2]"
    assert by_code["LOOKALIKE_DOMAIN"].params == {
        "domain": "adcb.com.verify-now-example.xyz", "official": "adcb.com", "method": "subdomain_spoof"}
    assert by_code["RISKY_TLD"].params == {"tld": "xyz"}
    assert ctx.impersonated_brand == "Abu Dhabi Commercial Bank (ADCB)"
    assert ctx.features["domain_age_days"] is None


def test_strongest_brand_finding_names_the_impersonated_brand():
    ctx = context(["https://noon-adcb-uae.test/"])
    url_signals(ctx, {})
    assert {"LOOKALIKE_DOMAIN", "BRAND_IN_DOMAIN", "BRAND_GEO_DOMAIN"} <= {f.code for f in ctx.findings}
    assert ctx.impersonated_brand == "Abu Dhabi Commercial Bank (ADCB)"


def test_repeated_hops_add_each_finding_once():
    ctx = context(["http://login-verify.test/", "https://login-verify.test/"])
    url_signals(ctx, {})
    assert [f.code for f in ctx.findings].count("DECEPTIVE_DOMAIN_WORDS") == 1


def test_user_content_hop_blocks_vouching_even_when_the_landing_page_is_not():
    ctx = context(["https://sites.google.com/view/x", "https://accounts.google.com/signin"])
    url_signals(ctx, {"google.com": facts(created="1997-09-15")})
    found = codes(ctx.findings)
    assert "TOP_SITE" not in found and "DOMAIN_OLD" not in found
    assert found["FREE_HOSTING"] == {"platform": "sites.google.com"}
    assert ctx.features["hosting_platform"] == "sites.google.com"
