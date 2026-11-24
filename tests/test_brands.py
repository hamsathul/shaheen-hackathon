import pytest

from shaheen.brands import (
    allowlist,
    gov_namespace,
    hosting_platform,
    is_typo,
    load_brands,
    match_domain,
    official_brand,
    skeleton,
)

# Every scam-looking host below is made up, and most sit under the reserved
# .test and .example TLDs (RFC 2606), so none can be a live site. Real domains
# appear only as official domains or as ordinary sites that must not match.


def methods(host: str) -> set[tuple[str, str]]:
    return {(m.method, m.brand.id) for m in match_domain(host)}


def test_every_brand_file_loads_with_official_domains():
    brands = load_brands()
    assert {b.id for b in brands} >= {"tamm", "adcb", "bose", "google"}
    assert all(b.official_domains for b in brands)


def test_every_official_domain_maps_back_to_its_brand():
    for brand in load_brands():
        for domain in brand.official_domains:
            assert official_brand(domain) == brand
            assert official_brand(f"https://login.{domain}/x") == brand
            assert match_domain(f"www.{domain}") == []


def test_government_namespaces_are_restricted_zones_only():
    assert gov_namespace("adpolice.gov.ae") == "gov.ae"
    assert gov_namespace("https://portal.army.mil.ae/") == "mil.ae"
    assert gov_namespace("www.gov.uk") == "gov.uk"
    assert gov_namespace("irs.gov") == "gov"
    for open_zone in ("uaeu.ac.ae", "tamm.abudhabi", "visit.dubai", "gov-ae.com", "adpolice.gov.ae.evil.com"):
        assert gov_namespace(open_zone) is None, open_zone


@pytest.mark.parametrize("host, method, brand", [
    ("uaepaas.test", "typo", "uae_pass"),
    ("etihda.test", "typo", "etihad"),  # a transposition is one edit
    ("rnashreq.test", "homoglyph", "mashreq"),
    ("et1had.test", "homoglyph", "etihad"),
    ("xn--dcb-5cd.test", "punycode", "adcb"),  # Cyrillic а in adcb
    ("xn--80ak6aa92e.test", "punycode", "apple"),
    ("rakbank.test", "tld_swap", "rakbank"),
    ("tamm.example", "tld_swap", "tamm"),
    ("adcb-secure-login.test", "combo", "adcb"),
    ("emiratesnbdlogin.test", "combo", "emirates_nbd"),
    ("dewa-gov-portal.test", "combo", "dewa"),
    ("dubai-police-fines.test", "combo", "dubai_police"),  # a keyword split by a hyphen
    ("adcb.com.verify-now.test", "subdomain_spoof", "adcb"),
    ("www.adcb.com-secure.test", "subdomain_spoof", "adcb"),
    ("tamm.abudhabi-gov.test", "subdomain_spoof", "tamm"),
])
def test_lookalike_methods(host, method, brand):
    assert (method, brand) in methods(host)


@pytest.mark.parametrize("host, brand, place", [
    ("uae-bose-outlet.test", "bose", "uae"),
    ("boseuae.test", "bose", "uae"),
    ("boseom.test", "bose", "om"),
    ("kuwait-bose-store.test", "bose", "kuwait"),
    ("jblsharjah.test", "jbl", "sharjah"),
    ("harmankardonbahrain.test", "harman_kardon", "bahrain"),
    ("bose-south-africa.test", "bose", "southafrica"),
])
def test_brand_with_a_place(host, brand, place):
    geo = [m for m in match_domain(host) if m.method == "geo"]
    assert [(m.brand.id, m.place) for m in geo] == [(brand, place)]


def test_a_common_word_token_is_a_mention_not_a_lookalike():
    assert methods("noon-sale.test") == {("mention", "noon")}
    assert methods("uae-bose-outlet.test") == {("mention", "bose"), ("geo", "bose")}
    assert methods("bose.test") == {("mention", "bose")}  # a token is never a tld_swap


def test_brand_named_only_in_a_subdomain_is_a_mention():
    assert methods("adcb.helpdesk-example.test") == {("mention", "adcb")}


@pytest.mark.parametrize("host", [
    "afternoon.com",  # noon inside a word
    "fabric.com",  # fab inside a word
    "dubai.com",  # du inside a word
    "verbose.com",  # bose inside a word
    "emiratesauction.com",  # emirates is a token, not a keyword
    "duke.edu",  # du + ke (Kenya) is not a brand with a place
    "metals.com",  # meta + ls
    "visage.com",  # visa + ge
    "centralbank.ie",  # same label as centralbank.ae, but not a distinctive brand name
    "malik.com",  # one letter from salik, but a different first letter
    "finance.com",  # one letter from binance
    "code-wars.com",  # dewa only appears once the hyphen is dropped
    "192.168.1.10",
])
def test_no_false_brand_matches(host):
    assert match_domain(host) == []


def test_place_codes_glued_to_a_brand_are_gulf_only():
    assert match_domain("dewalt.com") == []  # no "lt" place, and dewa inside an unrelated word
    assert {m.place for m in match_domain("jblqa.test")} == {None, "qa"}


def test_skeleton_maps_confusables_to_ascii():
    assert skeleton("аdсb") == "adcb"  # Cyrillic а and с
    assert skeleton("n00n") == "noon"
    assert skeleton("rnashreq") == "mashreq"
    assert skeleton("vvhatsapp") == "whatsapp"


def test_typo_rules():
    assert is_typo("salk", "salik") is False  # under 5 characters
    assert is_typo("sallk", "salik") is True
    assert is_typo("salikk", "salik") is True
    assert is_typo("saalikk", "salik") is False  # two edits on a 5-letter name
    assert is_typo("adpollce", "adpolice") is True
    assert is_typo("adpolllce", "adpolice") is True  # two edits allowed from 8 letters
    assert is_typo("police", "adpolice") is False  # different first letter
    assert is_typo("salik", "salik") is False


@pytest.mark.parametrize("url, platform", [
    ("https://sites.google.com/view/x", "sites.google.com"),
    ("https://docs.google.com/forms/d/e/x/viewform", "docs.google.com"),
    ("https://forms.office.com/r/abc", "forms.office.com"),
    ("https://www.dropbox.com/s/abc/file.pdf", "dropbox.com/s"),
    ("https://adcb-login-example.web.app/", "web.app"),
    ("https://contoso.sharepoint.com/sites/x", "sharepoint.com"),
    ("https://www.google.com/search?q=x", None),
    ("https://www.dropbox.com/business", None),
])
def test_hosting_platforms(url, platform):
    assert hosting_platform(url) == platform


def test_allowlist_needs_an_official_landing_and_clean_hops():
    allowed = allowlist(["https://www.adcb.com/"])
    assert allowed and allowed.code == "OFFICIAL_DOMAIN" and allowed.owner == "Abu Dhabi Commercial Bank (ADCB)"
    assert allowlist(["https://bit.ly/x", "https://www.adcb.com/"]).code == "OFFICIAL_DOMAIN"
    assert allowlist(["https://tamm.test/", "https://www.tamm.abudhabi/"]).owner == "TAMM"
    gov = allowlist(["https://www.example.gov.ae/"])
    assert gov and gov.code == "GOV_NAMESPACE" and gov.params == {"domain": "example.gov.ae", "suffix": "gov.ae"}
    assert allowlist(["https://www.adcb.com/go?u=x", "https://adcb-verify.test/"]) is None
    assert allowlist(["https://adcb-verify.test/", "https://www.adcb.com/"]) is None
    assert allowlist(["https://tamm.test/", "https://www.adcb.com/"]) is None  # tamm is not ADCB's name
    assert allowlist(["https://sites.google.com/view/x"]) is None
    assert allowlist(["https://example.com/"]) is None
