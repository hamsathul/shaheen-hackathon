import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
import yaml

from shaheen import intel, pipeline
from shaheen.config import DATA_DIR, Settings
from shaheen.domains import registrable_domain
from shaheen.pipeline import Scanner
from shaheen.reasons import LABELS
from shaheen.resolve import SHORTENERS, Hop, Resolution
from shaheen.score import TLD_SWAP_WEIGHT, WEIGHTS
from shaheen.store import Store

# Scam-looking hosts here are made up, mostly under the reserved .test TLD.
UAE_OFFICIAL = [d for b in yaml.safe_load((DATA_DIR / "brands_uae.yaml").read_text(encoding="utf-8"))["brands"]
                for d in b["official_domains"]]


@pytest.fixture
def scanner(tmp_path, monkeypatch):
    """A Scanner whose fetch and intel are fakes. `scanner.routes` maps a start
    URL to its redirect chain; anything else is a dead link that goes nowhere."""
    settings = Settings(db_path=tmp_path / "shaheen.db", evidence_dir=tmp_path / "evidence", llm_base_url="",
                        llm_model="", llm_api_key="", http_timeout=5, user_agent="test")
    routes: dict[str, list[str]] = {}
    gathered: list[str] = []

    def fake_resolve(url, client, insecure_client=None, headers=None):
        chain = routes.get(url, [url])
        hops = [Hop(u, None, "start" if i == 0 else "http") for i, u in enumerate(chain)]
        start = registrable_domain(url)
        return Resolution(final_url=chain[-1], fetch_status="dead", hops=hops,
                          shortener=start if start in SHORTENERS else None)

    def fake_gather(domain, store, host=None):
        gathered.append(domain)
        return {"domain": domain, "host": host or domain,
                "whois": {"source": "unknown", "created": None, "registrar": None},
                "dns": {"a": [], "nxdomain": None, "asn": None, "country": None},
                "cert": {"not_before": None}}

    monkeypatch.setattr(pipeline, "resolve", fake_resolve)
    monkeypatch.setattr(intel, "gather", fake_gather)
    with Scanner(settings, Store(settings.db_path)) as s:
        s.routes, s.gathered = routes, gathered
        yield s


def codes(result) -> set[str]:
    return {r.code for r in result.reasons}


@pytest.mark.parametrize("domain", UAE_OFFICIAL)
def test_every_official_uae_domain_is_legitimate(scanner, domain):
    for url in (domain, f"https://www.{domain}/"):
        result = scanner.scan(url)
        assert (result.verdict, result.risk_score) == ("legitimate", 0), url
        assert codes(result) == {"OFFICIAL_DOMAIN"}
    assert scanner.gathered == []  # allowlisted scans skip intel


def test_official_domain_redirecting_elsewhere_is_not_allowlisted(scanner):
    scanner.routes["https://www.adcb.com/go"] = ["https://www.adcb.com/go", "https://adcb-verify.test/"]
    result = scanner.scan("https://www.adcb.com/go")
    assert "OFFICIAL_DOMAIN" not in codes(result)
    assert result.verdict == "suspicious" and result.risk_score >= 40
    assert scanner.gathered == ["adcb-verify.test"]


def test_shortener_landing_on_an_official_domain_is_legitimate(scanner):
    scanner.routes["https://bit.ly/abc"] = ["https://bit.ly/abc", "https://www.adcb.com/en/"]
    result = scanner.scan("https://bit.ly/abc")
    assert result.verdict == "legitimate" and result.risk_score == 0
    assert codes(result) == {"URL_SHORTENER", "OFFICIAL_DOMAIN"}
    assert result.redirect_chain == ["https://bit.ly/abc", "https://www.adcb.com/en/"]


def test_defensive_registration_redirecting_to_the_brand_is_legitimate(scanner):
    scanner.routes["https://tamm.test/"] = ["https://tamm.test/", "https://www.tamm.abudhabi/"]
    assert scanner.scan("https://tamm.test/").verdict == "legitimate"


def test_government_namespace_is_legitimate(scanner):
    result = scanner.scan("https://services.example.gov.ae/")
    assert result.verdict == "legitimate"
    assert codes(result) == {"GOV_NAMESPACE"}


@pytest.mark.parametrize("url, platform", [
    ("https://sites.google.com/view/x", "sites.google.com"),
    ("https://docs.google.com/forms/d/e/x/viewform", "docs.google.com"),
])
def test_user_content_on_an_official_domain_is_not_allowlisted(scanner, url, platform):
    result = scanner.scan(url)
    assert "OFFICIAL_DOMAIN" not in codes(result)
    free = [r for r in result.reasons if r.code == "FREE_HOSTING"]
    assert free and platform in free[0].en
    assert "TOP_SITE" not in codes(result)


@pytest.mark.parametrize("url, method, brand", [
    ("uaepaas.test", "typo", "UAE PASS"),
    ("rakbnak.test", "typo", "RAKBANK"),
    ("rnashreq.test", "homoglyph", "Mashreq"),
    ("et1had.test", "homoglyph", "Etihad Airways"),
    ("xn--dcb-5cd.test", "punycode", "Abu Dhabi Commercial Bank (ADCB)"),
    ("xn--slik-53d.test", "punycode", "Salik"),  # Cyrillic а in salik
    ("adcb-secure-login.test", "combo", "Abu Dhabi Commercial Bank (ADCB)"),
    ("dewa-gov-portal.test", "combo", "Dubai Electricity and Water Authority (DEWA)"),
    ("salik-topup.test", "combo", "Salik"),
    ("emiratesnbdlogin.test", "combo", "Emirates NBD"),
    ("etisalat-rewards.test", "combo", "e& (Etisalat)"),
    ("adcb.com.verify-now.test", "subdomain_spoof", "Abu Dhabi Commercial Bank (ADCB)"),
    ("www.tamm.abudhabi-gov.test", "subdomain_spoof", "TAMM"),
    ("harmankardonbahrain.test", "combo", "Harman Kardon"),
])
def test_lookalikes_are_flagged_without_a_page_fetch(scanner, url, method, brand):
    result = scanner.scan(url)
    assert result.fetch_status == "dead"
    assert result.risk_score >= 40 and result.verdict in ("suspicious", "fraud"), result.reasons
    lookalike = next(r for r in result.reasons if r.code == "LOOKALIKE_DOMAIN")
    assert lookalike.evidence.startswith("redirects.json#chain[")
    assert LABELS[method][0] in lookalike.en
    assert result.impersonated_brand == brand


@pytest.mark.parametrize("url", ["rakbank.test", "tamm.example"])
def test_a_brand_name_under_another_ending_alone_is_not_flagged(scanner, url):
    result = scanner.scan(url)
    lookalike = next(r for r in result.reasons if r.code == "LOOKALIKE_DOMAIN")
    assert lookalike.weight == TLD_SWAP_WEIGHT and LABELS["tld_swap"][0] in lookalike.en
    assert result.verdict == "legitimate"


@pytest.mark.parametrize("url, brand", [
    ("uae-bose-outlet.test", "Bose"),
    ("boseuae.test", "Bose"),
    ("kuwait-bose-store.test", "Bose"),
    ("jblsharjah.test", "JBL"),
])
def test_brand_with_a_country_or_city_is_suspicious(scanner, url, brand):
    result = scanner.scan(url)
    assert result.risk_score >= 40 and result.verdict == "suspicious"
    assert {"BRAND_GEO_DOMAIN", "BRAND_IN_DOMAIN"} <= codes(result)
    assert result.impersonated_brand == brand


@pytest.mark.parametrize("url", ["afternoon.com", "fabric.com", "dubai.com", "emiratesauction.com", "verbose.com"])
def test_ordinary_domains_stay_legitimate(scanner, url):
    result = scanner.scan(url)
    assert result.verdict == "legitimate"
    assert not codes(result) & {"LOOKALIKE_DOMAIN", "BRAND_IN_DOMAIN", "BRAND_GEO_DOMAIN"}


def test_intel_is_written_to_the_evidence_pack(scanner):
    result = scanner.scan("https://www.adcb-verify.test/login")
    folder = scanner.settings.evidence_dir / result.id
    for name in ("redirects.json", "whois.json", "dns_hosting.json", "cert.json", "report.json"):
        assert (folder / name).is_file(), name
    assert json.loads((folder / "whois.json").read_text(encoding="utf-8"))["source"] == "unknown"
    assert scanner.gathered == ["adcb-verify.test"]
    intel_features = {"domain_age_days", "registrar", "asn", "hosting_country", "cert_age_days", "nxdomain"}
    assert intel_features <= set(result.signals)
    assert scanner.store.get_scan(result.id).verdict == result.verdict


def test_a_uae_scam_theme_counts_only_on_a_domain_naming_no_brand(scanner):
    themed = scanner.scan("dubai-traffic-fines.test")
    assert themed.risk_score == WEIGHTS["THEME_UAE_DOMAIN"] + WEIGHTS["DECEPTIVE_DOMAIN_WORDS"]
    assert themed.verdict == "legitimate"
    assert "THEME_UAE_DOMAIN" not in codes(scanner.scan("adcb-uae-bank.test"))


def _checked(store, url, scan_id, days_ago):
    store.enqueue(url, registrable_domain(url), "ctlogs")
    store.finish_candidate(store.claim_candidate()["id"], "done", scan_id)
    when = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat(timespec="seconds")
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE candidates SET scanned_at = ? WHERE url = ?", (when, url))


def test_a_checked_url_is_queued_again_once_its_check_is_old_enough(scanner):
    store = scanner.store
    legit, suspicious = scanner.scan("https://dubai-cafe.test/"), scanner.scan("https://boseuae.test/")
    _checked(store, legit.url, legit.id, 6)
    _checked(store, suspicious.url, suspicious.id, 2)
    assert not store.enqueue(legit.url, "dubai-cafe.test", "ctlogs")
    assert store.enqueue(suspicious.url, "boseuae.test", "storefronts")
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE scans SET verdict = 'fraud' WHERE id = ?", (legit.id,))
        db.execute("UPDATE candidates SET scanned_at = '2026-01-01T00:00:00+00:00'")
    assert not store.enqueue(legit.url, "dubai-cafe.test", "ctlogs")


def test_a_domain_is_investigated_again_only_when_it_turns_fraud(scanner):
    first = scanner.scan("boseuae.test")
    assert scanner.store.get_investigation(first.id)["status"] == "queued"
    assert scanner.store.get_investigation(scanner.scan("boseuae.test").id) is None
    assert not scanner.store.needs_investigation("boseuae.test", "fraud")
    scanner.store.set_investigation(first.id, "done")
    assert scanner.store.needs_investigation("boseuae.test", "fraud")
    assert not scanner.store.needs_investigation("boseuae.test", "suspicious")

