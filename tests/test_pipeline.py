import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
import yaml

from shaheen import contacts, focus, intel, pipeline, stealth
from shaheen.collectors import enqueue_host
from shaheen.config import DATA_DIR, Settings
from shaheen.domains import registrable_domain
from shaheen.models import ScanOptions
from shaheen.pipeline import Scanner
from shaheen.reasons import LABELS
from shaheen.render import Rendered
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


def test_sweep_finds_outside_the_uae_focus_wait_and_their_cases_are_parked(scanner):
    store = scanner.store
    away = scanner.scan("kuwait-bose-store.test", ScanOptions(source="storefronts"))
    home = scanner.scan("boseuae.test", ScanOptions(source="storefronts"))
    by_hand = scanner.scan("kuwait-jbl-store.test")
    assert [store.get_investigation(r.id)["status"] for r in (away, home, by_hand)] == ["parked", "queued", "queued"]
    for host, source in [("kuwait-bose-store.test", "storefronts"), ("boseuae.test", "storefronts"),
                         ("garden-tools.test", "maps")]:
        enqueue_host(store, host, source)
    assert [store.claim_candidate()["domain"] for _ in range(3)] == [
        "boseuae.test", "garden-tools.test", "kuwait-bose-store.test"]


def test_a_flagged_link_whose_host_does_not_exist_is_not_sent_to_the_ai(scanner, monkeypatch):
    found = intel.gather

    def unregistered(domain, store, host=None):
        facts = found(domain, store, host)
        return {**facts, "dns": {**facts["dns"], "nxdomain": True}}

    monkeypatch.setattr(intel, "gather", unregistered)
    result = scanner.scan("rakbnak.test")
    assert result.verdict == "suspicious" and scanner.store.get_investigation(result.id) is None


def test_refocus_applies_the_uae_focus_to_what_is_already_waiting(scanner):
    store = scanner.store
    for host in ("kuwait-bose-store.test", "boseuae.test"):
        store.enqueue(f"https://{host}/", host, "storefronts")
        row = store.claim_candidate()
        store.finish_candidate(row["id"], "done", scanner.scan(row["url"]).id)
    store.enqueue("https://kuwait-jbl-store.test/", "kuwait-jbl-store.test", "storefronts")
    counts = {"links_first": 0, "links_later": 1, "cases_queued": 1, "cases_parked": 1}
    assert focus.refocus(store) == counts and focus.refocus(store) == counts
    assert store.investigation_queue() == {"suspicious": 1}


def test_a_case_taken_out_of_the_queue_stays_out_until_put_back_in_its_old_place(scanner):
    store = scanner.store
    first, second = (scanner.scan(url).id for url in ("boseuae.test", "jblsharjah.test"))
    assert store.hold_investigation(first, held=True) and not store.hold_investigation(first, held=True)
    focus.refocus(store)
    assert [c["scan_id"] for c in store.next_investigations()] == [second]
    assert [c["scan_id"] for c in store.held_investigations()] == [first]
    assert store.hold_investigation(first, held=False)
    assert [c["scan_id"] for c in store.next_investigations()] == [first, second]
    assert store.move_up_investigation(second) and store.claim_investigation() == second


PAGE = ("<html><head><title>Traffic fine</title></head><body><p>Pay your fine today. Call +971 50 123 4567 or "
        '<a href="https://wa.me/971501234567">message us</a>. Transfer to AE07 0331 2345 6789 0123 456. '
        "Email help@fines-uae.test</p>" + "<p>Official notice.</p>" * 30 + "</body></html>")


def test_contacts_keep_what_the_page_shows_and_link_the_cases_sharing_it(scanner, monkeypatch):
    reply = {"phones": ["+971 50 123 4567", "+971 50 999 0000"], "whatsapp": ["wa.me/971501234567"],
             "emails": ["help@fines-uae.test"], "bank_accounts": ["AE07 0331 2345 6789 0123 456 (Example Bank)"],
             "payment_methods": ["bank transfer"], "claims_to_be": "Dubai Police"}
    monkeypatch.setattr(contacts, "chat", lambda *args: {"choices": [{"message": {"content": json.dumps(reply)}}]})
    for url in ("https://dubai-fines-pay.test/", "https://uae-fine-portal.test/"):
        case = scanner.scan(url)
        folder = scanner.settings.evidence_dir / case.id
        (folder / "page.html").write_text(PAGE, encoding="utf-8")
        record = contacts.read(case.id, scanner.settings, scanner.store)
    assert record["phones"] == ["+971 50 123 4567"] and record["dropped_not_on_page"] == ["+971 50 999 0000"]
    assert record["whatsapp"] and record["emails"] and record["bank_accounts"]
    assert "contacts.json" in [f["name"] for f in json.loads((folder / "manifest.json").read_text("utf-8"))["files"]]
    shared = scanner.store.domains_sharing(*contacts.fingerprint("bank_accounts", record["bank_accounts"][0]),
                                           exclude_domain="uae-fine-portal.test")
    assert shared == ["dubai-fines-pay.test"]


def test_a_fetch_blocked_by_a_bot_check_gets_a_second_look_as_chrome(scanner, monkeypatch):
    def fake_resolve(url, client, insecure_client=None, headers=None):
        if isinstance(client, stealth.ChromeClient):
            return Resolution(final_url=url, fetch_status="ok", hops=[Hop(url, 200, "start")], status_code=200,
                              html=PAGE)
        return Resolution(final_url=url, fetch_status="blocked", hops=[Hop(url, 403, "start")], status_code=403,
                          html="<title>Just a moment...</title>")

    monkeypatch.setattr(pipeline, "resolve", fake_resolve)
    result = scanner.scan("https://dubai-fines-pay.test/", ScanOptions(render=False, storefront=False))
    assert result.fetch_status == "ok" and result.signals["second_look"] == {"via": "own address", "fetch": "ok"}


# A hand-written stand-in for Cloudflare's phishing interstitial.
WARNING = ("<html><head><title>Suspected Phishing | Cloudflare</title></head><body><h1>Warning</h1>"
           "<p>This website has been reported for potential phishing.</p><p>Cloudflare Ray ID: 0000</p></body></html>")


def test_cloudflare_phishing_warning_flags_the_link_without_making_it_fraud(scanner, monkeypatch):
    def fake_resolve(url, client, insecure_client=None, headers=None):
        return Resolution(final_url=url, fetch_status="blocked", hops=[Hop(url, 403, "start")], status_code=403,
                          html=WARNING)

    def fake_render(url, timeout_s=0, as_chrome=False, proxy=""):
        assert not as_chrome, "no browser gets past the warning without a click"
        return Rendered(final_url=url, chain=[url], html=WARNING, status=403), None

    monkeypatch.setattr(pipeline, "resolve", fake_resolve)
    monkeypatch.setattr(pipeline, "render", fake_render)
    plain = scanner.scan("https://parcel-desk.test/", ScanOptions(storefront=False))
    assert codes(plain) >= {"CLOUDFLARE_PHISHING_WARNING"} and plain.verdict == "suspicious"
    assert plain.signals["second_look"]["render"] == "phishing warning"
    lookalike = scanner.scan("https://rakbnak.test/", ScanOptions(storefront=False))
    assert {"CLOUDFLARE_PHISHING_WARNING", "LOOKALIKE_DOMAIN", "NO_PAGE_EVIDENCE"} <= codes(lookalike)
    assert lookalike.verdict == "suspicious"
