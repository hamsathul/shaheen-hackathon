import json
import ssl
from pathlib import Path

import pytest

from shaheen import intel
from shaheen.store import Store

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_rdap_sample():
    data = json.loads((FIXTURES / "rdap_example_com.json").read_text(encoding="utf-8"))
    facts = intel.parse_rdap(data)
    assert facts["created"] == "1995-08-14"
    assert facts["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
    assert facts["status"] == ["client delete prohibited", "client transfer prohibited", "client update prohibited"]
    assert facts["nameservers"] == ["elliott.ns.cloudflare.com", "hera.ns.cloudflare.com"]


def test_parse_whois_sample_from_a_gtld_registry():
    facts = intel.parse_whois((FIXTURES / "whois_example_com.txt").read_text(encoding="utf-8"))
    assert facts["created"] == "1995-08-14"
    assert facts["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
    assert facts["registrar_abuse_email"] is None  # the field is present but empty
    assert facts["status"][0] == "clientDeleteProhibited"
    assert facts["nameservers"] == ["elliott.ns.cloudflare.com", "hera.ns.cloudflare.com"]


def test_parse_whois_sample_without_a_creation_date():
    text = (FIXTURES / "whois_tdra_gov_ae.txt").read_bytes().decode("utf-8")  # keeps the CRLF line ends
    facts = intel.parse_whois(text)
    assert facts["created"] is None
    assert facts["registrar"] == "Etisalat"
    assert facts["status"] == ["ok"]
    assert "ns1.etisalatdomains.ae" in facts["nameservers"]


def test_parse_whois_without_a_record():
    assert intel.parse_whois("No match for domain \"NOPE.COM\".\r\n") is None


@pytest.mark.parametrize("text, iso", [
    ("2024-03-05T10:00:00Z", "2024-03-05"),
    ("2024.03.05", "2024-03-05"),
    ("05-Mar-2024", "2024-03-05"),
    ("5 March 2024", "2024-03-05"),
    ("05/03/2024", "2024-03-05"),
    ("before 1996", None),
    ("2024-13-40", None),
])
def test_loose_date(text, iso):
    assert intel.loose_date(text) == iso


def test_unverified_certificate_is_decoded_from_der():
    der = ssl.PEM_cert_to_DER_cert((FIXTURES / "self_signed.pem").read_text(encoding="utf-8"))
    facts = intel.parse_cert(intel._decode_der(der))
    assert facts["subject"] == "CN=lookalike.test, O=Shaheen Test"
    assert facts["issuer"] == facts["subject"]
    assert facts["san"] == ["lookalike.test", "www.lookalike.test"]
    assert facts["not_before"].endswith("Z") and facts["not_before"] < facts["not_after"]


def test_gather_fails_soft_when_the_network_is_down(tmp_path, monkeypatch):
    def down(*args, **kwargs):
        raise OSError("network is unreachable")

    monkeypatch.setattr(intel, "_get_json", lambda url: None)
    monkeypatch.setattr(intel, "_whois", down)
    monkeypatch.setattr(intel, "_resolve", lambda name, rdtype: ([], "error"))
    monkeypatch.setattr(intel, "_peer_cert", down)
    facts = intel.gather("example.com", Store(tmp_path / "t.db"), "www.example.com")
    assert facts["whois"]["source"] == "unknown" and facts["whois"]["created"] is None
    assert facts["dns"]["nxdomain"] is None and facts["dns"]["a"] == []
    assert facts["cert"]["not_before"] is None and "unreachable" in facts["cert"]["error"]


def test_gather_caches_answers_but_not_failures(tmp_path, monkeypatch):
    calls = []

    def resolve(name, rdtype):
        calls.append((name, rdtype))
        if rdtype == "A":
            return ["192.0.2.10"], "ok"
        if rdtype == "TXT" and name.endswith("origin.asn.cymru.com"):
            return ["64500 | 192.0.2.0/24 | AE | ripencc | 2010-01-01"], "ok"
        if rdtype == "TXT":
            return ["64500 | AE | ripencc | 2010-01-01 | EXAMPLE-AS - Example Hosting, AE"], "ok"
        return [], "noanswer"

    monkeypatch.setattr(intel, "_resolve", resolve)
    monkeypatch.setattr(intel, "_get_json", lambda url: None)
    monkeypatch.setattr(intel, "_whois", lambda server, query: "")
    monkeypatch.setattr(intel, "_peer_cert", lambda host, verify: {"notBefore": "Nov 20 00:00:00 2026 GMT"})
    store = Store(tmp_path / "t.db")
    first = intel.gather("example.com", store)
    assert first["dns"]["asn"] == "AS64500"
    assert first["dns"]["asn_name"] == "EXAMPLE-AS - Example Hosting, AE"
    assert first["dns"]["country"] == "AE" and first["dns"]["nxdomain"] is False
    assert first["cert"]["not_before"] == "2026-11-20T00:00:00Z" and first["cert"]["verified"] is True
    assert first["whois"]["error"]
    lookups = len(calls)
    second = intel.gather("example.com", store)
    assert second["dns"] == first["dns"] and second["cert"] == first["cert"]
    assert len(calls) == lookups  # DNS came from the cache
    assert store.cache_get("example.com", "whois") is None  # the failed registration lookup was not cached
