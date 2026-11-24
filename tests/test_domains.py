from shaheen.domains import defang, normalize_url, refang, registrable_domain


def test_refang_and_defang_round_trip():
    assert refang("hxxps://brand-outlet[.]example/shop") == "https://brand-outlet.example/shop"
    assert refang(defang("https://brand-outlet.example/")) == "https://brand-outlet.example/"


def test_normalize_adds_scheme_lowercases_and_encodes_idn():
    assert normalize_url("Example.COM") == "https://example.com/"
    assert normalize_url("http://tämm.test/x?y=1") == "http://xn--tmm-qla.test/x?y=1"


def test_registrable_domain_respects_multi_part_and_private_suffixes():
    assert registrable_domain("https://www.adpolice.gov.ae/en") == "adpolice.gov.ae"
    assert registrable_domain("someone.github.io") == "someone.github.io"
    assert registrable_domain("https://login.tamm.abudhabi/") == "tamm.abudhabi"
    assert registrable_domain("http://192.168.1.10/login") == "192.168.1.10"
