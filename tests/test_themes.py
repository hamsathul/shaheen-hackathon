import pytest

from shaheen import themes
from shaheen.collectors import newdomains
from shaheen.signals import theme_findings

# Hosts here are made up, under the reserved .test TLD unless the .ae suffix is the point.


@pytest.mark.parametrize("host, theme, marker, words", [
    ("dubai-traffic-fines.test", "traffic_fines", "dubai", ("fines", "traffic")),
    ("uaevisa-apply.test", "visa_residency", "uae", ("visa",)),
    ("jobsdubai.test", "job_offers", "dubai", ("jobs",)),
    ("parcel-redelivery.ae", "parcel_delivery", ".ae", ("parcel", "delivery")),
])
def test_a_uae_marker_with_theme_words_matches(host, theme, marker, words):
    found = themes.match(host)
    assert (found[0].theme.id, found[0].marker, found[0].words) == (theme, marker, words)


@pytest.mark.parametrize("host", ["traffic-fines.test", "dubaimall.test", "baidubaike-jobs.test"])
def test_theme_words_need_a_uae_marker(host):
    assert themes.match(host) == []


def test_the_theme_signal_skips_official_and_government_hosts():
    assert theme_findings("dubai-traffic-fines.test", "e")[0].params["themes"] == ["traffic_fines"]
    assert theme_findings("fines.dubaipolice.gov.ae", "e") == []


def test_new_domains_come_branded_then_themed_then_local():
    found = newdomains.matches(["dubai-cafe.test", "uae-visa-apply.test", "traffic-fines.test", "adcb-verify.test"])
    assert [domain for domain, _ in found] == ["adcb-verify.test", "uae-visa-apply.test", "dubai-cafe.test"]
