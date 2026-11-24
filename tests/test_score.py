from shaheen.models import Finding
from shaheen.score import WEIGHTS, adjust, score


def f(code: str, weight: int | None = None) -> Finding:
    return Finding(code, "x.json#y", {}, weight)


def test_thresholds_map_to_verdicts():
    assert score([f("LOOKALIKE_DOMAIN")], "ok").verdict == "suspicious"  # 40
    assert score([f("LOOKALIKE_DOMAIN"), f("NEW_DOMAIN_30D")], "ok").verdict == "suspicious"  # 60
    assert score([f("LOOKALIKE_DOMAIN"), f("NEW_DOMAIN_7D"), f("URGENCY_WORDING")], "ok").verdict == "fraud"  # 80
    assert score([f("LOOKALIKE_DOMAIN"), f("SENSITIVE_FORM_BRAND"), f("NEW_DOMAIN_30D")], "ok").verdict == "fraud"
    assert score([f("NEW_TLS_CERT")], "ok").verdict == "legitimate"


def test_fraud_needs_evidence_from_the_scam_itself():
    s = score([f("LOOKALIKE_DOMAIN"), f("NEW_DOMAIN_7D"), f("BRAND_GEO_DOMAIN")], "dead")  # 95 from the name alone
    assert (s.verdict, s.risk_score) == ("suspicious", 69)
    note = s.findings[-1]
    assert note.code == "NO_PAGE_EVIDENCE" and sum(x.weight if x.weight is not None else WEIGHTS[x.code]
                                                   for x in s.findings) == 69


def test_same_code_counts_once_at_its_largest_weight():
    s = score([f("BRAND_IN_DOMAIN"), f("BRAND_IN_DOMAIN", 5)], "ok")
    assert s.risk_score == WEIGHTS["BRAND_IN_DOMAIN"]
    assert len(s.findings) == 1


def test_old_domain_is_ignored_when_a_strong_signal_fires():
    s = score([f("LOOKALIKE_DOMAIN"), f("DOMAIN_OLD")], "ok")
    assert s.risk_score == WEIGHTS["LOOKALIKE_DOMAIN"]
    assert "DOMAIN_OLD" not in {x.code for x in s.findings}


def test_old_domain_counts_without_a_strong_signal():
    s = score([f("BRAND_IN_DOMAIN"), f("DOMAIN_OLD")], "ok")
    assert s.risk_score == 0


def test_skimmer_gateway_forces_fraud_and_storefront_type():
    s = score([f("SKIMMER_GATEWAY"), f("TOP_SITE"), f("DOMAIN_OLD")], "ok")
    assert s.verdict == "fraud"
    assert s.fraud_type == "fake_storefront_skimmer"


def test_score_is_clamped_to_0_100():
    assert score([f("TOP_SITE"), f("DOMAIN_OLD")], "ok").risk_score == 0
    assert score([f("SKIMMER_GATEWAY"), f("LOOKALIKE_DOMAIN"), f("NEW_DOMAIN_7D")], "ok").risk_score == 100


def test_unfetched_page_lowers_confidence():
    findings = [f("LOOKALIKE_DOMAIN"), f("NEW_DOMAIN_7D")]
    assert score(findings, "dead").confidence < score(findings, "ok").confidence


def test_doorway_without_phishing_signals_is_typed_doorway():
    s = score([f("DOORWAY"), f("NEW_DOMAIN_7D")], "ok")
    assert s.fraud_type == "doorway"


def test_adjustment_is_clamped_and_only_moves_suspicious_cases():
    assert adjust(55, "suspicious", 50) == (75, "fraud")
    assert adjust(55, "suspicious", -50) == (35, "legitimate")
    assert adjust(80, "fraud", -20) == (80, "fraud")
    assert adjust(10, "legitimate", 20) == (10, "legitimate")
