"""Transparent weighted scoring: findings in, risk score and verdict out.

Every weight lives in `WEIGHTS`, keyed by signal code. A code that fires
twice counts once, at its largest weight. The official-domain allowlist is
applied before scoring, in the pipeline: an allowlisted scan never reaches
`score()`.
"""

from __future__ import annotations

from dataclasses import dataclass

from baaz.models import Finding

WEIGHTS: dict[str, int] = {
    "OFFICIAL_DOMAIN": 0,
    "GOV_NAMESPACE": 0,
    "URL_SHORTENER": 0,
    "SKIMMER_GATEWAY": 60,
    "CARD_FORM_NO_PROCESSOR": 35,
    "LOOKALIKE_DOMAIN": 40,
    "SENSITIVE_FORM_BRAND": 30,
    "NEW_DOMAIN_7D": 30,
    "NEW_DOMAIN_30D": 20,
    "SHARED_FINGERPRINT": 30,
    "BRAND_GEO_DOMAIN": 25,
    "DEEP_DISCOUNTS": 20,
    "BRAND_IN_DOMAIN": 15,
    "DOORWAY": 15,
    "CLOAKING": 15,
    "FORM_OFFSITE_POST": 15,
    "WEAK_GATEWAY": 15,
    "RAW_IP_HOST": 20,
    "AT_IN_URL": 15,
    "MANY_SUBDOMAINS": 10,
    "LONG_URL": 10,
    "NEW_TLS_CERT": 10,
    "FREE_HOSTING": 10,
    "RISKY_TLD": 10,
    "URGENCY_WORDING": 10,
    "DECEPTIVE_DOMAIN_WORDS": 10,
    "TOP_SITE": -25,
    "NO_PAGE_EVIDENCE": 0,
    "DOMAIN_OLD": -15,
}

# Reduced weights for brand findings that rest on a common-word token
# (`common_tokens` in the brand files: noon, visa, office, du), which also
# turn up in ordinary domains such as office-furniture-dubai.com.
COMMON_TOKEN_WEIGHTS: dict[str, int] = {"BRAND_IN_DOMAIN": 5, "BRAND_GEO_DOMAIN": 10}

# A brand's exact name under another ending (tamm.com for tamm.abudhabi) is
# often an unrelated owner of many years, so it weighs less than a typo or
# homoglyph and, as a reduced finding, does not cancel DOMAIN_OLD.
TLD_SWAP_WEIGHT = 25

# Data sent to a Telegram bot from a page is a phishing kit's drop box.
TELEGRAM_EXFIL_WEIGHT = 40

# Signals that come from seeing the scam itself: its page, its checkout or a
# fingerprint shared with known fraud. Without one, the name, registration and
# certificate alone make a link suspicious at most (NO_PAGE_EVIDENCE).
CONTENT = frozenset({
    "SKIMMER_GATEWAY", "CARD_FORM_NO_PROCESSOR", "SENSITIVE_FORM_BRAND", "SHARED_FINGERPRINT",
    "DEEP_DISCOUNTS", "WEAK_GATEWAY", "DOORWAY", "CLOAKING", "FORM_OFFSITE_POST", "URGENCY_WORDING",
})

# A new domain always has a new certificate: one fact, counted once.
NEW_DOMAIN = frozenset({"NEW_DOMAIN_7D", "NEW_DOMAIN_30D"})

# Signals strong enough that an old domain is no comfort (DOMAIN_OLD is dropped).
STRONG = frozenset({
    "SKIMMER_GATEWAY",
    "CARD_FORM_NO_PROCESSOR",
    "LOOKALIKE_DOMAIN",
    "SENSITIVE_FORM_BRAND",
    "SHARED_FINGERPRINT",
})

# Signals that decide the verdict on their own.
FORCE_FRAUD = frozenset({"SKIMMER_GATEWAY"})

STOREFRONT_CODES = frozenset({
    "SKIMMER_GATEWAY", "WEAK_GATEWAY", "CARD_FORM_NO_PROCESSOR", "DEEP_DISCOUNTS",
})
PHISHING_CODES = frozenset({
    "LOOKALIKE_DOMAIN", "SENSITIVE_FORM_BRAND", "FORM_OFFSITE_POST",
})

FRAUD_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 40


@dataclass(frozen=True)
class Score:
    risk_score: int
    verdict: str
    confidence: float
    fraud_type: str | None
    findings: list[Finding]


def weight_of(finding: Finding) -> int:
    return WEIGHTS[finding.code] if finding.weight is None else finding.weight


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Keep one finding per code, the one with the largest weight."""
    best: dict[str, Finding] = {}
    for f in findings:
        if f.code not in best or weight_of(f) > weight_of(best[f.code]):
            best[f.code] = f
    return sorted(best.values(), key=weight_of, reverse=True)


def verdict_for(risk_score: int) -> str:
    if risk_score >= FRAUD_THRESHOLD:
        return "fraud"
    if risk_score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "legitimate"


def fraud_type_for(codes: set[str], verdict: str) -> str | None:
    if verdict == "legitimate":
        return None
    if codes & STOREFRONT_CODES:
        return "fake_storefront_skimmer"
    if "DOORWAY" in codes and not codes & PHISHING_CODES:
        return "doorway"
    return "phishing"


def confidence_for(risk_score: int, fetch_status: str, forced: bool) -> float:
    """Distance from the nearest threshold, discounted when the page was not read."""
    if forced:
        return 0.95
    margin = min(abs(risk_score - FRAUD_THRESHOLD), abs(risk_score - SUSPICIOUS_THRESHOLD))
    base = 0.5 + 0.5 * min(margin / 30, 1.0)
    coverage = 1.0 if fetch_status == "ok" else 0.75
    return round(base * coverage, 2)


def score(findings: list[Finding], fetch_status: str) -> Score:
    kept = dedupe(findings)
    codes = {f.code for f in kept}
    if any(f.code in STRONG and weight_of(f) >= WEIGHTS[f.code] for f in kept):
        kept = [f for f in kept if f.code != "DOMAIN_OLD"]
    if codes & NEW_DOMAIN:
        kept = [f for f in kept if f.code != "NEW_TLS_CERT"]
    total = sum(weight_of(f) for f in kept)
    if total >= FRAUD_THRESHOLD and not codes & CONTENT:
        kept.append(Finding("NO_PAGE_EVIDENCE", "redirects.json#final_url", {}, FRAUD_THRESHOLD - 1 - total))
        total = FRAUD_THRESHOLD - 1
    risk = max(0, min(100, total))
    forced = bool(codes & FORCE_FRAUD)
    if forced:
        risk = max(risk, FRAUD_THRESHOLD)
    verdict = verdict_for(risk)
    return Score(
        risk_score=risk,
        verdict=verdict,
        confidence=confidence_for(risk, fetch_status, forced),
        fraud_type=fraud_type_for(codes, verdict),
        findings=kept,
    )


def adjust(risk_score: int, verdict: str, adjustment: int) -> tuple[int, str]:
    """Apply an investigator's score nudge: clamped to ±20, suspicious cases only."""
    if verdict != "suspicious":
        return risk_score, verdict
    nudged = max(0, min(100, risk_score + max(-20, min(20, adjustment))))
    return nudged, verdict_for(nudged)
