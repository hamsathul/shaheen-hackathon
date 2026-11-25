"""Data shapes shared by every stage of the scan pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shaheen.capture import Capture

VERDICTS = ("fraud", "suspicious", "legitimate")
FETCH_STATUSES = ("ok", "dead", "blocked", "timeout")
FRAUD_TYPES = ("phishing", "fake_storefront_skimmer", "doorway")


@dataclass
class Finding:
    """A signal that fired.

    `evidence` points at the evidence-pack file and field that proves it, as
    `<file>#<field>`. `params` fills the EN/AR reason template for `code`.
    `weight` overrides the default weight in `score.WEIGHTS` when set.
    """

    code: str
    evidence: str
    params: dict[str, Any] = field(default_factory=dict)
    weight: int | None = None


@dataclass
class Reason:
    code: str
    weight: int
    en: str
    ar: str
    evidence: str


@dataclass
class ScanOptions:
    render: bool = True
    storefront: bool = True
    write_evidence: bool = True
    capture_dir: Path | None = None
    source: str | None = None  # the collector that queued the link; None for a link scanned by hand


@dataclass
class ScanContext:
    """Mutable state handed from stage to stage during one `scan()`.

    `artifacts` maps an evidence-pack file name (`redirects.json`) to its
    content: a JSON-serialisable object, `str` or `bytes`. Stages add raw
    facts to `features` (reported as the result's `signals`) and fired
    signals to `findings`. `capture` is the saved evidence folder a re-analysis
    reads instead of the network.
    """

    id: str
    url: str
    scanned_at: datetime
    options: ScanOptions
    final_url: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    fetch_status: str = "dead"
    html: str = ""
    features: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    official_brand: str | None = None
    impersonated_brand: str | None = None
    capture: Capture | None = None

    @property
    def as_of(self) -> datetime:
        """When the facts were collected: the original scan's time for a
        re-analysis. Domain and certificate ages are measured from it."""
        if self.capture is None:
            return self.scanned_at
        return datetime.fromisoformat(self.capture.collected_at.replace("Z", "+00:00"))

    def add(self, code: str, evidence: str, weight: int | None = None, **params: Any) -> None:
        self.findings.append(Finding(code, evidence, params, weight))


@dataclass
class ScanResult:
    id: str
    url: str
    final_url: str
    redirect_chain: list[str]
    fetch_status: str
    verdict: str
    risk_score: int
    confidence: float
    fraud_type: str | None
    impersonated_brand: str | None
    reasons: list[Reason]
    signals: dict[str, Any]
    cluster_id: str | None
    analyst_confirmed: bool
    evidence_path: str
    scanned_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanResult:
        fields = dict(data)
        fields["reasons"] = [Reason(**r) for r in data.get("reasons", [])]
        return cls(**fields)

    @property
    def top_reason(self) -> str:
        positive = [r for r in self.reasons if r.weight > 0]
        chosen = max(positive, key=lambda r: r.weight) if positive else (self.reasons or [None])[0]
        return chosen.en if chosen else ""
