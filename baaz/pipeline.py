"""`scan(url)`: the one pipeline the CLI, batch runner, watcher, dashboard
and investigator all share.

resolve -> intel -> render -> signals -> score -> reasons -> evidence -> store
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

from baaz import reasons, score
from baaz.config import Settings, load_settings
from baaz.domains import normalize_url, registrable_domain
from baaz.evidence import write_pack
from baaz.models import ScanContext, ScanOptions, ScanResult
from baaz.resolve import make_clients, resolve
from baaz.store import Store


def new_scan_id(now: datetime) -> str:
    return f"{now:%Y%m%d}-{secrets.token_hex(3)}"


class Scanner:
    """Shared HTTP clients, settings and store for any number of scans."""

    def __init__(self, settings: Settings | None = None, store: Store | None = None):
        self.settings = settings or load_settings()
        self.store = store or Store(self.settings.db_path)
        self.client, self.insecure_client = make_clients(
            self.settings.user_agent, self.settings.http_timeout
        )

    def close(self) -> None:
        self.client.close()
        self.insecure_client.close()

    def __enter__(self) -> Scanner:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def scan(self, url: str, options: ScanOptions | None = None) -> ScanResult:
        now = datetime.now(timezone.utc)
        ctx = ScanContext(
            id=new_scan_id(now),
            url=normalize_url(url),
            scanned_at=now,
            options=options or ScanOptions(),
        )
        self._resolve(ctx)
        return self._finish(ctx)

    def _resolve(self, ctx: ScanContext) -> None:
        res = resolve(ctx.url, self.client, self.insecure_client)
        ctx.final_url = res.final_url
        ctx.redirect_chain = res.chain
        ctx.fetch_status = res.fetch_status
        ctx.html = res.html
        ctx.artifacts["redirects.json"] = res.to_json()
        ctx.features["final_domain"] = registrable_domain(res.final_url)
        ctx.features["status_code"] = res.status_code
        ctx.features["tls_verified"] = res.tls_verified
        if res.shortener:
            ctx.add("URL_SHORTENER", "redirects.json#shortener", shortener=res.shortener)
        if res.html:
            ctx.artifacts["page.html"] = res.html

    def _finish(self, ctx: ScanContext) -> ScanResult:
        result = self._verdict(ctx)
        if ctx.options.write_evidence:
            write_pack(ctx, result, self.settings.evidence_dir)
        self.store.save_scan(result, ctx.features["final_domain"])
        return result

    def _verdict(self, ctx: ScanContext) -> ScanResult:
        if ctx.official_brand:
            risk, verdict, confidence, fraud_type = 0, "legitimate", 0.95, None
            kept = ctx.findings
        else:
            s = score.score(ctx.findings, ctx.fetch_status)
            risk, verdict, confidence, fraud_type = s.risk_score, s.verdict, s.confidence, s.fraud_type
            kept = s.findings
        return ScanResult(
            id=ctx.id,
            url=ctx.url,
            final_url=ctx.final_url,
            redirect_chain=ctx.redirect_chain,
            fetch_status=ctx.fetch_status,
            verdict=verdict,
            risk_score=risk,
            confidence=confidence,
            fraud_type=fraud_type,
            impersonated_brand=ctx.impersonated_brand if verdict != "legitimate" else None,
            reasons=[reasons.render(f) for f in kept],
            signals=ctx.features,
            cluster_id=None,
            analyst_confirmed=False,
            evidence_path=f"{self.settings.evidence_dir.as_posix().rstrip('/')}/{ctx.id}/",
            scanned_at=ctx.scanned_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        )


def scan(url: str, options: ScanOptions | None = None) -> ScanResult:
    with Scanner() as scanner:
        return scanner.scan(url, options)
