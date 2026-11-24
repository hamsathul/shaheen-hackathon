"""`scan(url)`: the one pipeline the CLI, batch runner, watcher, dashboard
and investigator all share.

resolve -> render -> allowlist -> intel -> URL signals -> page signals and
profiles -> storefront -> score -> reasons -> evidence -> store

An allowlisted link (official or government domain all the way, JavaScript
redirects included) skips the signal stages but still gets its evidence pack
and stored result. A stage that fails is recorded in `stage_errors` and the
scan goes on to a verdict.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

from baaz import brands, intel, page, reasons, score, signals, storefront
from baaz.config import Settings, load_settings
from baaz.domains import host_of, normalize_url, registrable_domain
from baaz.evidence import write_pack
from baaz.models import ScanContext, ScanOptions, ScanResult
from baaz.render import Rendered, render
from baaz.resolve import PROFILES, SHORTENERS, make_clients, resolve, visible_text
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

    def scan(self, url: str, options: ScanOptions | None = None, *, fetch: bool = True) -> ScanResult:
        """Scan one link. With `fetch=False` nothing is requested from the site:
        the link is scored from its URL and domain alone, as `timeout`."""
        now = datetime.now(timezone.utc)
        ctx = ScanContext(
            id=new_scan_id(now),
            url=normalize_url(url),
            scanned_at=now,
            options=options or ScanOptions(),
        )
        ctx.final_url, ctx.redirect_chain = ctx.url, [ctx.url]
        ctx.features.update(final_domain=registrable_domain(ctx.url), fetched=fetch, rendered=False,
                            stage_seconds={})
        with ThreadPoolExecutor(max_workers=len(PROFILES) + 1) as side:
            profiles: list[Future[dict[str, Any]]] = []
            early: dict[str, Future[dict[str, Any]]] = {}
            if fetch:
                self._stage(ctx, "resolve", self._resolve)
            else:
                ctx.fetch_status = "timeout"
            if brands.allowlist(ctx.redirect_chain) is None:
                # intel and the visitor profiles are fetched while the browser renders
                domain = ctx.features["final_domain"]
                if domain not in SHORTENERS:
                    early[domain] = side.submit(intel.gather, domain, self.store, host_of(ctx.final_url))
                if ctx.fetch_status == "ok":
                    profiles = [side.submit(self._profile, ctx.url, key) for key in PROFILES]
            if fetch:
                self._stage(ctx, "render", self._render)
            if not self._stage(ctx, "allowlist", self._allowlist):
                self._stage(ctx, "url_signals", lambda c: signals.url_signals(c, self._intel(c, early)))
            self._stage(ctx, "page", lambda c: self._page(c, profiles))
        self._stage(ctx, "storefront", self._storefront)
        return self._finish(ctx)

    @staticmethod
    def _stage(ctx: ScanContext, name: str, step: Callable[[ScanContext], Any]) -> Any:
        """Run one stage; an unexpected error is recorded and the scan goes on."""
        start = time.monotonic()
        try:
            return step(ctx)
        except Exception as exc:  # always return a verdict
            ctx.features.setdefault("stage_errors", []).append(
                {"stage": name, "error": f"{type(exc).__name__}: {exc}"[:300]})
            return None
        finally:
            ctx.features["stage_seconds"][name] = round(time.monotonic() - start, 1)

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

    def _allowlist(self, ctx: ScanContext) -> bool:
        allowed = brands.allowlist(ctx.redirect_chain)
        if allowed is None:
            return False
        ctx.official_brand = allowed.owner
        ctx.add(allowed.code, "redirects.json#final_url", **allowed.params)
        return True

    def _intel(self, ctx: ScanContext, early: dict[str, Future[dict[str, Any]]]) -> dict[str, dict[str, Any]]:
        """Intel on the landing domain (gathered early unless the browser moved
        on to another domain), also written to the evidence pack."""
        domain = ctx.features["final_domain"]
        if domain in SHORTENERS:
            return {}
        facts = early[domain].result() if domain in early else intel.gather(domain, self.store,
                                                                              host_of(ctx.final_url))
        ctx.artifacts["whois.json"] = facts["whois"]
        ctx.artifacts["dns_hosting.json"] = facts["dns"]
        ctx.artifacts["cert.json"] = facts["cert"]
        return {domain: facts}

    def _render(self, ctx: ScanContext) -> None:
        """Render the landing page in the browser: its DOM replaces the fetched
        HTML, and a JavaScript redirect to another site extends the chain."""
        if not ctx.options.render or ctx.fetch_status == "dead":
            return
        rendered, error = render(ctx.final_url)
        if rendered is None:
            ctx.features["render_error"] = error
            return
        ctx.features["rendered"] = True
        if rendered.screenshot:
            ctx.artifacts["screenshot.png"] = rendered.screenshot
        self._follow_browser(ctx, rendered)
        if rendered.status and rendered.status < 400 and ctx.fetch_status != "ok":
            ctx.fetch_status = "ok"
            ctx.features["status_code"] = rendered.status
        ctx.html = rendered.html
        ctx.artifacts["page.html"] = rendered.html

    @staticmethod
    def _follow_browser(ctx: ScanContext, rendered: Rendered) -> None:
        """Append the browser's navigations to another registrable domain to
        the redirect chain (`via: browser`) and move the landing URL there."""
        start = registrable_domain(ctx.final_url)
        if registrable_domain(rendered.final_url) == start:
            return
        last_on_start = max((i for i, u in enumerate(rendered.chain) if registrable_domain(u) == start),
                            default=-1)
        hops = [u for u in rendered.chain[last_on_start + 1:] if u not in ctx.redirect_chain]
        chain = ctx.artifacts["redirects.json"]["chain"]
        chain[-1]["text_len"] = len(visible_text(ctx.html)) if ctx.html else None
        for url in hops or [rendered.final_url]:
            chain.append({"url": url, "status": None, "via": "browser", "text_len": None})
            ctx.redirect_chain.append(url)
        chain[-1]["status"] = rendered.status
        ctx.artifacts["redirects.json"]["final_url"] = rendered.final_url
        ctx.final_url = rendered.final_url
        ctx.features["final_domain"] = registrable_domain(rendered.final_url)

    def _page(self, ctx: ScanContext, profiles: list[Future[dict[str, Any]]]) -> None:
        """Page facts for the evidence pack; for a link that is not allowlisted,
        the page, doorway and cloaking signals too."""
        allowlisted = ctx.official_brand is not None
        if ctx.html:
            facts = page.analyse(ctx.html, ctx.final_url)
            named = signals.brands_on_page(facts, ctx.features["final_domain"])
            ctx.artifacts["page.json"] = {
                **facts.to_json(),
                "brands_on_page": [{"brand": b.brand.name_en, "where": b.where, "term": b.term} for b in named],
                "urgency_terms": signals.urgency_terms(facts.text),
                "exfiltration": signals.exfiltration_targets(ctx.html),
            }
            ctx.features.update(
                title=facts.title,
                brands_on_page=[b.brand.name_en for b in named],
                sensitive_fields=sorted(facts.sensitive_fields()),
                form_targets=sorted({registrable_domain(f.action) for f in facts.forms
                                     if f.action.startswith("http")}),
            )
            if not allowlisted:
                found, brand = signals.page_findings(facts, ctx.final_url, ctx.html)
                ctx.findings += found
                ctx.impersonated_brand = ctx.impersonated_brand or brand
        if allowlisted:
            return
        ctx.findings += signals.doorway_findings(ctx.artifacts.get("redirects.json", {}).get("chain", []))
        if profiles:
            views = dict(zip(PROFILES, (f.result() for f in profiles), strict=True))
            ctx.artifacts["profiles.json"] = views
            ctx.findings += signals.cloaking_findings(views)

    def _storefront(self, ctx: ScanContext) -> None:
        """Storefront checks on a reachable site. A site that blocks its pages
        to Baaz (403, a bot or phishing interstitial) often still answers on
        its public Store API, so blocked sites are checked too."""
        if ctx.options.storefront and ctx.fetch_status in ("ok", "blocked") and ctx.official_brand is None:
            client = self.client if ctx.features.get("tls_verified", True) else self.insecure_client
            storefront.inspect(ctx, client, self.store)

    def _profile(self, url: str, key: str) -> dict[str, Any]:
        """The link as one visitor profile sees it (phone in Arabic, desktop, crawler)."""
        res = resolve(url, self.client, self.insecure_client, headers=PROFILES[key])
        return signals.profile_view(res, page.analyse(res.html, res.final_url))

    def _finish(self, ctx: ScanContext) -> ScanResult:
        result = self._verdict(ctx)
        if ctx.options.write_evidence:
            write_pack(ctx, result, self.settings.evidence_dir, self.settings)
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
