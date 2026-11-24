"""The dashboard's reports: the library of every case's evidence report
(/reports), one dense table filtered on the server by verdict, brand, scan date
and domain, 50 cases a page; each case's printable evidence report, served
read-only from its pack (/case/<id>/report.html); and the threat summary for
the police (/reports/summary, see `shaheen.summary`)."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, Response

from shaheen import evidence, summary
from shaheen.config import Settings
from shaheen.domains import host_of
from shaheen.evidence import defang_text
from shaheen.models import ScanResult
from shaheen.store import Store
from shaheen.web import i18n

PAGE_SIZE = 50
VERDICTS = ("fraud", "suspicious", "legitimate")
RANGES = ("today", "7d", "all")
SUMMARY_LINKS = ("today", "24h", "7d")
# The summary and the evidence reports carry their own inline style and inlined fonts.
# The summary's style has a nonce; a stored report's cannot, and a report has no script.
SUMMARY_CSP = ("default-src 'self'; style-src 'nonce-{nonce}'; font-src data:; script-src 'self'; img-src 'self'; "
               "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
REPORT_CSP = ("default-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src 'self'; "
              "base-uri 'none'; frame-ancestors 'none'; form-action 'none'")


def _needle(text: str) -> str:
    """A domain search as typed or pasted, defanged or not: a link becomes its host."""
    text = text.strip().lower().replace("[.]", ".").replace("hxxp", "http")
    return (urlsplit(text).hostname or "") if "://" in text else text


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _href(filters: dict[str, str], **changes: Any) -> str:
    """The library's address with these filters changed, back on the first page."""
    params = {k: v for k, v in {**filters, "page": "", **changes}.items() if v not in ("", 1)}
    return "/reports" + (f"?{urlencode(params)}" if params else "")


def library(store: Store, settings: Settings, verdict: str, brand: str, scanned: str, q: str,
            page: int) -> dict[str, Any]:
    """One page of cases, newest first, with the links that change the filters or the page."""
    where, args = [], []
    if verdict:
        where.append("s.verdict = ?")
        args.append(verdict)
    if brand:
        where.append("s.impersonated_brand = ?")
        args.append(brand)
    since = summary.sql_time(summary.period_start(scanned, datetime.now(timezone.utc)))
    if since:
        where.append("s.scanned_at >= ?")
        args.append(since)
    if needle := _needle(q):
        where.append("(s.domain LIKE ? ESCAPE '\\' OR s.url LIKE ? ESCAPE '\\' OR s.final_url LIKE ? ESCAPE '\\')")
        args += [_like(needle)] * 3
    clause = f" WHERE {' AND '.join(where)}" if where else ""
    total = store.select(f"SELECT COUNT(*) AS n FROM scans s{clause}", args)[0]["n"]
    pages = max(1, -(-total // PAGE_SIZE))
    page = min(max(page, 1), pages)
    rows = store.select(
        f"""SELECT s.id, s.url, s.final_url, s.verdict, s.risk_score, s.fraud_type, s.impersonated_brand,
                   s.analyst_confirmed, s.scanned_at, i.status AS ai
            FROM scans s LEFT JOIN investigations i ON i.scan_id = s.id{clause}
            ORDER BY s.scanned_at DESC, s.rowid DESC LIMIT ? OFFSET ?""",
        [*args, PAGE_SIZE, (page - 1) * PAGE_SIZE],
    )
    filters = {"verdict": verdict, "brand": brand, "scanned": "" if scanned == "all" else scanned, "q": q}
    return {
        "rows": [{**row, "domain": defang_text(host_of(row["final_url"] or row["url"])),
                  "pack": (settings.evidence_dir / row["id"] / evidence.MANIFEST).is_file()} for row in rows],
        "total": total,
        "first": (page - 1) * PAGE_SIZE + 1 if rows else 0,
        "last": (page - 1) * PAGE_SIZE + len(rows),
        "newer": _href(filters, page=page - 1) if page > 1 else "",
        "older": _href(filters, page=page + 1) if page < pages else "",
        "verdicts": [(v, _href(filters, verdict=v)) for v in ("", *VERDICTS)],
        "ranges": [(r, _href(filters, scanned="" if r == "all" else r)) for r in RANGES],
        "brands": [r["brand"] for r in store.select(
            "SELECT DISTINCT impersonated_brand AS brand FROM scans WHERE impersonated_brand IS NOT NULL ORDER BY 1")],
        "cases": store.select("SELECT COUNT(*) AS n FROM scans")[0]["n"],
        "filtered": bool(clause),
    }


def add_routes(app: FastAPI, store: Store, settings: Settings, render_page: Callable[..., Response],
               get_case: Callable[[str], tuple[ScanResult, Path]]) -> None:
    @app.get("/reports")
    def reports(request: Request, verdict: str = "", brand: str = "", scanned: str = "all", q: str = "",
                page: int = 1) -> Response:
        verdict = verdict if verdict in VERDICTS else ""
        scanned = scanned if scanned in RANGES else "all"
        q = q.strip()[:200]
        lib = library(store, settings, verdict, brand, scanned, q, page)
        return render_page(request, "reports.html", lib=lib, verdict=verdict, brand=brand, scanned=scanned, q=q,
                           summary_links=SUMMARY_LINKS)

    @app.get("/reports/summary")
    def threat_summary(request: Request, period: str = "7d") -> Response:
        lang = i18n.lang_of(request.cookies.get(i18n.COOKIE))
        period = period if period in summary.PERIODS else "7d"
        nonce = secrets.token_urlsafe(18)
        html = summary.render(summary.build(store, settings, period, lang), lang, web=True, nonce=nonce)
        return HTMLResponse(html, headers={"Content-Security-Policy": SUMMARY_CSP.format(nonce=nonce)})

    @app.get("/case/{case_id}/report.html")
    def evidence_report(case_id: str) -> FileResponse:
        _, folder = get_case(case_id)
        path = folder / evidence.REPORT_HTML
        if not path.is_file():
            raise HTTPException(404, "no evidence report")
        return FileResponse(path, media_type="text/html; charset=utf-8",
                            headers={"Content-Security-Policy": REPORT_CSP})
