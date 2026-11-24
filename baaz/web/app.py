"""The dashboard: a live feed of scans with counters, one page per case
(reasons in English and Arabic, screenshot, AI investigation and its
tool-call trace, analyst confirmation, evidence download and verification)
and a box to scan a pasted link.

Everything is served from this package: no CDN, no web fonts, so it works
with the network unplugged. Suspect addresses are always defanged and never
links; page content from suspect sites is escaped like any other text.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader
from starlette.concurrency import run_in_threadpool

from baaz import evidence
from baaz.config import PACKAGE_DIR, Settings, load_settings
from baaz.domains import host_of
from baaz.evidence import GST, defang_text
from baaz.models import ScanResult
from baaz.pipeline import Scanner
from baaz.store import Store, utcnow
from baaz.web import i18n
from baaz.web.trace import read_trace

WEB_DIR = PACKAGE_DIR / "web"
CASE_ID = re.compile(r"[0-9A-Za-z][0-9A-Za-z_-]{0,63}")
FEED_LIMIT = 60
FILTERS = ("fraud", "suspicious", "legitimate")
SIGNAL_KEYS = (
    "final_domain", "title", "domain_age_days", "registrar", "hosting_country", "asn", "cert_age_days",
    "tls_verified", "status_code", "rendered", "brands_on_page", "sensitive_fields", "form_targets",
    "top_site_rank", "hosting_platform", "embedded_targets", "nxdomain", "render_error", "stage_errors",
)
STOREFRONT_KEYS = ("site_name", "payment_methods", "gateways", "checkout", "prices", "catalogue",
                   "admin_clusters", "shared_with_fraud")
# Evidence file names (`whois.json`, `takedown_request.md`) stay readable once defanged:
# these endings are not top-level domains, and `takedown_request` cannot be a host name.
_FILE_NAME = re.compile(r"(?<=\w)\[\.\](?=(?:jsonl?|html|png)\b)|(?<=takedown_request)\[\.\](?=md\b)")
NOTICES = {"confirmed": "confirm_done", "queued": "queued_done", "analyst": "analyst_required"}
SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; "
                                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
}


def _gst(iso: str | None) -> str:
    """An ISO-8601 time as `YYYY-MM-DD HH:MM` in UAE time."""
    if not iso:
        return ""
    try:
        moment = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return iso
    moment = moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(GST).strftime("%Y-%m-%d %H:%M")


def _defang(text: Any) -> str:
    """`evidence.defang_text`, keeping evidence file names readable."""
    return _FILE_NAME.sub(".", defang_text(text))


def _uptime(iso: str | None) -> str:
    if not iso:
        return ""
    try:
        start = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return ""
    minutes = max(int((datetime.now(timezone.utc) - start).total_seconds() // 60), 0)
    days, rest = divmod(minutes, 24 * 60)
    hours, minutes = divmod(rest, 60)
    return f"{days}d {hours}h" if days else f"{hours}h {minutes}m" if hours else f"{minutes}m"


def _read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _value(value: Any) -> str:
    """A fact as one line of text for a key/value table."""
    if isinstance(value, list) and all(isinstance(v, (str, int, float)) for v in value):
        return ", ".join(map(str, value))
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _rows(data: dict[str, Any], keys: tuple[str, ...]) -> list[tuple[str, str]]:
    return [(k, _value(data[k])) for k in keys if data.get(k) not in (None, "", [], {})]


def _strings(value: Any) -> list[str]:
    return [str(v) for v in value if v not in (None, "")] if isinstance(value, list) else []


def _report_view(report: dict[str, Any]) -> dict[str, Any]:
    """An investigation report, read defensively: every field may be missing."""
    adjustment = report.get("score_adjustment")
    review = report.get("needs_human_review")
    return {
        "summary_en": str(report.get("summary_en") or ""),
        "summary_ar": str(report.get("summary_ar") or ""),
        "fraud_type": report.get("fraud_type") if isinstance(report.get("fraud_type"), str) else None,
        "brand": report.get("impersonated_brand") if isinstance(report.get("impersonated_brand"), str) else None,
        "proven": _strings(report.get("proven")),
        "inferred": _strings(report.get("inferred")),
        "related": _strings(report.get("related_domains")),
        "actions": _strings(report.get("recommended_actions")),
        "adjustment": adjustment if isinstance(adjustment, int) and not isinstance(adjustment, bool) else None,
        "human_review": review if isinstance(review, bool) else None,
        "browser_actions": [{"tool": str(a.get("tool") or ""), "target": str(a.get("target") or "")}
                            for a in report.get("browser_actions") or [] if isinstance(a, dict)],
        "policy_violation": report.get("policy_violation") is True,
        "illustrative": report.get("illustrative") is True,
    }


def _safe_next(target: str | None) -> str:
    """A local path to go back to; anything else (another site, `//host`) means the feed."""
    if target and target.startswith("/") and not target.startswith(("//", "/\\")):
        return target
    return "/"


def _same_origin(request: Request) -> bool:
    """POSTs from a browser must come from this dashboard's own pages."""
    origin = request.headers.get("origin")
    if origin is None:
        return True
    return urlsplit(origin).netloc == request.headers.get("host")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    store = Store(settings.db_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        with Scanner(settings, store) as scanner:
            app.state.scanner = scanner
            yield

    app = FastAPI(title="Baaz", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")
    env = Environment(loader=FileSystemLoader(WEB_DIR / "templates"), autoescape=True,
                      trim_blocks=True, lstrip_blocks=True)
    env.filters.update(defang=_defang, gst=_gst)
    templates = Jinja2Templates(env=env)

    @app.middleware("http")
    async def guard(request: Request, call_next: Any) -> Response:
        if request.method == "POST" and not _same_origin(request):
            return Response("cross-site request refused", status_code=403)
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    def lang_of(request: Request) -> str:
        return i18n.lang_of(request.cookies.get(i18n.COOKIE))

    def page(request: Request, name: str, **context: Any) -> Response:
        lang = lang_of(request)
        return templates.TemplateResponse(request, name, {
            "t": i18n.STRINGS[lang], "lang": lang, "dir": "rtl" if lang == "ar" else "ltr",
            "verdicts": i18n.VERDICTS[lang], "fraud_types": i18n.FRAUD_TYPES[lang], "here": request.url.path,
            **context,
        })

    def case_folder(case_id: str) -> Path:
        """The evidence folder of a case, refusing any ID that could leave `evidence/`."""
        root = settings.evidence_dir.resolve()
        folder = (root / case_id).resolve()
        if not CASE_ID.fullmatch(case_id) or folder.parent != root:
            raise HTTPException(404, "no such case")
        return folder

    def get_case(case_id: str) -> tuple[ScanResult, Path]:
        folder = case_folder(case_id)
        result = store.get_scan(case_id)
        if result is None:
            raise HTTPException(404, "no such case")
        return result, folder

    def feed(lang: str, verdict: str | None) -> dict[str, Any]:
        scans = store.list_scans((verdict,) if verdict in FILTERS else (), FEED_LIMIT)
        sources = store.scan_sources([r.id for r in scans])
        started = store.get_meta("watch_started_at")
        rows = []
        for r in scans:
            source = "capture" if r.signals.get("captured_from") else sources.get(r.id, "manual")
            rows.append({
                "id": r.id,
                "time": _gst(r.scanned_at),
                "domain": defang_text(host_of(r.final_url or r.url)),
                "verdict": r.verdict,
                "verdict_label": i18n.label(i18n.VERDICTS, lang, r.verdict),
                "score": r.risk_score,
                "type": i18n.label(i18n.FRAUD_TYPES, lang, r.fraud_type) if r.fraud_type else "",
                "brand": r.impersonated_brand or "",
                "source": i18n.label(i18n.SOURCES, lang, source),
                "confirmed": r.analyst_confirmed,
            })
        return {"counters": store.counters(), "running_since": _gst(started), "uptime": _uptime(started),
                "rows": rows}

    def investigation(case_id: str, folder: Path) -> dict[str, Any] | None:
        row = store.get_investigation(case_id)
        report = _read_json(folder / "investigation.json")
        if not isinstance(report, dict):
            report = (row or {}).get("report")
        if row is None and not isinstance(report, dict):
            return None
        report = report if isinstance(report, dict) else {}
        return {
            "status": row["status"] if row else "done",
            "mode": report.get("mode") or (row or {}).get("mode"),
            "error": (row or {}).get("error"),
            **_report_view(report),
        }

    @app.get("/")
    def index(request: Request, verdict: str | None = None, notice: str | None = None) -> Response:
        lang = lang_of(request)
        return page(request, "feed.html", feed=feed(lang, verdict), verdict=verdict if verdict in FILTERS else None,
                    filters=FILTERS, error=notice == "scan")

    @app.get("/api/feed")
    def api_feed(request: Request, verdict: str | None = None) -> JSONResponse:
        return JSONResponse(feed(lang_of(request), verdict))

    @app.post("/scan")
    async def scan_form(url: str = Form("")) -> Response:
        if not url.strip():
            return RedirectResponse("/?notice=scan", status_code=303)
        result = await run_in_threadpool(app.state.scanner.scan, url.strip())
        return RedirectResponse(f"/case/{result.id}", status_code=303)

    @app.get("/api/scan")
    async def api_scan(url: str) -> JSONResponse:
        result = await run_in_threadpool(app.state.scanner.scan, url)
        return JSONResponse(result.to_dict())

    @app.get("/case/{case_id}")
    def case(request: Request, case_id: str, notice: str | None = None) -> Response:
        result, folder = get_case(case_id)
        redirects = _read_json(folder / "redirects.json") or {}
        chain = redirects.get("chain") or [{"url": u, "status": None, "via": None} for u in result.redirect_chain]
        problems = evidence.verify(folder)
        takedown = folder / evidence.TAKEDOWN
        return page(
            request, "case.html", r=result, host=host_of(result.final_url or result.url), chain=chain,
            signals=_rows(result.signals, SIGNAL_KEYS),
            storefront=_rows(_read_json(folder / "storefront.json") or {}, STOREFRONT_KEYS),
            screenshot=(folder / evidence.SCREENSHOT).is_file(),
            problems=problems,
            manifest_sha=evidence.manifest_sha256(folder) if not problems else None,
            confirmation=_read_json(folder / evidence.CONFIRMATION),
            takedown=takedown.read_text(encoding="utf-8") if takedown.is_file() else None,
            inv=investigation(case_id, folder),
            trace=read_trace(folder / "agent_trace.jsonl"),
            notice=NOTICES.get(notice or ""),
            error=notice == "confirm_error",
        )

    @app.get("/case/{case_id}/screenshot.png")
    def screenshot(case_id: str) -> FileResponse:
        path = case_folder(case_id) / evidence.SCREENSHOT
        if not path.is_file():
            raise HTTPException(404, "no screenshot")
        return FileResponse(path, media_type="image/png")

    @app.get("/case/{case_id}/evidence.zip")
    def evidence_zip(case_id: str) -> FileResponse:
        get_case(case_id)
        try:
            out = evidence.export_pack(case_id, settings=settings)
        except evidence.EvidenceError as exc:
            raise HTTPException(404, str(exc)) from exc
        return FileResponse(out, media_type="application/zip", filename=f"baaz-{case_id}.zip")

    @app.post("/case/{case_id}/confirm")
    def confirm(case_id: str, analyst: str = Form(""), note: str = Form("")) -> Response:
        get_case(case_id)
        if not analyst.strip():
            return RedirectResponse(f"/case/{case_id}?notice=analyst", status_code=303)
        try:
            evidence.confirm_case(case_id, analyst.strip(), note.strip(), store=store, settings=settings)
        except evidence.EvidenceError:
            return RedirectResponse(f"/case/{case_id}?notice=confirm_error", status_code=303)
        return RedirectResponse(f"/case/{case_id}?notice=confirmed", status_code=303)

    @app.post("/case/{case_id}/investigate")
    def reinvestigate(case_id: str) -> Response:
        get_case(case_id)
        if not store.queue_investigation(case_id):
            store.set_investigation(case_id, "queued", queued_at=utcnow(), error=None)
        return RedirectResponse(f"/case/{case_id}?notice=queued", status_code=303)

    @app.get("/lang/{code}")
    def switch_language(code: str, next: str | None = None) -> Response:
        response = RedirectResponse(_safe_next(next), status_code=303)
        response.set_cookie(i18n.COOKIE, i18n.lang_of(code), max_age=365 * 24 * 3600, samesite="lax")
        return response

    return app
