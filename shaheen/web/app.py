"""The dashboard: a live feed of scans with counters, the AI investigator's
live panel (the runs under way with their tool calls so far, the queue, the
latest reports) and the Google Maps watch (the searches of the last round,
on a Google map when a browser key is set), one page per case (reasons in
English and Arabic, screenshot, AI investigation and its tool-call trace,
followed live while the model works, analyst confirmation, evidence download
and verification), the Google Maps leads, and a box to scan a pasted link.

Everything is served from this package, the IBM Plex fonts included (no
CDN), so it works with the network unplugged. The one outside script is
Google's Maps JavaScript API, loaded on the feed only when
GOOGLE_MAPS_BROWSER_KEY is set. Suspect addresses are always defanged and
never links; page content from suspect sites is escaped like any other text.
The only outside links are Google Maps listing links on google.com.

A header switch, kept in a cookie like the language, picks the Analyst view
(all of the above) or the Simple view: headline numbers, the likely scams with
one plain sentence each in English and Arabic, and case pages without scores,
hashes or tool calls. /stats charts the store in either view's words, and
/hunts sends the AI hunter on a mission (see `shaheen.web.hunts`).
"""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader
from starlette.concurrency import run_in_threadpool

from shaheen import agents, evidence, investigator, watch
from shaheen.collectors import maps
from shaheen.config import PACKAGE_DIR, Settings, load_settings
from shaheen.domains import host_of
from shaheen.evidence import GST, defang_text
from shaheen.models import ScanResult
from shaheen.pipeline import Scanner
from shaheen.store import Store, utcnow
from shaheen.web import charts, hunts, i18n, reports, stats
from shaheen.web.trace import read_trace

WEB_DIR = PACKAGE_DIR / "web"
CASE_ID = re.compile(r"[0-9A-Za-z][0-9A-Za-z_-]{0,63}")
FEED_LIMIT = 60
TRACE = "agent_trace.jsonl"
LIVE_TOOLS = 12  # tool calls shown per running investigation, newest last
RECENT = 5  # finished investigations shown in the live panel
ALIVE_S = 4 * agents.HEARTBEAT_S  # an older queue heartbeat means the investigator is off
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
MAP_REFERRER = "strict-origin-when-cross-origin"
MODE_COOKIE = "shaheen_mode"
MODES = ("simple", "analyst")  # the first is the default
SIMPLE_LIMITS = {"fraud": 30, "suspicious": 15}  # newest sites listed per verdict in the Simple feed


def _map_headers(nonce: str) -> dict[str, str]:
    """The feed's headers when it loads Google's map: the CSP Google documents for the
    Maps JavaScript API, with a nonce for the scripts. Styles keep Google's allowlist
    form, since the map nonces the style elements it inserts only when the page has a
    `<style nonce>`. The referrer policy sends Google this dashboard's origin, which
    the browser key's website restriction checks."""
    policy = (
        f"default-src 'self'; script-src 'nonce-{nonce}' 'strict-dynamic' https: 'unsafe-eval' blob:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "img-src 'self' https://*.googleapis.com https://*.gstatic.com *.google.com *.googleusercontent.com data:; "
        "connect-src 'self' https://*.googleapis.com *.google.com https://*.gstatic.com data: blob:; "
        "font-src 'self' https://fonts.gstatic.com; frame-src *.google.com; worker-src blob:; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    return {"Content-Security-Policy": policy, "Referrer-Policy": MAP_REFERRER}


def _gst(iso: str | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    """An ISO-8601 time in UAE time, as `YYYY-MM-DD HH:MM` by default."""
    if not iso:
        return ""
    try:
        moment = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return iso
    moment = moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(GST).strftime(fmt)


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


def _age_s(iso: str | None) -> int | None:
    """Whole seconds since an ISO-8601 time, or None when it is missing or unreadable."""
    try:
        moment = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return None
    moment = moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
    return max(int((datetime.now(timezone.utc) - moment).total_seconds()), 0)


def _run_file(problem: str) -> bool:
    """Whether an `evidence.verify` line ("<problem>: <file>") is about a file that a
    running investigation is still writing (its report, trace or browser session)."""
    name = problem.split(": ", 1)[-1]
    return name in investigator.OWN_FILES or name.startswith("browser/")


def _live_step(step: dict[str, Any]) -> dict[str, Any]:
    """A trace step for the case page's live view, defanged like the rendered page."""
    if step["kind"] == "model":
        return {"kind": "model", "text": _defang(step["text"])}
    return {"kind": "tool", "server": step["server"], "tool": step["tool"], "args": _defang(step["args"]),
            "result": _defang(step["result"]) if step["result"] else "", "error": step["error"],
            "ms": round(step["ms"]) if step["ms"] is not None else None, "done": step["done"]}


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


def _maps_link(url: str) -> str | None:
    """A listing's Google Maps link, only when it is an https link on google.com."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    return url if parts.scheme == "https" and (host == "google.com" or host.endswith(".google.com")) else None


def _lead_view(row: dict[str, Any], lang: str) -> dict[str, Any]:
    """A Maps lead for the leads page and the case page; listing text is defanged like page content.
    The scan of its website comes with the leads page's rows only."""
    verdict = row.get("verdict")
    return {
        "time": _gst(row["found_at"]),
        "name": _defang(row["name"]),
        "address": _defang(row["address"]),
        "brand": row["brand"],
        "query": row["query"],
        "reasons": row["reasons"].split(","),
        "phone": row["phone"],
        "official_phones": row["official_phones"].replace(",", ", "),
        "website": _defang(row["website"]) if row["website"] else "",
        "maps_url": _maps_link(row["maps_url"]),
        "case": {"id": row["scan_id"], "verdict": verdict, "label": i18n.label(i18n.VERDICTS, lang, verdict),
                 "score": row["risk_score"]} if verdict else None,
        "queued": row.get("candidate_status") in ("queued", "scanning"),
    }


def _listing_view(listing: maps.Listing) -> dict[str, Any]:
    """A listing for the live Maps panel, defanged like page content. A lead shows
    what makes it one: its website, its helpline number, or both."""
    lead = listing.lead
    return {"name": _defang(listing.name), "lat": listing.lat, "lng": listing.lng, "outcome": listing.outcome,
            "website": _defang(lead.website) if lead and "website" in lead.reasons else "",
            "phone": lead.phone if lead and "helpline" in lead.reasons else ""}


def _search_view(search: maps.Search, current: bool) -> dict[str, Any]:
    listings = search.listings or ()
    return {"time": _gst(search.sent_at, "%H:%M:%S"), "query": search.query.text, "language": search.query.language,
            "state": "failed" if search.failed else "pending" if search.listings is None else "done",
            "current": current, "count": len(listings), "leads": sum(x.outcome == "lead" for x in listings),
            "listings": [_listing_view(x) for x in listings]}


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

    app = FastAPI(title="Shaheen", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
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
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    def lang_of(request: Request) -> str:
        return i18n.lang_of(request.cookies.get(i18n.COOKIE))

    def simple_of(request: Request) -> bool:
        return request.cookies.get(MODE_COOKIE) != "analyst"

    def page(request: Request, name: str, **context: Any) -> Response:
        lang = lang_of(request)
        return templates.TemplateResponse(request, name, {
            "t": i18n.STRINGS[lang], "lang": lang, "dir": "rtl" if lang == "ar" else "ltr",
            "mode": "simple" if simple_of(request) else "analyst",
            "js_strings": {k: i18n.STRINGS[lang][k] for k in i18n.JS_KEYS},
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

    def feed(lang: str, verdict: str | None, simple: bool = False) -> dict[str, Any]:
        scans = store.list_scans((verdict,) if verdict in FILTERS else (), FEED_LIMIT)
        sources = store.scan_sources([r.id for r in scans])
        ai = store.investigation_states([r.id for r in scans])
        listings = store.maps_leads_for_scans([r.id for r in scans])
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
                "listing": _defang(listings[r.id][0]["name"]) if r.id in listings else "",
                "confirmed": r.analyst_confirmed,
                "ai": ai.get(r.id, ""),
            })
        data = {"counters": store.counters(), "running_since": _gst(started), "uptime": _uptime(started),
                "rows": rows, "activity": activity(lang), "maps": maps_watch()}
        if simple:
            data["simple"] = simple_feed(lang, data)
        return data

    def simple_feed(lang: str, data: dict[str, Any]) -> dict[str, Any]:
        """The Simple feed: the newest likely scams and sites that need checking, each with
        one plain sentence in English and Arabic, and the AI and Maps watches in a line each."""
        t = i18n.STRINGS[lang]
        counters = data["counters"]
        totals = {"fraud": counters["fraud"], "suspicious": counters["flagged"] - counters["fraud"]}
        scans = {v: store.list_scans((v,), limit) for v, limit in SIMPLE_LIMITS.items()}
        with stats.connect(settings.db_path) as db:
            said = stats.summaries(db, [r.id for found in scans.values() for r in found])
        lists = {}
        for verdict, found in scans.items():
            total = totals[verdict]
            count = (t["simple_newest"].format(shown=len(found), total=total) if len(found) < total
                     else t["simple_all"].format(total=total) if total else "")
            lists[verdict] = {"count": count, "rows": [site_row(r, said.get(r.id), t) for r in found]}
        return {"suspicious_total": totals["suspicious"], "ai": ai_line(t, data["activity"]),
                "maps": maps_line(t, data["maps"], counters["maps_leads"], lang), **lists}

    def site_row(r: ScanResult, said: tuple[str, str] | None, t: dict[str, str]) -> dict[str, Any]:
        """A flagged site in plain words: the first sentence of its AI summary, or else its top reason."""
        top = max(r.reasons, key=lambda reason: reason.weight, default=None)
        en, ar = [investigator.first_sentence(s) for s in said] if said else (top.en, top.ar) if top else ("", "")
        return {
            "id": r.id, "verdict": r.verdict, "label": t[f"simple_{r.verdict}"],
            "date": _gst(r.scanned_at, "%Y-%m-%d"), "time": _gst(r.scanned_at, "%H:%M"),
            "domain": defang_text(host_of(r.final_url or r.url)),
            "brand": t["simple_pretends"].format(brand=r.impersonated_brand) if r.impersonated_brand else "",
            "kind": t.get(f"simple_type_{r.fraud_type}", "") if r.fraud_type and r.verdict == "fraud" else "",
            "en": _defang(en), "ar": _defang(ar),
        }

    def ai_line(t: dict[str, str], live: dict[str, Any]) -> str:
        """The AI investigator in one plain line, with its queue."""
        if live["state"] == "running":
            n = len(live["running"])
            line = t[{1: "simple_ai_one", 2: "simple_ai_two"}.get(n, "simple_ai_many")].format(n=n)
        else:
            line = t[{"waiting": "simple_ai_paused", "idle": "simple_ai_idle"}.get(live["state"], "simple_ai_off")]
        queued = sum(q["n"] for q in live["queue"])
        return f"{line} {t['simple_ai_queue'].format(n=queued)}" if queued else line

    def maps_line(t: dict[str, str], maps_state: dict[str, Any], leads: int, lang: str) -> str:
        """The Google Maps watch in one plain line. The Arabic line isolates the time so it keeps its order."""
        if maps_state["state"] == "searching":
            return t["simple_maps_now"]
        if maps_state["last_run"]:
            time = f"\u2066{maps_state['last_run']}\u2069" if lang == "ar" else maps_state["last_run"]
            return t["simple_maps_last"].format(time=time, n=leads)
        return t["simple_maps_off"] if maps_state["off"] == "no_key" else t["simple_maps_never"]

    def maps_watch() -> dict[str, Any]:
        """The live Google Maps panel: the searches of the last round and the one under
        way, held in memory by the collector of this process (`shaheen up`). Off, with the
        reason, when no watcher here runs Maps: no Places key, or another process."""
        searching, searches = maps.live.snapshot()
        attached = maps.live.attached
        last = watch.maps_last_round(store)
        due = last + timedelta(hours=settings.maps_interval_hours) if last else None
        allowed = watch.maps_allowed_at(store)
        current = searches[-1].query if searching and searches else None
        return {
            "state": "searching" if searching else "idle" if attached else "off",
            "off": "" if attached else "elsewhere" if settings.google_maps_api_key else "no_key",
            "query": current.text if current else "",
            "language": current.language if current else "",
            "last_run": _gst(last.isoformat()) if last else "",
            "next_run": _gst(due.isoformat()) if attached and due and due > datetime.now(timezone.utc) else "",
            "next_allowed": _gst(allowed.isoformat()) if allowed else "",
            "can_search": attached and not searching and allowed is None,
            "calls_today": maps.calls_today(store),
            "searches": [_search_view(s, searching and i == len(searches) - 1) for i, s in enumerate(searches)],
        }

    def case_row(row: dict[str, Any], lang: str) -> dict[str, Any]:
        return {"id": row["scan_id"], "domain": defang_text(host_of(row["final_url"] or row["url"])),
                "verdict": row["verdict"], "verdict_label": i18n.label(i18n.VERDICTS, lang, row["verdict"]),
                "score": row["risk_score"]}

    def investigator_alive() -> bool:
        """Whether the investigator's queue heartbeat is fresh."""
        beat = _age_s(store.get_meta(agents.HEARTBEAT_KEY))
        return beat is not None and beat <= ALIVE_S

    def activity(lang: str) -> dict[str, Any]:
        """The investigator for the live panel: each run under way with its tool calls so
        far, the queue by verdict and the latest finished investigations. Runs count only
        while the queue's heartbeat is fresh, so a killed investigator shows as off."""
        alive = investigator_alive()
        model_down = alive and bool(store.get_meta(agents.MODEL_DOWN_KEY))
        running = []
        for run in store.running_investigations() if alive else []:
            tools = [s for s in read_trace(settings.evidence_dir / run["scan_id"] / TRACE) if s["kind"] == "tool"]
            running.append({
                **case_row(run, lang), "mode": run["mode"] or "", "elapsed_s": _age_s(run["started_at"]) or 0,
                "tool_count": len(tools),
                "tools": [{"server": s["server"], "tool": s["tool"], "target": _defang(s["target"]),
                           "done": s["done"], "error": s["error"]} for s in tools[-LIVE_TOOLS:]],
            })
        queued = store.investigation_queue()
        recent = []
        for row in store.finished_investigations(RECENT):
            report = row["report"] if isinstance(row["report"], dict) else {}
            summary = (lang == "ar" and report.get("summary_ar")) or report.get("summary_en")
            kind = report.get("fraud_type") if isinstance(report.get("fraud_type"), str) else row["fraud_type"]
            recent.append({
                **case_row(row, lang), "time": _gst(row["finished_at"]),
                "type": i18n.label(i18n.FRAUD_TYPES, lang, kind) if kind else "",
                "summary": _defang(investigator.first_sentence(str(summary or ""))),
            })
        return {
            "state": "running" if running else "waiting" if model_down else "idle" if alive else "off",
            "model_down": model_down,
            "model": settings.llm_model,
            "running": running,
            "queue": [{"verdict": v, "label": i18n.label(i18n.VERDICTS, lang, v), "n": queued.get(v, 0)}
                      for v in ("fraud", "suspicious")],
            "recent": recent,
        }

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
        if simple_of(request):
            return page(request, "simple_feed.html", feed=feed(lang, None, simple=True), error=notice == "scan")
        key = settings.google_maps_browser_key
        nonce = secrets.token_urlsafe(18) if key else ""
        response = page(request, "feed.html", feed=feed(lang, verdict), verdict=verdict if verdict in FILTERS else None,
                        filters=FILTERS, error=notice == "scan", map_key=key, nonce=nonce,
                        referrer=MAP_REFERRER if key else "same-origin")
        if key:
            response.headers.update(_map_headers(nonce))
        return response

    @app.get("/api/feed")
    def api_feed(request: Request, verdict: str | None = None) -> JSONResponse:
        return JSONResponse(feed(lang_of(request), verdict, simple=simple_of(request)))

    @app.get("/stats")
    def stats_page(request: Request) -> Response:
        now = datetime.now(timezone.utc)
        view = charts.view(settings.db_path, now, lang_of(request), simple_of(request), investigator_alive(),
                           watching_since=store.get_meta("watch_started_at"), searches_today=maps.calls_today(store))
        return page(request, "stats.html", stats=view, as_of=_gst(now.isoformat()))

    @app.get("/mode/{code}")
    def switch_mode(code: str, next: str | None = None) -> Response:
        response = RedirectResponse(_safe_next(next), status_code=303)
        response.set_cookie(MODE_COOKIE, code if code in MODES else MODES[0], max_age=365 * 24 * 3600,
                            samesite="lax")
        return response

    @app.get("/maps")
    def maps_leads(request: Request) -> Response:
        lang = lang_of(request)
        leads = [_lead_view(row, lang) for row in store.maps_leads()]
        return page(request, "maps.html", leads=leads, enabled=bool(settings.google_maps_api_key),
                    last_run=_gst(store.get_meta(watch.last_run_key("maps"))),
                    kinds={kind: sum(kind in lead["reasons"] for lead in leads) for kind in ("website", "helpline")})

    @app.post("/maps/search")
    def maps_search_now() -> JSONResponse:
        """The feed's "Search Maps now" button: one round in the watcher of this process."""
        status = watch.search_maps_now(store)
        return JSONResponse({"status": status}, status_code=202 if status == "started" else 409)

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
        inv = investigation(case_id, folder)
        problems = evidence.verify(folder)
        running = inv is not None and inv["status"] == "running"
        if running:  # a run adds its report, trace and browser session to the manifest when it ends
            problems = [p for p in problems if not _run_file(p)]
        takedown = folder / evidence.TAKEDOWN
        leads = store.maps_leads_for_scans([case_id]).get(case_id, [])
        return page(
            request, "simple_case.html" if simple_of(request) else "case.html",
            r=result, host=host_of(result.final_url or result.url), chain=chain,
            signals=_rows(result.signals, SIGNAL_KEYS),
            storefront=_rows(_read_json(folder / "storefront.json") or {}, STOREFRONT_KEYS),
            screenshot=(folder / evidence.SCREENSHOT).is_file(),
            problems=problems,
            manifest_sha=evidence.manifest_sha256(folder) if not problems else None,
            confirmation=_read_json(folder / evidence.CONFIRMATION),
            takedown=takedown.read_text(encoding="utf-8") if takedown.is_file() else None,
            inv=inv,
            run_files_pending=running,
            trace=read_trace(folder / TRACE),
            listings=[_lead_view(lead, lang_of(request)) for lead in leads],
            notice=NOTICES.get(notice or ""),
            error=notice == "confirm_error",
        )

    @app.get("/api/case/{case_id}/live")
    def case_live(case_id: str) -> JSONResponse:
        """The investigation's status and, while it runs, its trace so far. `filed` turns
        true once the run's full record is saved (submit_report saves the report alone
        a few seconds before pi ends)."""
        _, folder = get_case(case_id)
        row = store.get_investigation(case_id)
        status = row["status"] if row else None
        report = (row or {}).get("report")
        filed = status == "failed" or (status == "done" and isinstance(report, dict) and "run" in report)
        live = status == "running" or (status == "done" and not filed)
        steps = [_live_step(s) for s in read_trace(folder / TRACE)] if live else []
        return JSONResponse({"status": status, "filed": filed, "steps": steps})

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
        return FileResponse(out, media_type="application/zip", filename=f"shaheen-{case_id}.zip")

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
        current = store.get_investigation(case_id)
        if current is None:
            store.queue_investigation(case_id)
        elif current["status"] != "running":  # a running case is never queued twice
            store.set_investigation(case_id, "queued", queued_at=utcnow(), error=None)
        return RedirectResponse(f"/case/{case_id}?notice=queued", status_code=303)

    @app.get("/lang/{code}")
    def switch_language(code: str, next: str | None = None) -> Response:
        response = RedirectResponse(_safe_next(next), status_code=303)
        response.set_cookie(i18n.COOKIE, i18n.lang_of(code), max_age=365 * 24 * 3600, samesite="lax")
        return response

    reports.add_routes(app, store, settings, page, get_case)
    hunts.add_routes(app, store, settings, page, investigator_alive)
    return app
