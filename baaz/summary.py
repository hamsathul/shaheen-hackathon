"""The threat summary: what Baaz found over a period, for the police. Headline
numbers, the new fraud sites, the brands hit, the clusters of linked sites,
suggested takedowns and Google Maps leads, in English or Arabic.

The dashboard serves it at /reports/summary with a print button; `baaz summary`
writes it as one self-contained HTML file (fonts inlined) to email or print.
Both print on A4. Every number comes from the store and the evidence packs.
Suspect addresses are defanged and never links.

Periods are UAE days: `today` starts at 00:00 GST, `7d` at 00:00 GST six days
ago (seven days with today), `24h` is the last 24 hours and `all` has no start.
"""

from __future__ import annotations

import json
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from baaz import __version__, investigator, storefront
from baaz.config import PACKAGE_DIR, Settings
from baaz.domains import host_of
from baaz.evidence import GST, REPORT_FONTS, defang_text, font_faces
from baaz.store import Store
from baaz.web import i18n

PERIODS = ("today", "24h", "7d", "all")
TEMPLATE = "summary.html"
FONTS = (*REPORT_FONTS, ("IBM Plex Sans Arabic", "600", "ibm-plex-sans-arabic-600-arabic.woff2"))
FLAGGED_FRAUD = "(s.verdict = 'fraud' OR s.analyst_confirmed = 1)"
CLUSTER_KINDS = ("admin", "catalogue", "gateway")

_templates = Environment(
    loader=FileSystemLoader(PACKAGE_DIR / "web" / "templates"),
    autoescape=True,
    trim_blocks=True,
    lstrip_blocks=True,
)


def period_start(period: str, now: datetime) -> datetime | None:
    """When a period starts, in UTC; None for `all`."""
    if period == "24h":
        return (now - timedelta(hours=24)).astimezone(timezone.utc)
    midnight = datetime.combine(now.astimezone(GST).date(), time(), tzinfo=GST)
    days = {"today": 0, "7d": 6}.get(period)
    return None if days is None else (midnight - timedelta(days=days)).astimezone(timezone.utc)


def sql_time(moment: datetime | None) -> str:
    """A bound for `>=` on the stored ISO-8601 UTC times ("" matches everything)."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") if moment else ""


def _local(moment: datetime | str | None) -> str:
    """A time (or a stored ISO-8601 time) as `YYYY-MM-DD HH:MM` in UAE time."""
    if not moment:
        return ""
    moment = datetime.fromisoformat(moment) if isinstance(moment, str) else moment
    return moment.astimezone(GST).strftime("%Y-%m-%d %H:%M")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _marks(n: int) -> str:
    return ",".join("?" * n)


# the figures, the sites and their brands


def figures(store: Store, since: str) -> dict[str, int]:
    """The links checked in the period, and how many were flagged, fraud, AI-investigated and confirmed."""
    row = store.select(
        """SELECT COUNT(*) AS checked, TOTAL(s.verdict IN ('fraud', 'suspicious')) AS flagged,
                  TOTAL(s.verdict = 'fraud') AS fraud, TOTAL(i.status = 'done') AS investigated,
                  TOTAL(s.analyst_confirmed) AS confirmed
           FROM scans s LEFT JOIN investigations i ON i.scan_id = s.id WHERE s.scanned_at >= ?""",
        (since,),
    )[0]
    return {key: int(value) for key, value in row.items()}


def fraud_sites(store: Store, settings: Settings, since: str, lang: str) -> list[dict[str, Any]]:
    """Each domain first flagged fraud (or confirmed by an analyst) in the period, newest
    first, shown by its best case: confirmed, then AI-investigated, then the latest."""
    rows = store.select(
        f"""SELECT s.id, s.url, s.final_url, s.domain, s.risk_score, s.fraud_type, s.impersonated_brand,
                   s.analyst_confirmed, s.result_json, i.report_json, f.first_flagged
            FROM scans s
            JOIN (SELECT domain, MIN(scanned_at) AS first_flagged FROM scans s
                  WHERE {FLAGGED_FRAUD} GROUP BY domain) f ON f.domain = s.domain
            LEFT JOIN investigations i ON i.scan_id = s.id AND i.status = 'done'
            WHERE {FLAGGED_FRAUD} AND f.first_flagged >= ?
            ORDER BY s.analyst_confirmed DESC, i.report_json IS NOT NULL DESC, s.scanned_at DESC""",
        (since,),
    )
    best: dict[str, dict[str, Any]] = {}
    for row in rows:
        best.setdefault(row["domain"], row)
    seen = first_seen(store, list(best))
    sites = [_site(row, seen.get(row["domain"]), settings, lang) for row in best.values()]
    return sorted(sites, key=lambda s: s["flagged_at"], reverse=True)


def first_seen(store: Store, domains: list[str]) -> dict[str, str]:
    """When Baaz first met each domain: as a queued candidate or a scan's landing domain."""
    if not domains:
        return {}
    rows = store.select(
        f"""SELECT domain, MIN(seen) AS seen FROM (
                SELECT domain, added_at AS seen FROM candidates WHERE domain IN ({_marks(len(domains))})
                UNION ALL SELECT domain, scanned_at FROM scans WHERE domain IN ({_marks(len(domains))}))
            GROUP BY domain""",
        [*domains, *domains],
    )
    return {r["domain"]: r["seen"] for r in rows}


def _site(row: dict[str, Any], seen: str | None, settings: Settings, lang: str) -> dict[str, Any]:
    report = json.loads(row["report_json"]) if row["report_json"] else {}
    summary = (lang == "ar" and report.get("summary_ar")) or report.get("summary_en") or ""
    folder = settings.evidence_dir / row["id"]
    whois, dns = _read_json(folder / "whois.json"), _read_json(folder / "dns_hosting.json")
    signals = json.loads(row["result_json"]).get("signals") or {}
    country = dns.get("country") or signals.get("hosting_country")
    # A network's name ends with its country ("CLOUDFLARENET - Cloudflare, Inc., US").
    hosting = [dns.get("asn") or signals.get("asn"), dns.get("asn_name") or country]
    return {
        "id": row["id"],
        "domain": defang_text(row["domain"]),
        "host": defang_text(host_of(row["final_url"] or row["url"])),
        "brand": row["impersonated_brand"] or "",
        "type": i18n.label(i18n.FRAUD_TYPES, lang, row["fraud_type"]) if row["fraud_type"] else "",
        "score": row["risk_score"],
        "confirmed": bool(row["analyst_confirmed"]),
        "flagged_at": row["first_flagged"],
        "first_seen": _local(seen or row["first_flagged"]),
        "summary": defang_text(investigator.first_sentence(str(summary))) if summary else "",
        "summary_lang": "ar" if lang == "ar" and report.get("summary_ar") else "en",
        "registrar": whois.get("registrar") or signals.get("registrar") or "",
        "abuse": whois.get("registrar_abuse_email") or "",
        "hosting": " ".join(filter(None, hosting)),
    }


def brands_hit(store: Store, since: str, sites: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each brand with its new fraud sites, and the other sites flagged suspicious in the period."""
    fraud: dict[str, set[str]] = {}
    for site in sites:
        if site["brand"]:
            fraud.setdefault(site["brand"], set()).add(site["domain"])
    rows = store.select(
        """SELECT DISTINCT impersonated_brand AS brand, domain FROM scans
           WHERE scanned_at >= ? AND verdict = 'suspicious' AND impersonated_brand IS NOT NULL""",
        (since,),
    )
    suspicious: dict[str, set[str]] = {}
    for row in rows:
        if defang_text(row["domain"]) not in fraud.get(row["brand"], set()):
            suspicious.setdefault(row["brand"], set()).add(row["domain"])
    brands = [{"brand": b, "fraud": len(fraud.get(b, ())), "suspicious": len(suspicious.get(b, ()))}
              for b in {*fraud, *suspicious}]
    return sorted(brands, key=lambda b: (-b["fraud"], -b["suspicious"], b["brand"]))


# linked clusters and takedowns


def clusters(store: Store, sites: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fingerprints shared by two or more domains, one of them a new fraud site: the same
    administrator account, product catalogue or private skimmer gateway. Raw values stay
    in the database; a cluster shows its derived ID (a gateway, its public slug)."""
    strong = sorted(storefront.gateway_lists()["strong"])
    rows = store.select(
        f"""SELECT f.kind, f.value, f.domain, s.verdict, s.analyst_confirmed, s.scanned_at
            FROM fingerprints f JOIN scans s ON s.id = f.scan_id
            WHERE f.kind IN ('admin', 'catalogue') OR (f.kind = 'gateway' AND f.value IN ({_marks(len(strong))}))
            ORDER BY s.scanned_at""",
        strong,
    )
    groups: dict[tuple[str, str], dict[str, bool]] = {}
    for row in rows:  # oldest first: a domain keeps the verdict of its latest scan with this fingerprint
        fraud = row["verdict"] == "fraud" or bool(row["analyst_confirmed"])
        groups.setdefault((row["kind"], row["value"]), {})[row["domain"]] = fraud
    new = {site["domain"] for site in sites}
    found = []
    for (kind, value), domains in groups.items():
        named = {defang_text(d): fraud for d, fraud in domains.items()}
        if len(named) < 2 or not new & named.keys():
            continue
        found.append({
            "kind": kind,
            "id": value if kind == "gateway" else storefront.cluster_id(kind, value),
            "domains": sorted(named.items(), key=lambda item: (not item[1], item[0])),
            "fraud": sum(named.values()),
        })
    return sorted(found, key=lambda c: (-len(c["domains"]), CLUSTER_KINDS.index(c["kind"]), c["id"]))


def takedowns(sites: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The new fraud sites grouped by registrar (largest group first), confirmed cases first."""
    groups: dict[str, dict[str, Any]] = {}
    for site in sites:
        group = groups.setdefault(site["registrar"], {"registrar": site["registrar"], "abuse": "", "sites": []})
        group["abuse"] = group["abuse"] or site["abuse"]
        group["sites"].append(site)
    for group in groups.values():
        group["sites"].sort(key=lambda s: (not s["confirmed"], s["domain"]))
    return sorted(groups.values(), key=lambda g: (not g["registrar"], -len(g["sites"]), g["registrar"]))


def maps_leads(store: Store, since: str, lang: str) -> list[dict[str, Any]]:
    """The Google Maps leads found in the period, with the scan of their website if any."""
    leads = []
    for row in store.maps_leads():
        if row["found_at"] < since:
            continue
        leads.append({
            "time": _local(row["found_at"]),
            "name": defang_text(row["name"]),
            "brand": row["brand"],
            "reasons": row["reasons"].split(","),
            "phone": row["phone"],
            "website": defang_text(row["website"]) if row["website"] else "",
            "case": {"id": row["scan_id"], "verdict": row["verdict"], "score": row["risk_score"],
                     "label": i18n.label(i18n.VERDICTS, lang, row["verdict"])} if row["verdict"] else None,
        })
    return leads


# the report


def build(store: Store, settings: Settings, period: str, lang: str, now: datetime | None = None) -> dict[str, Any]:
    """Everything the summary shows, for `render`."""
    now = now or datetime.now(timezone.utc)
    start = period_start(period, now)
    since = sql_time(start)
    sites = fraud_sites(store, settings, since, lang)
    return {
        "period": period,
        "start": _local(start),
        "end": _local(now),
        "generated_utc": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "figures": figures(store, since),
        "sites": sites,
        "brands": brands_hit(store, since, sites),
        "clusters": clusters(store, sites),
        "takedowns": takedowns(sites),
        "leads": maps_leads(store, since, lang),
        "version": __version__,
    }


def render(report: dict[str, Any], lang: str, web: bool = False, nonce: str = "") -> str:
    """The summary as one HTML document. On the dashboard (`web`) it gets a toolbar with
    the periods and a print button; the file `baaz summary` writes has neither."""
    return _templates.get_template(TEMPLATE).render(
        r=report, lang=lang, dir="rtl" if lang == "ar" else "ltr", t=i18n.STRINGS[lang], periods=PERIODS,
        web=web, nonce=nonce, fonts=font_faces(FONTS),
    )


def write(settings: Settings, period: str, lang: str, out: Path | None = None) -> Path:
    """Write the summary to `out`, by default `evidence/reports/threat-summary-<period>-<lang>-<time>.html`."""
    now = datetime.now(timezone.utc)
    report = build(Store(settings.db_path), settings, period, lang, now)
    name = f"threat-summary-{period}-{lang}-{now.astimezone(GST).strftime('%Y%m%d-%H%M')}.html"
    out = out or settings.evidence_dir / "reports" / name
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(report, lang), encoding="utf-8")
    return out
