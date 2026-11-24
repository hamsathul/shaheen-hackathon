"""Evidence pack: one folder per scan holding every artifact a reason cites,
a printable report and a manifest of SHA-256 hashes.

At scan time the folder gets the stage artifacts, `report.json`,
`report.html` and, last, `manifest.json`. `verify` recomputes every hash.
`confirm_case` (an analyst's decision, never the scan) adds
`confirmation.json` and `takedown_request.md` and extends the manifest
without touching the entries already in it. `export_pack` zips the folder.

Reason evidence pointers (`<file>#<field>`) name a file of the pack.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import zipfile
from datetime import datetime, timedelta, timezone
from functools import cache
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from baaz import __version__, intel, resolve
from baaz.config import PACKAGE_DIR, Settings, load_settings
from baaz.domains import host_of, registrable_domain
from baaz.models import ScanContext, ScanResult
from baaz.store import Store

MANIFEST = "manifest.json"
REPORT_HTML = "report.html"
CONFIRMATION = "confirmation.json"
TAKEDOWN = "takedown_request.md"
SCREENSHOT = "screenshot.png"
# The UAE keeps Gulf Standard Time all year (no daylight saving), so a fixed
# offset is exact and needs no time-zone database.
GST = timezone(timedelta(hours=4), "GST")
COLLECTION_STATEMENT = (
    "All collection was non-intrusive: unauthenticated GET requests to public pages and public "
    "endpoints, plus public DNS, RDAP/WHOIS and TLS certificate lookups. No form was submitted, "
    "no credential was entered and no login or access control was bypassed."
)
TOP_REASONS = 6
_ARTIFACTS = ("redirects.json", "whois.json", "dns_hosting.json", "cert.json",
              "page.json", "profiles.json", "storefront.json")
# The report is read from the pack, often on a machine with no network: the dashboard's
# fonts travel inside it (family, weight range, file in web/static/fonts).
REPORT_FONTS = (
    ("IBM Plex Sans", "100 700", "ibm-plex-sans-latin.woff2"),
    ("IBM Plex Mono", "400", "ibm-plex-mono-400-latin.woff2"),
    ("IBM Plex Sans Arabic", "400", "ibm-plex-sans-arabic-400-arabic.woff2"),
)
_SCHEME = re.compile(r"\bhttp(s?)(?=://)", re.I)
_HOST = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*[a-z]\b|\b\d{1,3}(?:\.\d{1,3}){3}\b", re.I)

_templates = Environment(
    loader=FileSystemLoader(PACKAGE_DIR / "web" / "templates"),
    autoescape=True,
    trim_blocks=True,
    lstrip_blocks=True,
)


class EvidenceError(Exception):
    """A pack that is missing, unknown or fails verification."""


def defang_text(text: Any) -> str:
    """Defang a URL, a host name or free text: hxxp(s):// for the scheme and
    [.] in every host name and IPv4 address, so nothing stays clickable."""
    text = _SCHEME.sub(r"hxxp\1", str(text))
    return _HOST.sub(lambda m: m.group(0).replace(".", "[.]"), text)


_templates.filters["defang"] = defang_text


def stamp(moment: datetime) -> dict[str, str]:
    """One moment in UTC and in UAE time (Asia/Dubai, UTC+4)."""
    utc = moment.astimezone(timezone.utc)
    return {
        "utc": utc.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "dubai": utc.astimezone(GST).isoformat(timespec="seconds"),
    }


def _parse_time(text: str) -> datetime:
    moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _write(path: Path, content: Any) -> None:
    if isinstance(content, bytes):
        path.write_bytes(content)
    elif isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_text(json.dumps(content, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def _read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _entry(folder: Path, name: str) -> dict[str, Any]:
    digest = hashlib.sha256()
    path = folder / name
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            digest.update(chunk)
    return {"name": name, "size": path.stat().st_size, "sha256": digest.hexdigest()}


def _pack_files(folder: Path) -> list[str]:
    """Every file in the pack except the manifest, as folder-relative POSIX paths."""
    return sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*")
                  if p.is_file() and p.name != MANIFEST)


def _user_agents(settings: Settings) -> dict[str, str]:
    """The desktop user agent of the HTTP clients and browser, plus each fetch
    profile's (`resolve.PROFILES`: name -> request headers, or an object with
    `headers` or `user_agent`)."""
    agents = {"desktop": settings.user_agent}
    for name, profile in getattr(resolve, "PROFILES", {}).items():
        headers = profile if isinstance(profile, dict) else getattr(profile, "headers", None) or {}
        agent = headers.get("User-Agent") or headers.get("user-agent") or getattr(profile, "user_agent", None)
        if agent:
            agents[f"profile:{name}"] = agent
    return agents


# writing the pack


def write_pack(ctx: ScanContext, result: ScanResult, root: Path, settings: Settings | None = None) -> Path:
    settings = settings or load_settings()
    folder = root / ctx.id
    folder.mkdir(parents=True, exist_ok=True)
    for name, content in ctx.artifacts.items():
        _write(folder / name, content)
    _write(folder / "report.json", result.to_dict())
    generated = datetime.now(timezone.utc)
    files = [_entry(folder, name) for name in _pack_files(folder)]
    _write(folder / REPORT_HTML, render_report(result, folder, files, generated))
    _write(folder / MANIFEST, {
        "tool": {"name": "baaz", "version": __version__},
        "scan_id": ctx.id,
        "url": result.url,
        "final_url": result.final_url,
        "scanned_at": stamp(ctx.scanned_at),
        "generated_at": stamp(generated),
        "user_agents": _user_agents(settings),
        "collection": COLLECTION_STATEMENT,
        "files": sorted([*files, _entry(folder, REPORT_HTML)], key=lambda e: e["name"]),
    })
    return folder


def _facts(data: Any) -> list[tuple[str, str]]:
    """Top-level fields of an artifact whose shape the report does not know, as text rows."""
    if not isinstance(data, dict):
        return [("value", _short(data))] if data else []
    return [(key, _short(value)) for key, value in data.items() if value not in (None, "", [], {})]


def _short(value: Any, limit: int = 400) -> str:
    if isinstance(value, list) and all(isinstance(v, (str, int, float)) for v in value):
        text = ", ".join(map(str, value))
    elif isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, default=str)
    else:
        text = str(value)
    return defang_text(text if len(text) <= limit else text[:limit] + "...")


@cache
def _report_fonts() -> str:
    """@font-face rules with each woff2 file inlined as a data URL."""
    faces = []
    for family, weight, name in REPORT_FONTS:
        data = base64.b64encode((PACKAGE_DIR / "web" / "static" / "fonts" / name).read_bytes()).decode("ascii")
        faces.append(f'@font-face {{ font-family: "{family}"; font-weight: {weight}; '
                     f'src: url(data:font/woff2;base64,{data}) format("woff2"); }}')
    return "\n".join(faces)


def render_report(result: ScanResult, folder: Path, files: list[dict[str, Any]], generated: datetime) -> str:
    artifacts = {name: _read_json(folder / name) for name in _ARTIFACTS if (folder / name).is_file()}
    redirects = artifacts.get("redirects.json") or {}
    chain = redirects.get("chain") or [{"url": url, "status": None, "via": None} for url in result.redirect_chain]
    return _templates.get_template(REPORT_HTML).render(
        r=result,
        chain=chain,
        whois=artifacts.get("whois.json"),
        dns=artifacts.get("dns_hosting.json"),
        cert=artifacts.get("cert.json"),
        page=_facts(artifacts.get("page.json")),
        profiles=_facts(artifacts.get("profiles.json")),
        storefront=_facts(artifacts.get("storefront.json")),
        screenshot=(folder / SCREENSHOT).is_file(),
        files=files,
        scanned=stamp(_parse_time(result.scanned_at)),
        generated=stamp(generated),
        version=__version__,
        collection=COLLECTION_STATEMENT,
        fonts=_report_fonts(),
    )


# verifying and extending the pack


def _manifest(folder: Path) -> dict[str, Any]:
    manifest = _read_json(folder / MANIFEST)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise EvidenceError(f"{folder / MANIFEST} is missing or unreadable")
    return manifest


def _audit(folder: Path) -> tuple[list[tuple[str, str]], list[str]]:
    """((problem, file) for every listed file that is missing or changed, unlisted files)."""
    manifest = _manifest(folder)
    problems: list[tuple[str, str]] = []
    listed: set[str] = set()
    for item in manifest["files"]:
        name = str(item.get("name", ""))
        listed.add(name)
        if not name or Path(name).is_absolute() or ".." in Path(name).parts:
            problems.append(("invalid entry", name))
        elif not (folder / name).is_file():
            problems.append(("missing", name))
        else:
            actual = _entry(folder, name)
            if (actual["sha256"], actual["size"]) != (item.get("sha256"), item.get("size")):
                problems.append(("hash mismatch", name))
    return problems, [name for name in _pack_files(folder) if name not in listed]


def verify(folder: Path) -> list[str]:
    """Problems with an evidence pack: listed files missing or changed, and files
    the manifest does not list. An empty list means every hash matches."""
    try:
        problems, unlisted = _audit(folder)
    except EvidenceError as exc:
        return [str(exc)]
    return [f"{kind}: {name}" for kind, name in problems] + [f"extra file: {name}" for name in unlisted]


def manifest_sha256(folder: Path) -> str:
    """The manifest's own hash, for an analyst to note down with the case."""
    return _entry(folder, MANIFEST)["sha256"]


def add_to_manifest(folder: Path, names: list[str]) -> None:
    """List files added to a pack after its scan (confirmation, investigation)
    in the manifest. Entries of other files stay exactly as they were."""
    manifest = _manifest(folder)
    entries = {item["name"]: item for item in manifest["files"]}
    for name in names:
        entries[name] = _entry(folder, name)
    manifest["files"] = sorted(entries.values(), key=lambda e: e["name"])
    manifest["updated_at"] = stamp(datetime.now(timezone.utc))
    _write(folder / MANIFEST, manifest)


def pack_folder(scan_id_or_path: str | Path, settings: Settings | None = None) -> Path:
    """A pack folder given either its scan ID or its path."""
    path = Path(scan_id_or_path)
    if path.is_dir():
        return path
    return (settings or load_settings()).evidence_dir / str(scan_id_or_path)


# analyst confirmation and takedown request


def confirm_case(scan_id: str, analyst: str, note: str = "", store: Store | None = None,
                 settings: Settings | None = None) -> Path:
    """Mark a case analyst-confirmed, add `confirmation.json` and the takedown
    request to its pack, and return the takedown request's path.

    Refuses a pack whose listed files are missing or changed. Files added since
    the scan (an investigation, say) are listed in the manifest with the
    confirmation, so the analyst's sign-off covers them.
    """
    settings = settings or load_settings()
    store = store or Store(settings.db_path)
    result = store.get_scan(scan_id)
    if result is None:
        raise EvidenceError(f"no case with ID {scan_id}")
    folder = settings.evidence_dir / scan_id
    problems, unlisted = _audit(folder)
    tampered = [f"{kind}: {name}" for kind, name in problems if name not in (CONFIRMATION, TAKEDOWN)]
    if tampered:
        raise EvidenceError(f"the evidence pack of {scan_id} fails verification: {'; '.join(tampered)}")
    added = [name for name in unlisted if name not in (CONFIRMATION, TAKEDOWN)]
    now = datetime.now(timezone.utc)
    _write(folder / CONFIRMATION, {
        "scan_id": scan_id,
        "analyst": analyst,
        "note": note,
        "confirmed_at": stamp(now),
        "files_added_since_scan": added,
    })
    listed = [e for e in _manifest(folder)["files"] if e["name"] not in (CONFIRMATION, TAKEDOWN)]
    evidence_files = sorted([*listed, *(_entry(folder, n) for n in (*added, CONFIRMATION))],
                            key=lambda e: e["name"])
    first_seen = store.first_seen(registrable_domain(result.final_url or result.url))
    _write(folder / TAKEDOWN, takedown_text(
        result, folder, evidence_files, analyst, note, now, settings,
        _parse_time(first_seen) if first_seen else None,
    ))
    add_to_manifest(folder, [*added, CONFIRMATION, TAKEDOWN])
    store.set_confirmed(scan_id)
    return folder / TAKEDOWN


def _when(moment: datetime) -> str:
    times = stamp(moment)
    return f"{times['utc']} ({times['dubai']} Dubai)"


def takedown_text(result: ScanResult, folder: Path, files: list[dict[str, Any]], analyst: str, note: str,
                  confirmed: datetime, settings: Settings, first_seen: datetime | None) -> str:
    """The abuse report for the registrar and the hosting provider. Lines whose
    value is unknown are left out; nothing is a placeholder."""
    whois = _read_json(folder / "whois.json") or {}
    dns = _read_json(folder / "dns_hosting.json") or {}
    final = result.final_url or result.url
    domain = registrable_domain(final)
    ip = dns.get("ip") or next(iter(dns.get("a") or []), None)
    hosting_email = intel.ip_abuse_contact(ip) if ip else None
    network = " ".join(filter(None, [dns.get("asn"), dns.get("asn_name")])) or None
    fraud = (result.fraud_type or "").replace("_", " ")

    def line(label: str, value: Any) -> list[str]:
        return [f"- {label}: {value}"] if value else []

    registrar_to = whois.get("registrar") or "Registrar"
    hosting_to = f"Hosting provider ({network})" if network else "Hosting provider"
    sender = settings.reporter_name + (f" <{settings.reporter_email}>" if settings.reporter_email else "")
    out = [f"# Abuse report: {defang_text(domain)}", ""]
    if whois.get("registrar_abuse_email") or whois.get("registrar"):
        out.append(f"To: {registrar_to} abuse desk"
                   + (f" <{whois['registrar_abuse_email']}>" if whois.get("registrar_abuse_email") else ""))
    if hosting_email or network:
        out.append(f"To: {hosting_to} abuse desk" + (f" <{hosting_email}>" if hosting_email else ""))
    out += [f"From: {sender}", f"Date: {_when(confirmed)}", ""]
    what = f"a {fraud} website" if fraud else "a fraudulent website"
    brand = f" impersonating {result.impersonated_brand}" if result.impersonated_brand else ""
    out += [f"We report {what}{brand}, operating on a domain you register or host. "
            "An analyst has reviewed the evidence below and confirmed the case.", ""]

    out += ["## Case", ""]
    out += line("Case ID", result.id)
    out += line("Domain", defang_text(domain))
    out += [f"- Domain (verbatim): {domain}"]
    out += line("Reported link", defang_text(result.url))
    if final != result.url:
        out += line("Landing page", defang_text(final))
    out += line("First seen", _when(first_seen) if first_seen else None)
    out += line("Scanned", _when(_parse_time(result.scanned_at)))
    out += line("Fraud type", fraud.capitalize() if fraud else None)
    out += line("Impersonated brand", result.impersonated_brand)
    out += [f"- Risk score: {result.risk_score}/100 ({result.verdict})", ""]

    reasons = sorted((r for r in result.reasons if r.weight > 0), key=lambda r: -r.weight)[:TOP_REASONS]
    if reasons:
        out += ["## Why it is fraudulent", ""]
        out += [f"- {defang_text(r.en)} (evidence: {r.evidence.split('#', 1)[0]})" for r in reasons]
        out.append("")

    facts = [
        *line("Registered", whois.get("created")),
        *line("Registrar", whois.get("registrar")),
        *line("Registrar abuse contact", whois.get("registrar_abuse_email")),
        *line("Name servers", ", ".join(whois.get("nameservers") or dns.get("ns") or [])),
        *line("Hosting host", defang_text(host_of(final)) if host_of(final) != domain else None),
        *line("IP address", ip),
        *line("Hosting network", network),
        *line("Hosting country", dns.get("country")),
        *line("Hosting abuse contact", hosting_email),
    ]
    if facts:
        out += ["## Key facts", "", *facts, ""]

    out += ["## Evidence", "",
            f"Evidence pack {result.id}, collected by Baaz {__version__}. {COLLECTION_STATEMENT}", "",
            "| File | Bytes | SHA-256 |", "|---|---:|---|"]
    out += [f"| {e['name']} | {e['size']} | {e['sha256']} |" for e in files]
    out += ["", "## Request", "",
            "Please suspend the domain (registrar) or the hosting account (hosting provider) that "
            "serves this website, and preserve the related logs, registration and payment records "
            "for law-enforcement requests.", ""]
    out.append(f"Confirmed by analyst {analyst} on {_when(confirmed)}.")
    if note:
        out.append(f"Analyst note: {defang_text(note)}")
    out += ["", settings.reporter_name]
    if settings.reporter_email:
        out.append(settings.reporter_email)
    return "\n".join(out) + "\n"


# export


def export_pack(scan_id: str, out: Path | None = None, settings: Settings | None = None) -> Path:
    """Zip a case's evidence folder (default `evidence/<id>.zip`) and return the zip's path."""
    settings = settings or load_settings()
    folder = settings.evidence_dir / scan_id
    if not (folder / MANIFEST).is_file():
        raise EvidenceError(f"no evidence pack for {scan_id} in {settings.evidence_dir}")
    out = out or settings.evidence_dir / f"{scan_id}.zip"
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in [*_pack_files(folder), MANIFEST]:
            zf.write(folder / name, f"{scan_id}/{name}")
    return out
