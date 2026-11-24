"""Domain intelligence: registration (RDAP, then WHOIS), DNS, the hosting
network (ASN) and the TLS certificate of a domain.

`gather()` runs the lookups concurrently, caches what it learns in the store
for 24 hours and never raises: anything it cannot learn stays null, an empty
list or "unknown". Every network call times out after at most TIMEOUT seconds.
"""

from __future__ import annotations

import re
import socket
import ssl
import tempfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import dns.exception
import dns.resolver
import httpx

from baaz.domains import is_ip
from baaz.store import Store

TIMEOUT = 6.0
DNS_TIMEOUT = 4.0
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_FALLBACK = "https://rdap.org/domain/{}"
IANA_WHOIS = "whois.iana.org"
MAX_WHOIS_BYTES = 256_000

_MONTHS = {m: i for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), start=1)}


def gather(domain: str, store: Store, host: str | None = None) -> dict[str, Any]:
    """Registration facts for `domain`; DNS, hosting network and certificate for
    `host`, the host the link landed on (default: `domain`)."""
    host = host or domain
    with ThreadPoolExecutor(max_workers=3) as pool:
        whois = pool.submit(_cached, store, domain, "whois", lambda: registration(domain, store))
        hosting_ = pool.submit(_cached, store, host, "dns", lambda: hosting(domain, host))
        cert = pool.submit(_cached, store, host, "cert", lambda: certificate(host))
        return {"domain": domain, "host": host,
                "whois": whois.result(), "dns": hosting_.result(), "cert": cert.result()}


def _cached(store: Store, key: str, kind: str, lookup: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """A cached answer, or a fresh one; failed lookups are not cached."""
    hit = store.cache_get(key, kind)
    if hit is not None:
        return hit
    data = lookup()
    if data["error"] is None:
        store.cache_put(key, kind, data)
    return data


# registration: RDAP, then WHOIS


def registration(domain: str, store: Store) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "domain": domain, "source": "unknown", "server": None, "created": None, "registrar": None,
        "registrar_abuse_email": None, "registrar_abuse_phone": None, "status": [],
        "nameservers": [], "error": None,
    }
    if is_ip(domain):
        facts["error"] = "an IP address has no registration record"
        return facts
    try:
        url = _rdap_url(domain, store)
        data = _get_json(url)
        if data and data.get("objectClassName") == "domain":
            return {**facts, **parse_rdap(data), "source": "rdap", "server": url}
        answer = whois_text(domain)
        parsed = parse_whois(answer[1]) if answer else None
        if parsed:
            return {**facts, **parsed, "source": "whois", "server": answer[0]}
        facts["error"] = "no RDAP or WHOIS record"
    except Exception as exc:  # noqa: BLE001 - intel must fail soft
        facts["error"] = f"{type(exc).__name__}: {exc}"[:200]
    return facts


def _rdap_url(domain: str, store: Store) -> str:
    """The registry's RDAP URL from the IANA bootstrap file, else rdap.org."""
    tld = domain.rsplit(".", 1)[-1]
    bases = _bootstrap(store).get(tld)
    if not bases:
        return RDAP_FALLBACK.format(domain)
    base = next((b for b in bases if b.startswith("https://")), bases[0])
    return f"{base.rstrip('/')}/domain/{domain}"


def _bootstrap(store: Store) -> dict[str, list[str]]:
    services = store.cache_get("data.iana.org", "rdap_bootstrap")
    if services is None:
        data = _get_json(BOOTSTRAP_URL)
        services = data.get("services") if data else None
        if not services:
            return {}
        store.cache_put("data.iana.org", "rdap_bootstrap", services)
    return {tld.lower(): urls for tlds, urls in services for tld in tlds}


def _get_json(url: str) -> dict[str, Any] | None:
    try:
        resp = httpx.get(url, timeout=TIMEOUT, follow_redirects=True,
                         headers={"Accept": "application/rdap+json, application/json"})
        return resp.json() if resp.status_code == 200 else None
    except (httpx.HTTPError, ValueError):
        return None


def _vcard(entity: dict[str, Any] | None, field: str) -> str | None:
    for item in ((entity or {}).get("vcardArray") or [None, []])[1]:
        if item and item[0] == field and item[3]:
            value = item[3] if isinstance(item[3], str) else str(item[3])
            return value.removeprefix("tel:").removeprefix("mailto:")
    return None


def parse_rdap(data: dict[str, Any]) -> dict[str, Any]:
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    registrar = next((e for e in data.get("entities", []) if "registrar" in e.get("roles", [])), None)
    abuse = next((e for e in (registrar or {}).get("entities", []) if "abuse" in e.get("roles", [])), None)
    return {
        "created": loose_date(events.get("registration") or ""),
        "registrar": _vcard(registrar, "fn"),
        "registrar_abuse_email": _vcard(abuse, "email"),
        "registrar_abuse_phone": _vcard(abuse, "tel"),
        "status": list(data.get("status", [])),
        "nameservers": sorted({ns["ldhName"].lower().rstrip(".")
                               for ns in data.get("nameservers", []) if ns.get("ldhName")}),
    }


def whois_text(domain: str) -> tuple[str, str] | None:
    """(server, answer) from the TLD's WHOIS server, found through IANA's referral."""
    referral = re.search(r"^(?:refer|whois):\s*(\S+)", _whois(IANA_WHOIS, domain.rsplit(".", 1)[-1]),
                         re.I | re.M)
    if not referral:
        return None
    server = referral.group(1)
    return server, _whois(server, domain)


def _whois(server: str, query: str) -> str:
    chunks: list[bytes] = []
    with socket.create_connection((server, 43), timeout=TIMEOUT) as sock:
        sock.sendall(query.encode("ascii") + b"\r\n")
        while sum(map(len, chunks)) < MAX_WHOIS_BYTES and (chunk := sock.recv(65536)):
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


_W_CREATED = re.compile(
    r"^\s*(?:creation date|created(?: on| date)?|registered(?: on| date)?|registration (?:date|time)"
    r"|domain registration date|record created)\s*:[ \t]*(\S.*)$", re.I | re.M)
_W_REGISTRAR = re.compile(
    r"^\s*(?:registrar(?: name)?|sponsoring registrar|registrar organization)\s*:[ \t]*\n?[ \t]*(\S.*)$",
    re.I | re.M)
_W_ABUSE_EMAIL = re.compile(r"^\s*registrar abuse contact email\s*:[ \t]*(\S+)", re.I | re.M)
_W_ABUSE_PHONE = re.compile(r"^\s*registrar abuse contact phone\s*:[ \t]*(\S+)", re.I | re.M)
_W_STATUS = re.compile(r"^\s*(?:domain )?status\s*:[ \t]*(\S+)", re.I | re.M)
_W_NAMESERVER = re.compile(r"^\s*(?:name server|nameserver|nserver)\s*:[ \t]*(\S+)", re.I | re.M)


def parse_whois(text: str) -> dict[str, Any] | None:
    """Loosely read a WHOIS answer; None when it names neither a date nor a registrar."""
    created = _W_CREATED.search(text)
    registrar = _W_REGISTRAR.search(text)
    if not (created or registrar):
        return None
    first = lambda m: m.group(1).strip() if m else None  # noqa: E731
    return {
        "created": loose_date(created.group(1)) if created else None,
        "registrar": first(registrar),
        "registrar_abuse_email": first(_W_ABUSE_EMAIL.search(text)),
        "registrar_abuse_phone": first(_W_ABUSE_PHONE.search(text)),
        "status": list(dict.fromkeys(m.group(1) for m in _W_STATUS.finditer(text))),
        "nameservers": sorted({m.group(1).lower().rstrip(".") for m in _W_NAMESERVER.finditer(text)}),
    }


def loose_date(text: str) -> str | None:
    """An ISO date (YYYY-MM-DD) from the common WHOIS and RDAP date formats."""
    m = re.search(r"(\d{4})[-./](\d{1,2})[-./](\d{1,2})", text)
    if m:
        y, mo, d = map(int, m.groups())
    elif m := re.search(r"(\d{1,2})[-. ]([A-Za-z]{3})[A-Za-z]*[-. ,]+(\d{4})", text):
        d, mo, y = int(m.group(1)), _MONTHS.get(m.group(2).lower(), 0), int(m.group(3))
    elif m := re.search(r"(\d{1,2})[-./](\d{1,2})[-./](\d{4})", text):
        d, mo, y = map(int, m.groups())
    else:
        return None
    try:
        return date(y, mo, d).isoformat()
    except ValueError:
        return None


# DNS and hosting network


def hosting(domain: str, host: str) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "domain": domain, "host": host, "a": [], "aaaa": [], "ns": [], "mx": [], "nxdomain": None,
        "ip": None, "asn": None, "asn_name": None, "country": None, "error": None,
    }
    try:
        if is_ip(host):
            facts.update(a=[host] if ":" not in host else [], aaaa=[host] if ":" in host else [], nxdomain=False)
        else:
            queries = {"a": (host, "A"), "aaaa": (host, "AAAA"), "ns": (domain, "NS"), "mx": (domain, "MX")}
            with ThreadPoolExecutor(max_workers=len(queries)) as pool:
                answers = dict(zip(queries, pool.map(lambda q: _resolve(*q), queries.values()), strict=True))
            for key, (records, _) in answers.items():
                facts[key] = records
            facts["nxdomain"] = {"nxdomain": True, "ok": False, "noanswer": False}.get(answers["a"][1])
            if all(status == "error" for _, status in answers.values()):
                facts["error"] = "DNS lookups failed"
        if facts["a"]:
            facts.update(asn_lookup(facts["a"][0]))
    except Exception as exc:  # noqa: BLE001 - intel must fail soft
        facts["error"] = f"{type(exc).__name__}: {exc}"[:200]
    return facts


def _resolve(name: str, rdtype: str) -> tuple[list[str], str]:
    """(records as text, status), status being ok, nxdomain, noanswer or error."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    try:
        answer = resolver.resolve(name, rdtype)
    except dns.resolver.NXDOMAIN:
        return [], "nxdomain"
    except dns.resolver.NoAnswer:
        return [], "noanswer"
    except dns.exception.DNSException:
        return [], "error"
    if rdtype == "MX":
        return [r.exchange.to_text().rstrip(".").lower() for r in sorted(answer, key=lambda r: r.preference)], "ok"
    if rdtype == "NS":
        return sorted(r.target.to_text().rstrip(".").lower() for r in answer), "ok"
    if rdtype == "TXT":
        return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answer], "ok"
    return [r.address for r in answer], "ok"


def asn_lookup(ip: str) -> dict[str, Any]:
    """Origin AS, its name and the allocation country of an IPv4 address, from
    Team Cymru's IP-to-ASN DNS service (no API key)."""
    if ":" in ip:
        return {"ip": ip}
    origin, _ = _resolve(".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com", "TXT")
    if not origin:
        return {"ip": ip}
    fields = [f.strip() for f in origin[0].split("|")]
    asn = fields[0].split()[0]
    described, _ = _resolve(f"AS{asn}.asn.cymru.com", "TXT")
    name_fields = described[0].split("|") if described else []
    return {
        "ip": ip,
        "asn": f"AS{asn}",
        "asn_name": name_fields[4].strip() if len(name_fields) > 4 else None,
        "country": fields[2] if len(fields) > 2 and fields[2] else None,
    }


# TLS certificate


def certificate(host: str) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "host": host, "verified": None, "subject": None, "issuer": None,
        "not_before": None, "not_after": None, "san": [], "error": None,
    }
    try:
        try:
            cert, verified = _peer_cert(host, verify=True), True
        except ssl.SSLCertVerificationError:
            cert, verified = _peer_cert(host, verify=False), False
        facts.update(parse_cert(cert), verified=verified)
    except Exception as exc:  # noqa: BLE001 - intel must fail soft
        facts["error"] = f"{type(exc).__name__}: {exc}"[:200]
    return facts


def _peer_cert(host: str, verify: bool) -> dict[str, Any]:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, 443), timeout=TIMEOUT) as sock, \
            context.wrap_socket(sock, server_hostname=host) as tls:
        if verify:
            return tls.getpeercert()
        der = tls.getpeercert(binary_form=True)
    if not der:
        raise ValueError("the server sent no certificate")
    return _decode_der(der)


def _decode_der(der: bytes) -> dict[str, Any]:
    """Decode a certificate the ssl module did not verify. The ssl module only
    decodes verified certificates itself; its long-stable test helper decodes
    any PEM file, which avoids a new dependency."""
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".pem", delete=False) as fh:
        fh.write(ssl.DER_cert_to_PEM_cert(der))
    pem = Path(fh.name)
    try:
        return ssl._ssl._test_decode_cert(str(pem))  # type: ignore[attr-defined]
    finally:
        pem.unlink()


def _x509_name(rdns: Any) -> str | None:
    parts = dict(kv for rdn in rdns or () for kv in rdn)
    names = [f"{short}={parts[key]}" for key, short in
             (("commonName", "CN"), ("organizationName", "O"), ("countryName", "C")) if key in parts]
    return ", ".join(names) or None


def _cert_time(value: str | None) -> str | None:
    if not value:
        return None
    moment = datetime.fromtimestamp(ssl.cert_time_to_seconds(value), timezone.utc)
    return moment.isoformat().replace("+00:00", "Z")


def parse_cert(cert: dict[str, Any]) -> dict[str, Any]:
    return {
        "subject": _x509_name(cert.get("subject")),
        "issuer": _x509_name(cert.get("issuer")),
        "not_before": _cert_time(cert.get("notBefore")),
        "not_after": _cert_time(cert.get("notAfter")),
        "san": [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"],
    }
