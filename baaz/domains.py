"""URL normalisation, defanging and registrable-domain helpers."""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from urllib.parse import urlsplit, urlunsplit

import tldextract

# Bundled Public Suffix List snapshot, private section included, so that
# `foo.github.io` is its own registrable domain and lookups never touch the network.
_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

_REFANG = [
    (re.compile(r"^hxxp", re.I), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
]


def refang(text: str) -> str:
    text = text.strip()
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


def defang(url: str) -> str:
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def normalize_url(raw: str) -> str:
    """Refang, add a scheme when missing, lowercase and IDNA-encode the host."""
    url = refang(raw)
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "https://" + url
    parts = urlsplit(url)
    host = (parts.hostname or "").rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        host = host.lower()
    netloc = host
    if parts.port:
        netloc = f"{host}:{parts.port}"
    if parts.username:
        cred = parts.username + (f":{parts.password}" if parts.password else "")
        netloc = f"{cred}@{netloc}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


@lru_cache(maxsize=4096)
def split_host(host: str) -> tuple[str, str, str]:
    """Return (subdomain, domain label, public suffix) for a host name."""
    ext = _extract(host)
    return ext.subdomain, ext.domain, ext.suffix


def registrable_domain(url_or_host: str) -> str:
    """Registrable domain (eTLD+1) of a URL or host; the bare host for IPs."""
    host = host_of(url_or_host) if "://" in url_or_host else url_or_host.lower().rstrip(".")
    if is_ip(host):
        return host
    _, label, suffix = split_host(host)
    if not label:
        return host
    return f"{label}.{suffix}" if suffix else label


def public_suffix(url_or_host: str) -> str:
    host = host_of(url_or_host) if "://" in url_or_host else url_or_host.lower()
    return split_host(host)[2]
