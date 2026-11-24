"""Follow a link to where it really lands: HTTP redirects, meta refresh,
script redirects on near-empty pages and URL shorteners, up to 10 hops."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from baaz.domains import registrable_domain

MAX_HOPS = 10
MAX_BODY = 3_000_000

SHORTENERS = frozenset({
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "v.gd",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "t.ly", "s.id", "lnkd.in",
    "buff.ly", "tiny.cc", "bit.do", "qrco.de", "shorturl.gg", "short.gy", "urlz.fr",
    "clck.ru", "u.to", "tr.ee", "surl.li", "x.gd", "shrtco.de",
})

_META_REFRESH = re.compile(
    r"""<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']?\s*\d*\s*;?\s*url\s*=\s*['"]?([^"'>\s]+)""",
    re.I,
)
_JS_REDIRECT = re.compile(
    r"""(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*(?:=|\.replace\(|\.assign\()\s*["'](https?://[^"']+)["']""",
    re.I,
)
_TAGS = re.compile(r"<script.*?</script>|<style.*?</style>|<[^>]+>", re.I | re.S)

BLOCKED_CODES = frozenset({401, 403, 429, 503})
DEAD_CODES = frozenset({404, 410, 500, 502, 504, 520, 521, 522, 523, 525, 526, 530})


@dataclass
class Hop:
    url: str
    status: int | None
    via: str  # start | http | meta | script


@dataclass
class Resolution:
    final_url: str
    fetch_status: str
    hops: list[Hop] = field(default_factory=list)
    status_code: int | None = None
    html: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    tls_verified: bool = True
    error: str | None = None
    shortener: str | None = None

    @property
    def chain(self) -> list[str]:
        return [h.url for h in self.hops]

    def to_json(self) -> dict:
        return {
            "final_url": self.final_url,
            "fetch_status": self.fetch_status,
            "status_code": self.status_code,
            "tls_verified": self.tls_verified,
            "shortener": self.shortener,
            "error": self.error,
            "chain": [{"url": h.url, "status": h.status, "via": h.via} for h in self.hops],
        }


def visible_text(html: str) -> str:
    return re.sub(r"\s+", " ", _TAGS.sub(" ", html)).strip()


def page_redirect(html: str) -> tuple[str, str] | None:
    """A meta-refresh target, or a script redirect target when the page is near-empty."""
    m = _META_REFRESH.search(html)
    if m:
        return m.group(1), "meta"
    if len(visible_text(html)) < 300:
        m = _JS_REDIRECT.search(html)
        if m:
            return m.group(1), "script"
    return None


def classify(status: int) -> str:
    if status in BLOCKED_CODES:
        return "blocked"
    if status in DEAD_CODES or status >= 400:
        return "dead"
    return "ok"


def resolve(url: str, client: httpx.Client, insecure_client: httpx.Client | None = None,
            headers: dict[str, str] | None = None) -> Resolution:
    """Fetch `url`, following up to MAX_HOPS redirects of any kind.

    When TLS verification fails and `insecure_client` is given, the fetch is
    retried without verification and `tls_verified` is set to False.
    """
    headers = headers or {}
    res = Resolution(final_url=url, fetch_status="dead", hops=[Hop(url, None, "start")])
    if registrable_domain(url) in SHORTENERS:
        res.shortener = registrable_domain(url)
    current, active = url, client
    for _ in range(MAX_HOPS + 1):
        try:
            resp = active.get(current, headers=headers, follow_redirects=False)
        except httpx.ConnectError as exc:
            if insecure_client is not None and active is client and "CERTIFICATE" in str(exc).upper():
                active, res.tls_verified = insecure_client, False
                try:
                    resp = active.get(current, headers=headers, follow_redirects=False)
                except httpx.HTTPError as exc2:
                    return _fail(res, current, exc2)
            else:
                return _fail(res, current, exc)
        except httpx.HTTPError as exc:
            return _fail(res, current, exc)
        res.hops[-1].status = resp.status_code
        location = resp.headers.get("location")
        if resp.is_redirect and location:
            nxt = urljoin(current, location)
            if len(res.hops) > MAX_HOPS:
                break
            res.hops.append(Hop(nxt, None, "http"))
            current = nxt
            continue
        body = resp.content[:MAX_BODY].decode(resp.encoding or "utf-8", errors="replace")
        target = page_redirect(body) if resp.status_code < 400 else None
        if target and len(res.hops) <= MAX_HOPS:
            nxt = urljoin(current, target[0])
            if nxt != current:
                res.hops.append(Hop(nxt, None, target[1]))
                current = nxt
                continue
        res.final_url = current
        res.status_code = resp.status_code
        res.html = body
        res.headers = {k.lower(): v for k, v in resp.headers.items()}
        res.fetch_status = classify(resp.status_code)
        return res
    res.final_url = current
    res.fetch_status = "ok"
    res.error = "redirect limit reached"
    return res


def _fail(res: Resolution, current: str, exc: Exception) -> Resolution:
    res.final_url = current
    res.error = f"{type(exc).__name__}: {exc}"[:300]
    res.fetch_status = "timeout" if isinstance(exc, httpx.TimeoutException) else "dead"
    return res


def make_clients(user_agent: str, timeout: float) -> tuple[httpx.Client, httpx.Client]:
    """A verifying client and a non-verifying fallback, sharing headers and timeouts."""
    common = dict(
        timeout=httpx.Timeout(timeout, connect=min(timeout, 8.0)),
        headers={"User-Agent": user_agent, "Accept-Language": "en-US,en;q=0.9,ar;q=0.8"},
        http2=False,
    )
    return httpx.Client(**common), httpx.Client(verify=False, **common)
