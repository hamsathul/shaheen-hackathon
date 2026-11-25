"""The second look at a page that turned Shaheen away: as an ordinary Chrome
browser would see it.

Many scam sites sit behind bot checks (Cloudflare's "Just a moment" page and
the like) that turn away scripted clients but let a victim's browser through.
When the first fetch or render is blocked, Shaheen tries once more: an HTTP
request with Chrome's network fingerprint (curl_cffi), and a page load in
Google Chrome driven by patchright, a Playwright build that does not announce
the automation (`render.render(as_chrome=True)`). It waits for a check that
clears by itself, and never solves a CAPTCHA, clicks through a warning or
submits anything. When the operator sets SHAHEEN_PROXY, an exit they control
or pay for, the second look goes through it, for sites that block the box's
own address. Each scan records whether it needed the second look.
"""

from __future__ import annotations

import re
from typing import Any

import httpx
from curl_cffi import requests as curl_requests
from curl_cffi.requests import exceptions as curl_errors

from shaheen.resolve import BLOCKED_CODES, visible_text
from shaheen.signals import is_challenge

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_DECODED = frozenset({"content-encoding", "content-length", "transfer-encoding"})
# Block pages that turn away the visitor's address (a firewall rule on its network or
# country, Cloudflare errors 1005 to 1020): no browser gets past them, only another exit.
_ADDRESS_BLOCK = re.compile(r"Sorry, you have been blocked|has banned you|error(?: code)?:? 10(?:0[5-9]|20)\b", re.I)


def blocked(status: int | None, html: str) -> bool:
    """Whether a fetch or render was turned away: a blocking status, or a bot check
    or block page in place of the site."""
    title = _TITLE.search(html[:50_000])
    return status in BLOCKED_CODES or is_challenge(title.group(1) if title else "", visible_text(html[:200_000]), html)


def address_blocked(html: str) -> bool:
    return bool(_ADDRESS_BLOCK.search(visible_text(html[:200_000])[:3000]))


class ChromeClient:
    """The part of `httpx.Client` that `resolve.resolve` uses, sending requests with
    Chrome's TLS and HTTP/2 fingerprint and Chrome's own headers (the `headers`
    argument is ignored, so the two always match)."""

    def __init__(self, timeout: float, proxy: str = "", verify: bool = True):
        self.session = curl_requests.Session(impersonate="chrome", timeout=timeout, verify=verify,
                                             proxy=proxy or None)

    def get(self, url: str, headers: Any = None, follow_redirects: bool = False) -> httpx.Response:
        try:
            resp = self.session.get(url, allow_redirects=follow_redirects)
        except curl_errors.CertificateVerifyError as exc:
            raise httpx.ConnectError(f"CERTIFICATE_VERIFY_FAILED: {exc}") from exc
        except curl_errors.Timeout as exc:
            raise httpx.ReadTimeout(str(exc)) from exc
        except curl_errors.RequestException as exc:
            raise httpx.ConnectError(str(exc)) from exc
        # curl has already decoded the body, so its encoding and length headers no longer apply.
        headers = [(k, v) for k, v in resp.headers.multi_items() if k.lower() not in _DECODED]
        return httpx.Response(resp.status_code, headers=headers, content=resp.content,
                              request=httpx.Request("GET", url))

    def close(self) -> None:
        self.session.close()


def chrome_clients(timeout: float, proxy: str = "") -> tuple[ChromeClient, ChromeClient]:
    """A verifying Chrome client and a non-verifying fallback, like `resolve.make_clients`."""
    return ChromeClient(timeout, proxy), ChromeClient(timeout, proxy, verify=False)
