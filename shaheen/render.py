"""Render a page in headless Chromium: the DOM after scripts ran, a
screenshot, and every main-frame navigation, so JavaScript redirects that a
plain HTTP fetch cannot see are caught.

With `as_chrome`, the page is loaded instead in Google Chrome driven by
patchright, in a window placed off the screen and with Chrome's own user agent,
for the second look at a page that blocked the first (`shaheen.stealth`); a
bot check that clears by itself gets up to CHECK_WAIT seconds to do so.

One browser per call; the sync API must not share a browser across threads,
so batch concurrency comes from running calls in separate threads.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from patchright.sync_api import Error as PatchrightError
from patchright.sync_api import sync_playwright as patched_playwright
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page, Response, sync_playwright

from shaheen.config import DESKTOP_UA
from shaheen.stealth import blocked

RENDER_TIMEOUT = 20.0
LATE_REDIRECT_WAIT = 3.0
CHECK_WAIT = 15.0
CHECK_POLL_MS = 1500
VIEWPORT = {"width": 1366, "height": 768}
ERRORS = (PlaywrightError, PatchrightError)
OFF_SCREEN = ["--window-position=-32000,-32000"]


@dataclass
class Rendered:
    final_url: str
    chain: list[str] = field(default_factory=list)  # committed main-frame URLs, in order
    html: str = ""
    screenshot: bytes = b""
    status: int | None = None


def _content(page: Page, left_ms: Callable[[], float]) -> str:
    """The DOM as HTML; a page still navigating gets one more chance to settle."""
    try:
        return page.content()
    except ERRORS:
        page.wait_for_load_state("load", timeout=left_ms())
        return page.content()


def _proxy(url: str) -> dict[str, str] | None:
    if not url:
        return None
    parts = urlsplit(url)
    found = {"server": f"{parts.scheme}://{parts.hostname}:{parts.port}" if parts.port else
             f"{parts.scheme}://{parts.hostname}"}
    if parts.username:
        found.update(username=parts.username, password=parts.password or "")
    return found


def _launch(pw: Any, as_chrome: bool, proxy: str, timeout_ms: float) -> Any:
    if not as_chrome:
        return pw.chromium.launch(headless=True, timeout=timeout_ms)
    options = {"headless": False, "args": OFF_SCREEN, "timeout": timeout_ms, "proxy": _proxy(proxy)}
    try:
        return pw.chromium.launch(channel="chrome", **options)
    except PatchrightError:  # no Google Chrome installed: patchright's own Chromium
        return pw.chromium.launch(**options)


def _wait_for_check(page: Page, left_ms: Callable[[float], float]) -> None:
    """Give a bot check that clears by itself (it reloads into the site) time to do so."""
    end = time.monotonic() + CHECK_WAIT
    while time.monotonic() < end and left_ms(CHECK_WAIT) > CHECK_POLL_MS:
        try:
            if not blocked(None, page.content()):
                return
        except ERRORS:
            pass
        page.wait_for_timeout(CHECK_POLL_MS)


def render(url: str, timeout_s: float = RENDER_TIMEOUT, as_chrome: bool = False,
           proxy: str = "") -> tuple[Rendered | None, str | None]:
    """Render `url` within `timeout_s` seconds in all (plus CHECK_WAIT `as_chrome`).
    Returns the rendering, or None and the reason it failed; never raises."""
    timeout_s += CHECK_WAIT if as_chrome else 0
    deadline = time.monotonic() + timeout_s

    def left_ms(cap: float = timeout_s) -> float:
        return max(min(deadline - time.monotonic(), cap), 0.1) * 1000

    try:
        with (patched_playwright if as_chrome else sync_playwright)() as pw:
            browser = _launch(pw, as_chrome, proxy, left_ms())
            try:
                context = browser.new_context(
                    **({} if as_chrome else {"user_agent": DESKTOP_UA}),
                    viewport=VIEWPORT,
                    locale="en-US",
                    accept_downloads=False,
                    ignore_https_errors=True,
                    service_workers="block",
                )
                page = context.new_page()
                out = Rendered(final_url=url)

                def on_nav(frame) -> None:
                    if frame == page.main_frame and frame.url.startswith("http") and (
                            not out.chain or out.chain[-1] != frame.url):
                        out.chain.append(frame.url)

                def on_response(resp: Response) -> None:
                    if resp.request.is_navigation_request() and resp.frame == page.main_frame:
                        out.status = resp.status

                page.on("framenavigated", on_nav)
                page.on("response", on_response)
                try:
                    page.goto(url, wait_until="load", timeout=left_ms())
                except ERRORS:
                    if not out.chain:
                        raise
                if as_chrome:
                    _wait_for_check(page, left_ms)
                page.wait_for_timeout(left_ms(LATE_REDIRECT_WAIT))
                try:
                    page.wait_for_load_state("load", timeout=left_ms())
                except ERRORS:
                    pass
                out.final_url = page.url if page.url.startswith("http") else (out.chain or [url])[-1]
                out.html = _content(page, left_ms)
                try:
                    out.screenshot = page.screenshot(type="png", timeout=left_ms())
                except ERRORS:
                    pass
                return out, None
            finally:
                browser.close()
    except Exception as exc:  # a broken page or browser must never break a scan
        return None, f"{type(exc).__name__}: {exc}".splitlines()[0][:300]
