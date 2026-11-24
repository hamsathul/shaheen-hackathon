"""Render a page in headless Chromium: the DOM after scripts ran, a
screenshot, and every main-frame navigation, so JavaScript redirects that a
plain HTTP fetch cannot see are caught.

One browser per call; the sync API must not share a browser across threads,
so batch concurrency comes from running calls in separate threads.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page, Response, sync_playwright

from shaheen.config import DESKTOP_UA

RENDER_TIMEOUT = 20.0
LATE_REDIRECT_WAIT = 3.0
VIEWPORT = {"width": 1366, "height": 768}


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
    except PlaywrightError:
        page.wait_for_load_state("load", timeout=left_ms())
        return page.content()


def render(url: str, timeout_s: float = RENDER_TIMEOUT) -> tuple[Rendered | None, str | None]:
    """Render `url` within `timeout_s` seconds in all. Returns the rendering, or
    None and the reason it failed; never raises."""
    deadline = time.monotonic() + timeout_s

    def left_ms(cap: float = timeout_s) -> float:
        return max(min(deadline - time.monotonic(), cap), 0.1) * 1000

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, timeout=left_ms())
            try:
                context = browser.new_context(
                    user_agent=DESKTOP_UA,
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
                except PlaywrightError:
                    if not out.chain:
                        raise
                page.wait_for_timeout(left_ms(LATE_REDIRECT_WAIT))
                try:
                    page.wait_for_load_state("load", timeout=left_ms())
                except PlaywrightError:
                    pass
                out.final_url = page.url if page.url.startswith("http") else (out.chain or [url])[-1]
                out.html = _content(page, left_ms)
                try:
                    out.screenshot = page.screenshot(type="png", timeout=left_ms())
                except PlaywrightError:
                    pass
                return out, None
            finally:
                browser.close()
    except Exception as exc:  # a broken page or browser must never break a scan
        return None, f"{type(exc).__name__}: {exc}".splitlines()[0][:300]
