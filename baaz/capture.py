"""A saved evidence folder read back as a scan's source, so the deterministic
pipeline can re-analyse a case with the network unplugged.

`Scanner.scan` takes it in place of the network when `ScanOptions.capture_dir`
is set: the redirect chain and page come from `redirects.json` and
`page.html`, the browser's rendering from `page.html` and `screenshot.png`,
the domain intel from `whois.json`, `dns_hosting.json` and `cert.json`, the
visitor profiles from `profiles.json` and the storefront facts from
`storefront.json`. Nothing is fetched.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from baaz.render import Rendered
from baaz.resolve import Hop, Resolution


class CaptureError(Exception):
    """A folder that is not an evidence pack Baaz can re-analyse."""


class Capture:
    def __init__(self, folder: Path):
        self.folder = Path(folder)
        report = self._json("report.json")
        if not isinstance(report, dict) or not report.get("url") or not report.get("scanned_at"):
            raise CaptureError(f"{self.folder} has no readable report.json")
        self.report = report
        self.id: str = report.get("id") or self.folder.name
        self.url: str = report["url"]
        # when the facts were collected: a re-analysis of a re-analysis keeps the first scan's time
        self.collected_at: str = (report.get("signals") or {}).get("captured_at") or report["scanned_at"]

    def _json(self, name: str) -> Any | None:
        path = self.folder / name
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise CaptureError(f"{path} is not valid JSON: {exc}") from exc

    def _html(self) -> str:
        path = self.folder / "page.html"
        return path.read_text(encoding="utf-8") if path.is_file() else ""

    def has(self, name: str) -> bool:
        return (self.folder / name).is_file()

    def resolution(self) -> Resolution:
        """The fetch as it was: the saved chain (browser hops included) and page."""
        saved = self._json("redirects.json") or {}
        chain = saved.get("chain") or [{"url": u, "status": None, "via": "start"}
                                       for u in self.report.get("redirect_chain") or [self.url]]
        return Resolution(
            final_url=saved.get("final_url") or self.report.get("final_url") or self.url,
            fetch_status=saved.get("fetch_status") or self.report.get("fetch_status") or "dead",
            hops=[Hop(h["url"], h.get("status"), h.get("via") or "start", h.get("text_len")) for h in chain],
            status_code=saved.get("status_code"),
            html=self._html(),
            tls_verified=saved.get("tls_verified", True),
            error=saved.get("error"),
            shortener=saved.get("shortener"),
        )

    def rendered(self, url: str) -> tuple[Rendered | None, str | None]:
        """The browser's rendering at capture time, landing where the saved chain ends."""
        if not (self.report.get("signals") or {}).get("rendered"):
            return None, "not rendered at capture time"
        screenshot = self.folder / "screenshot.png"
        return Rendered(final_url=url, html=self._html(),
                        screenshot=screenshot.read_bytes() if screenshot.is_file() else b""), None

    def intel(self, domain: str, host: str) -> dict[str, Any]:
        """The shape of `intel.gather()`, from the saved lookups."""
        missing = {"error": "not in the capture"}
        return {
            "domain": domain,
            "host": host,
            "whois": self._json("whois.json") or {"domain": domain, "created": None, **missing},
            "dns": self._json("dns_hosting.json") or {"domain": domain, "host": host, "a": [], **missing},
            "cert": self._json("cert.json") or {"host": host, "not_before": None, **missing},
        }

    def profile(self, key: str) -> dict[str, Any]:
        return (self._json("profiles.json") or {})[key]

    def storefront(self) -> dict[str, Any] | None:
        return self._json("storefront.json")
