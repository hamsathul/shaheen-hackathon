"""Runtime settings, read from the environment (and `.env` when present)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_DIR = PACKAGE_DIR.parent
DATA_DIR = REPO_DIR / "data"

DESKTOP_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
# Top-level domains the watcher's storefront sweep tries, in order.
STOREFRONT_TLDS = ("com", "shop", "store", "online", "net", "co")
GOOGLE_MAPS_API_BASE = "https://places.googleapis.com"


def _load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass(frozen=True)
class Settings:
    db_path: Path
    evidence_dir: Path
    llm_base_url: str
    llm_model: str
    llm_api_key: str
    http_timeout: float
    user_agent: str
    reporter_name: str = "Baaz analyst"
    reporter_email: str = ""
    storefront_tlds: tuple[str, ...] = STOREFRONT_TLDS
    investigators: int = 2  # parallel investigations (one pi process each)
    google_maps_api_key: str = ""  # Places API (New); empty turns the Maps collector off
    google_maps_api_base: str = GOOGLE_MAPS_API_BASE
    google_maps_browser_key: str = ""  # Maps JavaScript API, for the dashboard's map; empty shows the log alone
    maps_interval_hours: float = 6.0  # hours between Maps collector runs

    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm_base_url and self.llm_model)


def load_settings() -> Settings:
    _load_dotenv(Path.cwd() / ".env")
    return Settings(
        db_path=Path(os.environ.get("BAAZ_DB", "var/baaz.db")),
        evidence_dir=Path(os.environ.get("BAAZ_EVIDENCE_DIR", "evidence")),
        llm_base_url=os.environ.get("LLM_BASE_URL", "").rstrip("/"),
        llm_model=os.environ.get("LLM_MODEL", ""),
        llm_api_key=os.environ.get("LLM_API_KEY", "local"),
        http_timeout=float(os.environ.get("BAAZ_HTTP_TIMEOUT", "10")),
        user_agent=os.environ.get("BAAZ_USER_AGENT", DESKTOP_UA),
        reporter_name=os.environ.get("BAAZ_REPORTER_NAME") or "Baaz analyst",
        reporter_email=os.environ.get("BAAZ_REPORTER_EMAIL", ""),
        storefront_tlds=tuple(
            t.strip().lstrip(".").lower()
            for t in os.environ.get("BAAZ_STOREFRONT_TLDS", ",".join(STOREFRONT_TLDS)).split(",") if t.strip()
        ),
        investigators=max(1, int(os.environ.get("BAAZ_INVESTIGATORS") or 2)),
        google_maps_api_key=os.environ.get("GOOGLE_MAPS_API_KEY", "").strip(),
        google_maps_api_base=(os.environ.get("GOOGLE_MAPS_API_BASE") or GOOGLE_MAPS_API_BASE).rstrip("/"),
        google_maps_browser_key=os.environ.get("GOOGLE_MAPS_BROWSER_KEY", "").strip(),
        maps_interval_hours=float(os.environ.get("BAAZ_MAPS_INTERVAL_HOURS") or 6),
    )
