"""The dashboard's AI hunts (/hunts): a box that sends the AI hunter on a
mission, optionally narrowed to one UAE scam theme, and the list of hunts.
Each hunt has a page (/hunts/<id>) with its report, the domains it found with
Shaheen's latest check of each, and its tool calls. The page reloads itself
while the hunt waits or runs."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from shaheen import themes
from shaheen.config import Settings
from shaheen.domains import host_of
from shaheen.hunter import clean_mission, hunt_folder
from shaheen.store import Store
from shaheen.web.trace import read_trace

LIST_LIMIT = 50
TRACE = "agent_trace.jsonl"
LIVE = ("queued", "running")


def add_routes(app: FastAPI, store: Store, settings: Settings, page: Callable[..., Response],
               agents_alive: Callable[[], bool]) -> None:
    @app.get("/hunts")
    def hunts(request: Request, notice: str | None = None) -> Response:
        return page(request, "hunts.html", hunts=store.list_hunts(LIST_LIMIT), theme_names=themes.labels(),
                    alive=agents_alive(), error=notice == "mission")

    @app.post("/hunts")
    def start_hunt(mission: str = Form(""), theme: str = Form("")) -> Response:
        text = clean_mission(mission)
        if not text:
            return RedirectResponse("/hunts?notice=mission", status_code=303)
        hunt_id = store.add_hunt(text, theme if themes.get(theme) else None)
        return RedirectResponse(f"/hunts/{hunt_id}", status_code=303)

    @app.get("/hunts/{hunt_id}")
    def hunt_page(request: Request, hunt_id: int) -> Response:
        row = store.get_hunt(hunt_id)
        if row is None:
            raise HTTPException(404, "no such hunt")
        report: dict[str, Any] = row.get("report") or {}
        finds = [{**f, "host": host_of(f["url"])} for f in store.hunt_finds(hunt_id)]
        return page(request, "hunt.html", hunt=row, report=report, run=report.get("run") or {},
                    finds=finds, trace=read_trace(hunt_folder(settings, hunt_id) / TRACE),
                    theme_names=themes.labels(), alive=agents_alive(), live=row["status"] in LIVE)
