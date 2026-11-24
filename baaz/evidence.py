"""Evidence pack: one folder per scan holding every artifact a reason cites."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from baaz.models import ScanContext, ScanResult


def _write(path: Path, content: Any) -> None:
    if isinstance(content, bytes):
        path.write_bytes(content)
    elif isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_text(json.dumps(content, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def write_pack(ctx: ScanContext, result: ScanResult, root: Path) -> Path:
    folder = root / ctx.id
    folder.mkdir(parents=True, exist_ok=True)
    for name, content in ctx.artifacts.items():
        _write(folder / name, content)
    _write(folder / "report.json", result.to_dict())
    return folder
