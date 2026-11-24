"""Read an investigation's `agent_trace.jsonl` (pi's `--mode json` event
stream) into a timeline: each tool call with its arguments and a truncated
result, and the model's messages, the last one marked final.

Only `tool_execution_start`, `tool_execution_end` and assistant
`message_end` events are used. Unknown event types and malformed lines are
skipped, so a trace from another pi version or the one-shot fallback never
breaks the case view.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

MAX_ARGS = 400
MAX_RESULT = 700
MAX_MESSAGE = 2000
# Terminal colour codes that tool errors (Playwright's call log) carry.
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _clip(text: str, limit: int) -> str:
    text = ANSI.sub("", text)
    return text if len(text) <= limit else text[:limit].rstrip() + " ..."


def _text(holder: Any) -> str:
    """The text blocks of a message or tool result (`content`: a string or a list of blocks)."""
    content = holder.get("content") if isinstance(holder, dict) else None
    if isinstance(content, str):
        return content
    blocks = content if isinstance(content, list) else []
    return "\n".join(str(b.get("text") or "") for b in blocks if isinstance(b, dict) and b.get("type") == "text")


def _tool(name: Any) -> tuple[str, str]:
    """(server, tool) of an MCP tool name `mcp__<server>__<tool>`; a plain name has no server."""
    parts = str(name or "?").split("__")
    return (parts[1], "__".join(parts[2:])) if len(parts) >= 3 and parts[0] == "mcp" else ("", parts[0])


def read_trace(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    steps: list[dict[str, Any]] = []
    calls: dict[Any, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        kind = event.get("type") if isinstance(event, dict) else None
        if kind in ("tool_execution_start", "tool_execution_end"):
            step = calls.get(event.get("toolCallId"))
            if step is None:
                server, tool = _tool(event.get("toolName"))
                step = {"kind": "tool", "server": server, "tool": tool, "args": "", "result": None,
                        "error": False, "ms": None}
                calls[event.get("toolCallId")] = step
                steps.append(step)
            if kind == "tool_execution_start":
                step["args"] = _clip(json.dumps(event.get("args") or {}, ensure_ascii=False), MAX_ARGS)
            else:
                step.update(result=_clip(_text(event.get("result")), MAX_RESULT), error=bool(event.get("isError")),
                            ms=event.get("durationMs") if isinstance(event.get("durationMs"), (int, float)) else None)
        elif kind == "message_end":
            message = event.get("message")
            if isinstance(message, dict) and message.get("role") == "assistant" and (text := _text(message).strip()):
                steps.append({"kind": "model", "text": _clip(text, MAX_MESSAGE), "final": False})
    models = [s for s in steps if s["kind"] == "model"]
    if models:
        models[-1]["final"] = True
    return steps
