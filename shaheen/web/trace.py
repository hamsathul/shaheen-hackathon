"""Read an investigation's `agent_trace.jsonl` (pi's `--mode json` event
stream) into a timeline: each tool call with its arguments, a short target
(the URL, domain, element or case it works on), whether it has ended, a
truncated result and what it returned in a few words, and the model's
messages, the last one marked final. pi writes the stream while it runs, so a
trace read mid-run shows the calls so far. `read_live` also gives the model's
latest thinking note, for the live panel.

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
MAX_TARGET = 90
# The argument that best names what a tool call works on, in order of preference.
TARGET_KEYS = ("url", "domain", "domains", "term", "words", "element", "text", "regex", "filter", "key", "id")
# Terminal colour codes that tool errors (Playwright's call log) carry.
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
MAX_SAID = 90
# What a browser tool's markdown result says about the page, in order of preference.
PAGE_LINES = (re.compile(r"^- Page Title: (.+)$", re.M), re.compile(r"^- Page URL: (.+)$", re.M))
PAGE_TEXT = re.compile(r"<untrusted_page_text[^>]*>(.*?)</untrusted_page_text>", re.S)
REQUEST_LINE = re.compile(r"^\d+\. \[[A-Z]+\] ", re.M)


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


def _target(args: Any) -> str:
    """A short description of what a tool call works on: its URL, domain, element or case."""
    if not isinstance(args, dict):
        return ""
    value = next((args[k] for k in TARGET_KEYS if args.get(k) not in (None, "", [])), "")
    text = ", ".join(map(str, value)) if isinstance(value, list) else str(value)
    return _clip(" ".join(text.split()), MAX_TARGET)


def _json(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


def _said_data(tool: str, data: Any) -> str:
    """A few words on a JSON result of one of Shaheen's tools."""
    if isinstance(data, list):
        return f"{len(data)} found"
    if not isinstance(data, dict):
        return ""
    if "verdict" in data and "risk_score" in data:
        return f"{data['verdict']} {data['risk_score']}" + (", site dead" if data.get("fetch_status") == "dead" else "")
    if tool == "domain_intel":
        whois, dns = data.get("whois") or {}, data.get("dns") or {}
        parts = [f"registered {whois['created']}" if whois.get("created") else "registration unknown",
                 whois.get("registrar"), dns.get("asn_name"), dns.get("country")]
        return ", ".join(str(p) for p in parts if p)
    if "matches" in data:
        return f"{data['matches']} of {data.get('listed', '?')} new domains"
    if "recent_hosts" in data:
        return f"{data['recent_hosts']} new hosts on {data.get('certificates', 0)} certificates"
    if "accepted" in data:
        return f"{data['accepted']} queued, {data.get('not_registered', 0)} not registered"
    return ""


def _said(tool: str, text: str, error: bool) -> str:
    """What a tool call returned, in a few words: a verdict and score, a page's title,
    a count, or the first line of an error or a plain answer."""
    text = ANSI.sub("", text).strip()
    said = "" if error else _said_data(tool, _json(text))
    if not said and not error:
        page = PAGE_TEXT.search(text)
        requests = len(REQUEST_LINE.findall(text))
        said = (("no page text" if "(no page text was captured)" in page.group(1) else
                 f"{len(page.group(1).strip())} characters of page text") if page
                else f"{requests} requests" if requests
                else next((m.group(1) for pattern in PAGE_LINES if (m := pattern.search(text))), ""))
    if not said:
        lines = [line.strip("# ").strip() for line in text.splitlines()]
        said = next((line for line in lines if line and line not in ("Error", "Result")), "")
        said = re.sub(r"^(\w*Error:\s*)?(browserBackend\.callTool:\s*)?", "", said)
    return _clip(" ".join(said.split()), MAX_SAID)


def read_trace(path: Path) -> list[dict[str, Any]]:
    return read_live(path)[0]


def read_live(path: Path) -> tuple[list[dict[str, Any]], str]:
    """The timeline, and the model's latest thinking note (empty when it wrote none)."""
    if not path.is_file():
        return [], ""
    steps: list[dict[str, Any]] = []
    thought = ""
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
                step = {"kind": "tool", "server": server, "tool": tool, "args": "", "target": "",
                        "result": None, "said": "", "error": False, "ms": None, "done": False}
                calls[event.get("toolCallId")] = step
                steps.append(step)
            if kind == "tool_execution_start":
                step["args"] = _clip(json.dumps(event.get("args") or {}, ensure_ascii=False), MAX_ARGS)
                step["target"] = _target(event.get("args"))
            else:
                result, error = _text(event.get("result")), bool(event.get("isError"))
                step.update(result=_clip(result, MAX_RESULT), said=_said(step["tool"], result, error), error=error,
                            done=True,
                            ms=event.get("durationMs") if isinstance(event.get("durationMs"), (int, float)) else None)
        elif kind == "message_end":
            message = event.get("message")
            if not (isinstance(message, dict) and message.get("role") == "assistant"):
                continue
            if text := _text(message).strip():
                steps.append({"kind": "model", "text": _clip(text, MAX_MESSAGE), "final": False})
            notes = [str(b.get("thinking") or "") for b in message.get("content") or []
                     if isinstance(b, dict) and b.get("type") == "thinking"]
            thought = next((n.strip() for n in reversed(notes) if n.strip()), thought)
    models = [s for s in steps if s["kind"] == "model"]
    if models:
        models[-1]["final"] = True
    return steps, ANSI.sub("", thought)
