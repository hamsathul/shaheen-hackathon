"""The contact and payment details a flagged page shows, read by the local model.

A scam page tells its victims where to call, message or pay: phone and
WhatsApp numbers, emails, bank accounts and wallets. One call to the model
reads them from the saved page (its text and its tel:, mailto: and WhatsApp
links) as JSON, which takes far less time than a full investigation. Shaheen
keeps only the numbers, addresses and accounts that are written in the page
itself, adds the result to the evidence pack (`contacts.json`) and records
each one as a fingerprint, so cases sharing a number or an account are
linked. Nothing here changes a score.
"""

from __future__ import annotations

import html as html_lib
import json
import re
import time
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from shaheen import evidence
from shaheen.config import REPO_DIR, Settings
from shaheen.domains import registrable_domain
from shaheen.investigator import chat, parse_reply
from shaheen.resolve import visible_text
from shaheen.signals import is_challenge
from shaheen.store import Store

PROMPT_PATH = REPO_DIR / "agent" / "contacts.md"
FILE = "contacts.json"
TEXT_LIMIT = 20_000
TIMEOUT_S = 300.0
MIN_TEXT = 200  # a page with less visible text than this has nothing to read
MIN_DIGITS = 7
LIST_CAP, VALUE_CAP = 30, 200  # items kept per list, characters per item
# The fields holding numbers, addresses and accounts, with the fingerprint kind of each.
IDENTIFIERS = {"phones": "phone", "whatsapp": "phone", "emails": "email", "bank_accounts": "bank", "wallets": "wallet"}

_LINK = re.compile(r"""href\s*=\s*["']\s*((?:tel:|sms:|mailto:|https?://(?:wa\.me|api\.whatsapp\.com|"""
                   r"""chat\.whatsapp\.com|t\.me)/)[^"']*)""", re.I)
_NUMBER = re.compile(r"\+?\d[\d\s().-]{5,}\d")
_BRACKETS = re.compile(r"\s*\(.*\)\s*$")


class Contacts(BaseModel):
    model_config = ConfigDict(extra="ignore")

    phones: list[str] = Field(default_factory=list)
    whatsapp: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    bank_accounts: list[str] = Field(default_factory=list)
    wallets: list[str] = Field(default_factory=list)
    payment_methods: list[str] = Field(default_factory=list)
    claims_to_be: str = ""
    asks_for: list[str] = Field(default_factory=list)

    @field_validator("phones", "whatsapp", "emails", "bank_accounts", "wallets", "payment_methods", "asks_for")
    @classmethod
    def _cap_list(cls, value: list[str]) -> list[str]:
        return [str(v)[:VALUE_CAP] for v in value[:LIST_CAP]]

    @field_validator("claims_to_be")
    @classmethod
    def _cap_text(cls, value: str) -> str:
        return value[:VALUE_CAP]


def page_material(folder: Path) -> tuple[str, list[str]]:
    """The saved page's visible text (capped) and its contact links; empty when the
    page is missing, nearly empty or a bot check."""
    path = folder / "page.html"
    html = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    text = html_lib.unescape(visible_text(html))
    if len(text) < MIN_TEXT or is_challenge("", text, html):
        return "", []
    links = list(dict.fromkeys(html_lib.unescape(m.group(1)).strip() for m in _LINK.finditer(html)))
    return text[:TEXT_LIMIT], links[:50]


def messages(text: str, links: list[str]) -> list[dict[str, str]]:
    system = PROMPT_PATH.read_text(encoding="utf-8") + json.dumps(Contacts.model_json_schema(), ensure_ascii=False)
    page = re.sub(r"<\s*/?\s*untrusted_page[^>]*>", "[tag removed]", f"{text}\n\nLinks:\n" + "\n".join(links))
    return [{"role": "system", "content": system},
            {"role": "user", "content": f"<untrusted_page>\n{page}\n</untrusted_page>"}]


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def _flat(value: str) -> str:
    return re.sub(r"\s", "", _BRACKETS.sub("", value)).lower()


def check(found: Contacts, text: str, links: list[str]) -> list[str]:
    """Drop every number, address and account that is not written in the page;
    returns the dropped ones."""
    page = f"{text} {' '.join(links)}"
    numbers = {_digits(m.group(0)) for m in _NUMBER.finditer(page)} | {_digits(x) for x in links if _digits(x)}
    flat = _flat(page)

    def written(field: str, value: str) -> bool:
        if field in ("phones", "whatsapp"):
            digits = _digits(value)
            return len(digits) >= MIN_DIGITS and any(digits in n or n in digits for n in numbers
                                                      if len(n) >= MIN_DIGITS)
        return len(_flat(value)) >= 5 and _flat(value) in flat

    dropped = []
    for field in IDENTIFIERS:
        kept = []
        for value in dict.fromkeys(v.strip() for v in getattr(found, field) if v.strip()):
            (kept if written(field, value) else dropped).append(value)
        setattr(found, field, kept)
    return dropped


def fingerprint(field: str, value: str) -> tuple[str, str]:
    """The fingerprint that links cases showing this value: phone digits (WhatsApp
    included), and emails, bank accounts and wallets without spaces or case."""
    kind = IDENTIFIERS[field]
    return kind, _digits(value) if kind == "phone" else _flat(value)


def fingerprints(found: Contacts) -> list[tuple[str, str]]:
    return sorted({fingerprint(field, v) for field in IDENTIFIERS for v in getattr(found, field)})


def read(scan_id: str, settings: Settings, store: Store, timeout_s: float = TIMEOUT_S) -> dict[str, Any]:
    """Read one case's contacts and file them: in the store, in the evidence pack and
    as fingerprints. A page with nothing to read is filed as skipped."""
    result = store.get_scan(scan_id)
    folder = settings.evidence_dir / scan_id
    text, links = page_material(folder)
    if result is None or not text:
        store.set_contacts(scan_id, "skipped", error="no page text to read (a bot check, or an empty page)")
        return {"scan_id": scan_id, "status": "skipped"}
    started = time.monotonic()
    prompt = messages(text, links)
    body = {"model": settings.llm_model, "messages": prompt, "temperature": 0.1, "stream": False,
            "chat_template_kwargs": {"enable_thinking": False},
            "response_format": {"type": "json_schema",
                                "json_schema": {"name": "contacts", "schema": Contacts.model_json_schema()}}}
    try:
        reply = chat(settings, body, timeout_s)
        content = ((reply.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
        found = Contacts.model_validate(parse_reply(content))
    except (httpx.HTTPError, ValueError, ValidationError) as exc:
        error = f"{type(exc).__name__}: {exc}"[:300]
        store.set_contacts(scan_id, "failed", error=error)
        return {"scan_id": scan_id, "status": "failed", "error": error}
    dropped = check(found, text, links)
    record = {"scan_id": scan_id, "status": "done", **found.model_dump(), "dropped_not_on_page": dropped,
              "run": {"model": settings.llm_model, "wall_s": round(time.monotonic() - started, 1),
                      "usage": reply.get("usage") or {}, "page_chars": len(text), "links": len(links)}}
    (folder / FILE).write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        evidence.add_to_manifest(folder, [FILE])
    except evidence.EvidenceError:
        record["run"]["manifest"] = "not added: the pack has no readable manifest"
    store.add_fingerprints(scan_id, registrable_domain(result.final_url or result.url), fingerprints(found))
    store.set_contacts(scan_id, "done", result_json=record)
    return record
