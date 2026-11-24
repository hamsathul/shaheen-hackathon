"""Read a page's HTML into plain facts: its title and branding, the forms and
what they ask for, and the scripts and frames it loads.

`analyse()` is pure (stdlib `html.parser`, no network); the page signals and
the storefront checkout check both build on it.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

MAX_TEXT = 20_000
LEAD_CHARS = 1_500
MAX_INLINE_SCRIPT = 200_000

_SKIP_TEXT = frozenset({"script", "style", "noscript", "template", "head", "title", "svg"})
# Text inside these is navigation or a call to action, not what the page says it is
# ("Sign in with Google", a menu of brands a shop sells), so it stays out of `lead`.
_NOT_LEAD = frozenset({"a", "button", "nav", "footer", "option", "select"})
_VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
                   "source", "track", "wbr"})
_NOT_FIELDS = frozenset({"hidden", "submit", "button", "image", "reset", "checkbox", "radio", "file",
                         "range", "color"})

_CARD_AUTOCOMPLETE = {"cc-number": "number", "cc-csc": "cvv", "cc-exp": "expiry",
                      "cc-exp-month": "expiry", "cc-exp-year": "expiry"}
_FIELD_PATTERNS: dict[str, re.Pattern[str]] = {
    "password": re.compile(r"\bpass ?(word|wd)\b|\bpwd\b|\bpasswd\b|كلمة (ال)?(مرور|سر)|الرقم السري(?! للبطاقة)"),
    "number": re.compile(
        r"\b(credit |debit )?card ?(number|num|no)\b|\bcc ?(number|num|no)\b|\bcardnumber\b|\bccnum\b"
        r"|رقم (ال)?بطاق"
    ),
    "cvv": re.compile(r"\bcvv2?\b|\bcvc2?\b|\bcsc\b|\bcard ?(security|verification) ?code\b"
                      r"|رمز (ال)?(أمان|امان)|الرقم السري للبطاقة"),
    "expiry": re.compile(r"\bexp(iry|iration)?( ?date)?\b|\bexp ?(month|year|mm|yy)\b|\bmm ?/ ?yy\b"
                         r"|تاريخ (ال)?انتهاء"),
    "otp": re.compile(r"\botp\b|\bone ?time ?(pass ?code|password|code|pin)\b|\bsms ?code\b"
                      r"|\bverification ?code\b|رمز (ال)?تحقق|كلمة المرور المؤقتة|رمز لمرة واحدة"),
    "emirates_id": re.compile(r"\bemirates ?id\b|\beid (number|no)\b|الهوية|\b784 [\dx]{4} [\dx]{7}"),
}
_CARD_PLACEHOLDER = re.compile(r"^(?:[\d•*x]{4}[ -]?){3}[\d•*x]{1,4}$")
_CAMEL = re.compile(r"(?<=[a-z])(?=[A-Z])")
_SEPARATORS = re.compile(r"[_\-\[\].:]+")
_SPACES = re.compile(r"\s+")


def _words(value: str) -> str:
    """`wc_card_number`, `cardNumber` and `card-number` all become `card number`."""
    value = _SEPARATORS.sub(" ", _CAMEL.sub(" ", value or ""))
    return _SPACES.sub(" ", value).strip().lower()


@dataclass
class Input:
    tag: str
    type: str
    name: str = ""
    id: str = ""
    placeholder: str = ""
    autocomplete: str = ""
    aria_label: str = ""
    label: str = ""

    def kinds(self) -> set[str]:
        """Which sensitive things this input asks for: password, otp, emirates_id,
        and the card parts number, cvv and expiry."""
        if self.tag == "input" and self.type in _NOT_FIELDS:
            return set()
        found: set[str] = set()
        auto = self.autocomplete.lower()
        if self.type == "password" or auto in ("current-password", "new-password"):
            found.add("password")
        if auto in _CARD_AUTOCOMPLETE:
            found.add(_CARD_AUTOCOMPLETE[auto])
        if auto == "one-time-code":
            found.add("otp")
        if _CARD_PLACEHOLDER.match(self.placeholder.replace(" ", "")):
            found.add("number")
        text = " | ".join(_words(v) for v in (self.name, self.id, self.placeholder, self.aria_label, self.label))
        for kind, pattern in _FIELD_PATTERNS.items():
            if pattern.search(text):
                found.add(kind)
        if "otp" in found or "number" in found or "cvv" in found:
            found.discard("password")  # "OTP password", "card PIN/password" are not account passwords
        return found


@dataclass
class Form:
    action: str
    method: str
    inputs: list[Input] = field(default_factory=list)
    pseudo: bool = False  # inputs outside any <form> (single-page apps)

    def kinds(self) -> set[str]:
        return set().union(*(i.kinds() for i in self.inputs)) if self.inputs else set()

    def sensitive(self) -> set[str]:
        return _sensitive(self.kinds())


def _sensitive(kinds: set[str]) -> set[str]:
    keys = kinds & {"password", "otp", "emirates_id"}
    if kinds & {"number", "cvv"}:
        keys.add("card")
    return keys


@dataclass
class PageFacts:
    base_url: str
    title: str = ""
    site_name: str = ""
    h1: list[str] = field(default_factory=list)
    logos: list[str] = field(default_factory=list)
    text: str = ""
    lead: str = ""  # the first LEAD_CHARS of visible text outside links, buttons, menus and footers
    forms: list[Form] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    iframes: list[str] = field(default_factory=list)
    inline_script: str = ""

    @property
    def text_len(self) -> int:
        return len(self.text)

    def field_kinds(self) -> set[str]:
        return set().union(*(f.kinds() for f in self.forms)) if self.forms else set()

    def sensitive_fields(self) -> set[str]:
        """The sensitive things the page asks for, among password, card, otp and emirates_id."""
        return _sensitive(self.field_kinds())

    def hosts(self, urls: list[str]) -> list[str]:
        return list(dict.fromkeys(h for h in ((urlsplit(u).hostname or "").lower() for u in urls) if h))

    def to_json(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "site_name": self.site_name,
            "h1": self.h1,
            "logos": self.logos,
            "text_len": self.text_len,
            "forms": [{**asdict(f), "sensitive": sorted(f.sensitive())} for f in self.forms],
            "sensitive_fields": sorted(self.sensitive_fields()),
            "script_hosts": self.hosts(self.scripts),
            "iframe_hosts": self.hosts(self.iframes),
        }


class _Parser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.facts = PageFacts(base_url=base_url)
        self.base = base_url
        self.stack: list[str] = []
        self.text: list[str] = []
        self.lead: list[str] = []
        self.title: list[str] | None = None  # the page's own <title>, not an SVG one
        self.title_seen = False
        self.h1: list[str] | None = None
        self.script: list[str] | None = None
        self.inline: list[str] = []
        self.inline_len = 0
        self.form: Form | None = None
        self.loose = Form(action=base_url, method="get", pseudo=True)
        self.labels: dict[str, list[str]] = {}
        self.label_for: str | None = None
        self.label_text: list[str] | None = None
        self.label_inputs: list[Input] = []
        self.selects: list[Input] = []

    def _inside(self, tags: frozenset[str]) -> bool:
        return any(t in tags for t in self.stack)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "base" and a.get("href"):
            self.base = urljoin(self.base, a["href"])
        elif tag == "meta" and a.get("property", "").lower() == "og:site_name":
            self.facts.site_name = a.get("content", "").strip()
        elif tag == "title" and not self.title_seen and "svg" not in self.stack:
            self.title, self.title_seen = [], True
        elif tag == "h1":
            self.h1 = []
        elif tag == "img":
            self._img(a)
        elif tag == "script":
            if a.get("src"):
                self.facts.scripts.append(urljoin(self.base, a["src"]))
            self.script = []
        elif tag == "iframe" and a.get("src"):
            self.facts.iframes.append(urljoin(self.base, a["src"]))
        elif tag == "form":
            action = a.get("action", "").strip()
            self.form = Form(action=urljoin(self.base, action) if action else self.base,
                             method=(a.get("method") or "get").lower())
            self.facts.forms.append(self.form)
        elif tag == "label":
            self.label_for, self.label_text, self.label_inputs = a.get("for", ""), [], []
        elif tag in ("input", "select", "textarea"):
            self._field(tag, a)
        if tag not in _VOID:
            self.stack.append(tag)

    def _img(self, a: dict[str, str]) -> None:
        marks = " ".join(a.get(k, "") for k in ("class", "id", "alt")).lower()
        if "logo" in marks:
            text = (a.get("alt") or a.get("title") or "").strip()
            if text:
                self.facts.logos.append(text)

    def _field(self, tag: str, a: dict[str, str]) -> None:
        field_ = Input(
            tag=tag,
            type=(a.get("type") or "text").lower() if tag == "input" else tag,
            name=a.get("name", ""),
            id=a.get("id", ""),
            placeholder=a.get("placeholder", ""),
            autocomplete=a.get("autocomplete", ""),
            aria_label=a.get("aria-label", ""),
        )
        (self.form or self.loose).inputs.append(field_)
        if self.label_text is not None and not self.label_for:
            self.label_inputs.append(field_)

    def handle_endtag(self, tag: str) -> None:
        if tag == "h1" and self.h1 is not None:
            text = _SPACES.sub(" ", "".join(self.h1)).strip()
            if text:
                self.facts.h1.append(text)
            self.h1 = None
        elif tag == "script" and self.script is not None:
            code = "".join(self.script)
            if self.inline_len < MAX_INLINE_SCRIPT and code.strip():
                self.inline.append(code[: MAX_INLINE_SCRIPT - self.inline_len])
                self.inline_len += len(code)
            self.script = None
        elif tag == "title" and self.title is not None:
            self.facts.title = _SPACES.sub(" ", "".join(self.title)).strip()
            self.title = None
        elif tag == "form":
            self.form = None
        elif tag == "label" and self.label_text is not None:
            text = _SPACES.sub(" ", "".join(self.label_text)).strip()
            if self.label_for:
                self.labels.setdefault(self.label_for, []).append(text)
            for field_ in self.label_inputs:
                field_.label = text
            self.label_text = None
        if tag in self.stack:
            while self.stack and self.stack.pop() != tag:
                pass

    def handle_data(self, data: str) -> None:
        if self.script is not None:
            self.script.append(data)
            return
        if self.stack and self.stack[-1] == "title":
            if self.title is not None:
                self.title.append(data)
            return
        if self._inside(_SKIP_TEXT):
            return
        if self.h1 is not None:
            self.h1.append(data)
        if self.label_text is not None:
            self.label_text.append(data)
        if data.strip():
            self.text.append(data)
            if not self._inside(_NOT_LEAD):
                self.lead.append(data)

    def close(self) -> PageFacts:
        super().close()
        f = self.facts
        if self.title is not None:  # never closed
            f.title = _SPACES.sub(" ", "".join(self.title)).strip()
        f.text =_SPACES.sub(" ", " ".join(self.text)).strip()[:MAX_TEXT]
        f.lead = _SPACES.sub(" ", " ".join(self.lead)).strip()[:LEAD_CHARS]
        f.inline_script = "\n".join(self.inline)
        for form in [*f.forms, self.loose]:
            for field_ in form.inputs:
                if not field_.label and field_.id in self.labels:
                    field_.label = " ".join(self.labels[field_.id])
        if self.loose.inputs:
            f.forms.append(self.loose)
        return f


def analyse(html: str, base_url: str) -> PageFacts:
    """Facts about a page; never raises on malformed HTML."""
    parser = _Parser(base_url)
    parser.feed(html or "")
    return parser.close()
