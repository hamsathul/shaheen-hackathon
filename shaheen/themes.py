"""UAE scam themes (`data/themes_uae.yaml`): the kinds of scam aimed at people
in the UAE, such as traffic fines, visas, jobs and parcels, and the domain
words that mark them.

A host matches a theme when it carries a UAE marker (a place name, a name
ending in -ae, or the .ae suffix) and one of the theme's words. Words of five
letters or more also count inside a longer token. Shorter ones count as a
whole token, or as what is left of a token once a marker is cut from its start
or end (uaevisa, jobsdubai).

The collectors use the themes to pick new domains and certificate names to
scan, the scorer uses them for THEME_UAE_DOMAIN, and the AI hunter uses them
to choose its searches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import yaml

from shaheen.brands import split_tokens
from shaheen.config import DATA_DIR
from shaheen.domains import is_ip, split_host

SUBSTRING_MIN = 5
_AE_ENDING = re.compile(r"[-.]ae$")


@dataclass(frozen=True)
class Theme:
    id: str
    name_en: str
    name_ar: str
    words: tuple[str, ...]
    ct_terms: tuple[str, ...]


@dataclass(frozen=True)
class ThemeMatch:
    theme: Theme
    marker: str
    words: tuple[str, ...]


@lru_cache(maxsize=1)
def _data() -> dict[str, Any]:
    return yaml.safe_load((DATA_DIR / "themes_uae.yaml").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_themes() -> tuple[Theme, ...]:
    return tuple(
        Theme(id=t["id"], name_en=t["name_en"], name_ar=t["name_ar"],
              words=tuple(w.lower() for w in t["words"]), ct_terms=tuple(c.lower() for c in t["ct_terms"]))
        for t in _data()["themes"]
    )


def get(theme_id: str) -> Theme | None:
    return next((t for t in load_themes() if t.id == theme_id), None)


@lru_cache(maxsize=1)
def markers() -> tuple[str, ...]:
    """UAE place names, longest first, so "abudhabi" is reported over a shorter one."""
    return tuple(sorted(_data()["markers"], key=len, reverse=True))


def _name(host: str) -> str:
    sub, label, _ = split_host(host)
    return f"{sub}.{label}" if sub else label


def uae_marker(host: str) -> str | None:
    """The UAE marker in a host name: a place name anywhere in it, a name that
    ends in -ae, or the .ae suffix; None when it has none."""
    if is_ip(host):
        return None
    name = _name(host)
    for word in _data()["not_markers"]:
        name = name.replace(word, "")
    found = next((m for m in markers() if m in name), None)
    if found:
        return found
    if split_host(host)[2].split(".")[-1] == "ae":
        return ".ae"
    return "-ae" if _AE_ENDING.search(name) else None


def match(host: str) -> list[ThemeMatch]:
    """The themes a host name matches, in file order, each with the marker and
    the theme words found."""
    marker = uae_marker(host)
    if marker is None:
        return []
    name = _name(host)
    tokens = set(split_tokens(name))
    tokens |= {rest for token in tokens for m in markers()
               for rest in (token.removeprefix(m), token.removesuffix(m)) if rest and rest != token}
    found = []
    for theme in load_themes():
        words = [w for w in theme.words if w in tokens or (len(w) >= SUBSTRING_MIN and w in name)]
        # A word holding another word found is the same letters again (uaevisa holds "evisa").
        kept = tuple(w for w in words if not any(other != w and other in w for other in words))
        if kept:
            found.append(ThemeMatch(theme, marker, kept))
    return found


def ct_terms() -> list[str]:
    return sorted({term for theme in load_themes() for term in theme.ct_terms})


def labels() -> dict[str, tuple[str, str]]:
    """Each theme's English and Arabic name, keyed by its id (for reason text)."""
    return {t.id: (t.name_en, t.name_ar) for t in load_themes()}
