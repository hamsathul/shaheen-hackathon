"""The statistics page: its figures from `stats`, laid out for inline SVG in the
words of the chosen view. Horizontal positions are percentages of a chart's
width, so text keeps its size at any width, and vertical ones are pixels.
Right-to-left pages get every chart mirrored, the time axis included."""

from __future__ import annotations

import math
from datetime import datetime
from pathlib import Path
from typing import Any

from shaheen import storefront
from shaheen.evidence import GST
from shaheen.web import i18n, stats

GAP = 0.25  # percent of the width between touching segments
MIN_WIDTH = 0.4  # percent: the narrowest segment drawn for a non-zero count
PLOT_TOP, PLOT_HEIGHT, AXIS = 14, 200, 26  # px: the column chart
PLOT_START = 5.0  # percent of the width kept for the column chart's scale
BAR_SHARE = 0.55  # of each hour's slot
LABEL_MIN = 6.0  # percent: the narrowest block that prints its share
LABEL_TABLES = {"source": i18n.SOURCES, "type": i18n.FRAUD_TYPES}


def _step(top: int, ticks: int = 4) -> int:
    """A round gridline step (1, 2 or 5 times a power of ten) for values up to `top`."""
    raw = max(top, 1) / ticks
    power = 10 ** math.floor(math.log10(raw))
    return max(1, next(int(m * power) for m in (1, 2, 5, 10) if m * power >= raw))


def _mirror(x: float, width: float, rtl: bool) -> float:
    return round(100 - x - width if rtl else x, 3)


def segments(parts: list[tuple[str, int]], scale: int, rtl: bool) -> list[dict[str, Any]]:
    """Blocks laid end to end from the start edge, one per non-zero part, `scale`
    being the full width, with a gap between touching blocks."""
    drawn = [(key, n) for key, n in parts if n > 0]
    blocks, start = [], 0.0
    for i, (key, n) in enumerate(drawn):
        width = n / max(scale, 1) * 100
        visible = max(width - (GAP if i < len(drawn) - 1 else 0), MIN_WIDTH)
        blocks.append({"key": key, "n": n, "x": _mirror(start, visible, rtl), "width": round(visible, 3),
                       "share": round(n / max(scale, 1) * 100), "labelled": width >= LABEL_MIN,
                       "text_x": round(100 - start if rtl else start, 3)})
        start += width
    return blocks


def columns(buckets: list[dict[str, Any]], rtl: bool) -> dict[str, Any]:
    """Stacked columns, one per hour: fraud on the baseline, then suspicious, then legitimate."""
    top_total = max((sum(b[v] for v in stats.VERDICTS) for b in buckets), default=0)
    step = _step(top_total)
    top = max(step, math.ceil(top_total / step) * step)
    scale = PLOT_HEIGHT / top
    base = PLOT_TOP + PLOT_HEIGHT
    slot = (100 - PLOT_START) / len(buckets)
    cols = []
    for i, bucket in enumerate(buckets):
        hour = bucket["start"].astimezone(GST)
        centre = PLOT_START + slot * (i + 0.5)
        width = slot * BAR_SHARE
        rects, y = [], float(base)
        for verdict in stats.VERDICTS:
            height = bucket[verdict] * scale
            if not height:
                continue
            gap = 2 if y < base else 0
            drawn = max(height - gap, 1)
            rects.append({"verdict": verdict, "y": round(y - gap - drawn, 2), "height": round(drawn, 2)})
            y -= height
        cols.append({
            "hour": f"{hour:%H}:00", "span": f"{hour:%H}:00–{(hour.hour + 1) % 24:02d}:00",
            "counts": {v: bucket[v] for v in stats.VERDICTS}, "total": sum(bucket[v] for v in stats.VERDICTS),
            "rects": rects, "x": _mirror(centre - width / 2, width, rtl), "width": round(width, 3),
            "slot_x": _mirror(PLOT_START + slot * i, slot, rtl), "slot": round(slot, 3),
            "centre": round(100 - centre if rtl else centre, 3), "tick": hour.hour % 3 == 0,
        })
    return {
        "cols": cols, "height": base + AXIS, "base": base, "top": PLOT_TOP, "plot_height": PLOT_HEIGHT,
        "ticks": [{"value": v, "y": round(base - v * scale, 2)} for v in range(0, top + 1, step)],
        "plot_x": 0 if rtl else PLOT_START, "plot_width": 100 - PLOT_START, "scale_x": 100 if rtl else 0,
    }


def _label(kind: str, key: str, lang: str, simple: bool) -> str:
    """A source or fraud type in the words of the view."""
    if simple:
        return i18n.STRINGS[lang].get(f"simple_{kind}_{key}", key)
    return i18n.label(LABEL_TABLES[kind], lang, key)


def _bars(rows: list[dict[str, Any]], rtl: bool, label: Any = None) -> list[dict[str, Any]]:
    """Table rows with their flagged bar (fraud, then suspicious) on a shared scale."""
    scale = max((r["flagged"] for r in rows), default=0)
    return [{**r, "label": label(r["name"]) if label else r["name"],
             "blocks": segments([("fraud", r["fraud"]), ("suspicious", r["suspicious"])], scale, rtl)}
            for r in rows]


def _figures(h: dict[str, int], ai: dict[str, Any], names: dict[str, str], flagged: str, t: dict[str, str],
              simple: bool, hours_on_watch: int, searches_today: int) -> list[dict[str, Any]]:
    """The headline figures in three bands: everything checked, pace and links, the AI and Maps."""
    def said(key: str) -> str:
        return t.get(f"simple_{key}", t[key]) if simple else t[key]

    def item(label: str, value: Any, tone: str = "") -> dict[str, Any]:
        return {"label": label, "value": f"{value:,}" if isinstance(value, int) else value, "tone": tone}

    ai_items = [item(said(f"stats_ai_{s}"), ai["counts"][s]) for s in ("done", "running", "queued")]
    if ai["runs"]:
        ai_items += [item(said("stats_ai_minutes"), ai["minutes"]), item(said("stats_ai_calls"), ai["calls"])]
    return [
        {"title": said("fig_checked_group"), "cells": [
            item(said("fig_checked"), h["checked"]), item(said("fig_domains"), h["domains"]),
            item(said("fig_candidates"), h["candidates"]), item(flagged, h["fraud"] + h["suspicious"]),
            *(item(names[v], h[v], v) for v in stats.VERDICTS), item(said("fig_brands"), h["brands"])]},
        {"title": said("fig_pace_group"), "cells": [
            item(said("fig_last_hour"), h["last_hour"]), item(said("fig_last_day"), h["last_day"]),
            item(said("fig_fraud_day"), h["fraud_day"], "fraud"), item(said("fig_hours"), hours_on_watch),
            item(said("fig_links"), h["links"]), item(said("fig_linked_domains"), h["linked_domains"]),
            item(said("fig_confirmed"), h["confirmed"])]},
        {"title": said("fig_ai_group"), "cells": [
            *ai_items, item(said("fig_maps_searches"), searches_today),
            item(said("fig_maps_places"), h["maps_places"]), item(said("fig_maps_leads"), h["maps_leads"])]},
    ]


def view(path: Path, now: datetime, lang: str, simple: bool, alive: bool, *,
         watching_since: str | None, searches_today: int) -> dict[str, Any]:
    """Everything the statistics page shows, in the words of the Simple or the Analyst view."""
    t = i18n.STRINGS[lang]
    rtl = lang == "ar"
    with stats.connect(path) as db:
        head = stats.headline(db, now, sorted(storefront.gateway_lists()["strong"]))
        hours = stats.hourly(db, now)
        verdicts = stats.verdicts(db)
        brands = stats.brands(db)
        sources = stats.sources(db)
        types = stats.fraud_types(db)
        ai = stats.investigations(db, alive)
    names = {v: t[f"simple_{v}"] for v in stats.VERDICTS} if simple else i18n.VERDICTS[lang]
    total = sum(verdicts.values())
    flagged = t["simple_stats_found" if simple else "flagged"]
    hours_on_watch = int((now - datetime.fromisoformat(watching_since)).total_seconds() // 3600) if watching_since else 0
    basis = (t[f"{'simple_' if simple else ''}stats_ai_basis"].format(n=ai["runs"]) if ai["runs"]
             else t["stats_ai_none"])
    return {
        "prefix": "simple_" if simple else "",
        "names": names,
        "figures": _figures(head, ai, names, flagged, t, simple, hours_on_watch, searches_today),
        "figures_note": f"{t['simple_fig_links_note' if simple else 'fig_links_note']} {basis}",
        "heads": {"flagged": flagged,
                  "fraud": t["simple_fraud_title"] if simple else names["fraud"],
                  "scanned": t["simple_stats_checked" if simple else "scanned"]},
        "hourly": columns(hours, rtl),
        "hourly_total": sum(c[v] for c in hours for v in stats.VERDICTS),
        "verdicts": {"total": total, "counts": verdicts,
                     "blocks": segments([(v, verdicts[v]) for v in stats.VERDICTS], total, rtl)},
        "brands": _bars(brands, rtl),
        "sources": _bars(sources, rtl, lambda key: _label("source", key, lang, simple)),
        "types": _bars(types, rtl, lambda key: _label("type", key, lang, simple)),
    }
