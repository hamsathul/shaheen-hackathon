"""Batch scanning and evaluation: read a list of links in whatever shape it
comes, scan them in parallel, and score Baaz against the labels.

`fraud` is the positive class. Baaz flags a link when its verdict is in
FLAG_VERDICTS.
"""

from __future__ import annotations

import contextlib
import csv
import io
import re
import sys
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from baaz.config import Settings, load_settings
from baaz.domains import defang, refang
from baaz.models import ScanOptions, ScanResult
from baaz.pipeline import Scanner
from baaz.store import Store

FLAG_VERDICTS = ("fraud", "suspicious")
_HOST = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
DEFAULT_TIMEOUT = 90.0

URL_COLUMNS = ("url", "link", "domain", "website")
LABEL_COLUMNS = ("label", "class", "type", "status", "is_phishing", "phishing", "result")
FRAUD_LABELS = frozenset({"phishing", "fraud", "malicious", "scam", "bad", "1", "true", "yes"})
LEGIT_LABELS = frozenset({"legitimate", "benign", "legit", "good", "safe", "0", "false", "no"})


@dataclass
class Target:
    url: str
    label: str | None = None  # fraud, legitimate or unknown (None)


def normalise_label(value: str | None) -> str | None:
    value = (value or "").strip().strip('"').lower()
    if value in FRAUD_LABELS:
        return "fraud"
    if value in LEGIT_LABELS:
        return "legitimate"
    return None


def call(result: ScanResult) -> str:
    """Baaz's binary call on a scan."""
    return "fraud" if result.verdict in FLAG_VERDICTS else "legitimate"


def read_targets(path: Path) -> list[Target]:
    """Links from a text file (one per line, `#` comments, `# label: <x>` for
    the lines below it, optional `,label` or tab-separated label) or from a CSV
    whose header names a URL column. Defanged links are refanged."""
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    lines = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if lines:
        header = _header(lines[0])
        if header:
            return _read_csv("\n".join(lines), *header)
    return _read_lines(text)


def _header(line: str) -> tuple[str, int, int | None] | None:
    """(delimiter, URL column, label column) when `line` is a CSV header."""
    for delimiter in (",", "\t", ";"):
        cells = [c.strip().strip('"').lower() for c in next(csv.reader([line], delimiter=delimiter))]
        url_col = next((cells.index(name) for name in URL_COLUMNS if name in cells), None)
        if url_col is not None:
            label_col = next((cells.index(name) for name in LABEL_COLUMNS if name in cells), None)
            return delimiter, url_col, label_col
    return None


def _read_csv(text: str, delimiter: str, url_col: int, label_col: int | None) -> list[Target]:
    rows = list(csv.reader(io.StringIO(text), delimiter=delimiter))[1:]
    targets = []
    for row in rows:
        if len(row) > url_col and row[url_col].strip():
            label = normalise_label(row[label_col]) if label_col is not None and len(row) > label_col else None
            targets.append(Target(refang(row[url_col]), label))
    return targets


def _read_lines(text: str) -> list[Target]:
    targets: list[Target] = []
    default: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            key, _, value = line.lstrip("#").partition(":")
            if key.strip().lower() == "label":
                default = normalise_label(value)
            continue
        url, label = line, default
        if "\t" in line:
            url, _, tail = line.partition("\t")
            label = normalise_label(tail) or default
        elif "," in line:
            head, _, tail = line.rpartition(",")
            if not any(c in tail for c in "/.=&?"):  # a label column, not part of the URL
                url, label = head, normalise_label(tail) or default
        targets.append(Target(refang(url.strip()), label))
    return targets


def run_batch(targets: list[Target], workers: int = 8, options: ScanOptions | None = None,
              timeout: float = DEFAULT_TIMEOUT, settings: Settings | None = None,
              progress: bool = True) -> list[ScanResult]:
    """Scan every target with a pool of workers (one Scanner per worker
    thread), keeping the input order. A link still running after `timeout`
    seconds is scored from its URL and domain alone, as `timeout`."""
    settings = settings or load_settings()
    store = Store(settings.db_path)
    local = threading.local()
    scanners: list[Scanner] = []
    lock = threading.Lock()
    done = [0]
    show = progress and sys.stderr.isatty()

    def scanner() -> Scanner:
        if not hasattr(local, "scanner"):
            local.scanner = Scanner(settings, store)
            with lock:
                scanners.append(local.scanner)
        return local.scanner

    def one(target: Target) -> ScanResult:
        result = scan_with_timeout(scanner(), target.url, options or ScanOptions(), timeout)
        with lock:
            done[0] += 1
            if show:
                print(f"\r  scanned {done[0]}/{len(targets)}", end="", file=sys.stderr, flush=True)
        return result

    try:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            results = list(pool.map(one, targets))
    finally:
        if show:
            print(file=sys.stderr)
        for s in scanners:
            s.close()
    return results


def scan_with_timeout(scanner: Scanner, url: str, options: ScanOptions, timeout: float) -> ScanResult:
    """A full scan, or a URL-only scan when the full one has not finished in time
    (the full one is left to finish in the background)."""
    done: list[ScanResult] = []

    def run() -> None:
        with contextlib.suppress(Exception):  # the batch always gets a row: the URL-only scan below
            done.append(scanner.scan(url, options))

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout)
    if done:
        return done[0]
    quick = ScanOptions(render=False, storefront=False, write_evidence=options.write_evidence)
    return scanner.scan(url, quick, fetch=False)


def write_results(path: Path, targets: list[Target], results: list[ScanResult]) -> None:
    """The batch CSV: url,label,risk_score,verdict,top_reason (label is Baaz's call)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        out = csv.writer(fh)
        out.writerow(["url", "label", "risk_score", "verdict", "top_reason"])
        for target, r in zip(targets, results, strict=True):
            out.writerow([target.url, call(r), r.risk_score, r.verdict, r.top_reason])


# Evaluation


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    def add(self, truth: str, predicted: str) -> None:
        if truth == "fraud":
            self.tp += predicted == "fraud"
            self.fn += predicted != "fraud"
        else:
            self.fp += predicted == "fraud"
            self.tn += predicted != "fraud"

    @property
    def labelled(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p is not None and r is not None and p + r else None

    @property
    def fpr(self) -> float | None:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else None


def metrics(targets: list[Target], results: list[ScanResult]) -> Metrics:
    m = Metrics()
    for target, result in zip(targets, results, strict=True):
        if target.label:
            m.add(target.label, call(result))
    return m


def _num(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _shown(target: Target) -> str:
    return defang(target.url) if target.label == "fraud" else target.url


def _reason(target: Target, result: ScanResult) -> str:
    """The top reason; host names in it are defanged for links labelled fraud."""
    if target.label != "fraud":
        return result.top_reason
    return _HOST.sub(lambda m: m.group(0).replace(".", "[.]"), result.top_reason)


def file_report(name: str, targets: list[Target], results: list[ScanResult]) -> str:
    """The plain-text evaluation block for one input file."""
    fetch = Counter(r.fetch_status for r in results)
    verdicts = Counter(r.verdict for r in results)
    m = metrics(targets, results)
    lines = [
        f"== {name}",
        f"total {len(results)}  live {fetch['ok']}  (fetch: "
        + ", ".join(f"{k} {fetch[k]}" for k in ("ok", "dead", "blocked", "timeout") if fetch[k]) + ")",
        "verdicts: " + ", ".join(f"{v} {verdicts[v]}" for v in ("fraud", "suspicious", "legitimate")),
    ]
    if m.labelled:
        lines += [
            f"labelled {m.labelled}: TP {m.tp}  FP {m.fp}  TN {m.tn}  FN {m.fn}",
            f"precision {_num(m.precision)}  recall {_num(m.recall)}  F1 {_num(m.f1)}  "
            f"false-positive rate {_num(m.fpr)}",
        ]
        for title, wanted in (("false positives", "legitimate"), ("false negatives", "fraud")):
            wrong = [(t, r) for t, r in zip(targets, results, strict=True) if t.label == wanted and call(r) != wanted]
            if wrong:
                lines.append(f"{title} ({len(wrong)}):")
                lines += [f"  {_shown(t)}  {r.verdict} {r.risk_score} [{r.fetch_status}]  {_reason(t, r)}"
                          for t, r in wrong]
    return "\n".join(lines)


def combined_table(rows: list[tuple[str, list[Target], list[ScanResult]]]) -> str:
    """One line per file plus a total line."""
    head = f"{'file':<32} {'total':>5} {'live':>5} {'fraud':>5} {'susp':>5} {'legit':>5} " \
           f"{'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} {'prec':>6} {'recall':>6} {'F1':>6} {'FPR':>6}"
    lines = [head]
    all_targets: list[Target] = []
    all_results: list[ScanResult] = []
    for name, targets, results in [*rows, ("total", [], [])]:
        if name == "total":
            targets, results = all_targets, all_results
        else:
            all_targets += targets
            all_results += results
        v = Counter(r.verdict for r in results)
        live = sum(r.fetch_status == "ok" for r in results)
        m = metrics(targets, results)
        lines.append(f"{name[:32]:<32} {len(results):>5} {live:>5} {v['fraud']:>5} {v['suspicious']:>5} "
                     f"{v['legitimate']:>5} {m.tp:>4} {m.fp:>4} {m.tn:>4} {m.fn:>4} {_num(m.precision):>6} "
                     f"{_num(m.recall):>6} {_num(m.f1):>6} {_num(m.fpr):>6}")
    return "\n".join(lines)


def write_eval_rows(path: Path, targets: list[Target], results: list[ScanResult]) -> None:
    """Per-URL evaluation rows; links labelled fraud are defanged."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        out = csv.writer(fh)
        out.writerow(["url", "truth", "label", "risk_score", "verdict", "fetch_status", "fraud_type", "top_reason"])
        for t, r in zip(targets, results, strict=True):
            out.writerow([_shown(t), t.label or "", call(r), r.risk_score, r.verdict, r.fetch_status,
                          r.fraud_type or "", _reason(t, r)])
