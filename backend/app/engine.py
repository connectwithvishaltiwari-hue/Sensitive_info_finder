from __future__ import annotations
import re
import time
from typing import Callable

from .config import MAX_INPUT_CHARS
from .detectors.base import Detector
from .detectors.rules import RuleDetector, KeywordDetector
from .models import Finding, ScanResult

MODES = ("rules", "nlp", "hybrid")
# 'nlp' mode lets Presidio/spaCy handle everything it can (for comparison);
# 'hybrid' uses rules for structured data + NLP only for names/locations.
_NLP_ONLY_ENTITIES = ("PERSON", "LOCATION", "EMAIL_ADDRESS", "PHONE_NUMBER",
                      "CREDIT_CARD", "IP_ADDRESS")

PLACEHOLDER_RE = re.compile(r"\[[A-Z_]+?(?:_[0-9]+)?\]")


def _rank(f: Finding):
    return (f.score, f.end - f.start)


def cluster_overlaps(findings: list[Finding]) -> list[list[Finding]]:
    """Group findings whose half-open ranges overlap."""
    clusters: list[list[Finding]] = []
    cur_end = -1
    for f in sorted(findings, key=lambda f: (f.start, -f.end)):
        if clusters and f.start < cur_end:
            clusters[-1].append(f)
            cur_end = max(cur_end, f.end)
        else:
            clusters.append([f])
            cur_end = f.end
    return clusters


def cluster_span(c: list[Finding]) -> tuple[int, int]:
    return min(f.start for f in c), max(f.end for f in c)


def apply_masking(text: str, clusters: list[list[Finding]],
                  mask_if: Callable[[list[Finding]], bool] = lambda c: True,
                  numbered: bool = False) -> tuple[str, dict[str, str]]:
    """Replace the UNION of each selected overlap cluster with a placeholder.
    Returns (masked_text, mapping placeholder->original). The mapping is only
    filled when numbered=True and must never be logged or stored."""
    parts, pos = [], 0
    mapping: dict[str, str] = {}
    seen: dict[tuple, str] = {}
    counters: dict[str, int] = {}
    for c in clusters:
        if not mask_if(c):
            continue
        start, end = cluster_span(c)
        label = max(c, key=_rank).entity_type
        if numbered:
            key = (label, text[start:end])
            if key not in seen:
                counters[label] = counters.get(label, 0) + 1
                seen[key] = f"[{label}_{counters[label]}]"
                mapping[seen[key]] = text[start:end]
            ph = seen[key]
        else:
            ph = f"[{label}]"
        parts.append(text[pos:start])
        parts.append(ph)
        pos = end
    parts.append(text[pos:])
    return "".join(parts), mapping


def mask_text(text: str, clusters: list[list[Finding]]) -> str:
    return apply_masking(text, clusters)[0]


class Scanner:
    def __init__(self, mode: str = "rules", custom_keywords=()):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.mode = mode
        self.detectors: list[Detector] = []
        self._kw: Detector | None = None
        if mode in ("rules", "hybrid"):
            self.detectors.append(RuleDetector())
        if mode in ("nlp", "hybrid"):
            from .detectors.presidio_detector import PresidioDetector
            ents = _NLP_ONLY_ENTITIES if mode == "nlp" else ("PERSON", "LOCATION")
            self.detectors.append(PresidioDetector(entities=ents))
        self.set_keywords(custom_keywords)

    def set_keywords(self, keywords) -> None:
        self._kw = KeywordDetector(keywords) if keywords else None

    def scan(self, text: str) -> ScanResult:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if len(text) > MAX_INPUT_CHARS:
            raise ValueError(f"input exceeds {MAX_INPUT_CHARS} characters")
        t0 = time.perf_counter()
        raw: list[Finding] = []
        dets = self.detectors + ([self._kw] if self._kw else [])
        for d in dets:
            raw.extend(d.detect(text))
        clusters = cluster_overlaps(raw)
        findings = [max(c, key=_rank) for c in clusters]
        sanitized = apply_masking(text, clusters)[0]
        return ScanResult(findings=findings, sanitized_text=sanitized,
                          latency_ms=(time.perf_counter() - t0) * 1000,
                          mode=self.mode, clusters=clusters)
