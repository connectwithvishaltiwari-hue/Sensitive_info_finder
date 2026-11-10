from __future__ import annotations
from dataclasses import dataclass, field
from .config import risk_of, max_risk


@dataclass(frozen=True)
class Finding:
    """One detection. Offsets are half-open: text[start:end].
    The raw value is intentionally NOT stored."""
    entity_type: str
    start: int
    end: int
    score: float
    detector: str

    @property
    def risk(self) -> str:
        return risk_of(self.entity_type)

    def to_dict(self) -> dict:
        return {"entity_type": self.entity_type, "start": self.start,
                "end": self.end, "score": round(self.score, 3),
                "detector": self.detector, "risk": self.risk}


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    sanitized_text: str = ""
    latency_ms: float = 0.0
    mode: str = "rules"
    clusters: list = field(default_factory=list, repr=False)  # internal, not serialised

    @property
    def overall_risk(self) -> str:
        return max_risk(f.risk for f in self.findings)

    def to_dict(self) -> dict:
        return {"mode": self.mode, "overall_risk": self.overall_risk,
                "latency_ms": round(self.latency_ms, 2),
                "findings": [f.to_dict() for f in self.findings],
                "sanitized_text": self.sanitized_text}
