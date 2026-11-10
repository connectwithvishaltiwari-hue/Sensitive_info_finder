"""Policy engine: turns detections into actions.

Detection says 'this looks like X'. Policy says 'what do we do about X'.
Keeping them separate lets an admin change behaviour without touching detectors.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from ..config import ENTITY_CATALOG, DEFAULT_ENTITY_ACTIONS
from ..engine import _rank
from ..models import Finding

Action = Literal["ALLOW", "WARN", "MASK", "BLOCK"]

# How strongly an action PROTECTS the data (used inside one overlap cluster:
# a MASK member must win over a WARN member, otherwise the span would leak).
_PROTECT = {"ALLOW": 0, "WARN": 1, "MASK": 2, "BLOCK": 3}
# Which action dominates the OVERALL request decision (a pending WARN needs a
# human decision before anything else can happen).
_OVERALL = {"ALLOW": 0, "MASK": 1, "WARN": 2, "BLOCK": 3}


class PolicySettings(BaseModel):
    entity_actions: dict[str, Action] = Field(
        default_factory=lambda: dict(DEFAULT_ENTITY_ACTIONS))
    default_action: Action = "MASK"           # for entity types not listed
    ignore_below: float = Field(0.30, ge=0.0, le=1.0)   # weaker findings are ignored
    warn_below: float = Field(0.50, ge=0.0, le=1.0)     # MASK/BLOCK findings weaker than this become WARN
    custom_keywords: list[str] = Field(default_factory=list, max_length=200)
    allow_placeholder_restoration: bool = False

    @field_validator("entity_actions")
    @classmethod
    def _known_entities(cls, v):
        unknown = set(v) - set(ENTITY_CATALOG)
        if unknown:
            raise ValueError(f"unknown entity types: {sorted(unknown)}")
        return v

    @field_validator("custom_keywords")
    @classmethod
    def _clean_keywords(cls, v):
        out = []
        for k in v:
            k = k.strip()
            if not k:
                continue
            if len(k) > 100:
                raise ValueError("keywords must be at most 100 characters")
            out.append(k)
        return out

    @model_validator(mode="after")
    def _thresholds(self):
        if self.warn_below < self.ignore_below:
            raise ValueError("warn_below must be >= ignore_below")
        return self


def default_policy() -> PolicySettings:
    return PolicySettings()


@dataclass
class Decision:
    overall: str = "ALLOW"
    cluster_actions: list[str] = field(default_factory=list)
    items: list[dict] = field(default_factory=list)       # one per cluster
    messages: list[str] = field(default_factory=list)

    def is_masked(self, index: int) -> bool:
        return self.cluster_actions[index] == "MASK"


def _finding_action(f: Finding, p: PolicySettings) -> tuple[str, str]:
    if f.score < p.ignore_below:
        return "ALLOW", f"confidence {f.score:.2f} below ignore threshold"
    base = p.entity_actions.get(f.entity_type, p.default_action)
    if base in ("MASK", "BLOCK") and f.score < p.warn_below:
        return "WARN", f"low confidence ({f.score:.2f}) - review required"
    return base, f"policy for {f.entity_type}"


def evaluate(clusters: list[list[Finding]], policy: PolicySettings,
             output: bool = False) -> Decision:
    """output=True: WARN is converted to MASK, because a model response has no
    human in the loop who could confirm a warning."""
    d = Decision()
    for c in clusters:
        verdicts = [_finding_action(f, policy) for f in c]
        action, reason = max(verdicts, key=lambda v: _PROTECT[v[0]])
        if output and action == "WARN":
            action, reason = "MASK", reason + " (response: masked automatically)"
        rep = max(c, key=_rank)
        d.cluster_actions.append(action)
        d.items.append({"entity_type": rep.entity_type, "action": action, "reason": reason})
    if d.cluster_actions:
        d.overall = max(d.cluster_actions, key=lambda a: _OVERALL[a])
    counts: dict[tuple, int] = {}
    for it in d.items:
        if it["action"] != "ALLOW":
            counts[(it["entity_type"], it["action"])] = counts.get((it["entity_type"], it["action"]), 0) + 1
    d.messages = [f"{n} x {t}: {a}" for (t, a), n in sorted(counts.items())]
    return d
