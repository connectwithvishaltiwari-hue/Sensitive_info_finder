"""Exact-span and lenient-span precision/recall/F1, leakage and FPR."""
from __future__ import annotations
from collections import defaultdict


def _prf(tp_pred, fp, tp_gold, fn):
    p = tp_pred / (tp_pred + fp) if (tp_pred + fp) else 0.0
    r = tp_gold / (tp_gold + fn) if (tp_gold + fn) else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f


def _overlap(a, b) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def count_doc(pred: list[tuple], gold: list[tuple], labels, lenient: bool, acc: dict):
    """pred/gold: (label,start,end). Adds counts per label into acc."""
    for lab in labels:
        P = {(s, e) for l, s, e in pred if l == lab}
        G = {(s, e) for l, s, e in gold if l == lab}
        c = acc.setdefault(lab, defaultdict(int))
        if lenient:
            tp_pred = sum(1 for p in P if any(_overlap(p, g) for g in G))
            tp_gold = sum(1 for g in G if any(_overlap(p, g) for p in P))
            c["tp_pred"] += tp_pred; c["fp"] += len(P) - tp_pred
            c["tp_gold"] += tp_gold; c["fn"] += len(G) - tp_gold
        else:
            tp = len(P & G)
            c["tp_pred"] += tp; c["tp_gold"] += tp
            c["fp"] += len(P - G); c["fn"] += len(G - P)
        c["support"] += len(G)


def summarise(acc: dict) -> dict:
    per, T = {}, defaultdict(int)
    for lab, c in acc.items():
        p, r, f = _prf(c["tp_pred"], c["fp"], c["tp_gold"], c["fn"])
        per[lab] = {"precision": p, "recall": r, "f1": f, "support": c["support"],
                    "tp": c["tp_gold"], "fp": c["fp"], "fn": c["fn"]}
        for k in ("tp_pred", "fp", "tp_gold", "fn"):
            T[k] += c[k]
    p, r, f = _prf(T["tp_pred"], T["fp"], T["tp_gold"], T["fn"])
    return {"overall": {"precision": p, "recall": r, "f1": f, "tp": T["tp_gold"], "fp": T["fp"], "fn": T["fn"]},
            "per_category": per}


def leaked(text_gold_values: list[str], sanitized: str) -> int:
    """How many gold values still appear verbatim in the sanitized text."""
    return sum(1 for v in text_gold_values if v and v in sanitized)


def percentile(xs: list[float], q: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    k = min(len(xs) - 1, max(0, int(round(q * (len(xs) - 1)))))
    return xs[k]
