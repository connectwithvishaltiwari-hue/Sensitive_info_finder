"""Compare rules vs NLP-only vs hybrid detection on the labeled dataset.
Run from the project root:  python evaluation/evaluate.py
Writes evaluation/results/{summary.json, per_category.csv, summary.md}."""
import csv, json, sys, time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
from app.engine import Scanner  # noqa: E402
from app.evalkit import dataset, metrics  # noqa: E402

OUT = ROOT / "evaluation" / "results"
LABELS = dataset.LABELS


def run_mode(mode: str, docs: list[dict]) -> dict:
    sc = Scanner(mode)
    sc.scan("Warm up the models with a short sentence by Ananya Iyer.")   # exclude load time
    strict, lenient = {}, {}
    lat, leak, total_gold = [], 0, 0
    benign = {"negative": [0, 0], "hard_negative": [0, 0]}
    out_of_scope = 0
    for d in docs:
        res = sc.scan(d["text"])
        lat.append(res.latency_ms)
        preds_all = [(f.entity_type, f.start, f.end) for f in res.findings]
        preds = [p for p in preds_all if p[0] in LABELS]
        out_of_scope += len(preds_all) - len(preds)
        gold = [(e["label"], e["start"], e["end"]) for e in d["entities"]]
        metrics.count_doc(preds, gold, LABELS, False, strict)
        metrics.count_doc(preds, gold, LABELS, True, lenient)
        vals = [d["text"][s:e] for _, s, e in gold]
        total_gold += len(vals)
        leak += metrics.leaked(vals, res.sanitized_text)
        if d["kind"] in benign:
            benign[d["kind"]][0] += 1
            benign[d["kind"]][1] += 1 if preds else 0
    n_ben = sum(v[0] for v in benign.values()); fp_ben = sum(v[1] for v in benign.values())
    return {"strict": metrics.summarise(strict)["overall"],
            "per_category": metrics.summarise(strict)["per_category"],
            "lenient": metrics.summarise(lenient)["overall"],
            "fpr_benign": fp_ben / n_ben if n_ben else 0.0,
            "fpr_negative": benign["negative"][1] / benign["negative"][0] if benign["negative"][0] else 0.0,
            "fpr_hard_negative": benign["hard_negative"][1] / benign["hard_negative"][0] if benign["hard_negative"][0] else 0.0,
            "leakage_rate": leak / total_gold if total_gold else 0.0,
            "leaked_spans": leak, "gold_spans": total_gold,
            "out_of_scope_predictions_ignored": out_of_scope,
            "latency_ms": {"mean": sum(lat) / len(lat), "p95": metrics.percentile(lat, 0.95)}}


def main():
    docs = dataset.load(ROOT / "data")
    kinds = {}
    for d in docs:
        kinds[d["kind"]] = kinds.get(d["kind"], 0) + 1
    summary = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "dataset": {"n_docs": len(docs), "n_entities": sum(len(d["entities"]) for d in docs),
                           "seed": 42, "kinds": {k: kinds.get(k, 0) for k in ("positive", "negative", "hard_negative")},
                           "labels": LABELS, "note": "synthetic data; not a public benchmark"},
               "modes": {}}
    for mode in ("rules", "nlp", "hybrid"):
        print("evaluating", mode, "...", flush=True)
        summary["modes"][mode] = run_mode(mode, docs)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    with (OUT / "per_category.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["mode", "category", "support", "precision", "recall", "f1", "tp", "fp", "fn"])
        for m, r in summary["modes"].items():
            for c, v in r["per_category"].items():
                w.writerow([m, c, v["support"], f"{v['precision']:.4f}", f"{v['recall']:.4f}", f"{v['f1']:.4f}", v["tp"], v["fp"], v["fn"]])
    L = ["| Mode | Precision | Recall | F1 | Lenient F1 | Benign FPR | Hard-neg FPR | Leakage | Mean ms | p95 ms |", "|---|---|---|---|---|---|---|---|---|---|"]
    for m, r in summary["modes"].items():
        L.append(f"| {m} | {r['strict']['precision']:.3f} | {r['strict']['recall']:.3f} | {r['strict']['f1']:.3f} | "
                 f"{r['lenient']['f1']:.3f} | {r['fpr_benign']:.3f} | {r['fpr_hard_negative']:.3f} | {r['leakage_rate']:.3f} | "
                 f"{r['latency_ms']['mean']:.2f} | {r['latency_ms']['p95']:.2f} |")
    L += ["", "Per-category strict F1:", "", "| Category | support | " + " | ".join(summary["modes"]) + " |",
          "|---|---|" + "---|" * len(summary["modes"])]
    for c in LABELS:
        sup = summary["modes"]["rules"]["per_category"][c]["support"]
        L.append(f"| {c} | {sup} | " + " | ".join(f"{summary['modes'][m]['per_category'][c]['f1']:.3f}" for m in summary["modes"]) + " |")
    (OUT / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main()
