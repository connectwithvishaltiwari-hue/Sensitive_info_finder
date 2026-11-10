"""Generate the synthetic labeled dataset.
Run from the project root:  python evaluation/generate_dataset.py [--seed 42]"""
import argparse, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
from app.evalkit import dataset  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    docs = dataset.generate(seed=a.seed)
    dataset.validate(docs)
    tp, ap_ = dataset.save(docs, ROOT / "data")
    kinds = {}
    for d in docs:
        kinds[d["kind"]] = kinds.get(d["kind"], 0) + 1
    print(f"seed={a.seed} documents={len(docs)} spans={sum(len(d['entities']) for d in docs)} kinds={kinds}")
    print("wrote", tp.relative_to(ROOT), "and", ap_.relative_to(ROOT))


if __name__ == "__main__":
    main()
