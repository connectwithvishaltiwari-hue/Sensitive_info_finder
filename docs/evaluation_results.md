# Evaluation results (actual run, synthetic data, seed 42)

Produced by `python evaluation/evaluate.py`. Raw files: `evaluation/results/summary.json`, `per_category.csv`, `summary.md`.
Latency was measured on the author's sandbox; yours will differ.

| Mode | Precision | Recall | F1 | Lenient F1 | Benign FPR | Hard-neg FPR | Leakage | Mean ms | p95 ms |
|---|---|---|---|---|---|---|---|---|---|
| rules | 0.984 | 0.777 | 0.868 | 0.868 | 0.047 | 0.077 | 0.223 | 0.07 | 0.10 |
| nlp | 0.704 | 0.550 | 0.617 | 0.654 | 0.109 | 0.154 | 0.314 | 6.21 | 8.10 |
| hybrid | 0.878 | 0.921 | 0.899 | 0.931 | 0.062 | 0.077 | 0.033 | 4.62 | 6.31 |

## What the numbers mean
* **Rules**: near-perfect precision, but recall is capped at 77.7% because it has no name detector. All 54 PERSON spans are missed, which is exactly the 22.3% leakage.
* **NLP-only**: Presidio/spaCy cover only emails, phones, cards, IPs and names. Aadhaar, PAN, keys, passwords, private keys, DB URLs and UPI are never found (F1 = 0), so recall and leakage are poor.
* **Hybrid**: best overall (F1 0.899, leakage 3.3%). Rules supply structured data; spaCy supplies names.
* **Why hybrid precision is lower than rules**: spaCy mislabels some tokens as PERSON (e.g. a sentence-initial verb "Summarise", the Hinglish word "mera") and sometimes includes the preceding word ("Reach Karan Sharma"). The jump from strict F1 0.899 to lenient 0.931 shows many of these are boundary errors.
* **Rules false positives**: all 3 come from version strings like `v1.2.3.4` that are valid IPv4 syntax (IP precision 85%). This is a known limitation, not hidden.
* **Cost**: hybrid is about 100x slower than rules (spaCy inference) but still only a few milliseconds per document.

See `per_category.csv` for every category.
