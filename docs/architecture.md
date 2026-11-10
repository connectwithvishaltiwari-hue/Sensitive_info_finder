# Architecture

```
 Browser (static HTML/JS) ──HTTP──►  FastAPI backend  (the ONLY enforcement point)
                                      │
   /api/scan, /api/scan-file          ├─ Scanner ── RuleDetector (regex + checksum + context)
   /api/chat                          │          ├─ PresidioDetector (spaCy NER)   [hybrid/nlp]
   /api/settings (admin key)          │          └─ KeywordDetector (custom terms)
   /api/stats, /api/evaluation        ├─ overlap clustering + masking (union of spans)
                                      ├─ Policy engine  (ALLOW / WARN / MASK / BLOCK)
                                      ├─ LLM gateway ── provider interface ── Mock | OpenAI-compatible
                                      └─ SQLite: settings + anonymous counts (no raw text)
```

## Gateway flow (`services/gateway.py`)
1. Validate (Pydantic: type, 1..100 000 chars).
2. Scan the prompt -> clusters of findings.
3. Policy per cluster -> overall decision. **BLOCK** stops here; **WARN** needs `confirm_warnings`.
4. Mask the MASK clusters (the *union* of overlapping findings, so no fragment survives).
5. **Verify**: re-scan the exact outbound text with the deterministic rules scanner; if any
   MASK/BLOCK-level pattern survived, fail closed (nothing is sent).
6. Call the provider (timeout from `LLM_TIMEOUT`; errors become a generic message).
7. Scan the response; BLOCK withholds it, MASK/WARN mask it (no human can confirm a response).
8. Optional restoration of numbered placeholders, low-risk PII only, off unless an admin enables it.

## Modules
| Path | Role |
|---|---|
| `detectors/rules.py` | 25 regex rules + an Indian-address heuristic, validators (Luhn, Verhoeff, IPv4, placeholder filter), context boosting |
| `detectors/presidio_detector.py` | Presidio + spaCy NER (lazy import, lock for thread-safety) |
| `engine.py` | `Scanner`, overlap clustering, `apply_masking` |
| `policies/engine.py` | `PolicySettings` (validated), `evaluate()` |
| `services/gateway.py` | Provider-independent flow above |
| `providers/` | `LLMProvider` interface, `MockProvider`, `OpenAICompatibleProvider` |
| `services/store.py` | SQLite settings + counters |
| `services/files.py` | In-memory text extraction (txt/md/csv/log/json/pdf/docx) |
| `evalkit/` | Dataset generator and metrics used by `evaluation/*.py` and tests |

## Design decisions (and why)
* **Detection is separate from policy.** A detector says what something looks like; policy says what to do. Admins change behaviour without touching detectors.
* **Offsets, not values, over the API.** The browser already has the text; the server never echoes secrets back.
* **Clusters, not single findings.** Detectors can disagree on boundaries; masking the union prevents partial leaks.
* **Fail closed.** Unverifiable sanitisation, oversized responses and provider failures all end in "nothing shown / nothing sent".
* **Protection order vs decision order.** Inside one cluster MASK beats WARN (never leave a span exposed); for the whole request WARN beats MASK (a human decision is pending).
* **No raw text persisted.** Only counts by entity/action/source.
* **Vanilla frontend, strict CSP.** No inline scripts, no `innerHTML`; user text only reaches the DOM through `textContent`.
