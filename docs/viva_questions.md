# Likely viva questions and accurate answers
**1. Why not only regex?** Regex handles fixed formats well but cannot find names or context. Hybrid adds a statistical NER model; our evaluation shows recall rising from 0.777 to 0.921.
**2. Why not only an NLP model?** The small spaCy model has no concept of Aadhaar, PAN, API keys or DB URLs (F1 = 0 for them). NLP-only scored F1 0.617 vs 0.899 for hybrid.
**3. What is Luhn / Verhoeff?** Check-digit algorithms for cards and Aadhaar. They remove random-number false positives but cannot prove a number is real.
**4. Precision vs recall here?** Precision = of what we flag, how much is truly sensitive; recall = of what is sensitive, how much we flag. Over-flagging annoys users; missing leaks data. Policy thresholds let admins choose.
**5. Why is the confidence score not a probability?** It is a rule-based heuristic (pattern, checksum, context), not calibrated.
**6. How do you stop a user bypassing policy?** All decisions are on the server. `/api/chat` accepts only the prompt and flags; settings need an admin key; tests prove client-supplied policy fields are ignored.
**7. How do you know the original prompt never reaches the LLM?** Gateway tests record every call to the mock provider and assert masked/blocked prompts are absent; a second verification scan fails closed.
**8. Why mask the union of overlapping findings?** Detectors disagree on boundaries; masking only one would leave a fragment of the secret.
**9. What happens when masking changes meaning?** The UI says the answer may be less specific; placeholders can optionally be restored (low-risk PII only, never credentials, admin must enable).
**10. Do you store prompts?** No. Only counts by category/action; a test dumps the whole database and asserts no prompt text is present.
**11. Does this stop prompt injection?** No. That is a different problem (untrusted instructions), not covered.
**12. Weaknesses of your evaluation?** Synthetic, same author as rules, small; no public benchmark yet. Results are real runs, not invented.
**13. Why is hybrid slower?** spaCy neural inference costs milliseconds; regex costs microseconds.
**14. PII vs credentials vs contextual confidentiality vs LLM security?** PII = data about people; credentials = secrets granting access; contextual = confidential because of meaning/ownership (needs keywords or ML); LLM security = injection, jailbreaks, model abuse - a broader area.
**15. How would you improve it?** Public-benchmark evaluation, a trained classifier for ambiguous cases, better multilingual NER, per-user auth.
