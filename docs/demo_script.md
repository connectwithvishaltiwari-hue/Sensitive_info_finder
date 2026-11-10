# Demo script (about 8 minutes)
1. **Problem (30 s):** people paste secrets and personal data into chatbots.
2. **Scanner:** paste `Email priya.sharma@example.com, PAN ABCPE1234F phone number 1234567890` -> findings table, highlights, sanitized text. Then `Explain gradient descent` -> "No sensitive data detected".
3. **Hard negatives:** `Part number ABCDE1234F`, `Password is required`, a bad-checksum card -> not flagged. Explain checksums.
4. **Hybrid:** switch to Hybrid, scan `Ananya Iyer sent the report to John Smith.` -> names found; explain NER limits.
5. **File upload:** upload a .docx or .pdf containing a fake email.
6. **Playground (mock model):** send `Draft a reply to priya.sharma@example.com` -> show "exactly what was sent" (masked). Send `use key AKIAIOSFODNN7EXAMPLE` -> blocked, "model call made: no".
7. **Response scanning:** send `hello [[LEAK_TEST]]` -> mock model leaks a fake key -> response withheld.
8. **Settings:** enter the admin key, change EMAIL_ADDRESS to BLOCK, save, resend -> blocked. Without the key the save fails (server-side enforcement).
9. **Analytics:** counts, then the evaluation table (rules vs nlp vs hybrid).
10. **Tests:** run `python -m pytest -q` live. Close with limitations.
