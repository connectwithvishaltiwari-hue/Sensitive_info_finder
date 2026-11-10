# Limitations (read before claiming anything)
* **Cannot guarantee detection.** It reduces exposure; any detector can miss values.
* **Format match is not proof of genuineness** (a Verhoeff-valid Aadhaar-like or Luhn-valid card number can be fake or random).
* **Rules** miss values in unusual formats (e.g. a bare 10-digit number with no phone context starting with 1-5) and can flag look-alikes (`v1.2.3.4` as an IP).
* **PASSWORD** heuristic needs a digit/symbol and a keyword; all-letter passwords and passwords without a keyword are missed.
* **PERSON/LOCATION** come from a small statistical model: misses, wrong labels and boundary errors are expected. Not every name or place is confidential.
* **ADDRESS / DATE_OF_BIRTH** are experimental. ADDRESS uses trigger words (address, location, stay at...) and an address-keyword heuristic (road, hostel, flat, sector + a house number or 6-digit pincode). Free-form addresses without these cues are missed, and place names alone (e.g. 'Jalandhar, Punjab') are not flagged by rules.
* **English-centric NER**; Hindi/Hinglish support is limited to regex rules and a few context words.
* **Masking changes meaning**; the model may answer less specifically. The UI says so.
* **Contextual confidentiality** ("our unreleased roadmap") cannot be found by patterns; only admin keywords help.
* **Not a prompt-injection defence** and not a complete data-loss-prevention system. Those are different problems.
* **Evaluation is on synthetic data** authored by the same person as the detectors; no public benchmark has been run.
* **Verification step** re-scans with rules only, so it protects pattern-based categories, not names.
* **Admin key** is a single shared secret, not per-user authentication. Run behind HTTPS in any real deployment.
* **PDF/DOCX parsing** handles text only (no OCR; scanned PDFs yield nothing); files are size-limited but parsers process untrusted input.

## Future work
React + Vite + Tailwind port of the UI; a small ML classifier for ambiguous contexts; public-benchmark evaluation (e.g. a PII NER dataset, with licence documented); prompt-injection heuristics as a separate module; per-user auth and organisation policy profiles; browser extension; OCR for scanned files.
