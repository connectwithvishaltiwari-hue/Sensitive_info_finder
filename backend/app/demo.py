from .engine import Scanner
from .samples import SAMPLES, sample_passes


def main() -> int:
    scanners, failed, skipped = {}, 0, 0
    for s in SAMPLES:
        try:
            if s.mode not in scanners:
                scanners[s.mode] = Scanner(s.mode)
            sc = scanners[s.mode]
        except Exception as exc:  # e.g. spaCy model missing
            skipped += 1
            print(f"SKIP  {s.id:<22} ({s.mode} unavailable: {exc})")
            continue
        res = sc.scan(s.text)
        got = {f.entity_type for f in res.findings}
        ok = sample_passes(s, got)
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {s.id:<22} expected={sorted(s.expect)} got={sorted(got)}")
        print(f"      sanitized: {res.sanitized_text!r}")
    ran = len(SAMPLES) - skipped
    print(f"\n{ran - failed} / {ran} passed, {failed} failed, {skipped} skipped")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
