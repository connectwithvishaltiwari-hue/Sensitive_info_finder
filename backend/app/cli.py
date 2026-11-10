import argparse, json, sys
from .engine import Scanner, MODES


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Sensitive information scanner")
    ap.add_argument("text", nargs="?", help="text to scan (or use --file / stdin)")
    ap.add_argument("--file", help="UTF-8 text file to scan")
    ap.add_argument("--mode", choices=MODES, default="rules")
    ap.add_argument("--keyword", action="append", default=[],
                    help="custom confidential keyword (repeatable)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--show-values", action="store_true",
                    help="print the detected raw values (local debugging only)")
    a = ap.parse_args(argv)

    if a.file:
        text = open(a.file, encoding="utf-8").read()
    elif a.text is not None:
        text = a.text
    else:
        text = sys.stdin.read()

    result = Scanner(a.mode, a.keyword).scan(text)
    if a.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        return 0

    print(f"mode={result.mode}  overall_risk={result.overall_risk}  "
          f"latency={result.latency_ms:.1f} ms  findings={len(result.findings)}")
    for f in result.findings:
        val = f"  value={text[f.start:f.end]!r}" if a.show_values else ""
        print(f"  {f.entity_type:<22} [{f.start}:{f.end}] score={f.score:.2f} "
              f"risk={f.risk:<6} by {f.detector}{val}")
    print("\nSanitized text:\n" + result.sanitized_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
