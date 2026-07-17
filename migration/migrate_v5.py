#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from mac.migration import convert_v5, scan_v5


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only scan and idempotent v5 to v6 conversion")
    parser.add_argument("repo", type=Path)
    parser.add_argument("--scan", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    payload = scan_v5(args.repo) if args.scan and not args.apply else convert_v5(args.repo, output=args.output, dry_run=not args.apply)
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if args.report:
        args.report.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
