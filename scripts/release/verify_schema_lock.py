"""Verify the executable schema bundle before packaging artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys


def verify(root: Path) -> list[str]:
    lock_path = root / ".agents" / "schemas.lock.json"
    schema_dir = root / "schemas"
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        records = lock["files"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        return [f"invalid schema lock: {exc}"]
    expected = {Path(str(item["path"])).name: str(item["sha256"]) for item in records}
    actual_names = {path.name for path in schema_dir.glob("*.json") if path.is_file()}
    issues = []
    if set(expected) != actual_names:
        issues.append(f"schema set mismatch: lock={sorted(expected)} files={sorted(actual_names)}")
    for name in sorted(set(expected) & actual_names):
        digest = "sha256:" + hashlib.sha256((schema_dir / name).read_bytes()).hexdigest()
        if digest != expected[name]:
            issues.append(f"schema digest mismatch: {name}")
    return issues


def main() -> int:
    issues = verify(Path(".").resolve())
    if issues:
        print("\n".join(issues), file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
