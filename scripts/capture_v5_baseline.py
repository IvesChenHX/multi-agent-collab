#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_PATHS = ["AGENTS.md", ".agents/config.yaml", ".agents/ownership.yaml", ".agents/workflows/evidence-driven-development.yaml"]


class BaselineCaptureError(RuntimeError):
    pass


def _resolve_commit(root: Path, source_ref: str) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "--end-of-options", f"{source_ref}^{{commit}}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise BaselineCaptureError(f"source ref does not resolve to a commit: {source_ref}") from exc


def _read_ref_file(root: Path, commit: str, relative: str) -> bytes:
    try:
        return subprocess.run(
            ["git", "-C", str(root), "show", f"{commit}:{relative}"],
            check=True,
            capture_output=True,
        ).stdout
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise BaselineCaptureError(f"file not found at source commit: {relative}") from exc


def capture_baseline(repo: Path, *, paths: list[str] | None = None, source_ref: str | None = None) -> dict[str, Any]:
    root = repo.resolve()
    if source_ref is not None:
        source_commit = _resolve_commit(root, source_ref)
    else:
        try:
            source_commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
        except (FileNotFoundError, subprocess.CalledProcessError):
            source_commit = None
    rows = []
    for relative in paths or DEFAULT_PATHS:
        normalized = Path(relative).as_posix()
        if source_ref is not None:
            content = _read_ref_file(root, source_commit, normalized)
            rows.append({"path": normalized, "present": True, "digest": "sha256:" + hashlib.sha256(content).hexdigest()})
        else:
            path = root / relative
            rows.append({"path": normalized, "present": path.is_file(), "digest": ("sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()) if path.is_file() else None})
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    result = {
        "schema_version": 1, "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_commit": source_commit, "recommended_tag": "pre-v6-migration", "files": rows,
        "combined_digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
    }
    if source_ref is not None:
        result["requested_ref"] = source_ref
    return result


def verify_baseline(repo: Path, manifest: dict[str, Any]) -> bool:
    requested_ref = manifest.get("requested_ref")
    source_commit = manifest.get("source_commit") if requested_ref is not None else None
    if requested_ref is not None and not isinstance(source_commit, str):
        return False
    try:
        current = capture_baseline(repo, paths=[str(item["path"]) for item in manifest.get("files", [])], source_ref=source_commit)
    except BaselineCaptureError:
        return False
    return current["files"] == manifest.get("files") and current["combined_digest"] == manifest.get("combined_digest")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo", type=Path, nargs="?", default=Path("."))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source-ref")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        manifest = json.loads(args.out.read_text(encoding="utf-8"))
        return 0 if verify_baseline(args.repo, manifest) else 1
    try:
        payload = capture_baseline(args.repo, source_ref=args.source_ref)
    except BaselineCaptureError as exc:
        parser.exit(2, f"baseline capture failed: {exc}\n")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
