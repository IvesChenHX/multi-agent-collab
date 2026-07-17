"""Run the v6 governance checks for a pull request base/head pair."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any

import yaml


_TASK_DIRECTORY = re.compile(r"^tasks/(?P<directory>TASK-(?P<ulid>[0-9A-HJKMNP-TV-Z]{26})(?:-[^/]+)?)/")
_TASK_ID = re.compile(r"^TASK-[0-9A-HJKMNP-TV-Z]{26}(?:-[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?)?$")
_LEVEL = re.compile(r"^\s*governance_level\s*:\s*(observe|advisory|enforced|regulated)\s*$", re.MULTILINE)


def _git_changed_paths(base: str, head: str) -> list[str]:
    completed = subprocess.run(
        ["git", "diff", "--name-only", "-z", f"{base}...{head}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git diff failed: {message}")
    return [item.decode("utf-8") for item in completed.stdout.split(b"\0") if item]


def discover_task_ids(paths: list[str], explicit: list[str]) -> list[str]:
    task_ids = set(explicit)
    for path in paths:
        normalized = PurePosixPath(path.replace("\\", "/")).as_posix()
        match = _TASK_DIRECTORY.match(normalized)
        if match:
            task_ids.add(match.group("directory"))
    invalid = sorted(identifier for identifier in task_ids if not _TASK_ID.fullmatch(identifier))
    if invalid:
        raise ValueError(f"invalid v6 task identifiers: {', '.join(invalid)}")
    return sorted(task_ids)


def read_governance_level(config: Path) -> str:
    override = os.environ.get("MAC_GOVERNANCE_LEVEL", "").strip()
    if override:
        if override not in {"observe", "advisory", "enforced", "regulated"}:
            raise ValueError(f"invalid MAC_GOVERNANCE_LEVEL: {override!r}")
        return override
    text = config.read_text(encoding="utf-8")
    match = _LEVEL.search(text)
    if not match:
        raise ValueError(f"governance_level is missing from {config}")
    return match.group(1)


def _run(argv: list[str]) -> dict[str, Any]:
    completed = subprocess.run(argv, check=False, text=True, encoding="utf-8", capture_output=True)
    parsed: object = None
    if completed.stdout.strip():
        try:
            parsed = json.loads(completed.stdout)
        except json.JSONDecodeError:
            parsed = None
    return {
        "argv": argv,
        "exit_code": completed.returncode,
        "output": parsed,
        "stdout": completed.stdout.strip() if parsed is None else None,
        "stderr": completed.stderr.strip() or None,
    }


def _resolve_commit(ref: str) -> tuple[str, str]:
    commit = subprocess.run(["git", "rev-parse", f"{ref}^{{commit}}"], check=False, text=True, encoding="utf-8", capture_output=True)
    tree = subprocess.run(["git", "rev-parse", f"{ref}^{{tree}}"], check=False, text=True, encoding="utf-8", capture_output=True)
    if commit.returncode or tree.returncode:
        raise RuntimeError(f"cannot resolve Evidence target {ref}")
    return commit.stdout.strip().lower(), tree.stdout.strip().lower()


_TASK_METADATA_FILES = {"task.yaml", "scope-contract.yaml", "report.md"}
_TASK_METADATA_DIRECTORIES = {"approvals", "events", "evidence", "findings", "private", "results", "risk-acceptances", "runs", "scope-history", "work-units"}


def _is_task_metadata(path: str, task_directory: str) -> bool:
    prefix = f"tasks/{task_directory}/"
    if not path.startswith(prefix):
        return False
    relative = path[len(prefix):]
    first, separator, remainder = relative.partition("/")
    return relative in _TASK_METADATA_FILES or bool(separator and remainder and first in _TASK_METADATA_DIRECTORIES)


def _current_code_commit(ref: str, task_directory: str) -> tuple[str, str]:
    cursor, _ = _resolve_commit(ref)
    while True:
        ancestry = subprocess.run(["git", "rev-list", "--parents", "-n", "1", cursor], check=False, text=True, encoding="utf-8", capture_output=True)
        values = ancestry.stdout.strip().split()
        if ancestry.returncode or len(values) < 2:
            return _resolve_commit(cursor)
        parent = values[1]
        changed = subprocess.run(["git", "diff", "--name-only", "-z", parent, cursor], check=False, capture_output=True)
        if changed.returncode:
            raise RuntimeError(f"cannot inspect code subject {cursor}")
        paths = [value.decode("utf-8") for value in changed.stdout.split(b"\0") if value]
        if any(not _is_task_metadata(path, task_directory) for path in paths):
            return _resolve_commit(cursor)
        cursor = parent


def check_current_evidence(repo: Path, task_directory: str, head: str) -> dict[str, Any]:
    """Fail unless valid Evidence covers every required claim at the exact PR head."""
    task_dir = repo / "tasks" / task_directory
    task_path = task_dir / "task.yaml"
    if not task_path.is_file():
        return {"argv": ["evidence-gate", task_directory], "exit_code": 7, "output": {"ok": False, "error": "task.yaml is missing"}, "stdout": None, "stderr": None}
    task = yaml.safe_load(task_path.read_text(encoding="utf-8"))
    commit_sha, tree_sha = _current_code_commit(head, task_directory)
    required = {str(value) for value in task.get("required_gates", [])}
    required.update(str(item["id"]) for item in task.get("acceptance_criteria", []) if item.get("required"))
    policy_digest = str((task.get("policy_ref") or {}).get("combined_digest", ""))
    runs: dict[str, dict[str, Any]] = {}
    for path in sorted((task_dir / "runs").glob("*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        runs[str(value.get("id"))] = value
    covered: set[str] = set()
    accepted_ids: list[str] = []
    rejected: dict[str, list[str]] = {}
    for path in sorted((task_dir / "evidence").glob("*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        reasons: list[str] = []
        subject = value.get("subject") or {}
        if value.get("validity", {}).get("status") != "valid" or value.get("validity", {}).get("invalidated_by"):
            reasons.append("invalid status")
        if subject != {"type": "commit", "commit_sha": commit_sha, "tree_sha": tree_sha}:
            reasons.append("not bound to PR head commit/tree")
        if value.get("policy_digest") != policy_digest:
            reasons.append("policy digest mismatch")
        run_id = value.get("run_id")
        if value.get("kind") != "manual" and (not run_id or runs.get(str(run_id), {}).get("status") != "succeeded"):
            reasons.append("run missing or unsuccessful")
        if value.get("kind") in {"command", "ci", "static_analysis", "deployment"} and (value.get("execution") or {}).get("exit_code") != 0:
            reasons.append("execution failed")
        evidence_id = str(value.get("id", path.stem))
        if reasons:
            rejected[evidence_id] = reasons
            continue
        accepted_ids.append(evidence_id)
        for claim in value.get("claims", []):
            covered.update(str(claim[key]) for key in ("gate", "acceptance_criterion") if claim.get(key))
    missing = sorted(required - covered)
    ok = not missing
    return {
        "argv": ["evidence-gate", task_directory, head],
        "exit_code": 0 if ok else 7,
        "output": {"ok": ok, "task_directory": task_directory, "head_commit": commit_sha, "accepted_evidence": accepted_ids, "rejected_evidence": rejected, "covered": sorted(covered), "missing": missing},
        "stdout": None,
        "stderr": None,
    }


def evaluate(level: str, checks: list[dict[str, Any]], task_ids: list[str]) -> tuple[bool, int]:
    failed = any(check["exit_code"] != 0 for check in checks)
    missing_task = not task_ids
    if level in {"observe", "advisory"}:
        return True, 0
    if missing_task:
        return False, 7
    if failed:
        nonzero = next(int(check["exit_code"]) for check in checks if check["exit_code"] != 0)
        return False, nonzero if 1 < nonzero <= 20 else 20
    return True, 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--task-id", action="append", default=[])
    parser.add_argument("--config", type=Path, default=Path(".agents/config.yaml"))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    explicit = list(args.task_id)
    explicit.extend(
        item for item in re.split(r"[,\s]+", os.environ.get("MAC_TASK_IDS", "")) if item
    )
    try:
        level = read_governance_level(args.config)
        changed_paths = _git_changed_paths(args.base, args.head)
        task_ids = discover_task_ids(changed_paths, explicit)
        checks = [_run(["mac", "validate", "--json"])]
        checks.extend(
            _run(
                [
                    "mac",
                    "scope",
                    "check",
                    task_id,
                    "--base",
                    args.base,
                    "--head",
                    args.head,
                    "--json",
                ]
            )
            for task_id in task_ids
        )
        checks.extend(check_current_evidence(Path("."), task_id, args.head) for task_id in task_ids)
        ok, exit_code = evaluate(level, checks, task_ids)
        report = {
            "ok": ok,
            "governance_level": level,
            "base": args.base,
            "head": args.head,
            "task_ids": task_ids,
            "changed_path_count": len(changed_paths),
            "checks": checks,
            "warnings": (
                ["No v6 task was associated with this PR; set MAC_TASK_IDS or commit task metadata."]
                if not task_ids
                else []
            ),
        }
    except (OSError, RuntimeError, ValueError) as exc:
        report = {
            "ok": False,
            "error": {"code": "CI_GOVERNANCE_INTERNAL", "message": str(exc)},
        }
        exit_code = 20
    if args.json:
        print(json.dumps(report, ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
