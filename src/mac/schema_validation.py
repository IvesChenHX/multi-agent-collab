from __future__ import annotations

import json
import hashlib
from importlib import resources
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from .errors import ExitCode, MacError, MacIssue
from .io import load_data

SCHEMA_NAMES = {
    "approval.schema.json",
    "common.schema.json",
    "config.schema.json",
    "event.schema.json",
    "evidence.schema.json",
    "finding.schema.json",
    "ownership.schema.json",
    "result.schema.json",
    "risk-acceptance.schema.json",
    "run.schema.json",
    "runtime-profile.schema.json",
    "scope-contract.schema.json",
    "task.schema.json",
    "workflow.schema.json",
    "work-unit.schema.json",
}


def schema_lock_issues(repo_root: Path, schema_dir: Path | None = None) -> list[MacIssue]:
    """Verify that the executable schemas are exactly the files frozen by the lock."""
    root = repo_root.resolve()
    schemas = (schema_dir or root / "schemas").resolve()
    lock_path = root / ".agents/schemas.lock.json"
    relative_lock = ".agents/schemas.lock.json"
    if not lock_path.is_file():
        return [MacIssue("SCHEMA_LOCK_MISSING", "schema lock is required", relative_lock)]
    try:
        lock = load_data(lock_path)
    except Exception as exc:
        return [MacIssue("SCHEMA_LOCK_INVALID", str(exc), relative_lock)]
    records = lock.get("files") if isinstance(lock, dict) else None
    if not isinstance(records, list):
        return [MacIssue("SCHEMA_LOCK_INVALID", "files must be an array", relative_lock)]
    expected: dict[str, str] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str) or not isinstance(record.get("sha256"), str):
            return [MacIssue("SCHEMA_LOCK_INVALID", "every lock entry requires path and sha256", relative_lock)]
        name = Path(record["path"]).name
        if name in expected:
            return [MacIssue("SCHEMA_LOCK_DUPLICATE", f"duplicate schema lock entry: {name}", relative_lock)]
        expected[name] = record["sha256"]
    issues: list[MacIssue] = []
    actual_names = {path.name for path in schemas.glob("*.json") if path.is_file()}
    for name in sorted(SCHEMA_NAMES - expected.keys()):
        issues.append(MacIssue("SCHEMA_LOCK_ENTRY_MISSING", f"lock omits {name}", relative_lock))
    for name in sorted(expected.keys() - SCHEMA_NAMES):
        issues.append(MacIssue("SCHEMA_LOCK_ENTRY_UNKNOWN", f"lock includes unknown schema {name}", relative_lock))
    for name in sorted(SCHEMA_NAMES - actual_names):
        issues.append(MacIssue("SCHEMA_FILE_MISSING", f"schema file is missing: {name}", f"schemas/{name}"))
    for name in sorted(actual_names - SCHEMA_NAMES):
        issues.append(MacIssue("SCHEMA_FILE_UNKNOWN", f"unlocked schema file: {name}", f"schemas/{name}"))
    for name in sorted(SCHEMA_NAMES & actual_names & expected.keys()):
        digest = "sha256:" + hashlib.sha256((schemas / name).read_bytes()).hexdigest()
        if digest != expected[name]:
            issues.append(MacIssue("SCHEMA_LOCK_MISMATCH", f"digest mismatch for {name}", f"schemas/{name}", details={"expected": expected[name], "actual": digest}))
    return issues


def require_schema_lock(repo_root: Path, schema_dir: Path | None = None) -> None:
    """Fail closed when a repository schema bundle differs from its lock."""
    issues = schema_lock_issues(repo_root, schema_dir)
    if not issues:
        return
    issue = issues[0]
    raise MacError(
        issue.code,
        issue.message,
        exit_code=ExitCode.VALIDATION,
        path=issue.path,
        field=issue.field,
        details={"issues": [item.as_dict() for item in issues]},
    )


def _default_lock_path(schema_root: Path) -> Path | None:
    source_lock = schema_root.parent / ".agents/schemas.lock.json"
    if source_lock.is_file():
        return source_lock
    packaged_lock = schema_root.parent / "schemas.lock.json"
    return packaged_lock if packaged_lock.is_file() else None


def _enforce_default_lock(schema_root: Path) -> None:
    lock_path = _default_lock_path(schema_root)
    if lock_path is None:
        raise ValueError("schema lock is missing")
    lock = load_data(lock_path)
    expected = {Path(str(item["path"])).name: str(item["sha256"]) for item in lock.get("files", [])}
    if set(expected) != SCHEMA_NAMES:
        raise ValueError("schema lock does not exactly cover the executable schemas")
    for name in sorted(SCHEMA_NAMES):
        digest = "sha256:" + hashlib.sha256((schema_root / name).read_bytes()).hexdigest()
        if digest != expected[name]:
            raise ValueError(f"schema lock mismatch: {name}")


def _default_schema_dir() -> Path:
    source_root = Path(__file__).resolve().parents[2] / "schemas"
    if source_root.is_dir():
        return source_root
    packaged = resources.files("mac").joinpath("schemas")
    return Path(str(packaged))


def require_executable_schema_lock() -> None:
    """Verify the source/installed executable schema bundle before CLI dispatch."""
    root = _default_schema_dir()
    try:
        _enforce_default_lock(root)
    except (OSError, TypeError, ValueError) as exc:
        raise MacError(
            "SCHEMA_LOCK_MISMATCH",
            str(exc),
            exit_code=ExitCode.VALIDATION,
            path=str(_default_lock_path(root) or "schemas.lock.json"),
        ) from exc


def install_schema_bundle(repo_root: Path) -> None:
    """Materialize the versioned executable schemas and their exact digest lock."""
    from .io import atomic_write_json, atomic_write_text

    source = _default_schema_dir()
    target = repo_root.resolve() / "schemas"
    records: list[dict[str, str]] = []
    for name in sorted(SCHEMA_NAMES):
        content = (source / name).read_bytes()
        atomic_write_text(target / name, content.decode("utf-8"))
        records.append({"path": f"schemas/{name}", "sha256": "sha256:" + hashlib.sha256(content).hexdigest()})
    atomic_write_json(repo_root.resolve() / ".agents/schemas.lock.json", {"schema_version": 1, "generated_from": "schemas", "files": records})


class SchemaSet:
    def __init__(self, schema_dir: Path | None = None) -> None:
        root = schema_dir or _default_schema_dir()
        if schema_dir is None:
            _enforce_default_lock(root)
        self.schemas = {
            path.name: json.loads(path.read_text(encoding="utf-8")) for path in sorted(root.glob("*.json"))
        }
        missing = SCHEMA_NAMES - self.schemas.keys()
        if missing:
            raise ValueError(f"missing schemas: {', '.join(sorted(missing))}")
        registry = Registry()
        for name, schema in self.schemas.items():
            Draft202012Validator.check_schema(schema)
            resource = Resource.from_contents(schema)
            registry = registry.with_resource(schema["$id"], resource).with_resource(name, resource)
        self.registry = registry
        self.validators = {
            name: Draft202012Validator(schema, registry=self.registry, format_checker=Draft202012Validator.FORMAT_CHECKER)
            for name, schema in self.schemas.items()
        }

    def validate(self, data: dict[str, Any], schema_name: str, *, path: str) -> list[MacIssue]:
        if schema_name not in self.schemas:
            return [MacIssue("SCHEMA_UNKNOWN", f"unknown schema {schema_name}", path)]
        validator = self.validators[schema_name]
        issues: list[MacIssue] = []
        errors = sorted(validator.iter_errors(data), key=lambda item: (list(item.absolute_path), item.message))
        for error in errors:
            field = ".".join(str(part) for part in error.absolute_path) or None
            issues.append(MacIssue("SCHEMA_INVALID", error.message, path, field))
        return issues

    def validate_file(self, path: Path, schema_name: str, *, root: Path) -> list[MacIssue]:
        relative = path.resolve().relative_to(root.resolve()).as_posix()
        try:
            data = load_data(path)
        except Exception as exc:  # diagnostics aggregate parser errors by design
            return [MacIssue("PARSE_ERROR", str(exc), relative)]
        return self.validate(data, schema_name, path=relative)
