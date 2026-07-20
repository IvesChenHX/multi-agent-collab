from __future__ import annotations

import json
import hashlib
from functools import lru_cache
from importlib import resources
import os
from pathlib import Path
import re
import stat
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

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def canonical_schema_bytes(content: bytes) -> bytes:
    """Return the cross-platform byte representation frozen by the schema lock.

    Schemas are UTF-8 JSON text tracked by Git.  Git may materialize the same
    blob with CRLF on Windows, so hashing checkout bytes directly makes a lock
    depend on ``core.autocrlf`` rather than on repository content.
    """
    text = content.decode("utf-8")
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def schema_digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(canonical_schema_bytes(content)).hexdigest()


def _is_link_or_reparse(path_stat: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(path_stat.st_mode) or bool(
        getattr(path_stat, "st_file_attributes", 0) & reparse_flag
    )


def _lexical_absolute(root: Path, path: Path) -> Path:
    candidate = path if path.is_absolute() else root / path
    return Path(os.path.abspath(candidate))


def _repository_path_issue(root: Path, path: Path, display_path: str) -> MacIssue | None:
    candidate = _lexical_absolute(root, path)
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return MacIssue(
            "SCHEMA_PATH_OUTSIDE_REPO",
            f"schema integrity path is outside the repository: {candidate}",
            display_path,
        )
    current = root
    for part in relative.parts:
        current /= part
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            return MacIssue("SCHEMA_PATH_INVALID", str(exc), display_path)
        if _is_link_or_reparse(current_stat):
            return MacIssue(
                "SCHEMA_PATH_UNSAFE_LINK",
                f"schema integrity path traverses a symlink or reparse point: {current}",
                display_path,
            )
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        return MacIssue(
            "SCHEMA_PATH_OUTSIDE_REPO",
            f"schema integrity path does not resolve within the repository: {candidate}",
            display_path,
            details={"reason": str(exc)},
        )
    return None


def _path_exists_without_following(path: Path) -> bool:
    try:
        path.lstat()
    except OSError:
        return False
    return True


def schema_lock_issues(repo_root: Path, schema_dir: Path | None = None) -> list[MacIssue]:
    """Verify that the executable schemas are exactly the files frozen by the lock."""
    root = repo_root.resolve()
    schemas = _lexical_absolute(root, schema_dir or root / "schemas")
    lock_path = root / ".agents/schemas.lock.json"
    relative_lock = ".agents/schemas.lock.json"
    if issue := _repository_path_issue(root, schemas, "schemas"):
        return [issue]
    if issue := _repository_path_issue(root, lock_path, relative_lock):
        return [issue]
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
        if record["path"] != f"schemas/{name}" or name not in SCHEMA_NAMES:
            return [MacIssue("SCHEMA_LOCK_PATH_INVALID", f"schema lock path is not canonical: {record['path']}", relative_lock)]
        if not _DIGEST.fullmatch(record["sha256"]):
            return [MacIssue("SCHEMA_LOCK_DIGEST_INVALID", f"invalid schema digest for {name}", relative_lock)]
        if name in expected:
            return [MacIssue("SCHEMA_LOCK_DUPLICATE", f"duplicate schema lock entry: {name}", relative_lock)]
        expected[name] = record["sha256"]
    issues: list[MacIssue] = []
    actual_paths: dict[str, Path] = {}
    for path in schemas.glob("*.json"):
        display_path = f"schemas/{path.name}"
        if issue := _repository_path_issue(root, path, display_path):
            return [issue]
        if path.is_file():
            actual_paths[path.name] = path
    actual_names = set(actual_paths)
    for name in sorted(SCHEMA_NAMES - expected.keys()):
        issues.append(MacIssue("SCHEMA_LOCK_ENTRY_MISSING", f"lock omits {name}", relative_lock))
    for name in sorted(expected.keys() - SCHEMA_NAMES):
        issues.append(MacIssue("SCHEMA_LOCK_ENTRY_UNKNOWN", f"lock includes unknown schema {name}", relative_lock))
    for name in sorted(SCHEMA_NAMES - actual_names):
        issues.append(MacIssue("SCHEMA_FILE_MISSING", f"schema file is missing: {name}", f"schemas/{name}"))
    for name in sorted(actual_names - SCHEMA_NAMES):
        issues.append(MacIssue("SCHEMA_FILE_UNKNOWN", f"unlocked schema file: {name}", f"schemas/{name}"))
    for name in sorted(SCHEMA_NAMES & actual_names & expected.keys()):
        try:
            schema_path = actual_paths[name]
            before = schema_path.lstat()
            content = schema_path.read_bytes()
            after = schema_path.lstat()
            if _is_link_or_reparse(after) or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                issues.append(MacIssue("SCHEMA_PATH_CHANGED", f"schema changed while being read: {name}", f"schemas/{name}"))
                continue
            digest = schema_digest(content)
        except (OSError, UnicodeError) as exc:
            issues.append(MacIssue("SCHEMA_FILE_INVALID", str(exc), f"schemas/{name}"))
            continue
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
    if _path_exists_without_following(source_lock):
        return source_lock
    packaged_lock = schema_root.parent / "schemas.lock.json"
    return packaged_lock if _path_exists_without_following(packaged_lock) else None


def _enforce_default_lock(schema_root: Path) -> None:
    lock_path = _default_lock_path(schema_root)
    if lock_path is None:
        raise ValueError("schema lock is missing")
    boundary = schema_root.parent.resolve()
    for path, display_path in ((schema_root, "schemas"), (lock_path, "schemas.lock.json")):
        if issue := _repository_path_issue(boundary, path, display_path):
            raise ValueError(f"unsafe schema integrity path: {issue.message}")
    lock = load_data(lock_path)
    records = lock.get("files")
    if not isinstance(records, list):
        raise ValueError("schema lock files must be an array")
    expected: dict[str, str] = {}
    for item in records:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not isinstance(item.get("sha256"), str):
            raise ValueError("schema lock entries require path and sha256")
        name = Path(item["path"]).name
        if item["path"] != f"schemas/{name}" or name in expected or not _DIGEST.fullmatch(item["sha256"]):
            raise ValueError(f"invalid schema lock entry: {item!r}")
        expected[name] = item["sha256"]
    if set(expected) != SCHEMA_NAMES:
        raise ValueError("schema lock does not exactly cover the executable schemas")
    actual_paths: dict[str, Path] = {}
    for path in schema_root.glob("*.json"):
        if issue := _repository_path_issue(boundary, path, f"schemas/{path.name}"):
            raise ValueError(f"unsafe schema integrity path: {issue.message}")
        if path.is_file():
            actual_paths[path.name] = path
    if set(actual_paths) != SCHEMA_NAMES:
        raise ValueError("schema directory does not exactly match the schema lock")
    for name in sorted(SCHEMA_NAMES):
        digest = schema_digest(actual_paths[name].read_bytes())
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
        records.append({"path": f"schemas/{name}", "sha256": schema_digest(content)})
    atomic_write_json(repo_root.resolve() / ".agents/schemas.lock.json", {"schema_version": 1, "generated_from": "schemas", "files": records})


@lru_cache(maxsize=32)
def _compile_schema_bundle(
    root_text: str,
    lock_digest: str,
) -> tuple[dict[str, dict[str, Any]], Registry, dict[str, Draft202012Validator]]:
    """Compile an integrity-checked schema bundle once per immutable lock digest."""

    del lock_digest  # It is deliberately part of the cache key.
    root = Path(root_text)
    schemas = {
        name: json.loads((root / name).read_text(encoding="utf-8"))
        for name in sorted(SCHEMA_NAMES)
    }
    missing = SCHEMA_NAMES - schemas.keys()
    if missing:
        raise ValueError(f"missing schemas: {', '.join(sorted(missing))}")
    registry = Registry()
    for name, schema in schemas.items():
        Draft202012Validator.check_schema(schema)
        resource = Resource.from_contents(schema)
        registry = registry.with_resource(schema["$id"], resource).with_resource(name, resource)
    validators = {
        name: Draft202012Validator(
            schema,
            registry=registry,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        )
        for name, schema in schemas.items()
    }
    return schemas, registry, validators


class SchemaSet:
    def __init__(self, schema_dir: Path | None = None) -> None:
        root = schema_dir or _default_schema_dir()
        _enforce_default_lock(root)
        lock_path = _default_lock_path(root)
        if lock_path is None:
            raise ValueError("schema lock is missing")
        lock_digest = schema_digest(lock_path.read_bytes())
        self.schemas, self.registry, self.validators = _compile_schema_bundle(
            str(root.resolve()),
            lock_digest,
        )
        missing = SCHEMA_NAMES - self.schemas.keys()
        if missing:
            raise ValueError(f"missing schemas: {', '.join(sorted(missing))}")

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
