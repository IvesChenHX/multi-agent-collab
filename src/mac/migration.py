from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Mapping

import yaml

from .errors import ExitCode, MacError, MacIssue
from .ids import is_identifier, prefixed
from .io import atomic_write_json, atomic_write_yaml, load_data
from .repository import FilesystemTaskRepository, build_policy_ref, sha256_bytes, utc_now
from .events import replay_events
from .schema_validation import SchemaSet
from .ownership import OwnershipResolver


_V5_TASK_ID = re.compile(r"^TASK-[0-9]{4,}(?:-[a-z0-9][a-z0-9-]*)?$")
_REFERENCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_INVALID_SOURCE_PROBLEMS = {
    "invalid_entry", "missing_id", "illegal_id", "duplicate_id", "detail_path_unsafe",
}


def _digest(path: Path) -> str | None:
    return sha256_bytes(path.read_bytes()) if path.is_file() else None


def _portable_source_digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    content = path.read_bytes()
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        canonical = content
    else:
        canonical = content.replace(b"\r\n", b"\n")
    return sha256_bytes(canonical)


def _entity_digest(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(payload)


def _source_record(root: Path, path: Path, *, kind: str) -> dict[str, Any]:
    return {
        "path": path.relative_to(root).as_posix(),
        "kind": kind,
        "digest": _digest(path),
        "status": "present" if path.is_file() else "missing",
    }


def _directory_digest(path: Path) -> str | None:
    if not path.is_dir():
        return None
    manifest = []
    for child in sorted(item for item in path.rglob("*") if item.is_file()):
        manifest.append({
            "path": child.relative_to(path).as_posix(),
            "digest": _portable_source_digest(child),
        })
    return _entity_digest(manifest)


def scan_authorityless_v6(repo: Path, task_id: str) -> dict[str, Any]:
    """Classify one immutable v6 event stream without changing repository state."""

    root = repo.resolve()
    if not is_identifier(task_id, "TASK"):
        raise MacError(
            "MIGRATION_TASK_ID_INVALID",
            "authorityless v6 migration requires a safe Task identifier",
            exit_code=ExitCode.SECURITY,
            task_id=task_id or None,
        )
    repository = FilesystemTaskRepository(root)
    task_dir = repository.task_dir(task_id)
    if not task_dir.is_dir() or _is_link_like(task_dir):
        raise MacError(
            "MIGRATION_SOURCE_INVALID",
            "authorityless v6 migration source must be a real Task directory",
            exit_code=ExitCode.SECURITY,
            path=task_dir.relative_to(root).as_posix(),
            task_id=task_id,
        )
    try:
        repository.list_events(task_id)
    except MacError as exc:
        if exc.code != "EVENT_AUTHORITY_MISSING":
            raise
    else:
        return {
            "task_id": task_id,
            "eligible": False,
            "classification": None,
            "verification_status": "verified",
            "reason": None,
            "source_path": task_dir.relative_to(root).as_posix(),
            "source_digest": _directory_digest(task_dir),
            "planned_writes": [],
        }
    return {
        "task_id": task_id,
        "eligible": True,
        "classification": "metadata_only",
        "verification_status": "unverifiable",
        "reason": "EVENT_AUTHORITY_MISSING",
        "source_path": task_dir.relative_to(root).as_posix(),
        "source_digest": _directory_digest(task_dir),
        "planned_writes": [],
    }


def _authorityless_v6_identity(task_id: str) -> tuple[str, str, str]:
    source_ulid = task_id.split("-", 2)[1]
    return (
        f"TASK-{source_ulid}-legacy",
        f"SCOPE-{source_ulid}",
        f"EVT-{source_ulid}",
    )


def _authorityless_v6_result(
    scanned: dict[str, Any], *, action: str, migrated_task_id: str,
) -> dict[str, Any]:
    return {
        "task_id": scanned["task_id"],
        "action": action,
        "classification": scanned["classification"],
        "verification_status": scanned["verification_status"],
        "reason": scanned["reason"],
        "source_path": scanned["source_path"],
        "source_digest": scanned["source_digest"],
        "manifest_path": f"migration/v6-authorityless/{scanned['task_id']}.json",
        "migrated_task_id": migrated_task_id,
        "migrated_task_path": f"tasks-v6/{migrated_task_id}",
    }


def _authorityless_v6_manifest_matches(
    manifest: dict[str, Any], scanned: dict[str, Any], migrated_task_id: str,
) -> bool:
    expected = {
        "schema_version": 1,
        "kind": "authorityless_v6_migration",
        "source_task_id": scanned["task_id"],
        "source_path": scanned["source_path"],
        "source_digest": scanned["source_digest"],
        "classification": "metadata_only",
        "verification_status": "unverifiable",
        "reason": "EVENT_AUTHORITY_MISSING",
        "migrated_task_id": migrated_task_id,
        "migrated_task_path": f"tasks-v6/{migrated_task_id}",
    }
    return set(manifest) == {*expected, "recorded_at"} and all(
        manifest.get(key) == value for key, value in expected.items()
    ) and isinstance(manifest.get("recorded_at"), str)


def apply_authorityless_v6(
    repo: Path, task_id: str, *, expected_source_digest: str,
) -> dict[str, Any]:
    """Preserve an authorityless v6 stream and publish an unverifiable record."""

    root = repo.resolve()
    scanned = scan_authorityless_v6(root, task_id)
    if not scanned["eligible"]:
        raise MacError(
            "MIGRATION_SOURCE_NOT_ELIGIBLE",
            "v6 history with valid authority must not be downgraded by migration",
            exit_code=ExitCode.VALIDATION,
            task_id=task_id,
        )
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_source_digest or ""):
        raise MacError(
            "MIGRATION_SOURCE_DIGEST_REQUIRED",
            "apply requires the exact source digest returned by --scan",
            exit_code=ExitCode.CLI_USAGE,
            task_id=task_id,
        )
    if scanned["source_digest"] != expected_source_digest:
        raise MacError(
            "MIGRATION_SOURCE_CHANGED",
            "authorityless v6 source no longer matches the approved scan",
            exit_code=ExitCode.CONFLICT,
            task_id=task_id,
            details={"expected": expected_source_digest, "actual": scanned["source_digest"]},
        )

    migrated_task_id, scope_id, event_id = _authorityless_v6_identity(task_id)
    output_root = root / "tasks-v6"
    migrated_task_dir = output_root / migrated_task_id
    manifest_root = root / "migration" / "v6-authorityless"
    manifest_path = manifest_root / f"{task_id}.json"
    for path, code in (
        (output_root, "MIGRATION_OUTPUT_UNSAFE"),
        (manifest_root, "MIGRATION_MANIFEST_UNSAFE"),
    ):
        if path.exists() and (_is_link_like(path) or not path.is_dir()):
            raise MacError(
                code,
                "migration output must be a real repository directory",
                exit_code=ExitCode.SECURITY,
                path=path.relative_to(root).as_posix(),
            )

    source_binding = {**scanned, "legacy_id": task_id}
    output_exists = migrated_task_dir.exists() or _is_link_like(migrated_task_dir)
    if output_exists and not _existing_output_matches_source(migrated_task_dir, source_binding):
        raise MacError(
            "MIGRATION_EXISTING_PROVENANCE_MISMATCH",
            "existing authorityless migration output does not match the source",
            exit_code=ExitCode.CORRUPTION,
            path=migrated_task_dir.relative_to(root).as_posix(),
            task_id=task_id,
        )
    if manifest_path.exists() or _is_link_like(manifest_path):
        if _is_link_like(manifest_path) or not manifest_path.is_file():
            raise MacError(
                "MIGRATION_MANIFEST_UNSAFE",
                "authorityless migration manifest must be a real file",
                exit_code=ExitCode.SECURITY,
                path=manifest_path.relative_to(root).as_posix(),
            )
        try:
            manifest = load_data(manifest_path)
        except Exception as exc:
            raise MacError(
                "MIGRATION_MANIFEST_INVALID",
                "authorityless migration manifest is not valid structured data",
                exit_code=ExitCode.CORRUPTION,
                path=manifest_path.relative_to(root).as_posix(),
            ) from exc
        if not output_exists or not _authorityless_v6_manifest_matches(manifest, scanned, migrated_task_id):
            raise MacError(
                "MIGRATION_MANIFEST_PROVENANCE_MISMATCH",
                "authorityless migration manifest is not bound to the current source and output",
                exit_code=ExitCode.CORRUPTION,
                path=manifest_path.relative_to(root).as_posix(),
                task_id=task_id,
            )
        return _authorityless_v6_result(scanned, action="unchanged", migrated_task_id=migrated_task_id)

    timestamp = utc_now()
    if output_exists:
        try:
            existing_event = load_data(migrated_task_dir / "events" / f"{event_id}.json")
        except Exception as exc:
            raise MacError(
                "MIGRATION_EXISTING_PROVENANCE_MISMATCH",
                "existing authorityless migration event is not canonical",
                exit_code=ExitCode.CORRUPTION,
                path=migrated_task_dir.relative_to(root).as_posix(),
                task_id=task_id,
            ) from exc
        if (
            existing_event.get("event_id") != event_id
            or existing_event.get("event_type") != "legacy_imported"
            or not isinstance(existing_event.get("occurred_at"), str)
        ):
            raise MacError(
                "MIGRATION_EXISTING_PROVENANCE_MISMATCH",
                "existing authorityless migration event is not canonical",
                exit_code=ExitCode.CORRUPTION,
                path=migrated_task_dir.relative_to(root).as_posix(),
                task_id=task_id,
            )
        timestamp = existing_event["occurred_at"]
    if not output_exists:
        source_task = load_data(root / str(scanned["source_path"]) / "task.yaml")
        source_title = str(source_task.get("title") or task_id)
        task = {
            "schema_version": 6,
            "id": migrated_task_id,
            "legacy_id": task_id,
            "title": f"Authorityless v6 history: {source_title}"[:200],
            "mode": "standard",
            "state": "failed",
            "revision": 0,
            "created_at": timestamp,
            "updated_at": timestamp,
            "objective": "Preserve authorityless v6 metadata without claiming historical verification.",
            "acceptance_criteria": [{
                "id": "AC-001",
                "text": "Preserve source metadata and classify historical verification as unverifiable.",
                "required": False,
            }],
            "policy_ref": source_task["policy_ref"],
            "ownership_ref": source_task["ownership_ref"],
            "scope_contract_ref": f"tasks-v6/{migrated_task_id}/scope-contract.yaml",
            "runtime_profile": "legacy-import",
            "required_gates": [],
            "active_controller": None,
            "relationships": {"parent_task": None, "supersedes": [], "superseded_by": None},
            "legacy_integrity": "metadata_only",
            "terminal": {
                "closed_at": timestamp,
                "closed_by": "migration-automation",
                "summary": "Authorityless v6 history retained as unverifiable metadata.",
            },
        }
        scope = {
            "schema_version": 1,
            "id": scope_id,
            "task_id": migrated_task_id,
            "version": 1,
            "status": "approved",
            "proposed_by": "migration-automation",
            "approved_by": ["migration-automation"],
            "allowed_paths": ["legacy-unverifiable/**"],
            "denied_paths": [],
            "allowed_operations": ["read"],
            "owners": ["legacy-unassigned"],
            "risk_tags": ["legacy_unverifiable"],
            "required_gates": [],
            "network_access": "none",
            "secret_access": [],
            "amendment_policy": {
                "max_amendments": 0,
                "max_paths_per_amendment": 1,
                "require_independent_approval_for": [],
            },
        }
        event = {
            "schema_version": 1,
            "event_id": event_id,
            "task_id": migrated_task_id,
            "event_type": "legacy_imported",
            "occurred_at": timestamp,
            "actor": {"id": "migration-automation", "kind": "automation"},
            "run_id": None,
            "expected_revision": -1,
            "new_revision": 0,
            "idempotency_key": f"authorityless-v6-import:{task_id}:{expected_source_digest}",
            "payload": {
                "task": task,
                "legacy_id": task_id,
                "legacy_status": source_task.get("state"),
                "integrity": "metadata_only",
                "verification_status": "unverifiable",
                "source_path": scanned["source_path"],
                "source_digest": scanned["source_digest"],
            },
        }
        projection = replay_events([event])
        schemas = SchemaSet()
        issues = [
            *schemas.validate(projection, "task.schema.json", path=f"{migrated_task_id}/task.yaml"),
            *schemas.validate(scope, "scope-contract.schema.json", path=f"{migrated_task_id}/scope-contract.yaml"),
            *schemas.validate(event, "event.schema.json", path=f"{migrated_task_id}/events/{event_id}.json"),
        ]
        if issues:
            raise MacError(
                "MIGRATION_OUTPUT_INVALID",
                "authorityless migration output does not satisfy v6 schemas",
                exit_code=ExitCode.CORRUPTION,
                details={"issues": [item.as_dict() for item in issues]},
            )

        staging_root = root / f".m-{prefixed('TXN').split('-', 1)[1]}.tmp"
        staged_task = staging_root
        published = False
        try:
            staged_task.mkdir(exist_ok=False)
            atomic_write_json(staged_task / "events" / f"{event_id}.json", event)
            atomic_write_yaml(staged_task / "scope-contract.yaml", scope)
            atomic_write_yaml(staged_task / "task.yaml", projection)
            rescanned = scan_authorityless_v6(root, task_id)
            if rescanned["source_digest"] != expected_source_digest:
                raise MacError(
                    "MIGRATION_SOURCE_CHANGED",
                    "authorityless v6 source changed before publication",
                    exit_code=ExitCode.CONFLICT,
                    task_id=task_id,
                )
            output_root.mkdir(parents=True, exist_ok=True)
            if migrated_task_dir.exists() or _is_link_like(migrated_task_dir):
                raise MacError(
                    "MIGRATION_OUTPUT_CONFLICT",
                    "authorityless migration output appeared during publication",
                    exit_code=ExitCode.CONFLICT,
                    path=migrated_task_dir.relative_to(root).as_posix(),
                )
            os.replace(staged_task, migrated_task_dir)
            published = True
        except BaseException:
            if published and _existing_output_matches_source(migrated_task_dir, source_binding):
                shutil.rmtree(migrated_task_dir)
            raise
        finally:
            if staging_root.is_dir() and not _is_link_like(staging_root):
                shutil.rmtree(staging_root)

    manifest = {
        "schema_version": 1,
        "kind": "authorityless_v6_migration",
        "source_task_id": task_id,
        "source_path": scanned["source_path"],
        "source_digest": scanned["source_digest"],
        "classification": "metadata_only",
        "verification_status": "unverifiable",
        "reason": "EVENT_AUTHORITY_MISSING",
        "migrated_task_id": migrated_task_id,
        "migrated_task_path": f"tasks-v6/{migrated_task_id}",
        "recorded_at": timestamp,
    }
    atomic_write_json(manifest_path, manifest)
    return _authorityless_v6_result(scanned, action="created", migrated_task_id=migrated_task_id)


def _authorityless_v6_warning(manifest: Mapping[str, Any]) -> MacIssue:
    task_id = str(manifest["source_task_id"])
    return MacIssue(
        "LEGACY_TASK_UNVERIFIABLE",
        "authorityless v6 history is preserved as metadata and cannot prove historical verification",
        str(manifest["source_path"]),
        severity="warning",
        task_id=task_id,
        details={
            "source_format": "v6",
            "legacy_integrity": "metadata_only",
            "verification_status": "unverifiable",
            "reason": "EVENT_AUTHORITY_MISSING",
            "source_digest": manifest["source_digest"],
            "migration_record": f"migration/v6-authorityless/{task_id}.json",
            "migrated_task_id": manifest["migrated_task_id"],
        },
    )


def validate_authorityless_v6_migrations(
    repo: Path,
    issues: list[MacIssue],
    schema_set: SchemaSet,
) -> list[MacIssue]:
    """Replace only an exactly-bound authority error with an unverifiable warning."""

    root = repo.resolve()
    result = list(issues)
    manifest_root = root / "migration" / "v6-authorityless"
    if not manifest_root.exists():
        return result
    if not manifest_root.is_dir() or _is_link_like(manifest_root):
        result.append(MacIssue(
            "MIGRATION_MANIFEST_UNSAFE",
            "authorityless migration manifest root must be a real repository directory",
            "migration/v6-authorityless",
        ))
        return result
    trusted_schemas = schema_set if type(schema_set) is SchemaSet else SchemaSet()
    recognized: set[str] = set()
    for manifest_path in sorted(manifest_root.iterdir()):
        relative_manifest = manifest_path.relative_to(root).as_posix()
        if (
            manifest_path.suffix != ".json"
            or not manifest_path.is_file()
            or _is_link_like(manifest_path)
        ):
            result.append(MacIssue(
                "MIGRATION_MANIFEST_UNSAFE",
                "authorityless migration manifest entries must be real JSON files",
                relative_manifest,
            ))
            continue
        try:
            manifest = load_data(manifest_path)
        except Exception as exc:
            result.append(MacIssue("MIGRATION_MANIFEST_INVALID", str(exc), relative_manifest))
            continue
        task_id = str(manifest.get("source_task_id", ""))
        if task_id in recognized:
            result.append(MacIssue(
                "MIGRATION_MANIFEST_DUPLICATE",
                "authorityless v6 source has more than one migration manifest",
                relative_manifest,
                task_id=task_id or None,
            ))
            continue
        try:
            scanned = scan_authorityless_v6(root, task_id)
        except MacError as exc:
            result.append(MacIssue(
                exc.code,
                str(exc),
                exc.issue.path or f"tasks/{task_id}",
                task_id=exc.issue.task_id or task_id or None,
                details=exc.issue.details,
            ))
            continue
        migrated_task_id, _scope_id, event_id = _authorityless_v6_identity(task_id)
        if scanned["source_digest"] != manifest.get("source_digest"):
            result.append(MacIssue(
                "MIGRATION_SOURCE_CHANGED",
                "authorityless v6 source no longer matches its migration record",
                str(scanned["source_path"]),
                task_id=task_id,
                details={"expected": manifest.get("source_digest"), "actual": scanned["source_digest"]},
            ))
            continue
        if not _authorityless_v6_manifest_matches(manifest, scanned, migrated_task_id):
            result.append(MacIssue(
                "MIGRATION_MANIFEST_PROVENANCE_MISMATCH",
                "authorityless migration manifest is not canonical",
                relative_manifest,
                task_id=task_id or None,
            ))
            continue
        migrated_dir = root / "tasks-v6" / migrated_task_id
        expected_files = {
            "task.yaml",
            "scope-contract.yaml",
            f"events/{event_id}.json",
        }
        actual_files = {
            child.relative_to(migrated_dir).as_posix()
            for child in migrated_dir.rglob("*")
            if child.is_file() and not _is_link_like(child)
        } if migrated_dir.is_dir() and not _is_link_like(migrated_dir) else set()
        if actual_files != expected_files or not _existing_output_matches_source(
            migrated_dir, {**scanned, "legacy_id": task_id},
        ):
            result.append(MacIssue(
                "MIGRATION_OUTPUT_INVALID",
                "authorityless migration output is missing, unsafe, or not bound to its source",
                f"tasks-v6/{migrated_task_id}",
                task_id=task_id,
            ))
            continue
        output_issues: list[MacIssue] = []
        for filename, schema_name in (
            ("task.yaml", "task.schema.json"),
            ("scope-contract.yaml", "scope-contract.schema.json"),
            (f"events/{event_id}.json", "event.schema.json"),
        ):
            output_issues.extend(trusted_schemas.validate_file(
                migrated_dir / filename,
                schema_name,
                root=root,
            ))
        if output_issues:
            result.extend(output_issues)
            continue
        try:
            migrated_task = load_data(migrated_dir / "task.yaml")
            migrated_scope = load_data(migrated_dir / "scope-contract.yaml")
            migrated_event = load_data(migrated_dir / "events" / f"{event_id}.json")
            projection = replay_events([migrated_event])
        except Exception as exc:
            result.append(MacIssue(
                "MIGRATION_OUTPUT_INVALID",
                str(exc),
                f"tasks-v6/{migrated_task_id}",
                task_id=task_id,
            ))
            continue
        payload = migrated_event.get("payload")
        structurally_bound = bool(
            isinstance(payload, Mapping)
            and set(payload) == {
                "task", "legacy_id", "legacy_status", "integrity",
                "verification_status", "source_path", "source_digest",
            }
            and migrated_task == projection
            and migrated_event.get("event_id") == event_id
            and migrated_event.get("task_id") == migrated_task_id
            and migrated_event.get("event_type") == "legacy_imported"
            and migrated_event.get("actor") == {"id": "migration-automation", "kind": "automation"}
            and migrated_event.get("run_id") is None
            and migrated_event.get("expected_revision") == -1
            and migrated_event.get("new_revision") == 0
            and migrated_event.get("occurred_at") == manifest.get("recorded_at")
            and migrated_task.get("legacy_id") == task_id
            and migrated_task.get("legacy_integrity") == "metadata_only"
            and migrated_task.get("state") == "failed"
            and migrated_task.get("scope_contract_ref") == f"tasks-v6/{migrated_task_id}/scope-contract.yaml"
            and migrated_scope.get("task_id") == migrated_task_id
            and migrated_scope.get("allowed_operations") == ["read"]
            and payload.get("task") == migrated_task
            and payload.get("legacy_id") == task_id
            and payload.get("integrity") == "metadata_only"
            and payload.get("verification_status") == "unverifiable"
            and payload.get("source_path") == scanned["source_path"]
            and payload.get("source_digest") == scanned["source_digest"]
        )
        task_errors = [
            item for item in result
            if item.task_id == task_id and item.severity == "error"
        ]
        if not structurally_bound or not task_errors or any(
            item.code != "EVENT_AUTHORITY_MISSING" for item in task_errors
        ):
            result.append(MacIssue(
                "MIGRATION_OUTPUT_PROVENANCE_MISMATCH",
                "authorityless migration cannot replace errors beyond the exact missing-authority condition",
                f"tasks-v6/{migrated_task_id}",
                task_id=task_id,
            ))
            continue
        result = [
            item for item in result
            if not (
                item.task_id == task_id
                and item.severity == "error"
                and item.code == "EVENT_AUTHORITY_MISSING"
            )
        ]
        result.append(_authorityless_v6_warning(manifest))
        recognized.add(task_id)
    return result


def _verify_sources(root: Path, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matrix: list[dict[str, Any]] = []
    for item in records:
        path = root / str(item["path"])
        actual = _digest(path)
        expected = item.get("digest")
        matrix.append({
            "check": "source_unchanged",
            "path": item["path"],
            "expected_digest": expected,
            "actual_digest": actual,
            "status": "verified" if expected is not None and actual == expected else "mismatch",
        })
    return matrix


def _resolve_git_ref(root: Path, ref: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", f"{ref}^{{commit}}"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip() or None


def _safe_reference_path(root: Path, directory: str, reference: str, suffix: str) -> Path | None:
    if not _REFERENCE_ID.fullmatch(reference):
        return None
    return root / directory / f"{reference}{suffix}"


def _is_link_like(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(os.path, "isjunction", None)
        return bool(is_junction is not None and is_junction(path))
    except OSError:
        return True


def _safe_legacy_detail(root: Path, legacy_id: str) -> Path | None:
    if not _V5_TASK_ID.fullmatch(legacy_id):
        return None
    tasks = root / "tasks"
    if _is_link_like(tasks):
        return None
    task_dir = tasks / legacy_id
    detail = task_dir / "task.md"
    if _is_link_like(task_dir) or _is_link_like(detail):
        return None
    try:
        resolved_tasks = tasks.resolve(strict=False)
        resolved_detail = detail.resolve(strict=False)
        resolved_detail.relative_to(resolved_tasks)
    except (OSError, ValueError):
        return None
    return detail


def map_v5_state(status: str, *, blocked_kind: str | None = None) -> str:
    if status == "blocked":
        return {"input": "waiting_input", "external": "waiting_external", "failed": "failed"}.get(blocked_kind or "", "failed")
    return {
        "complete": "completed", "archived": "completed", "accepted_risk": "completed_with_risk",
        "triage": "triage", "ready": "ready", "executing": "executing", "verifying": "verifying",
        "reviewing": "reviewing", "fixing": "repairing", "repairing": "repairing",
        "cancelled": "cancelled", "superseded": "superseded", "failed": "failed",
    }.get(status, "failed")


def scan_v5(repo: Path) -> dict[str, Any]:
    """Read-only v5 inventory. The function performs no mkdir, cache, or report write."""
    root = repo.resolve()
    registry = root / "tasks/index.yaml"
    raw = load_data(registry) if registry.is_file() else {}
    entries = raw.get("tasks", []) if isinstance(raw, dict) else []
    seen: set[str] = set()
    rows = []
    status_matrix: list[dict[str, Any]] = []
    warnings = []
    known_statuses = {"complete", "archived", "accepted_risk", "triage", "ready", "executing", "verifying", "reviewing", "fixing", "repairing", "blocked", "cancelled", "superseded", "failed"}
    registry_digest = _digest(registry)
    for entry_index, source_entry in enumerate(entries):
        entry = source_entry if isinstance(source_entry, dict) else {}
        legacy_id = str(entry.get("id", ""))
        problems = []
        if not isinstance(source_entry, dict):
            problems.append("invalid_entry")
        if not legacy_id:
            problems.append("missing_id")
        elif not _V5_TASK_ID.fullmatch(legacy_id):
            problems.append("illegal_id")
        elif legacy_id in seen:
            problems.append("duplicate_id")
        seen.add(legacy_id)
        detail = _safe_legacy_detail(root, legacy_id)
        if legacy_id and _V5_TASK_ID.fullmatch(legacy_id) and detail is None:
            problems.append("detail_path_unsafe")
        if entry.get("status") == "blocked":
            problems.append("blocked_requires_manual_classification")
        if str(entry.get("status", "")) not in known_statuses:
            problems.append("unknown_status")
        if str(entry.get("status", "")) in {"complete", "archived", "accepted_risk"} and not entry.get("archived_at"):
            problems.append("terminal_timestamp_missing")
        if str(entry.get("status", "")) not in {"complete", "archived", "accepted_risk", "cancelled", "superseded", "failed"} and entry.get("archived_at"):
            problems.append("active_has_terminal_timestamp")
        source_refs = [{
            "path": "tasks/index.yaml",
            "selector": f"tasks[{entry_index}]",
            "document_digest": registry_digest,
            "entity_digest": _entity_digest(source_entry),
        }]
        detail_present = detail is not None and detail.is_file()
        detail_digest = _digest(detail) if detail_present and detail is not None else None
        if detail_present and detail is not None:
            source_refs.append({
                "path": detail.relative_to(root).as_posix(),
                "selector": None,
                "document_digest": detail_digest,
                "entity_digest": detail_digest,
            })
        mapped_state = map_v5_state(str(entry.get("status", "")))
        status_matrix.append({
            "legacy_id": legacy_id,
            "source_status": entry.get("status"),
            "mapped_state": mapped_state,
            "recognized": str(entry.get("status", "")) in known_statuses,
            "manual_classification_required": entry.get("status") == "blocked",
            "problems": list(problems),
        })
        rows.append({
            "legacy_id": legacy_id, "title": entry.get("title"), "status": entry.get("status"),
            "detail_present": detail_present, "detail_digest": detail_digest,
            "integrity": "partial" if detail_present else "metadata_only",
            "verification_status": "unverifiable", "problems": problems,
            "source_path": detail.relative_to(root).as_posix() if detail_present and detail is not None else "tasks/index.yaml",
            "source_digest": detail_digest or _entity_digest(source_entry),
            "source_refs": source_refs,
        })
    if not registry.is_file():
        warnings.append("tasks/index.yaml is missing")
    detail_directories = sorted(
        path.relative_to(root).as_posix()
        for path in (root / "tasks").glob("TASK-*")
        if not _is_link_like(path) and path.is_dir()
    ) if not _is_link_like(root / "tasks") and (root / "tasks").is_dir() else []
    config_path = root / ".agents/config.yaml"
    ownership_path = root / ".agents/ownership.yaml"
    missing_references: list[str] = []
    reference_checks: list[dict[str, Any]] = []
    ownership_ambiguities: list[dict[str, Any]] = []
    source_documents = [_source_record(root, registry, kind="registry")]
    source_documents.extend(
        _source_record(root, root / reference["path"], kind="task_detail")
        for row in rows
        for reference in row["source_refs"]
        if reference["selector"] is None
    )
    try:
        config = load_data(config_path)
        workflow_id = config.get("default_workflow") or config.get("workflow")
        if workflow_id:
            workflow_ref = str(workflow_id)
            target = _safe_reference_path(root, ".agents/workflows", workflow_ref, ".yaml")
            status = "invalid" if target is None else ("resolved" if target.is_file() else "missing")
            target_path = f".agents/workflows/{workflow_ref}.yaml" if target is not None else None
            reference_checks.append({
                "kind": "workflow",
                "reference": workflow_ref,
                "source_path": ".agents/config.yaml",
                "source_digest": _digest(config_path),
                "target_path": target_path,
                "target_digest": _digest(target) if target is not None else None,
                "status": status,
            })
            if status != "resolved":
                missing_references.append(f"workflow:{workflow_ref}")
            elif target is not None:
                source_documents.append(_source_record(root, target, kind="workflow"))
    except Exception as exc:
        config = {}
        warnings.append(f".agents/config.yaml is invalid: {type(exc).__name__}")
    source_documents.append(_source_record(root, config_path, kind="config"))
    try:
        ownership_data = load_data(ownership_path)
        for owner, definition in (ownership_data.get("owners") or {}).items():
            role = definition.get("implementation_role")
            if role:
                role_ref = str(role)
                target = _safe_reference_path(root, ".agents/agents", role_ref, ".md")
                status = "invalid" if target is None else ("resolved" if target.is_file() else "missing")
                target_path = f".agents/agents/{role_ref}.md" if target is not None else None
                reference_checks.append({
                    "kind": "role",
                    "owner": str(owner),
                    "reference": role_ref,
                    "source_path": ".agents/ownership.yaml",
                    "source_digest": _digest(ownership_path),
                    "target_path": target_path,
                    "target_digest": _digest(target) if target is not None else None,
                    "status": status,
                })
                if status != "resolved":
                    missing_references.append(f"role:{role_ref}")
                elif target is not None:
                    source_documents.append(_source_record(root, target, kind="role"))
            for pattern in definition.get("include", []):
                probe = str(pattern).replace("**", "probe").replace("*", "probe").rstrip("/") or "probe"
                try:
                    match = OwnershipResolver(ownership_data).resolve(probe)
                except Exception as exc:
                    ownership_ambiguities.append({
                        "path": probe, "owners": [], "status": "invalid_pattern", "error": type(exc).__name__,
                    })
                    continue
                if match.status == "ambiguous":
                    ownership_ambiguities.append({
                        "path": probe, "owners": list(match.owners), "status": "ambiguous",
                    })
    except Exception as exc:
        ownership_data = {}
        warnings.append(f".agents/ownership.yaml is invalid: {type(exc).__name__}")
    source_documents.append(_source_record(root, ownership_path, kind="ownership"))
    deduplicated_documents = {
        (item["path"], item["kind"]): item for item in source_documents
    }
    source_documents = sorted(deduplicated_documents.values(), key=lambda item: (item["path"], item["kind"]))
    sources = []
    for row in rows:
        for reference in row["source_refs"]:
            sources.append({
                "path": reference["path"],
                "selector": reference["selector"],
                "digest": reference["document_digest"],
                "entity_digest": reference["entity_digest"],
                "kind": "task_detail" if reference["selector"] is None else "registry_entry",
                "legacy_id": row["legacy_id"],
            })
    pre_migration_commit = _resolve_git_ref(root, "refs/tags/pre-v6-migration")
    rollback_matrix = [{
        "check": "pre_migration_ref",
        "ref": "refs/tags/pre-v6-migration",
        "expected_commit": pre_migration_commit,
        "status": "verified" if pre_migration_commit else "missing",
    }]
    rollback_matrix.extend({
        "check": "source_unchanged",
        "path": item["path"],
        "expected_digest": item["digest"],
        "status": "captured" if item["digest"] else "missing",
    } for item in source_documents)
    warnings.extend(["Legacy completion metadata is not v6 Evidence.", "No Evidence is generated by migration."])
    return {
        "schema_version": 1, "repository": str(root), "registry": "tasks/index.yaml",
        "registry_schema_version": raw.get("schema_version"), "policy_schema_version": config.get("schema_version"),
        "registry_digest": registry_digest, "task_count": len(rows), "tasks": rows, "visible_task_directories": detail_directories,
        "status_matrix": status_matrix, "reference_checks": reference_checks,
        "missing_references": sorted(set(missing_references)), "ownership_ambiguities": ownership_ambiguities,
        "source_documents": source_documents, "source_entities": sources, "warnings": warnings,
        "scan_matrix": ["schema_version", "status_consistency", "terminal_timestamp", "detail_reference", "duplicate_or_illegal_id", "blocked_classification", "role_reference", "workflow_reference", "ownership_ambiguity", "source_path_and_digest"],
        "rollback": {
            "pre_migration_tag": "pre-v6-migration",
            "precondition": "create the tag before apply",
            "precondition_satisfied": pre_migration_commit is not None,
            "method": "git revert the migration commit or switch to pre-v6-migration; v5 inputs are never deleted",
            "v5_inputs_preserved": True,
            "verification_matrix": rollback_matrix,
        },
    }


def _existing_legacy(output: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for path in output.glob("TASK-*/task.yaml") if output.is_dir() else []:
        try:
            item = load_data(path)
        except Exception:
            continue
        if item.get("legacy_id"):
            result[str(item["legacy_id"])] = path.parent
    return result


def _existing_output_matches_source(task_dir: Path, scanned: dict[str, Any]) -> bool:
    """Accept an idempotent migration output only when its source is still bound.

    A failed conversion can leave a published directory only when a process dies
    after a per-directory rename.  Never treat its legacy_id alone as proof that
    it is a valid prior conversion: the immutable import event must bind the
    exact source path and digest observed by the current scan.
    """
    if _is_link_like(task_dir) or not task_dir.is_dir():
        return False
    task_path = task_dir / "task.yaml"
    events = task_dir / "events"
    if _is_link_like(task_path) or _is_link_like(events) or not task_path.is_file() or not events.is_dir():
        return False
    try:
        task = load_data(task_path)
    except Exception:
        return False
    imported: list[dict[str, Any]] = []
    for event_path in events.glob("*.json"):
        if _is_link_like(event_path) or not event_path.is_file():
            return False
        try:
            event = load_data(event_path)
        except Exception:
            return False
        if event.get("event_type") == "legacy_imported":
            imported.append(event)
    if len(imported) != 1:
        return False
    payload = imported[0].get("payload") or {}
    return (
        task.get("legacy_id") == scanned["legacy_id"]
        and imported[0].get("task_id") == task.get("id")
        and payload.get("legacy_id") == scanned["legacy_id"]
        and payload.get("source_path") == scanned["source_path"]
        and payload.get("source_digest") == scanned["source_digest"]
    )


def _remove_published_outputs(paths: list[tuple[Path, str]], target: Path) -> None:
    """Best-effort rollback of only directories atomically published by this call."""
    for path, digest in reversed(paths):
        try:
            if path.parent != target or _is_link_like(path) or not path.is_dir():
                continue
            if _directory_digest(path) != digest:
                continue
            shutil.rmtree(path)
        except OSError:
            continue


def convert_v5(
    repo: Path, *, output: Path | None = None, dry_run: bool = True,
    blocked_classification: dict[str, str] | None = None,
) -> dict[str, Any]:
    root = repo.resolve()
    target = (output or (root / "tasks-v6")).resolve()
    try:
        target_path = target.relative_to(root)
    except ValueError as exc:
        raise MacError(
            "MIGRATION_OUTPUT_OUTSIDE_REPOSITORY",
            "migration output must be contained within the repository",
            exit_code=ExitCode.SECURITY,
            path=str(target),
        ) from exc
    if target_path == Path("."):
        raise MacError(
            "MIGRATION_OUTPUT_INVALID",
            "migration output must be a repository subdirectory",
            exit_code=ExitCode.VALIDATION,
            path=str(target),
        )
    target_relative = target_path.as_posix()
    report = scan_v5(root)
    invalid_rows = [
        {
            "legacy_id": row["legacy_id"],
            "problems": sorted(_INVALID_SOURCE_PROBLEMS.intersection(row["problems"])),
        }
        for row in report["tasks"]
        if _INVALID_SOURCE_PROBLEMS.intersection(row["problems"])
    ]
    if invalid_rows:
        raise MacError(
            "MIGRATION_SOURCE_INVALID",
            "legacy migration source contains invalid or duplicate task rows",
            exit_code=ExitCode.SECURITY,
            path="tasks/index.yaml",
            details={"rows": invalid_rows},
        )
    source_verification = _verify_sources(root, report["source_documents"])
    if any(item["status"] != "verified" for item in source_verification):
        raise RuntimeError("legacy migration source changed or is missing")
    registry = load_data(root / "tasks/index.yaml")
    by_id = {str(item.get("id")): item for item in registry.get("tasks", [])}
    if target.exists() and (_is_link_like(target) or not target.is_dir()):
        raise MacError(
            "MIGRATION_OUTPUT_UNSAFE",
            "migration output root must be a real directory",
            exit_code=ExitCode.SECURITY,
            path=str(target),
        )
    existing = _existing_legacy(target)
    policy = build_policy_ref(root, ["AGENTS.md", ".agents/config.yaml", ".agents/workflows/evidence-driven-development.yaml"])
    ownership = build_policy_ref(root, [".agents/ownership.yaml"])
    actions = []
    candidates: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    for scanned in report["tasks"]:
        legacy_id = scanned["legacy_id"]
        if legacy_id in existing:
            task_dir = existing[legacy_id]
            if not _existing_output_matches_source(task_dir, scanned):
                raise MacError(
                    "MIGRATION_EXISTING_PROVENANCE_MISMATCH",
                    "existing migration output is not bound to the current legacy source",
                    exit_code=ExitCode.CORRUPTION,
                    path=task_dir.relative_to(root).as_posix(),
                    details={"legacy_id": legacy_id, "source_path": scanned["source_path"], "source_digest": scanned["source_digest"]},
                )
            actions.append({"legacy_id": legacy_id, "task_id": task_dir.name, "action": "unchanged"})
            continue
        entry = by_id[legacy_id]
        task_id, scope_id, event_id = prefixed("TASK", str(entry.get("title") or legacy_id)), prefixed("SCOPE"), prefixed("EVT")
        timestamp = str(entry.get("archived_at") or utc_now())
        state = map_v5_state(str(entry.get("status", "")), blocked_kind=(blocked_classification or {}).get(legacy_id))
        task = {
            "schema_version": 6, "id": task_id, "legacy_id": legacy_id, "title": str(entry.get("title") or legacy_id),
            "mode": "standard", "state": state, "revision": 0, "created_at": timestamp, "updated_at": timestamp,
            "objective": str(entry.get("summary") or "Imported legacy task metadata; historical verification is unverifiable."),
            "acceptance_criteria": [{"id": "AC-001", "text": "Preserve legacy metadata without claiming historical verification.", "required": False}],
            "policy_ref": policy, "ownership_ref": ownership, "scope_contract_ref": f"{target_relative}/{task_id}/scope-contract.yaml",
            "runtime_profile": "legacy-import", "required_gates": [], "active_controller": None,
            "relationships": {"parent_task": None, "supersedes": [], "superseded_by": None},
            "legacy_integrity": scanned["integrity"],
            "terminal": ({"closed_at": timestamp, "closed_by": "migration-automation", "summary": str(entry.get("summary") or f"Imported legacy {entry.get('status')}")} if state in {"completed", "completed_with_risk", "failed", "cancelled", "superseded"} else None),
        }
        scope = {
            "schema_version": 1, "id": scope_id, "task_id": task_id, "version": 1, "status": "approved",
            "proposed_by": "migration-automation", "approved_by": ["migration-automation"], "allowed_paths": ["legacy-unverifiable/**"],
            "denied_paths": [], "allowed_operations": ["read"], "owners": ["legacy-unassigned"],
            "risk_tags": ["legacy_unverifiable"], "required_gates": [], "network_access": "none", "secret_access": [],
            "amendment_policy": {"max_amendments": 0, "max_paths_per_amendment": 1, "require_independent_approval_for": []},
        }
        event = {
            "schema_version": 1, "event_id": event_id, "task_id": task_id, "event_type": "legacy_imported",
            "occurred_at": timestamp, "actor": {"id": "migration-automation", "kind": "automation"}, "run_id": None,
            "expected_revision": -1, "new_revision": 0, "idempotency_key": f"legacy-import:{legacy_id}",
            "payload": {"task": task, "legacy_id": legacy_id, "legacy_status": entry.get("status"), "integrity": scanned["integrity"], "verification_status": "unverifiable", "source_path": scanned["source_path"], "source_digest": scanned["source_digest"]},
        }
        projection = replay_events([event])
        schema_set = SchemaSet()
        validation = [
            *schema_set.validate(projection, "task.schema.json", path=f"{task_id}/task.yaml"),
            *schema_set.validate(scope, "scope-contract.schema.json", path=f"{task_id}/scope-contract.yaml"),
            *schema_set.validate(event, "event.schema.json", path=f"{task_id}/events/{event_id}.json"),
        ]
        if validation:
            raise ValueError(f"migration output is invalid: {validation[0].message}")
        action = {"legacy_id": legacy_id, "task_id": task_id, "action": "would_create", "source_path": scanned["source_path"], "source_digest": scanned["source_digest"]}
        actions.append(action)
        candidates.append((action, event, scope, projection))

    if dry_run:
        source_verification = _verify_sources(root, report["source_documents"])
        if any(item["status"] != "verified" for item in source_verification):
            raise RuntimeError("legacy migration source changed during conversion")
    elif candidates:
        staging_root = target.parent / f".{target.name}.{prefixed('TXN')}.tmp"
        staging_root.mkdir(parents=True, exist_ok=False)
        published: list[tuple[Path, str]] = []
        published_root = False
        try:
            for action, event, scope, projection in candidates:
                staged_task = staging_root / str(action["task_id"])
                staged_task.mkdir()
                atomic_write_json(staged_task / "events" / f"{event['event_id']}.json", event)
                atomic_write_yaml(staged_task / "scope-contract.yaml", scope)
                atomic_write_yaml(staged_task / "task.yaml", projection)
            source_verification = _verify_sources(root, report["source_documents"])
            if any(item["status"] != "verified" for item in source_verification):
                raise RuntimeError("legacy migration source changed before publication")
            if not target.exists():
                os.replace(staging_root, target)
                published_root = True
                for action, _event, _scope, _projection in candidates:
                    task_dir = target / str(action["task_id"])
                    published.append((task_dir, _directory_digest(task_dir) or ""))
            else:
                for action, _event, _scope, _projection in candidates:
                    task_dir = target / str(action["task_id"])
                    if task_dir.exists() or _is_link_like(task_dir):
                        raise MacError("MIGRATION_OUTPUT_CONFLICT", "migration output appeared during publication", exit_code=ExitCode.CONFLICT, path=str(task_dir))
                    os.replace(staging_root / str(action["task_id"]), task_dir)
                    published.append((task_dir, _directory_digest(task_dir) or ""))
            source_verification = _verify_sources(root, report["source_documents"])
            if any(item["status"] != "verified" for item in source_verification):
                raise RuntimeError("legacy migration source changed during publication")
            for action, _event, _scope, _projection in candidates:
                action["action"] = "created"
        except BaseException:
            _remove_published_outputs(published, target)
            if published_root:
                try:
                    if target.exists() and not _is_link_like(target) and target.is_dir() and not any(target.iterdir()):
                        target.rmdir()
                except OSError:
                    pass
            raise
        finally:
            if staging_root.is_dir() and not _is_link_like(staging_root):
                shutil.rmtree(staging_root)
    source_verification = _verify_sources(root, report["source_documents"])
    if any(item["status"] != "verified" for item in source_verification):
        raise RuntimeError("legacy migration source changed during conversion")
    generated_outputs = []
    for item in actions:
        if item["action"] not in {"created", "would_create"}:
            continue
        relative = f"{target_relative}/{item['task_id']}"
        generated_outputs.append({
            "path": relative,
            "action": item["action"],
            "digest": _directory_digest(root / relative) if item["action"] == "created" else None,
            "rollback_action": "revert the migration commit; never delete v5 inputs",
            "status": "materialized" if item["action"] == "created" else "planned",
        })
    pre_ref = report["rollback"]["verification_matrix"][0]
    rollback = {
        **report["rollback"],
        "verification_matrix": [pre_ref, *source_verification],
        "generated_outputs": generated_outputs,
        "generated_paths": [item["path"] for item in generated_outputs],
        "verification": [
            "confirm every source_unchanged row is verified",
            "run mac validate against the v6 output",
            "compare migrated task count and legacy_id coverage",
        ],
    }
    return {"ok": True, "dry_run": dry_run, "output": str(target), "actions": actions, "created": sum(item["action"] == "created" for item in actions), "unverifiable_evidence_created": 0, "rollback": rollback}


def list_tasks_dual(repo: Path, *, v6_root: Path | None = None) -> list[dict[str, Any]]:
    root = repo.resolve()
    v6 = (v6_root or (root / "tasks-v6")).resolve()
    rows = []
    imported: set[str] = set()
    for path in sorted(v6.glob("TASK-*/task.yaml")) if v6.is_dir() else []:
        item = load_data(path)
        row = {**item, "source_format": "v6"}
        if item.get("legacy_id") and item.get("legacy_integrity") in {"partial", "metadata_only"}:
            row["verification_status"] = "unverifiable"
        rows.append(row)
        if item.get("legacy_id"): imported.add(str(item["legacy_id"]))
    for item in scan_v5(root)["tasks"]:
        if item["legacy_id"] not in imported:
            rows.append({
                "id": item["legacy_id"], "legacy_id": item["legacy_id"], "title": item["title"],
                "state": map_v5_state(str(item["status"])), "source_format": "v5-read-only",
                "legacy_integrity": item["integrity"], "verification_status": item["verification_status"],
            })
    return rows
