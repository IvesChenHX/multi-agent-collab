from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

from .errors import ExitCode, MacError
from .ids import prefixed
from .io import atomic_write_json, atomic_write_yaml, load_data
from .repository import build_policy_ref, sha256_bytes, utc_now
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
            "digest": _digest(child),
        })
    return _entity_digest(manifest)


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


def _existing_legacy(output: Path) -> dict[str, str]:
    result = {}
    for path in output.glob("TASK-*/task.yaml") if output.is_dir() else []:
        try:
            item = load_data(path)
        except Exception:
            continue
        if item.get("legacy_id"):
            result[str(item["legacy_id"])] = str(item["id"])
    return result


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
    existing = _existing_legacy(target)
    policy = build_policy_ref(root, ["AGENTS.md", ".agents/config.yaml", ".agents/workflows/evidence-driven-development.yaml"])
    ownership = build_policy_ref(root, [".agents/ownership.yaml"])
    actions = []
    for scanned in report["tasks"]:
        legacy_id = scanned["legacy_id"]
        if legacy_id in existing:
            actions.append({"legacy_id": legacy_id, "task_id": existing[legacy_id], "action": "unchanged"})
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
        actions.append({"legacy_id": legacy_id, "task_id": task_id, "action": "would_create" if dry_run else "created", "source_path": scanned["source_path"], "source_digest": scanned["source_digest"]})
        if not dry_run:
            task_dir = target / task_id
            staging = target / f".{task_id}.{prefixed('TXN')}.tmp"
            staging.mkdir(parents=True, exist_ok=False)
            try:
                atomic_write_json(staging / "events" / f"{event_id}.json", event)
                atomic_write_yaml(staging / "scope-contract.yaml", scope)
                atomic_write_yaml(staging / "task.yaml", projection)
                os.replace(staging, task_dir)
            except BaseException:
                if staging.is_dir(): shutil.rmtree(staging)
                raise
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
