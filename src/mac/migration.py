from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

import yaml

from .ids import prefixed
from .io import atomic_write_json, atomic_write_yaml, load_data
from .repository import build_policy_ref, sha256_bytes, utc_now
from .events import replay_events
from .schema_validation import SchemaSet
from .ownership import OwnershipResolver


_V5_TASK_ID = re.compile(r"^TASK-[0-9]{4,}(?:-[a-z0-9][a-z0-9-]*)?$")


def _digest(path: Path) -> str | None:
    return sha256_bytes(path.read_bytes()) if path.is_file() else None


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
    warnings = []
    known_statuses = {"complete", "archived", "accepted_risk", "triage", "ready", "executing", "verifying", "reviewing", "fixing", "repairing", "blocked", "cancelled", "superseded", "failed"}
    for entry in entries:
        legacy_id = str(entry.get("id", ""))
        detail = root / "tasks" / legacy_id / "task.md"
        problems = []
        if not legacy_id:
            problems.append("missing_id")
        elif not _V5_TASK_ID.fullmatch(legacy_id):
            problems.append("illegal_id")
        elif legacy_id in seen:
            problems.append("duplicate_id")
        seen.add(legacy_id)
        if entry.get("status") == "blocked":
            problems.append("blocked_requires_manual_classification")
        if str(entry.get("status", "")) not in known_statuses:
            problems.append("unknown_status")
        if str(entry.get("status", "")) in {"complete", "archived", "accepted_risk"} and not entry.get("archived_at"):
            problems.append("terminal_timestamp_missing")
        if str(entry.get("status", "")) not in {"complete", "archived", "accepted_risk", "cancelled", "superseded", "failed"} and entry.get("archived_at"):
            problems.append("active_has_terminal_timestamp")
        rows.append({
            "legacy_id": legacy_id, "title": entry.get("title"), "status": entry.get("status"),
            "detail_present": detail.is_file(), "detail_digest": _digest(detail),
            "integrity": "partial" if detail.is_file() else "metadata_only",
            "verification_status": "unverifiable", "problems": problems,
            "source_path": detail.relative_to(root).as_posix() if detail.is_file() else "tasks/index.yaml",
            "source_digest": _digest(detail) or _digest(registry),
        })
    if not registry.is_file():
        warnings.append("tasks/index.yaml is missing")
    detail_directories = sorted(path.relative_to(root).as_posix() for path in (root / "tasks").glob("TASK-*") if path.is_dir()) if (root / "tasks").is_dir() else []
    config_path = root / ".agents/config.yaml"
    ownership_path = root / ".agents/ownership.yaml"
    missing_references: list[str] = []
    ownership_ambiguities: list[dict[str, Any]] = []
    try:
        config = load_data(config_path)
        workflow_id = config.get("default_workflow") or config.get("workflow")
        if workflow_id and not (root / ".agents/workflows" / f"{workflow_id}.yaml").is_file():
            missing_references.append(f"workflow:{workflow_id}")
    except Exception:
        config = {}
    try:
        ownership_data = load_data(ownership_path)
        for owner, definition in (ownership_data.get("owners") or {}).items():
            role = definition.get("implementation_role")
            if role and not (root / ".agents/agents" / f"{role}.md").is_file():
                missing_references.append(f"role:{role}")
            for pattern in definition.get("include", []):
                probe = str(pattern).replace("**", "probe").replace("*", "probe").rstrip("/") or "probe"
                match = OwnershipResolver(ownership_data).resolve(probe)
                if match.status == "ambiguous":
                    ownership_ambiguities.append({"path": probe, "owners": list(match.owners)})
    except Exception:
        ownership_data = {}
    sources = [{"path": "tasks/index.yaml", "digest": _digest(registry), "kind": "registry"}]
    sources.extend({"path": row["source_path"], "digest": row["source_digest"], "kind": "task_detail" if row["detail_present"] else "registry_entry", "legacy_id": row["legacy_id"]} for row in rows)
    warnings.extend(["Legacy completion metadata is not v6 Evidence.", "No Evidence is generated by migration."])
    return {
        "schema_version": 1, "repository": str(root), "registry": "tasks/index.yaml",
        "registry_schema_version": raw.get("schema_version"), "policy_schema_version": config.get("schema_version"),
        "registry_digest": _digest(registry), "task_count": len(rows), "tasks": rows, "visible_task_directories": detail_directories,
        "missing_references": sorted(set(missing_references)), "ownership_ambiguities": ownership_ambiguities,
        "source_entities": sources, "warnings": warnings,
        "scan_matrix": ["schema_version", "status_consistency", "terminal_timestamp", "detail_reference", "duplicate_or_illegal_id", "blocked_classification", "role_reference", "workflow_reference", "ownership_ambiguity", "source_path_and_digest"],
        "rollback": {"pre_migration_tag": "pre-v6-migration", "precondition": "create the tag before apply", "method": "git revert the migration commit or switch to pre-v6-migration; v5 inputs are never deleted", "v5_inputs_preserved": True},
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
    report = scan_v5(root)
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
            "policy_ref": policy, "ownership_ref": ownership, "scope_contract_ref": f"{target.relative_to(root).as_posix()}/{task_id}/scope-contract.yaml",
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
    rollback = {**report["rollback"], "generated_paths": [f"{target.relative_to(root).as_posix()}/{item['task_id']}" for item in actions if item["action"] in {"created", "would_create"}], "verification": ["confirm v5 paths are unchanged", "run mac validate against the v6 output", "compare migrated task count and legacy_id coverage"]}
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
