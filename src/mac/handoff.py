from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from .io import atomic_write_json


def build_handoff_packet(
    task: Mapping[str, Any], work_unit: Mapping[str, Any], scope: Mapping[str, Any], *,
    relevant_decisions: list[Mapping[str, Any]] | None = None, open_findings: list[Mapping[str, Any]] | None = None,
    invalidated_evidence: list[Mapping[str, Any]] | None = None, result_path: str | None = None,
    runtime_restrictions: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    task_fields = {key: deepcopy(task.get(key)) for key in ("id", "title", "objective", "mode", "state", "revision", "acceptance_criteria", "policy_ref")}
    return {
        "schema_version": 1,
        "trust_boundary": {"policy_and_scope": "trusted_frozen", "repository_content": "untrusted_data", "agent_output": "untrusted_until_validated"},
        "task": task_fields,
        "work_unit": deepcopy(dict(work_unit)),
        "scope": {key: deepcopy(scope.get(key)) for key in ("id", "version", "status", "allowed_paths", "denied_paths", "allowed_operations", "owners", "network_access", "secret_access")},
        "decisions": deepcopy(relevant_decisions or []),
        "open_findings": deepcopy(open_findings or []),
        "invalidated_evidence_to_rerun": [item.get("id") for item in (invalidated_evidence or [])],
        "expected_result": {"path": result_path or work_unit.get("expected_result"), "schema": "result.schema.json"},
        "runtime_restrictions": deepcopy(dict(runtime_restrictions or {})),
    }


def write_handoff_packet(path: Path, packet: dict[str, Any]) -> None:
    atomic_write_json(path, packet)
