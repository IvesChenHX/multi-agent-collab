from __future__ import annotations

from pathlib import Path
from typing import Any

from mac.ids import is_identifier, prefixed
from mac.io import load_data
from mac.policy import ownership_source_path, policy_source_paths
from mac.repository import FilesystemTaskRepository, build_policy_ref, git_head, utc_now


class TaskService:
    def __init__(self, repo: Path, repository: FilesystemTaskRepository | None = None) -> None:
        self.repo = repo.resolve()
        self.repository = repository or FilesystemTaskRepository(self.repo)

    def create(
        self, *, title: str, mode: str, objective: str, acceptance: list[str], allowed_paths: list[str],
        owners: list[str], runtime_profile: str, required_gates: list[str], actor: dict[str, Any],
        idempotency_key: str, parent_task: str | None = None, supersedes: list[str] | None = None,
    ) -> dict[str, Any]:
        if mode not in {"standard", "high_risk", "audit"}:
            raise ValueError("persistent task mode must be standard, high_risk, or audit")
        if not acceptance or not allowed_paths or not owners:
            raise ValueError("acceptance, allowed_paths, and owners are required")
        if existing := self.repository.find_idempotency(idempotency_key):
            existing_id, _ = existing
            return {"task": self.repository.load_task(existing_id), "scope": load_data(self.repository.task_dir(existing_id) / "scope-contract.yaml"), "idempotent_replay": True}
        if parent_task is not None and not is_identifier(parent_task, "TASK"):
            raise ValueError("parent_task must be a safe TASK identifier")
        predecessor_ids = list(dict.fromkeys(supersedes or []))
        if any(not is_identifier(value, "TASK") for value in predecessor_ids):
            raise ValueError("every supersedes entry must be a safe TASK identifier")
        task_id, scope_id, now = prefixed("TASK", title), prefixed("SCOPE"), utc_now()
        config = load_data(self.repo / ".agents/config.yaml") if (self.repo / ".agents/config.yaml").is_file() else {
            "default_workflow": "evidence-driven-development",
            "default_runtime_profile": runtime_profile,
            "paths": {},
        }
        policy_ref = build_policy_ref(self.repo, list(policy_source_paths(config, runtime_profile)))
        ownership_ref = build_policy_ref(self.repo, [ownership_source_path(config)])
        task = {
            "schema_version": 6, "id": task_id, "title": title, "mode": mode, "state": "triage", "revision": 0,
            "created_at": now, "updated_at": now, "objective": objective,
            "acceptance_criteria": [{"id": f"AC-{index:03d}", "text": text, "required": True} for index, text in enumerate(acceptance, 1)],
            "policy_ref": policy_ref,
            "ownership_ref": ownership_ref,
            "scope_contract_ref": f"tasks/{task_id}/scope-contract.yaml", "runtime_profile": runtime_profile,
            "required_gates": list(dict.fromkeys(["approved_scope", *required_gates])), "active_controller": None,
            "relationships": {"parent_task": parent_task, "supersedes": predecessor_ids, "superseded_by": None}, "legacy_integrity": "full", "terminal": None,
        }
        scope = {
            "schema_version": 1, "id": scope_id, "task_id": task_id, "version": 1, "status": "proposed",
            "proposed_by": str(actor["id"]), "approved_by": [], "allowed_paths": allowed_paths, "denied_paths": [],
            "allowed_operations": ["read", "write", "execute_tests", "generate_artifacts"], "owners": owners,
            "risk_tags": [], "required_gates": required_gates, "network_access": "none", "secret_access": [],
            "amendment_policy": {"max_amendments": 2, "max_paths_per_amendment": 4, "require_independent_approval_for": ["auth_security", "production_deploy"]},
        }
        if base_commit := git_head(self.repo):
            scope["base_commit"] = base_commit
        created = self.repository.create_task(
            task,
            actor=actor,
            idempotency_key=idempotency_key,
            initial_entities=[("scope-contract.yaml", scope)],
        )
        return {"task": created.projection, "scope": scope, "idempotent_replay": created.idempotent_replay}
