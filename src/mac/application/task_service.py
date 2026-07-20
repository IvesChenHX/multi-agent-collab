from __future__ import annotations

from pathlib import Path
from typing import Any

from mac.ids import is_identifier, prefixed
from mac.io import load_data
from mac.policy import ownership_source_path, policy_source_paths
from mac.repository import (
    CreateTask,
    FilesystemTaskRepository,
    MutationGateway,
    build_policy_ref,
    git_head,
    utc_now,
)


class TaskService:
    def __init__(
        self,
        repo: Path,
        repository: FilesystemTaskRepository | None = None,
        gateway: MutationGateway | None = None,
    ) -> None:
        self.repo = repo.resolve()
        self.repository = repository or FilesystemTaskRepository(self.repo)
        self.mutations = gateway or MutationGateway(self.repo, repository=self.repository)

    def create(
        self, *, title: str, mode: str, objective: str, acceptance: list[str], allowed_paths: list[str],
        owners: list[str], runtime_profile: str, required_gates: list[str], actor: dict[str, Any],
        idempotency_key: str, parent_task: str | None = None, supersedes: list[str] | None = None,
        allowed_operations: list[str] | None = None,
    ) -> dict[str, Any]:
        if mode not in {"standard", "high_risk", "audit"}:
            raise ValueError("persistent task mode must be standard, high_risk, or audit")
        if not acceptance or not allowed_paths or not owners:
            raise ValueError("acceptance, allowed_paths, and owners are required")
        if parent_task is not None and not is_identifier(parent_task, "TASK"):
            raise ValueError("parent_task must be a safe TASK identifier")
        predecessor_ids = list(dict.fromkeys(supersedes or []))
        operations = list(dict.fromkeys(
            ["read", "write", "execute_tests", "generate_artifacts"]
            if allowed_operations is None
            else allowed_operations
        ))
        if not operations:
            raise ValueError("allowed_operations must not be empty")
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
            "allowed_operations": operations, "owners": owners,
            "risk_tags": [], "required_gates": required_gates, "network_access": "none", "secret_access": [],
            "amendment_policy": {"max_amendments": 2, "max_paths_per_amendment": 4, "require_independent_approval_for": ["auth_security", "production_deploy"]},
        }
        if base_commit := git_head(self.repo):
            scope["base_commit"] = base_commit
        replay_intent = {
            "title": title,
            "mode": mode,
            "objective": objective,
            "acceptance": list(acceptance),
            "allowed_paths": list(allowed_paths),
            "allowed_operations": list(operations),
            "owners": list(owners),
            "runtime_profile": runtime_profile,
            "required_gates": list(required_gates),
            "parent_task": parent_task,
            "supersedes": predecessor_ids,
        }
        created = self.mutations.execute(
            CreateTask(
                task=task,
                initial_entities=(("scope-contract.yaml", scope),),
                actor_claim=actor,
                idempotency_key=idempotency_key,
                replay_intent=replay_intent,
            )
        )
        stored_task = dict(created.projection)
        stored_scope = load_data(self.repository.task_dir(str(stored_task["id"])) / "scope-contract.yaml")
        return {"task": stored_task, "scope": stored_scope, "idempotent_replay": created.idempotent_replay}
