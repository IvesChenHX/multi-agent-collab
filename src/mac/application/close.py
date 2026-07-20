from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from mac.authority import owner_approvers, valid_scope_approvals, verified_entity_ids
from mac.errors import MacIssue
from mac.git import GitRepository
from mac.io import load_data
from mac.ownership import OwnershipResolver
from mac.policy import CompiledPolicy, compile_policy
from mac.schema_validation import SchemaSet
from mac.scope import check_changes

from .governance import CloseDecision, evaluate_close


def _load_many(task_dir: Path, directory: str) -> list[dict[str, Any]]:
    suffix = "yaml" if directory == "work-units" else "json"
    return [load_data(path) for path in sorted((task_dir / directory).glob(f"*.{suffix}"))]


def evaluate_repository_close(
    repo: Path, task_id: str, close_actor: str, *, compiled_policy: CompiledPolicy | None = None,
) -> CloseDecision:
    """Recompute every Close input from current repository state."""

    root = repo.resolve()
    task_dir = root / "tasks" / task_id
    persisted_task = load_data(task_dir / "task.yaml")
    task = deepcopy(persisted_task)
    scope = load_data(task_dir / "scope-contract.yaml")
    evidence = _load_many(task_dir, "evidence")
    findings = _load_many(task_dir, "findings")
    runs = {str(item["id"]): item for item in _load_many(task_dir, "runs")}
    acceptances = _load_many(task_dir, "risk-acceptances")
    approvals = _load_many(task_dir, "approvals")
    work_units = _load_many(task_dir, "work-units")
    events = [load_data(path) for path in sorted((task_dir / "events").glob("*.json"))]
    task["work_units_complete"] = bool(work_units) and all(item.get("status") == "completed" for item in work_units)

    compiled = compiled_policy or compile_policy(root, task=task)
    config = compiled.config
    ownership = compiled.ownership
    schema_set = SchemaSet(root / "schemas")
    schema_inputs = [
        (persisted_task, "task.schema.json", "task.yaml"),
        (scope, "scope-contract.schema.json", "scope-contract.yaml"),
        *[(item, "evidence.schema.json", f"evidence/{item.get('id')}.json") for item in evidence],
        *[(item, "finding.schema.json", f"findings/{item.get('id')}.json") for item in findings],
        *[(item, "run.schema.json", f"runs/{item.get('id')}.json") for item in runs.values()],
        *[(item, "risk-acceptance.schema.json", f"risk-acceptances/{item.get('id')}.json") for item in acceptances],
        *[(item, "approval.schema.json", f"approvals/{item.get('id')}.json") for item in approvals],
        *[(item, "work-unit.schema.json", f"work-units/{item.get('id')}.yaml") for item in work_units],
    ]
    schema_issues = [issue for value, schema, path in schema_inputs for issue in schema_set.validate(value, schema, path=path)]
    git = GitRepository(root)
    changes = git.changes_since(scope.get("base_commit"), task_id=task_id)
    mode_policy = (config.get("modes") or {}).get(str(task.get("mode")), {})
    resolved_gates = set(str(value) for value in task.get("required_gates", []))
    resolved_gates.update(str(value) for value in scope.get("required_gates", []))
    resolved_gates.update(str(value) for value in mode_policy.get("required_gates", []))
    resolver = OwnershipResolver(ownership)
    for change in changes:
        for path in ([change.old_path, change.path] if change.old_path else [change.path]):
            if path:
                _, gates = resolver.sensitive(path)
                resolved_gates.update(gates)
    task["required_gates"] = sorted(resolved_gates)
    trusted_approval_ids = verified_entity_ids(events, "approval_id")
    trusted_run_ids = verified_entity_ids(events, "run_id")
    trusted_risk_acceptance_ids = verified_entity_ids(events, "risk_acceptance_id")
    valid_approvals = valid_scope_approvals(
        task, scope, approvals, ownership, config,
        trusted_approval_ids=trusted_approval_ids,
    )
    scope_result = check_changes(
        changes,
        scope,
        ownership=ownership,
        repo_root=root,
        task_id=task_id,
        governance_approval_level=max((str(item.get("independence_level", "L0")) for item in valid_approvals), default=None),
        submodule_approved=any("submodule_change" in item.get("comment", "") for item in valid_approvals),
        governance_sensitive_patterns=list(((config.get("security") or {}).get("governance_sensitive_paths") or [])),
    )
    workspace_changes = git.workspace_changes(task_id=task_id)
    current_subject = git.current_code_subject(task_id) if not workspace_changes else git.workspace_subject(task_id=task_id)
    authorized = owner_approvers(scope, ownership)
    minimum_review = str(mode_policy.get("minimum_review_independence", "L1"))
    decision = evaluate_close(
        task,
        scope,
        evidence,
        findings,
        runs,
        acceptances,
        current_subject=current_subject,
        policy_digest=str((task.get("policy_ref") or {}).get("combined_digest", "")),
        close_actor=close_actor,
        authorized_closers=authorized,
        non_waivable_gates=set((config.get("close_policy") or {}).get("non_waivable_gates", [])),
        authorized_risk_acceptors=authorized,
        current_diff_digest=git.review_diff_digest(scope.get("base_commit"), task_id=task_id),
        runtime_profiles={str(compiled.runtime_profile.get("id")): compiled.runtime_profile},
        minimum_review_level=minimum_review,
        review_required=("independent_review" in resolved_gates or str(task.get("mode")) in {"high_risk", "audit"}),
        verified_run_ids=trusted_run_ids,
        trusted_risk_acceptance_ids=trusted_risk_acceptance_ids,
    )
    issues = [*schema_issues, *decision.issues]
    if not valid_approvals:
        issues.append(MacIssue("CLOSE_SCOPE_APPROVAL_INVALID", "approved scope has no authorized independent Approval"))
    issues.extend(scope_result.issues)
    return CloseDecision(not issues, tuple(issues), decision.covered_gates, decision.covered_acceptance)


__all__ = ["CloseDecision", "evaluate_close", "evaluate_repository_close"]
