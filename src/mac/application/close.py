from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from mac.authority import actor_authorized_for_scope, load_runtime_profiles, owner_approvers, valid_scope_approvals
from mac.errors import MacIssue
from mac.git import GitRepository
from mac.policy import compile_policy, ownership_source_path, policy_source_paths
from mac.repository import FilesystemTaskRepository, policy_ref_matches_executable
from mac.scope import check_changes

from .governance import CloseDecision, evaluate_close


def evaluate_repository_close(repo: Path, task_id: str, close_actor: str) -> CloseDecision:
    """Recompute every Close input from current repository state."""

    root = repo.resolve()
    aggregate = FilesystemTaskRepository(root).load_verified_aggregate(task_id)
    task = deepcopy(aggregate.task)
    if aggregate.scope is None:
        raise ValueError("Event-replayed Task has no Scope Contract")
    scope = deepcopy(aggregate.scope)
    evidence = list(deepcopy(aggregate.entities["evidence"]).values())
    findings = list(deepcopy(aggregate.entities["findings"]).values())
    runs = deepcopy(aggregate.entities["runs"])
    acceptances = list(deepcopy(aggregate.entities["risk-acceptances"]).values())
    approvals = list(deepcopy(aggregate.entities["approvals"]).values())
    work_units = list(deepcopy(aggregate.entities["work-units"]).values())
    task["work_units_complete"] = bool(work_units) and all(item.get("status") == "completed" for item in work_units)

    compiled = compile_policy(root, runtime_profile_id=str(task.get("runtime_profile") or "") or None)
    config = compiled.config
    ownership = compiled.ownership
    git = GitRepository(root)
    changes = git.changes_since(scope.get("base_commit"), task_id=task_id)
    valid_approvals = valid_scope_approvals(task, scope, approvals, ownership, config)
    scope_result = check_changes(
        changes,
        scope,
        ownership=ownership,
        repo_root=root,
        task_id=task_id,
        governance_approval_level=max((str(item.get("independence_level", "L0")) for item in valid_approvals), default=None),
        submodule_approved=any("submodule_change" in item.get("comment", "") for item in valid_approvals),
    )
    workspace_changes = git.workspace_changes(task_id=task_id)
    current_subject = git.current_code_subject(task_id) if not workspace_changes else git.workspace_subject(task_id=task_id)
    authorized_closers = {close_actor} if actor_authorized_for_scope(close_actor, scope, ownership) else set()
    authorized_risk_acceptors = owner_approvers(scope, ownership)
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
        authorized_closers=authorized_closers,
        non_waivable_gates=set((config.get("close_policy") or {}).get("non_waivable_gates", [])),
        authorized_risk_acceptors=authorized_risk_acceptors,
        current_diff_digest=git.review_diff_digest(scope.get("base_commit"), task_id=task_id),
        runtime_profiles=load_runtime_profiles(root, config),
        mode_required_gates=(config.get("modes", {}).get(str(task.get("mode")), {}) or {}).get("required_gates", []),
        evidence_revisions=aggregate.entity_revisions["evidence"],
        minimum_evidence_revision=aggregate.scope_revision,
        require_commit_bound_evidence=bool(
            (config.get("close_policy") or {}).get("require_commit_bound_evidence", False)
        ),
    )
    issues = list(decision.issues)
    if aggregate.projection_drift:
        issues.append(MacIssue(
            "CLOSE_PROJECTION_DRIFT",
            "mutable Task projections differ from the verified Event aggregate",
            details={"paths": list(aggregate.projection_drift)},
        ))
    required_policy_paths = set(policy_source_paths(config, str(task.get("runtime_profile") or "") or None))
    if not policy_ref_matches_executable(root, task.get("policy_ref") or {}, required_paths=required_policy_paths):
        issues.append(MacIssue("CLOSE_POLICY_DRIFT", "frozen policy does not match the executable task policy"))
    if not policy_ref_matches_executable(root, task.get("ownership_ref") or {}, required_paths={ownership_source_path(config)}):
        issues.append(MacIssue("CLOSE_OWNERSHIP_DRIFT", "frozen ownership does not match the executable ownership policy"))
    if not valid_approvals:
        issues.append(MacIssue("CLOSE_SCOPE_APPROVAL_INVALID", "approved scope has no authorized independent Approval"))
    issues.extend(scope_result.issues)
    return CloseDecision(
        not issues,
        tuple(issues),
        decision.covered_gates,
        decision.covered_acceptance,
        decision.accepted_risk_acceptances,
    )


__all__ = ["CloseDecision", "evaluate_close", "evaluate_repository_close"]
