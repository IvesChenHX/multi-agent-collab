from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from mac.authority import actor_authorized_for_scope, load_runtime_profiles, valid_scope_approvals
from mac.errors import MacIssue
from mac.git import GitRepository
from mac.io import load_data
from mac.policy import compile_policy, ownership_source_path, policy_source_paths
from mac.repository import policy_ref_matches_executable
from mac.scope import check_changes

from .governance import CloseDecision, evaluate_close


def _load_many(task_dir: Path, directory: str) -> list[dict[str, Any]]:
    suffix = "yaml" if directory == "work-units" else "json"
    return [load_data(path) for path in sorted((task_dir / directory).glob(f"*.{suffix}"))]


def evaluate_repository_close(repo: Path, task_id: str, close_actor: str) -> CloseDecision:
    """Recompute every Close input from current repository state."""

    root = repo.resolve()
    task_dir = root / "tasks" / task_id
    task = deepcopy(load_data(task_dir / "task.yaml"))
    scope = load_data(task_dir / "scope-contract.yaml")
    evidence = _load_many(task_dir, "evidence")
    findings = _load_many(task_dir, "findings")
    runs = {str(item["id"]): item for item in _load_many(task_dir, "runs")}
    acceptances = _load_many(task_dir, "risk-acceptances")
    approvals = _load_many(task_dir, "approvals")
    work_units = _load_many(task_dir, "work-units")
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
    authorized = {
        actor
        for actor in {close_actor, *(str((item.get("actor") or {}).get("id", "")) for item in approvals)}
        if actor_authorized_for_scope(actor, scope, ownership)
    }
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
        runtime_profiles=load_runtime_profiles(root, config),
        mode_required_gates=(config.get("modes", {}).get(str(task.get("mode")), {}) or {}).get("required_gates", []),
    )
    issues = list(decision.issues)
    required_policy_paths = set(policy_source_paths(config, str(task.get("runtime_profile") or "") or None))
    if not policy_ref_matches_executable(root, task.get("policy_ref") or {}, required_paths=required_policy_paths):
        issues.append(MacIssue("CLOSE_POLICY_DRIFT", "frozen policy does not match the executable task policy"))
    if not policy_ref_matches_executable(root, task.get("ownership_ref") or {}, required_paths={ownership_source_path(config)}):
        issues.append(MacIssue("CLOSE_OWNERSHIP_DRIFT", "frozen ownership does not match the executable ownership policy"))
    if not valid_approvals:
        issues.append(MacIssue("CLOSE_SCOPE_APPROVAL_INVALID", "approved scope has no authorized independent Approval"))
    issues.extend(scope_result.issues)
    return CloseDecision(not issues, tuple(issues), decision.covered_gates, decision.covered_acceptance)


__all__ = ["CloseDecision", "evaluate_close", "evaluate_repository_close"]
