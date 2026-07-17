from __future__ import annotations

from dataclasses import replace

import pytest

from mac.ownership import OwnershipResolver
from mac.scope import Change, amend_scope, check_changes, normalize_repo_path, validate_patterns
from mac.state_machine import DEFAULT_TRANSITIONS, TransitionContext, evaluate_transition, parse_transitions, validate_workflow_invariants


def test_scope_amendment_is_versioned_budgeted_and_sensitive_approval_is_explicit() -> None:
    contract = {"id": "SCOPE-01K0W4Z36K3W5C2R0A3M8N9P80", "version": 1, "status": "approved", "allowed_paths": ["src/**"], "risk_tags": [], "amendment_policy": {"max_amendments": 1, "max_paths_per_amendment": 2, "require_independent_approval_for": ["auth_security"]}}
    amended = amend_scope(contract, add_paths=["tests/**"], actor="a", approvers=["b"])
    assert amended["version"] == 2 and amended["allowed_paths"] == ["src/**", "tests/**"]
    with pytest.raises(ValueError, match="budget exhausted"):
        amend_scope(amended, add_paths=["docs/**"], actor="a", approvers=["b"])
    sensitive = amend_scope(contract, add_paths=["auth/**"], actor="a", approvers=["b"], added_risk_tags=["auth_security"])
    assert sensitive["status"] == "proposed" and sensitive["approved_by"] == []
    assert amend_scope(contract, add_paths=["auth/**"], actor="a", approvers=["b"], added_risk_tags=["auth_security"], independent_approval=True)["status"] == "proposed"


def test_scope_reports_submodule_unassigned_owner_and_pattern_negation() -> None:
    ownership = {"owners": {"backend": {"include": ["src/**"], "priority": 1}}, "sensitive_paths": [{"pattern": "src/auth/**", "risk_tags": ["auth_security"], "required_gates": ["review"]}]}
    result = check_changes([Change("modify", "vendor/lib", submodule=True)], {"allowed_paths": ["**"], "denied_paths": [], "owners": ["backend"], "governance_sensitive_approved": True}, ownership=ownership)
    assert {issue.code for issue in result.issues} >= {"SCOPE_SUBMODULE_SENSITIVE", "OWNERSHIP_UNASSIGNED"}
    assert validate_patterns(["!src/private/**"])[0].code == "SCOPE_PATTERN_UNSAFE"
    tags, gates = OwnershipResolver(ownership).sensitive("src/auth/service.py")
    assert tags == {"auth_security"} and gates == {"review"}
    with pytest.raises(ValueError):
        normalize_repo_path("")


def full_context() -> TransitionContext:
    return TransitionContext(triage_complete=True, scope_approved=True, gates_selected=True, runtime_satisfied=True, result_submitted=True, work_units_complete=True, scope_clean=True, evidence_complete=True, review_complete=True, risk_acceptance_valid=True, review_required=True, blocking_findings=True, human_input_required=True, external_dependency_pending=True, input_received=True, risk_surface_changed=True, external_evidence_received=True, dependency_recovered=True, unrecoverable_failure=True, authorized_cancellation=True, successor_task_id="TASK-X", lease_valid=True, executor_run_created=True, dependencies_complete=True, baseline_recorded=True, controller_lease_valid=True, work_unit_dependencies_complete=True, current_subject_digest=True, close_findings_clean=True, close_actor_authorized=True, blocking_findings_exist=True, external_dependency_recovered=True)


def test_every_declared_transition_has_a_satisfiable_guard_assignment() -> None:
    base = full_context()
    for transition in DEFAULT_TRANSITIONS:
        context = base
        if "no_review_required" in transition.conditions:
            context = replace(context, review_required=False)
        if "risk_surface_unchanged" in transition.conditions:
            context = replace(context, risk_surface_changed=False)
        assert evaluate_transition(transition.sources[0], transition.target, context).ok, transition.id


def test_workflow_parser_and_invariant_diagnostics_cover_invalid_references() -> None:
    workflow = {"initial_state": "missing", "states": ["triage", "done", "orphan"], "terminal_states": ["done", "unknown"], "guards": {"ok": {}}, "transitions": [{"id": "x", "from": "triage", "to": "done", "requires": ["missing_guard"]}, {"id": "x", "from": "bad", "to": "bad-target"}, {"id": "out", "from": "done", "to": "triage"}]}
    parsed = parse_transitions({"transitions": [{"id": "a", "from": ["triage"], "to": "done", "requires": ["ok"], "when": "condition"}]})
    assert parsed[0].conditions == ("condition",)
    codes = {issue.code for issue in validate_workflow_invariants(workflow, "workflow.yaml")}
    assert {"WORKFLOW_INITIAL_STATE_UNKNOWN", "WORKFLOW_TERMINAL_STATE_UNKNOWN", "WORKFLOW_DUPLICATE_TRANSITION", "WORKFLOW_SOURCE_UNKNOWN", "WORKFLOW_TARGET_UNKNOWN", "WORKFLOW_GUARD_UNKNOWN", "WORKFLOW_STATE_UNREACHABLE", "WORKFLOW_TERMINAL_HAS_OUTBOUND"} <= codes
