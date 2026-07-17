from __future__ import annotations

from mac.state_machine import (
    DEFAULT_TRANSITIONS,
    TASK_STATES,
    TERMINAL_STATES,
    TransitionContext,
    evaluate_transition,
)


def context(**overrides: object) -> TransitionContext:
    values: dict[str, object] = {
        "triage_complete": True,
        "scope_approved": True,
        "gates_selected": True,
        "runtime_satisfied": True,
        "result_submitted": True,
        "work_units_complete": True,
        "scope_clean": True,
        "evidence_complete": True,
        "review_complete": True,
        "risk_acceptance_valid": True,
        "review_required": False,
        "blocking_findings": False,
        "human_input_required": False,
        "external_dependency_pending": False,
        "input_received": True,
        "risk_surface_changed": False,
        "external_evidence_received": True,
        "dependency_recovered": True,
        "unrecoverable_failure": False,
        "authorized_cancellation": True,
        "successor_task_id": "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        "lease_valid": True,
        "executor_run_created": True,
        "dependencies_complete": True,
        "baseline_recorded": True,
        "controller_lease_valid": True,
        "work_unit_dependencies_complete": True,
        "current_subject_digest": True,
        "close_findings_clean": True,
        "close_actor_authorized": True,
        "blocking_findings_exist": False,
        "external_dependency_recovered": True,
    }
    values.update(overrides)
    return TransitionContext(**values)  # type: ignore[arg-type]


def test_v6_defines_exactly_13_states_and_all_design_transitions() -> None:
    assert len(TASK_STATES) == 13
    assert TERMINAL_STATES == {
        "completed",
        "completed_with_risk",
        "failed",
        "cancelled",
        "superseded",
    }
    pairs = {(source, transition.target) for transition in DEFAULT_TRANSITIONS for source in transition.sources}
    assert ("waiting_external", "executing") in pairs
    assert ("waiting_external", "verifying") in pairs
    assert ("waiting_input", "triage") in pairs
    assert ("waiting_input", "executing") in pairs
    assert all((state, "cancelled") in pairs for state in TASK_STATES - TERMINAL_STATES)
    assert all((state, "superseded") in pairs for state in TASK_STATES - TERMINAL_STATES)


def test_transition_evaluates_required_guards_and_conditions() -> None:
    denied = evaluate_transition("triage", "ready", context(scope_approved=False))
    assert not denied.ok
    assert denied.codes == ("TRANSITION_GUARD_FAILED",)
    assert denied.failed_guards == ("scope_approved",)

    assert evaluate_transition("triage", "ready", context()).ok
    assert evaluate_transition("ready", "executing", context()).ok
    assert evaluate_transition("waiting_external", "executing", context()).ok


def test_terminal_states_are_immutable() -> None:
    result = evaluate_transition("completed", "executing", context())
    assert not result.ok
    assert result.codes == ("TERMINAL_STATE_IMMUTABLE",)
