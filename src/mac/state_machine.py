from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any, Iterable

from .errors import MacIssue

TASK_STATE_ORDER = (
    "triage", "ready", "executing", "verifying", "reviewing", "repairing",
    "waiting_input", "waiting_external", "completed", "completed_with_risk",
    "failed", "cancelled", "superseded",
)
TASK_STATES = set(TASK_STATE_ORDER)
TERMINAL_STATES = {"completed", "completed_with_risk", "failed", "cancelled", "superseded"}
ACTIVE_STATES = TASK_STATES - TERMINAL_STATES
ACTIVE_STATE_ORDER = tuple(state for state in TASK_STATE_ORDER if state in ACTIVE_STATES)


@dataclass(frozen=True, slots=True)
class Transition:
    id: str
    sources: tuple[str, ...]
    target: str
    requires: tuple[str, ...] = ()
    conditions: tuple[str, ...] = ()


def _transition(id: str, sources: str | Iterable[str], target: str, requires: Iterable[str] = (), conditions: Iterable[str] = ()) -> Transition:
    return Transition(id, (sources,) if isinstance(sources, str) else tuple(sources), target, tuple(requires), tuple(conditions))


DEFAULT_TRANSITIONS = (
    _transition("triage_to_ready", "triage", "ready", ("triage_complete", "scope_approved", "gates_selected")),
    _transition("ready_to_executing", "ready", "executing", ("runtime_satisfied", "controller_lease_valid", "work_unit_dependencies_complete", "baseline_recorded")),
    _transition("executing_to_verifying", "executing", "verifying", ("result_submitted", "scope_clean", "current_subject_digest")),
    _transition("verifying_to_reviewing", "verifying", "reviewing", ("evidence_complete",), ("review_required",)),
    _transition("verifying_to_completed", "verifying", "completed", ("evidence_complete", "scope_clean", "close_findings_clean", "close_actor_authorized"), ("no_review_required",)),
    _transition("reviewing_to_completed", "reviewing", "completed", ("review_complete", "evidence_complete", "scope_clean", "close_findings_clean", "close_actor_authorized")),
    _transition("active_to_repairing", ("verifying", "reviewing"), "repairing", conditions=("blocking_findings_exist",)),
    _transition("repairing_to_verifying", "repairing", "verifying", ("result_submitted", "scope_clean", "current_subject_digest")),
    _transition("active_to_waiting_input", ("triage", "ready", "executing", "verifying", "reviewing", "repairing"), "waiting_input", conditions=("human_input_required",)),
    _transition("active_to_waiting_external", ("executing", "verifying", "reviewing"), "waiting_external", conditions=("external_dependency_pending",)),
    _transition("waiting_input_to_executing", "waiting_input", "executing", conditions=("input_received", "risk_surface_unchanged")),
    _transition("waiting_input_to_triage", "waiting_input", "triage", conditions=("input_received", "risk_surface_changed")),
    _transition("waiting_external_to_verifying", "waiting_external", "verifying", conditions=("external_evidence_received",)),
    _transition("waiting_external_to_executing", "waiting_external", "executing", ("controller_lease_valid", "runtime_satisfied"), ("external_dependency_recovered",)),
    _transition("to_completed_with_risk", ("verifying", "reviewing"), "completed_with_risk", ("evidence_complete", "risk_acceptance_valid", "scope_clean", "close_findings_clean", "close_actor_authorized")),
    _transition("active_to_failed", ACTIVE_STATE_ORDER, "failed", conditions=("unrecoverable_failure",)),
    _transition("active_to_cancelled", ACTIVE_STATE_ORDER, "cancelled", conditions=("authorized_cancellation",)),
    _transition("active_to_superseded", ACTIVE_STATE_ORDER, "superseded", conditions=("successor_task_exists",)),
)


def default_workflow_document() -> dict[str, Any]:
    """Build the init workflow from the same transitions used at runtime."""
    guard_names = sorted({name for transition in DEFAULT_TRANSITIONS for name in (*transition.requires, *transition.conditions)})
    transitions: list[dict[str, Any]] = []
    for transition in DEFAULT_TRANSITIONS:
        row: dict[str, Any] = {
            "id": transition.id,
            "from": transition.sources[0] if len(transition.sources) == 1 else list(transition.sources),
            "to": transition.target,
        }
        if transition.requires:
            row["requires"] = list(transition.requires)
        if transition.conditions:
            row["when"] = " and ".join(transition.conditions)
        transitions.append(row)
    return {
        "schema_version": 6,
        "name": "evidence-driven-development",
        "version": 6,
        "initial_state": "triage",
        "states": list(TASK_STATE_ORDER),
        "terminal_states": [state for state in TASK_STATE_ORDER if state in TERMINAL_STATES],
        "guards": {name: {"description": name, "machine_check": name} for name in guard_names},
        "transitions": transitions,
    }


@dataclass(frozen=True, slots=True)
class TransitionContext:
    triage_complete: bool = False
    scope_approved: bool = False
    gates_selected: bool = False
    runtime_satisfied: bool = False
    result_submitted: bool = False
    work_units_complete: bool = False
    scope_clean: bool = False
    evidence_complete: bool = False
    review_complete: bool = False
    risk_acceptance_valid: bool = False
    review_required: bool = False
    blocking_findings: bool = False
    human_input_required: bool = False
    external_dependency_pending: bool = False
    input_received: bool = False
    risk_surface_changed: bool = False
    external_evidence_received: bool = False
    dependency_recovered: bool = False
    unrecoverable_failure: bool = False
    authorized_cancellation: bool = False
    successor_task_id: str | None = None
    lease_valid: bool = False
    executor_run_created: bool = False
    dependencies_complete: bool = False
    baseline_recorded: bool = False
    controller_lease_valid: bool = False
    work_unit_dependencies_complete: bool = False
    current_subject_digest: bool = False
    current_subject: dict[str, str] | None = None
    close_findings_clean: bool = False
    close_actor_authorized: bool = False
    blocking_findings_exist: bool = False
    external_dependency_recovered: bool = False

    @property
    def risk_surface_unchanged(self) -> bool:
        return not self.risk_surface_changed

    @property
    def no_review_required(self) -> bool:
        return not self.review_required

    @property
    def successor_task_exists(self) -> bool:
        return bool(self.successor_task_id)


@dataclass(frozen=True, slots=True)
class TransitionDecision:
    ok: bool
    codes: tuple[str, ...] = ()
    transition: Transition | None = None
    failed_guards: tuple[str, ...] = ()
    failed_conditions: tuple[str, ...] = ()


def find_transition(source: str, target: str, transitions: Iterable[Transition] = DEFAULT_TRANSITIONS) -> Transition | None:
    return next((item for item in transitions if source in item.sources and target == item.target), None)


def evaluate_transition(
    source: str,
    target: str,
    context: TransitionContext,
    transitions: Iterable[Transition] = DEFAULT_TRANSITIONS,
    *,
    states: Iterable[str] | None = None,
    terminal_states: Iterable[str] | None = None,
) -> TransitionDecision:
    executable_states = set(TASK_STATES if states is None else states)
    executable_terminal_states = set(TERMINAL_STATES if terminal_states is None else terminal_states)
    if source not in executable_states or target not in executable_states:
        return TransitionDecision(False, ("STATE_UNKNOWN",))
    if source in executable_terminal_states:
        return TransitionDecision(False, ("TERMINAL_STATE_IMMUTABLE",))
    transition = find_transition(source, target, transitions)
    if transition is None:
        return TransitionDecision(False, ("TRANSITION_NOT_ALLOWED",))
    aliases = {
        "controller_lease_valid": "lease_valid",
        "work_unit_dependencies_complete": "dependencies_complete",
        "blocking_findings_exist": "blocking_findings",
        "external_dependency_recovered": "dependency_recovered",
    }
    def context_value(name: str) -> bool:
        direct = bool(getattr(context, name, False))
        alias = aliases.get(name)
        return direct or bool(getattr(context, alias, False)) if alias else direct
    failed_guards = tuple(name for name in transition.requires if not context_value(name))
    failed_conditions = tuple(name for name in transition.conditions if not context_value(name))
    if failed_guards or failed_conditions:
        return TransitionDecision(False, ("TRANSITION_GUARD_FAILED",), transition, failed_guards, failed_conditions)
    return TransitionDecision(True, transition=transition)


def parse_transitions(workflow: dict[str, Any]) -> tuple[Transition, ...]:
    def condition_name(raw: str) -> str:
        value = raw.strip()
        negated = value.startswith("not ")
        if negated:
            value = value[4:].strip()
        if value.endswith(")") and "(" in value:
            value = value.split("(", 1)[0].strip()
        if negated and value == "review_required":
            return "no_review_required"
        return value
    result = []
    for raw in workflow.get("transitions", []):
        sources = raw["from"] if isinstance(raw["from"], list) else [raw["from"]]
        conditions = tuple(condition_name(part) for part in str(raw.get("when", "")).split(" and ") if part.strip())
        result.append(_transition(raw["id"], sources, raw["to"], raw.get("requires", ()), conditions))
    return tuple(result)


def validate_workflow_invariants(workflow: dict[str, Any], path: str) -> list[MacIssue]:
    issues: list[MacIssue] = []
    states = set(workflow.get("states", []))
    guards = set(workflow.get("guards", {}))
    initial = workflow.get("initial_state", "triage")
    if initial not in states:
        issues.append(MacIssue("WORKFLOW_INITIAL_STATE_UNKNOWN", f"initial state {initial!r} is not declared", path))
    terminal_states = set(workflow.get("terminal_states", []))
    for terminal in sorted(terminal_states - states):
        issues.append(MacIssue("WORKFLOW_TERMINAL_STATE_UNKNOWN", terminal, path))
    seen: set[str] = set()
    adjacency = {state: set() for state in states}
    for raw in workflow.get("transitions", []):
        transition_id = raw.get("id", "")
        if transition_id in seen:
            issues.append(MacIssue("WORKFLOW_DUPLICATE_TRANSITION", transition_id, path))
        seen.add(transition_id)
        sources = raw.get("from", [])
        sources = sources if isinstance(sources, list) else [sources]
        target = raw.get("to")
        for source in sources:
            if source not in states:
                issues.append(MacIssue("WORKFLOW_SOURCE_UNKNOWN", f"{transition_id}: {source}", path))
            elif target in states:
                adjacency[source].add(target)
        if target not in states:
            issues.append(MacIssue("WORKFLOW_TARGET_UNKNOWN", f"{transition_id}: {target}", path))
        for guard in raw.get("requires", []):
            if guard not in guards:
                issues.append(MacIssue("WORKFLOW_GUARD_UNKNOWN", f"{transition_id}: {guard}", path))
    reachable = {initial} if initial in states else set()
    pending = list(reachable)
    while pending:
        for target in adjacency[pending.pop()]:
            if target not in reachable:
                reachable.add(target)
                pending.append(target)
    for state in sorted(states - reachable):
        issues.append(MacIssue("WORKFLOW_STATE_UNREACHABLE", state, path, severity="warning"))
    for terminal in terminal_states:
        if adjacency.get(terminal):
            issues.append(MacIssue("WORKFLOW_TERMINAL_HAS_OUTBOUND", terminal, path))
    return issues
