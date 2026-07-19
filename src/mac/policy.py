from __future__ import annotations

from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from .errors import ExitCode, MacError, MacIssue
from .io import load_data
from .schema_validation import SchemaSet
from .state_machine import Transition, TransitionContext, parse_transitions, validate_workflow_invariants


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    config: dict[str, Any]
    workflow: dict[str, Any]
    ownership: dict[str, Any]
    runtime_profile: dict[str, Any]
    transitions: tuple[Transition, ...]
    states: frozenset[str]
    terminal_states: frozenset[str]


def _raise_issues(issues: list[MacIssue]) -> None:
    if issues:
        raise MacError(
            "POLICY_COMPILE_FAILED",
            "machine governance policy is invalid",
            exit_code=ExitCode.SECURITY,
            details={"issues": [issue.as_dict() for issue in issues]},
        )


def policy_source_paths(config: dict[str, Any], runtime_profile_id: str | None = None) -> tuple[str, ...]:
    paths = config.get("paths") or {}
    workflow_id = str(config.get("default_workflow", ""))
    profile_id = runtime_profile_id or str(config.get("default_runtime_profile", ""))
    return (
        "AGENTS.md",
        ".agents/config.yaml",
        (Path(str(paths.get("workflows", ".agents/workflows"))) / f"{workflow_id}.yaml").as_posix(),
        (Path(str(paths.get("runtime_profiles", ".agents/runtime-profiles"))) / f"{profile_id}.yaml").as_posix(),
    )


def ownership_source_path(config: dict[str, Any]) -> str:
    return Path(str((config.get("paths") or {}).get("ownership", ".agents/ownership.yaml"))).as_posix()


def compile_policy(
    repo: Path,
    schemas: SchemaSet | None = None,
    *,
    runtime_profile_id: str | None = None,
) -> CompiledPolicy:
    """Compile the runtime policy exclusively from the repository machine sources."""

    root = repo.resolve()
    schema_set = schemas or SchemaSet()
    config_path = root / ".agents/config.yaml"
    config = load_data(config_path)
    issues = schema_set.validate(config, "config.schema.json", path=".agents/config.yaml")

    paths = config.get("paths") or {}
    workflow_id = str(config.get("default_workflow", ""))
    workflow_path = root / str(paths.get("workflows", ".agents/workflows")) / f"{workflow_id}.yaml"
    ownership_path = root / str(paths.get("ownership", ".agents/ownership.yaml"))
    profile_id = runtime_profile_id or str(config.get("default_runtime_profile", ""))
    profile_path = root / str(paths.get("runtime_profiles", ".agents/runtime-profiles")) / f"{profile_id}.yaml"

    workflow = load_data(workflow_path)
    ownership = load_data(ownership_path)
    runtime_profile = load_data(profile_path)
    issues.extend(schema_set.validate(workflow, "workflow.schema.json", path=workflow_path.relative_to(root).as_posix()))
    issues.extend(schema_set.validate(ownership, "ownership.schema.json", path=ownership_path.relative_to(root).as_posix()))
    issues.extend(schema_set.validate(runtime_profile, "runtime-profile.schema.json", path=profile_path.relative_to(root).as_posix()))
    issues.extend(validate_workflow_invariants(workflow, workflow_path.relative_to(root).as_posix()))

    if workflow.get("name") != workflow_id:
        issues.append(MacIssue("POLICY_WORKFLOW_ID_MISMATCH", "default_workflow does not match workflow name", workflow_path.relative_to(root).as_posix()))
    if runtime_profile.get("id") != profile_id:
        issues.append(MacIssue("POLICY_RUNTIME_ID_MISMATCH", "default_runtime_profile does not match profile id", profile_path.relative_to(root).as_posix()))

    transitions = parse_transitions(workflow)
    known_context = {field.name for field in fields(TransitionContext)} | {
        "no_review_required",
        "risk_surface_unchanged",
        "successor_task_exists",
    }
    for transition in transitions:
        for name in (*transition.requires, *transition.conditions):
            if name not in known_context:
                issues.append(MacIssue("POLICY_GUARD_UNIMPLEMENTED", f"guard {name!r} has no machine implementation", workflow_path.relative_to(root).as_posix()))

    owner_names = set((ownership.get("owners") or {}).keys())
    for owner_name, definition in (ownership.get("owners") or {}).items():
        for coowner in definition.get("coowners", []):
            if coowner not in owner_names:
                issues.append(MacIssue("POLICY_OWNER_REFERENCE_UNKNOWN", f"owner {owner_name!r} references unknown coowner {coowner!r}", ownership_path.relative_to(root).as_posix()))

    _raise_issues(issues)
    return CompiledPolicy(
        config,
        workflow,
        ownership,
        runtime_profile,
        transitions,
        frozenset(str(value) for value in workflow.get("states", [])),
        frozenset(str(value) for value in workflow.get("terminal_states", [])),
    )
