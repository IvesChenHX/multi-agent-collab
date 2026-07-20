from __future__ import annotations

from dataclasses import dataclass, fields
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from .errors import ExitCode, MacError, MacIssue
from .io import load_data, normalize_data
from .security import parse_yaml_safely
from .schema_validation import SchemaSet, schema_lock_issues
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


def _load_mapping(raw: bytes, path: str) -> dict[str, Any]:
    if len(raw) > 1_048_576:
        raise MacError("INPUT_TOO_LARGE", f"{path} exceeds the 1 MiB policy limit", exit_code=ExitCode.SECURITY, path=path)
    value = json.loads(raw.decode("utf-8")) if path.endswith(".json") else parse_yaml_safely(raw)
    if not isinstance(value, dict):
        raise MacError("POLICY_SOURCE_INVALID", f"{path} must contain an object", exit_code=ExitCode.SECURITY, path=path)
    return normalize_data(value)


def _frozen_sources(root: Path, task: dict[str, Any]) -> tuple[dict[str, bytes], str | None]:
    references = [task.get("policy_ref") or {}, task.get("ownership_ref") or {}]
    commits = {str(ref.get("source_commit")) for ref in references if ref.get("source_commit")}
    if len(commits) > 1:
        raise MacError("POLICY_SOURCE_COMMIT_MISMATCH", "policy and ownership snapshots use different source commits", exit_code=ExitCode.SECURITY)
    commit = next(iter(commits), None)
    sources: dict[str, bytes] = {}
    for reference in references:
        rows = list(reference.get("files") or [])
        canonical_rows: list[dict[str, str]] = []
        for row in rows:
            path = str(row.get("path", ""))
            if not path or Path(path).is_absolute() or ".." in Path(path).parts:
                raise MacError("POLICY_SOURCE_PATH_UNSAFE", f"unsafe frozen policy path: {path}", exit_code=ExitCode.SECURITY)
            if commit:
                try:
                    raw = subprocess.run(
                        ["git", "-C", str(root), "show", f"{commit}:{Path(path).as_posix()}"],
                        check=True, capture_output=True,
                    ).stdout
                except (FileNotFoundError, subprocess.CalledProcessError) as exc:
                    raise MacError("POLICY_SOURCE_UNAVAILABLE", f"cannot read frozen policy source {path} at {commit}", exit_code=ExitCode.SECURITY, path=path) from exc
            else:
                raw = (root / path).read_bytes()
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            if digest != row.get("digest"):
                raise MacError("POLICY_SOURCE_DIGEST_MISMATCH", f"frozen policy source digest mismatch: {path}", exit_code=ExitCode.SECURITY, path=path)
            sources[path] = raw
            canonical_rows.append({"path": Path(path).as_posix(), "digest": digest})
        canonical_rows.sort(key=lambda item: item["path"])
        combined = "sha256:" + hashlib.sha256(json.dumps(canonical_rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if rows and combined != reference.get("combined_digest"):
            raise MacError("POLICY_REFERENCE_DIGEST_MISMATCH", "frozen policy reference aggregate digest mismatch", exit_code=ExitCode.SECURITY)
    return sources, commit


def compile_policy(repo: Path, schemas: SchemaSet | None = None, *, task: dict[str, Any] | None = None) -> CompiledPolicy:
    """Compile the runtime policy exclusively from the repository machine sources."""

    root = repo.resolve()
    local_schema_dir = root / "schemas"
    if schemas is not None:
        schema_set = schemas
    elif local_schema_dir.is_dir():
        _raise_issues(schema_lock_issues(root, local_schema_dir))
        schema_set = SchemaSet(local_schema_dir)
    else:
        schema_set = SchemaSet()
    issues: list[MacIssue] = []
    frozen, commit = _frozen_sources(root, task) if task is not None else ({}, None)

    def read(relative: str) -> dict[str, Any]:
        normalized = Path(relative).as_posix()
        if normalized in frozen:
            return _load_mapping(frozen[normalized], normalized)
        if task is not None and commit:
            try:
                raw = subprocess.run(
                    ["git", "-C", str(root), "show", f"{commit}:{normalized}"],
                    check=True, capture_output=True,
                ).stdout
            except (FileNotFoundError, subprocess.CalledProcessError) as exc:
                raise MacError("POLICY_SOURCE_UNAVAILABLE", f"cannot read frozen policy dependency {normalized} at {commit}", exit_code=ExitCode.SECURITY, path=normalized) from exc
            return _load_mapping(raw, normalized)
        return load_data(root / normalized)

    config_path = root / ".agents/config.yaml"
    config = read(".agents/config.yaml")
    issues.extend(schema_set.validate(config, "config.schema.json", path=".agents/config.yaml"))

    paths = config.get("paths") or {}
    workflow_id = str(config.get("default_workflow", ""))
    workflow_path = root / str(paths.get("workflows", ".agents/workflows")) / f"{workflow_id}.yaml"
    ownership_path = root / str(paths.get("ownership", ".agents/ownership.yaml"))
    profile_id = str((task or {}).get("runtime_profile") or config.get("default_runtime_profile", ""))
    profile_path = root / str(paths.get("runtime_profiles", ".agents/runtime-profiles")) / f"{profile_id}.yaml"

    workflow = read(workflow_path.relative_to(root).as_posix())
    ownership = read(ownership_path.relative_to(root).as_posix())
    runtime_profile = read(profile_path.relative_to(root).as_posix())
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
        config, workflow, ownership, runtime_profile, transitions,
        frozenset(str(value) for value in workflow.get("states", [])),
        frozenset(str(value) for value in workflow.get("terminal_states", [])),
    )
