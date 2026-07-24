from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, fields
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .errors import ExitCode, MacError, MacIssue
from .io import load_data, normalize_data
from .schema_validation import SchemaSet
from .security import parse_yaml_safely
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


def _compile_documents(
    config: dict[str, Any],
    workflow: dict[str, Any],
    ownership: dict[str, Any],
    runtime_profile: dict[str, Any],
    *,
    schema_set: SchemaSet,
    config_path: str,
    workflow_path: str,
    ownership_path: str,
    profile_path: str,
    profile_id: str,
) -> CompiledPolicy:
    issues = schema_set.validate(config, "config.schema.json", path=config_path)
    issues.extend(schema_set.validate(workflow, "workflow.schema.json", path=workflow_path))
    issues.extend(schema_set.validate(ownership, "ownership.schema.json", path=ownership_path))
    issues.extend(schema_set.validate(runtime_profile, "runtime-profile.schema.json", path=profile_path))
    issues.extend(validate_workflow_invariants(workflow, workflow_path))

    workflow_id = str(config.get("default_workflow", ""))
    if workflow.get("name") != workflow_id:
        issues.append(MacIssue("POLICY_WORKFLOW_ID_MISMATCH", "default_workflow does not match workflow name", workflow_path))
    if runtime_profile.get("id") != profile_id:
        issues.append(MacIssue("POLICY_RUNTIME_ID_MISMATCH", "default_runtime_profile does not match profile id", profile_path))

    transitions = parse_transitions(workflow)
    known_context = {field.name for field in fields(TransitionContext)} | {
        "no_review_required",
        "risk_surface_unchanged",
        "successor_task_exists",
    }
    for transition in transitions:
        for name in (*transition.requires, *transition.conditions):
            if name not in known_context:
                issues.append(MacIssue("POLICY_GUARD_UNIMPLEMENTED", f"guard {name!r} has no machine implementation", workflow_path))

    owner_names = set((ownership.get("owners") or {}).keys())
    for owner_name, definition in (ownership.get("owners") or {}).items():
        for coowner in definition.get("coowners", []):
            if coowner not in owner_names:
                issues.append(MacIssue("POLICY_OWNER_REFERENCE_UNKNOWN", f"owner {owner_name!r} references unknown coowner {coowner!r}", ownership_path))

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


def _safe_frozen_path(value: object) -> str:
    raw = str(value)
    path = PurePosixPath(raw)
    if not raw or path.is_absolute() or ".." in path.parts or "\x00" in raw or path.as_posix() != raw:
        raise MacError(
            "FROZEN_POLICY_REFERENCE_INVALID",
            "frozen policy reference contains an unsafe path",
            exit_code=ExitCode.CORRUPTION,
            path=raw,
        )
    return raw


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _frozen_reference_blobs(repo: Path, reference: Mapping[str, Any]) -> tuple[str, dict[str, bytes]]:
    try:
        rows = [
            {"path": _safe_frozen_path(item["path"]), "digest": str(item["digest"])}
            for item in reference.get("files", [])
        ]
    except (KeyError, TypeError, ValueError) as exc:
        raise MacError(
            "FROZEN_POLICY_REFERENCE_INVALID",
            "frozen policy reference is malformed",
            exit_code=ExitCode.CORRUPTION,
        ) from exc
    rows.sort(key=lambda item: item["path"])
    paths = [item["path"] for item in rows]
    aggregate = _sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode())
    source_commit = str(reference.get("source_commit", ""))
    if (
        not rows
        or len(paths) != len(set(paths))
        or aggregate != reference.get("combined_digest")
        or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None
    ):
        raise MacError(
            "FROZEN_POLICY_REFERENCE_INVALID",
            "frozen policy reference is not commit-bound and internally consistent",
            exit_code=ExitCode.CORRUPTION,
        )
    try:
        resolved = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", f"{source_commit}^{{commit}}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip().lower()
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise MacError(
            "FROZEN_POLICY_COMMIT_UNAVAILABLE",
            "frozen policy source commit is unavailable",
            exit_code=ExitCode.CORRUPTION,
        ) from exc
    if resolved != source_commit:
        raise MacError(
            "FROZEN_POLICY_COMMIT_UNAVAILABLE",
            "frozen policy source does not resolve to the recorded commit",
            exit_code=ExitCode.CORRUPTION,
        )

    blobs: dict[str, bytes] = {}
    for row in rows:
        try:
            raw = subprocess.run(
                ["git", "-C", str(repo), "show", f"{source_commit}:{row['path']}"],
                check=True,
                capture_output=True,
            ).stdout
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            raise MacError(
                "FROZEN_POLICY_BLOB_UNAVAILABLE",
                "frozen policy blob is unavailable",
                exit_code=ExitCode.CORRUPTION,
                path=row["path"],
            ) from exc
        if len(raw) > 1_048_576:
            raise MacError(
                "FROZEN_POLICY_BLOB_INVALID",
                "frozen policy blob exceeds the structured-input limit",
                exit_code=ExitCode.CORRUPTION,
                path=row["path"],
            )
        allowed_digests = {_sha256(raw)}
        if b"\x00" not in raw and b"\r" not in raw:
            try:
                raw.decode("utf-8")
            except UnicodeDecodeError:
                pass
            else:
                allowed_digests.add(_sha256(raw.replace(b"\n", b"\r\n")))
        if row["digest"] not in allowed_digests:
            raise MacError(
                "FROZEN_POLICY_BLOB_TAMPERED",
                "frozen policy blob does not match its recorded digest",
                exit_code=ExitCode.CORRUPTION,
                path=row["path"],
            )
        blobs[row["path"]] = raw
    return source_commit, blobs


def _load_frozen_document(blobs: Mapping[str, bytes], path: str) -> dict[str, Any]:
    raw = blobs.get(path)
    if raw is None:
        raise MacError(
            "FROZEN_POLICY_SOURCE_MISSING",
            "frozen policy reference omits a required executable source",
            exit_code=ExitCode.CORRUPTION,
            path=path,
        )
    try:
        value = parse_yaml_safely(raw)
    except Exception as exc:
        raise MacError(
            "FROZEN_POLICY_SOURCE_INVALID",
            "frozen policy source cannot be parsed safely",
            exit_code=ExitCode.CORRUPTION,
            path=path,
        ) from exc
    if not isinstance(value, dict):
        raise MacError(
            "FROZEN_POLICY_SOURCE_INVALID",
            "frozen policy source must contain an object",
            exit_code=ExitCode.CORRUPTION,
            path=path,
        )
    return normalize_data(value)


def compile_frozen_policy(
    repo: Path,
    policy_ref: Mapping[str, Any],
    ownership_ref: Mapping[str, Any],
    *,
    runtime_profile_id: str | None = None,
    schemas: SchemaSet | None = None,
) -> CompiledPolicy:
    """Compile the exact policy blobs frozen by a Task's commit-bound references."""

    root = repo.resolve()
    policy_commit, policy_blobs = _frozen_reference_blobs(root, policy_ref)
    ownership_commit, ownership_blobs = _frozen_reference_blobs(root, ownership_ref)
    if policy_commit != ownership_commit:
        raise MacError(
            "FROZEN_POLICY_COMMIT_MISMATCH",
            "policy and ownership references must bind the same source commit",
            exit_code=ExitCode.CORRUPTION,
        )
    config_path = ".agents/config.yaml"
    config = _load_frozen_document(policy_blobs, config_path)
    paths = config.get("paths") or {}
    workflow_id = str(config.get("default_workflow", ""))
    profile_id = runtime_profile_id or str(config.get("default_runtime_profile", ""))
    workflow_path = (PurePosixPath(str(paths.get("workflows", ".agents/workflows"))) / f"{workflow_id}.yaml").as_posix()
    profile_path = (PurePosixPath(str(paths.get("runtime_profiles", ".agents/runtime-profiles"))) / f"{profile_id}.yaml").as_posix()
    ownership_path = PurePosixPath(str(paths.get("ownership", ".agents/ownership.yaml"))).as_posix()
    workflow = _load_frozen_document(policy_blobs, workflow_path)
    runtime_profile = _load_frozen_document(policy_blobs, profile_path)
    ownership = _load_frozen_document(ownership_blobs, ownership_path)
    return _compile_documents(
        config,
        workflow,
        ownership,
        runtime_profile,
        schema_set=schemas or SchemaSet(),
        config_path=config_path,
        workflow_path=workflow_path,
        ownership_path=ownership_path,
        profile_path=profile_path,
        profile_id=profile_id,
    )


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
    paths = config.get("paths") or {}
    workflow_id = str(config.get("default_workflow", ""))
    workflow_path = root / str(paths.get("workflows", ".agents/workflows")) / f"{workflow_id}.yaml"
    ownership_path = root / str(paths.get("ownership", ".agents/ownership.yaml"))
    profile_id = runtime_profile_id or str(config.get("default_runtime_profile", ""))
    profile_path = root / str(paths.get("runtime_profiles", ".agents/runtime-profiles")) / f"{profile_id}.yaml"

    workflow = load_data(workflow_path)
    ownership = load_data(ownership_path)
    runtime_profile = load_data(profile_path)
    return _compile_documents(
        config,
        workflow,
        ownership,
        runtime_profile,
        schema_set=schema_set,
        config_path=".agents/config.yaml",
        workflow_path=workflow_path.relative_to(root).as_posix(),
        ownership_path=ownership_path.relative_to(root).as_posix(),
        profile_path=profile_path.relative_to(root).as_posix(),
        profile_id=profile_id,
    )
