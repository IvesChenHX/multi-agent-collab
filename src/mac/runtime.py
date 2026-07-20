from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .authority import VerifiedAuthorityContext, require_external_authority
from .errors import ExitCode, MacError, MacIssue
from .io import load_data


@dataclass(frozen=True, slots=True)
class CapabilityDecision:
    ok: bool
    issues: tuple[MacIssue, ...]
    actions: tuple[str, ...]


def resolve_run_registration(
    *,
    frozen_profile_id: str,
    declared_profile: str,
    declared_context_id: str,
    declared_actor: str,
    declared_actor_kind: str,
    declared_independence_level: str,
    declared_provider: str | None = None,
    declared_model: str | None = None,
    declared_read_only: bool = False,
    declared_commit_participation: list[str] | None = None,
    authority_context: VerifiedAuthorityContext | None = None,
) -> dict[str, Any]:
    """Resolve Run metadata without promoting CLI declarations into attestations."""

    if declared_profile != frozen_profile_id:
        raise MacError(
            "RUNTIME_PROFILE_MISMATCH",
            "run profile must match the task's frozen runtime profile",
            exit_code=ExitCode.RUNTIME,
            details={"declared": declared_profile, "frozen": frozen_profile_id},
        )
    participation = list(declared_commit_participation or [])
    if declared_independence_level not in {"L0", "L1", "L2", "L3"}:
        raise MacError("RUN_INDEPENDENCE_INVALID", "unsupported independence level", exit_code=ExitCode.VALIDATION)
    if declared_independence_level in {"L0", "L1"}:
        if declared_provider or declared_model or declared_read_only or participation:
            raise MacError(
                "PROVENANCE_UNVERIFIED",
                "provider, model, read-only state, and commit participation require an external runtime verifier",
                exit_code=ExitCode.EXTERNAL,
            )
        # L0/L1 values remain declarations. They intentionally carry no
        # provider/model or independence_attestation fields.
        return {
            "actor": {"id": declared_actor, "kind": declared_actor_kind},
            "runtime": {"profile": frozen_profile_id, "execution_context_id": declared_context_id},
            "independence_level": declared_independence_level,
        }

    if authority_context is None:
        raise MacError(
            "PROVENANCE_UNVERIFIED",
            f"{declared_independence_level} run requires an external runtime verifier",
            exit_code=ExitCode.EXTERNAL,
            suggestion="register the run through a runtime adapter with verified provenance",
        )
    context = require_external_authority(
        declared_actor, authority_context, operation=f"{declared_independence_level} run registration",
    )
    runtime = context.runtime
    if runtime is None:
        raise MacError(
            "PROVENANCE_UNVERIFIED",
            f"{declared_independence_level} run requires externally verified runtime provenance",
            exit_code=ExitCode.EXTERNAL,
        )
    conflicts = {
        "actor_kind": (declared_actor_kind, context.actor_kind),
        "profile": (declared_profile, runtime.profile),
        "execution_context_id": (declared_context_id, runtime.execution_context_id),
        "provider": (declared_provider, runtime.provider),
        "model": (declared_model, runtime.model),
        "read_only": (declared_read_only, runtime.read_only),
        "commit_participation": (participation, list(runtime.commit_participation)),
    }
    mismatches = {
        name: {"declared": declared, "verified": verified}
        for name, (declared, verified) in conflicts.items()
        if declared != verified
    }
    if mismatches:
        raise MacError(
            "RUNTIME_CONTEXT_MISMATCH",
            "declared run metadata does not match externally verified provenance",
            exit_code=ExitCode.SECURITY,
            details={"mismatches": mismatches},
        )
    if declared_independence_level == "L3" and context.actor_kind != "human":
        raise MacError("REVIEW_HUMAN_REQUIRED", "L3 requires a verified human actor", exit_code=ExitCode.SECURITY)
    return {
        "actor": context.actor(),
        "runtime": {
            "profile": runtime.profile,
            "execution_context_id": runtime.execution_context_id,
            "provider": runtime.provider,
            "model": runtime.model,
        },
        "independence_level": declared_independence_level,
        "independence_attestation": {
            "read_only": runtime.read_only,
            "commit_participation": list(runtime.commit_participation),
        },
    }


def resolve_profile(
    profiles_dir: Path, *, explicit: str | None = None, project_default: str | None = None,
    user_default: str | None = None,
) -> dict[str, Any]:
    selected = explicit or project_default or user_default or "local-single"
    path = profiles_dir / f"{selected}.yaml"
    if path.is_file():
        return load_data(path)
    if selected != "local-single":
        raise FileNotFoundError(path)
    return {
        "schema_version": 1, "id": "local-single",
        "capabilities": {"spawn_agent": False, "parallel_runs": False, "fresh_context": "manual", "read_only_run": "policy_only", "worktree": "external", "human_gate": "interactive", "command_execution": True, "network_control": "unavailable", "secret_broker": "unavailable", "artifact_store": "filesystem", "tracing": "basic", "cancellation": "manual"},
        "fallback": {"fresh_context": "build_handoff_and_wait", "independent_review": "wait_for_manual", "worktree": "serialize_and_lock", "artifact_store": "digest_only"},
        "limits": {"max_parallel_runs": 1, "default_timeout_seconds": 3600, "max_output_bytes": 10_485_760},
    }


def evaluate_capabilities(profile: Mapping[str, Any], requirements: Mapping[str, Any], *, mode: str) -> CapabilityDecision:
    capabilities = profile.get("capabilities", {})
    fallback = profile.get("fallback", {})
    issues: list[MacIssue] = []
    actions: list[str] = []
    for name, required in requirements.items():
        actual = capabilities.get(name)
        satisfied = actual is True if required is True else actual == required
        if satisfied:
            continue
        action = fallback.get(name) or fallback.get("independent_review" if name == "read_only_run" else name)
        if action:
            actions.append(str(action))
        if mode in {"high_risk", "audit"} or not action:
            issues.append(MacIssue("RUNTIME_CAPABILITY_MISSING", f"runtime capability {name} does not satisfy {required!r}", details={"actual": actual, "fallback": action}))
    return CapabilityDecision(not issues, tuple(issues), tuple(actions))
