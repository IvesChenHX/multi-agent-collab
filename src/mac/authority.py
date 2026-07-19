from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Protocol

from pathspec import GitIgnoreSpec

from .errors import ExitCode, MacError
from .io import load_data


_LEVEL = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}


@dataclass(frozen=True, slots=True)
class AuthorityDecision:
    allowed: bool
    actor_id: str
    operation: str
    task_id: str | None
    authenticated: bool
    issuer: str
    reason: str = ""


class AuthorityVerifier(Protocol):
    """Trusted runtime seam; CLI actor strings are claims, not authority."""

    def authorize(self, *, actor_claim: Mapping[str, Any], operation: str, task_id: str | None) -> AuthorityDecision: ...


def require_authority(
    verifier: AuthorityVerifier | None,
    *,
    actor_claim: Mapping[str, Any],
    operation: str,
    task_id: str | None,
) -> AuthorityDecision:
    if verifier is None:
        raise MacError(
            "AUTHORITY_VERIFIER_REQUIRED",
            "a trusted authority verifier is required for this mutation",
            exit_code=ExitCode.SECURITY,
            task_id=task_id,
        )
    decision = verifier.authorize(actor_claim=actor_claim, operation=operation, task_id=task_id)
    claimed_actor = str(actor_claim.get("id", ""))
    if (
        not decision.allowed
        or not decision.authenticated
        or not decision.issuer
        or decision.actor_id != claimed_actor
        or decision.operation != operation
        or decision.task_id != task_id
    ):
        raise MacError(
            "ACTOR_AUTHORITY_DENIED",
            decision.reason or "actor authority is absent or does not bind this operation",
            exit_code=ExitCode.SECURITY,
            task_id=task_id,
        )
    return decision


def level_at_least(actual: str | None, required: str) -> bool:
    return _LEVEL.get(str(actual), -1) >= _LEVEL[required]


def owner_approvers(scope: Mapping[str, Any], ownership: Mapping[str, Any]) -> set[str]:
    result: set[str] = set()
    definitions = ownership.get("owners") or {}
    for owner in scope.get("owners", []):
        definition = definitions.get(str(owner)) or {}
        result.update(str(actor) for actor in definition.get("approvers", []))
    return result

def governance_sensitive(scope: Mapping[str, Any], config: Mapping[str, Any]) -> bool:
    patterns = ((config.get("security") or {}).get("governance_sensitive_paths") or [])
    if not patterns:
        return False
    matcher = GitIgnoreSpec.from_lines(patterns)
    return any(matcher.match_file(str(path)) for path in scope.get("allowed_paths", []))


def valid_scope_approvals(
    task: Mapping[str, Any], scope: Mapping[str, Any], approvals: Iterable[Mapping[str, Any]],
    ownership: Mapping[str, Any], config: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    authorized = owner_approvers(scope, ownership)
    required = "L2" if governance_sensitive(scope, config) or task.get("mode") == "high_risk" else "L1"
    proposer = str(scope.get("proposed_by", ""))
    result: list[Mapping[str, Any]] = []
    for approval in approvals:
        actor = str((approval.get("actor") or {}).get("id", ""))
        if (
            approval.get("kind") == "scope"
            and approval.get("decision") == "approved"
            and actor in authorized
            and actor != proposer
            and level_at_least(approval.get("independence_level"), required)
            and str(approval.get("subject_ref")) in {"scope-contract.yaml", str(task.get("scope_contract_ref", ""))}
        ):
            result.append(approval)
    return result


def actor_authorized_for_scope(actor: str, scope: Mapping[str, Any], ownership: Mapping[str, Any]) -> bool:
    return actor in owner_approvers(scope, ownership)


def load_runtime_profiles(repo: Path, config: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    root = repo / str((config.get("paths") or {}).get("runtime_profiles", ".agents/runtime-profiles"))
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(root.glob("*.yaml")):
        profile = load_data(path)
        result[str(profile.get("id"))] = profile
    return result
