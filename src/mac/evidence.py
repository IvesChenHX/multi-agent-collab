from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from typing import Any, Iterable, Mapping

from .application.governance import Decision, evaluate_evidence
from .ids import prefixed
from .repository import utc_now

INVALIDATION_MATRIX = {
    "documentation": {"documentation_check"},
    "local_implementation": {"targeted_tests", "affected_module"},
    "public_contract": {"caller_tests", "compatibility", "integration"},
    "data_migration": {"data_compatibility", "migration", "rollback_verification"},
    "auth_security": {"positive_security_tests", "negative_security_tests", "independent_review"},
    "build_deploy": {"build", "startup", "environment_integration"},
    "policy_rebase": {"policy_dependent"},
    "scope_amendment": {"targeted_tests", "independent_review"},
}


def invalidate_evidence(evidence: Mapping[str, Any], *, event_id: str, reason: str) -> dict[str, Any]:
    result = deepcopy(dict(evidence))
    validity = result.setdefault("validity", {})
    previous = list(validity.get("invalidated_by", []))
    validity["status"] = "invalid"
    validity["invalidated_by"] = list(dict.fromkeys([*previous, event_id]))
    validity["reason"] = reason
    return result


def claims_invalidated(change_types: Iterable[str]) -> set[str]:
    return set().union(*(INVALIDATION_MATRIX.get(change_type, set()) for change_type in change_types))


def invalidate_for_changes(evidence: Iterable[Mapping[str, Any]], change_types: Iterable[str], *, event_id: str) -> list[dict[str, Any]]:
    affected = claims_invalidated(change_types)
    result = []
    for item in evidence:
        claims = {str(value) for claim in item.get("claims", []) for value in claim.values()}
        result.append(invalidate_evidence(item, event_id=event_id, reason="change invalidated claims") if claims & affected else deepcopy(dict(item)))
    return result


@dataclass(frozen=True, slots=True)
class PromotionResult:
    evidence: dict[str, Any]
    event_payload: dict[str, Any]


WORKSPACE_EQUIVALENCE_CHECKS = frozenset({
    "source_subject_bound",
    "target_commit_resolved",
    "effective_tree_matches",
    "index_matches",
    "untracked_empty",
    "special_paths_match",
    "lfs_verified",
})


@dataclass(frozen=True, slots=True)
class WorkspaceEquivalenceProof:
    source_workspace_subject: dict[str, Any]
    observed_workspace_subject: dict[str, Any]
    target_commit_subject: dict[str, Any]
    checks: dict[str, bool]
    verifier: str
    digest: str

    @staticmethod
    def _digest(payload: Mapping[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    @classmethod
    def verified(
        cls,
        *,
        source_workspace_subject: Mapping[str, Any],
        observed_workspace_subject: Mapping[str, Any],
        target_commit_subject: Mapping[str, Any],
        checks: Mapping[str, bool],
        verifier: str,
    ) -> "WorkspaceEquivalenceProof":
        payload = {
            "source_workspace_subject": dict(source_workspace_subject),
            "observed_workspace_subject": dict(observed_workspace_subject),
            "target_commit_subject": dict(target_commit_subject),
            "checks": dict(checks),
            "verifier": verifier,
        }
        return cls(**payload, digest=cls._digest(payload))

    def valid(self) -> bool:
        payload = {
            "source_workspace_subject": self.source_workspace_subject,
            "observed_workspace_subject": self.observed_workspace_subject,
            "target_commit_subject": self.target_commit_subject,
            "checks": self.checks,
            "verifier": self.verifier,
        }
        return (
            bool(self.verifier)
            and WORKSPACE_EQUIVALENCE_CHECKS.issubset(self.checks)
            and all(self.checks[name] is True for name in WORKSPACE_EQUIVALENCE_CHECKS)
            and self.digest == self._digest(payload)
        )


def promote_evidence(
    evidence: Mapping[str, Any], *, current_workspace_subject: Mapping[str, Any], target_commit_subject: Mapping[str, Any],
    equivalence_proof: WorkspaceEquivalenceProof | None = None,
    workspace_equivalent: bool | None = None,
) -> PromotionResult:
    if (evidence.get("subject") or {}).get("type") != "workspace" or current_workspace_subject.get("type") != "workspace":
        raise ValueError("only workspace Evidence can be promoted")
    if target_commit_subject.get("type") != "commit" or not target_commit_subject.get("tree_sha"):
        raise ValueError("target commit subject is incomplete")
    if equivalence_proof is None or not equivalence_proof.valid():
        raise ValueError("a structured, verified workspace equivalence proof is required")
    if dict(evidence.get("subject") or {}) != equivalence_proof.source_workspace_subject:
        raise ValueError("workspace equivalence proof does not bind the source Evidence subject")
    if dict(current_workspace_subject) != equivalence_proof.observed_workspace_subject:
        raise ValueError("workspace equivalence proof does not bind the observed workspace")
    if dict(target_commit_subject) != equivalence_proof.target_commit_subject:
        raise ValueError("workspace equivalence proof does not bind the target commit")
    promoted = deepcopy(dict(evidence))
    source_id = str(promoted.get("id"))
    promoted["id"] = prefixed("EVD")
    promoted["subject"] = dict(target_commit_subject)
    promoted["recorded_at"] = utc_now()
    return PromotionResult(promoted, {"source_evidence_id": source_id, "promoted_evidence_id": promoted["id"], "workspace_subject": dict(current_workspace_subject), "commit_subject": dict(target_commit_subject), "equivalence_proof": {"verifier": equivalence_proof.verifier, "digest": equivalence_proof.digest, "checks": dict(equivalence_proof.checks)}})


@dataclass(frozen=True, slots=True)
class GateCoverage:
    complete: bool
    covered_gates: tuple[str, ...]
    missing_gates: tuple[str, ...]
    covered_acceptance: tuple[str, ...]
    missing_acceptance: tuple[str, ...]


def gate_coverage(
    task: Mapping[str, Any], evidence: Iterable[Mapping[str, Any]], *, current_subject: Mapping[str, Any],
    policy_digest: str, runs: Mapping[str, Mapping[str, Any]] | None = None,
) -> GateCoverage:
    required_gates = {str(value) for value in task.get("required_gates", [])}
    required_ac = {str(value["id"]) for value in task.get("acceptance_criteria", []) if value.get("required", True)}
    applicable = required_gates | required_ac
    covered: set[str] = set()
    for item in evidence:
        if evaluate_evidence(item, current_subject=current_subject, policy_digest=policy_digest, runs=runs, applicable_claims=applicable).ok:
            for claim in item.get("claims", []):
                covered.update(str(value) for value in claim.values())
    missing_gates, missing_ac = required_gates - covered, required_ac - covered
    return GateCoverage(not missing_gates and not missing_ac, tuple(sorted(required_gates & covered)), tuple(sorted(missing_gates)), tuple(sorted(required_ac & covered)), tuple(sorted(missing_ac)))
