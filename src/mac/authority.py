from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol

from pathspec import PathSpec

from .errors import ExitCode, MacError
from .io import load_data


_LEVEL = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}
_VERIFIED_CONTEXT_SEAL = object()


class ExternalAuthorityVerifier(Protocol):
    """Trust-boundary port implemented by a runtime adapter or human gate."""

    def verify(self, assertion: Mapping[str, Any]) -> Mapping[str, Any] | None: ...


@dataclass(frozen=True, slots=True)
class VerifiedRuntimeProvenance:
    profile: str
    execution_context_id: str
    provider: str
    model: str
    read_only: bool
    commit_participation: tuple[str, ...]


@dataclass(frozen=True, slots=True, init=False)
class VerifiedAuthorityContext:
    """Normalized output from an injected verifier; public CLI flags cannot create it."""

    actor_id: str
    actor_kind: str
    source: str
    assertion_digest: str
    runtime: VerifiedRuntimeProvenance | None = None

    def __init__(
        self,
        actor_id: str,
        actor_kind: str,
        source: str,
        assertion_digest: str,
        runtime: VerifiedRuntimeProvenance | None = None,
        *,
        _seal: object | None = None,
    ) -> None:
        if _seal is not _VERIFIED_CONTEXT_SEAL:
            raise TypeError("VerifiedAuthorityContext must be created by an injected external verifier")
        object.__setattr__(self, "actor_id", actor_id)
        object.__setattr__(self, "actor_kind", actor_kind)
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "assertion_digest", assertion_digest)
        object.__setattr__(self, "runtime", runtime)

    def actor(self) -> dict[str, str]:
        return {"id": self.actor_id, "kind": self.actor_kind}

    def audit_record(self) -> dict[str, str]:
        # Persist only identity/source correlation, never the assertion or credential.
        return {
            "actor_id": self.actor_id,
            "source": self.source,
            "assertion_digest": self.assertion_digest,
        }


def verify_external_authority(
    assertion: Mapping[str, Any], verifier: ExternalAuthorityVerifier,
) -> VerifiedAuthorityContext:
    """Convert an external assertion only after an injected verifier accepts it."""

    verified = verifier.verify(assertion)
    if not isinstance(verified, Mapping):
        raise MacError(
            "EXTERNAL_AUTHORITY_REJECTED",
            "external authority verifier rejected the assertion",
            exit_code=ExitCode.EXTERNAL,
        )
    actor = verified.get("actor") or {}
    actor_id = str(actor.get("id", ""))
    actor_kind = str(actor.get("kind", ""))
    source = str(verified.get("source", ""))
    if not actor_id or actor_kind not in {"human", "agent", "automation"} or not source:
        raise MacError(
            "EXTERNAL_AUTHORITY_INVALID",
            "verified authority requires actor id, actor kind, and source",
            exit_code=ExitCode.EXTERNAL,
        )
    runtime_value = verified.get("runtime")
    runtime: VerifiedRuntimeProvenance | None = None
    normalized: dict[str, Any] = {"actor": {"id": actor_id, "kind": actor_kind}, "source": source}
    if runtime_value is not None:
        if not isinstance(runtime_value, Mapping):
            raise MacError("PROVENANCE_UNVERIFIED", "verified runtime provenance is invalid", exit_code=ExitCode.EXTERNAL)
        required = ("profile", "execution_context_id", "provider", "model")
        values = {name: str(runtime_value.get(name, "")) for name in required}
        read_only = runtime_value.get("read_only")
        participation = runtime_value.get("commit_participation")
        if any(not value for value in values.values()) or read_only is not True or not isinstance(participation, (list, tuple)):
            raise MacError(
                "PROVENANCE_UNVERIFIED",
                "verified runtime provenance must prove profile, context, provider, model, read-only state, and commit participation",
                exit_code=ExitCode.EXTERNAL,
            )
        commits = tuple(str(value) for value in participation)
        if any(len(value) != 40 or any(char not in "0123456789abcdef" for char in value) for value in commits):
            raise MacError("PROVENANCE_UNVERIFIED", "commit participation must contain Git object ids", exit_code=ExitCode.EXTERNAL)
        runtime = VerifiedRuntimeProvenance(
            profile=values["profile"],
            execution_context_id=values["execution_context_id"],
            provider=values["provider"],
            model=values["model"],
            read_only=True,
            commit_participation=commits,
        )
        normalized["runtime"] = {
            **values,
            "read_only": True,
            "commit_participation": list(commits),
        }
    digest = "sha256:" + hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return VerifiedAuthorityContext(
        actor_id, actor_kind, source, digest, runtime, _seal=_VERIFIED_CONTEXT_SEAL,
    )


def require_external_authority(
    declared_actor: str, context: VerifiedAuthorityContext | None, *, operation: str,
) -> VerifiedAuthorityContext:
    if context is None:
        raise MacError(
            "EXTERNAL_AUTHORITY_REQUIRED",
            f"{operation} requires identity verified by an external runtime adapter or human gate",
            exit_code=ExitCode.EXTERNAL,
            suggestion="supply the operation through a runtime adapter or external approval gate",
        )
    if context.actor_id != declared_actor:
        raise MacError(
            "ACTOR_CONTEXT_MISMATCH",
            "declared actor does not match the externally verified actor",
            exit_code=ExitCode.SECURITY,
            details={"declared_actor": declared_actor, "verified_actor": context.actor_id},
        )
    return context


def verified_entity_ids(events: Iterable[Mapping[str, Any]], reference_key: str) -> set[str]:
    result: set[str] = set()
    for event in events:
        payload = event.get("payload") or {}
        authority = payload.get("verified_authority") or {}
        value = payload.get(reference_key)
        actor = event.get("actor") or {}
        actor_id = str(actor.get("id", ""))
        actor_kind = str(actor.get("kind", ""))
        source = str(authority.get("source", ""))
        digest = str(authority.get("assertion_digest", ""))
        if not value or authority.get("actor_id") != actor_id or not source:
            continue
        normalized: dict[str, Any] = {"actor": {"id": actor_id, "kind": actor_kind}, "source": source}
        if reference_key == "run_id":
            run = payload.get("run") or {}
            runtime = run.get("runtime") or {}
            attestation = run.get("independence_attestation") or {}
            if not all(runtime.get(name) for name in ("profile", "execution_context_id", "provider", "model")):
                continue
            if attestation.get("read_only") is not True or not isinstance(attestation.get("commit_participation"), list):
                continue
            normalized["runtime"] = {
                "profile": str(runtime["profile"]),
                "execution_context_id": str(runtime["execution_context_id"]),
                "provider": str(runtime["provider"]),
                "model": str(runtime["model"]),
                "read_only": True,
                "commit_participation": [str(item) for item in attestation["commit_participation"]],
            }
        expected = "sha256:" + hashlib.sha256(
            json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if digest == expected:
            result.add(str(value))
    return result


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
    matcher = PathSpec.from_lines("gitwildmatch", patterns)
    return any(matcher.match_file(str(path)) for path in scope.get("allowed_paths", []))


def valid_scope_approvals(
    task: Mapping[str, Any], scope: Mapping[str, Any], approvals: Iterable[Mapping[str, Any]],
    ownership: Mapping[str, Any], config: Mapping[str, Any], *,
    trusted_approval_ids: set[str] | None = None,
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
            and (trusted_approval_ids is None or str(approval.get("id", "")) in trusted_approval_ids)
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
