from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from mac.evidence import PromotionResult, WorkspaceEquivalenceProof, invalidate_evidence, promote_evidence
from mac.ids import prefixed
from mac.io import load_data
from mac.repository import AppendEvent, FilesystemTaskRepository, MutationGateway


class EvidenceService:
    """Event-first Evidence mutation service."""

    def __init__(
        self,
        repo: Path,
        repository: FilesystemTaskRepository | None = None,
        gateway: MutationGateway | None = None,
    ) -> None:
        self.repository = repository or FilesystemTaskRepository(repo)
        self.mutations = gateway or MutationGateway(repo, repository=self.repository)

    def invalidate(
        self, task_id: str, evidence_id: str, *, reason: str, expected_revision: int,
        idempotency_key: str, actor: Mapping[str, str],
    ) -> dict[str, Any]:
        path = self.repository.task_dir(task_id) / "evidence" / f"{evidence_id}.json"
        existing = self.repository._existing_idempotency(task_id, idempotency_key)
        if existing is not None:
            payload = dict(existing.get("payload") or {})
            snapshot = payload.get("evidence")
            if existing.get("event_type") != "evidence_invalidated" or not isinstance(snapshot, dict):
                raise ValueError("idempotency key belongs to another Evidence mutation")
            replayed = self.mutations.execute(AppendEvent(
                task_id=task_id,
                event_type="evidence_invalidated",
                payload=payload,
                actor_claim=actor,
                expected_revision=expected_revision,
                idempotency_key=idempotency_key,
                operation="evidence.invalidate",
                event_id=str(existing.get("event_id") or "") or None,
                materializations=((path, snapshot),),
                replace_existing=frozenset({path}),
                replay_intent={"evidence_id": evidence_id, "reason": reason},
            ))
            replay_snapshot = ((replayed.event or {}).get("payload") or {}).get("evidence")
            return dict(replay_snapshot) if isinstance(replay_snapshot, dict) else dict(snapshot)
        event_id = prefixed("EVT")
        value = invalidate_evidence(load_data(path), event_id=event_id, reason=reason)
        appended = self.mutations.execute(AppendEvent(
            task_id=task_id,
            event_type="evidence_invalidated",
            payload={"evidence_id": evidence_id, "evidence": value, "reason": reason},
            actor_claim=dict(actor),
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            operation="evidence.invalidate",
            event_id=event_id,
            materializations=((path, value),),
            replace_existing=frozenset({path}),
            replay_intent={"evidence_id": evidence_id, "reason": reason},
        ))
        snapshot = ((appended.event or {}).get("payload") or {}).get("evidence")
        return dict(snapshot) if isinstance(snapshot, dict) else load_data(path)

    def promote(
        self, source: Mapping[str, Any], *, current_workspace_subject: Mapping[str, Any],
        target_commit_subject: Mapping[str, Any], equivalence_proof: WorkspaceEquivalenceProof,
    ) -> PromotionResult:
        return promote_evidence(
            source, current_workspace_subject=current_workspace_subject,
            target_commit_subject=target_commit_subject, equivalence_proof=equivalence_proof,
        )
