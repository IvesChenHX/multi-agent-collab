from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from mac.evidence import PromotionResult, WorkspaceEquivalenceProof, invalidate_evidence, promote_evidence
from mac.ids import prefixed
from mac.io import load_data
from mac.repository import FilesystemTaskRepository


class EvidenceService:
    """Event-first Evidence mutation service."""

    def __init__(self, repo: Path) -> None:
        self.repository = FilesystemTaskRepository(repo)

    def invalidate(
        self, task_id: str, evidence_id: str, *, reason: str, expected_revision: int,
        idempotency_key: str, actor: Mapping[str, str],
    ) -> dict[str, Any]:
        path = self.repository.task_dir(task_id) / "evidence" / f"{evidence_id}.json"
        event_id = prefixed("EVT")
        value = invalidate_evidence(load_data(path), event_id=event_id, reason=reason)
        appended = self.repository.append_event(
            task_id, "evidence_invalidated", {"evidence_id": evidence_id, "evidence": value, "reason": reason},
            actor=dict(actor), expected_revision=expected_revision, idempotency_key=idempotency_key,
            event_id=event_id, materializations=[(path, value)], replace_existing={path},
        )
        snapshot = (appended.event.get("payload") or {}).get("evidence")
        return dict(snapshot) if isinstance(snapshot, dict) else load_data(path)

    def promote(
        self, source: Mapping[str, Any], *, current_workspace_subject: Mapping[str, Any],
        target_commit_subject: Mapping[str, Any], equivalence_proof: WorkspaceEquivalenceProof,
    ) -> PromotionResult:
        return promote_evidence(
            source, current_workspace_subject=current_workspace_subject,
            target_commit_subject=target_commit_subject, equivalence_proof=equivalence_proof,
        )
