from __future__ import annotations

from copy import deepcopy

import pytest

from mac.evidence import (
    claims_invalidated,
    gate_coverage,
    invalidate_evidence,
    invalidate_for_changes,
    promote_evidence,
    WorkspaceEquivalenceProof,
)


POLICY = "sha256:" + "a" * 64
WORKSPACE = {
    "type": "workspace", "head_commit": "a" * 40, "index_digest": POLICY,
    "worktree_diff_digest": POLICY, "untracked_manifest_digest": POLICY,
}


def item() -> dict[str, object]:
    return {
        "id": "EVD-01K0W4Z36K3W5C2R0A3M8N9P7X", "kind": "command", "subject": WORKSPACE,
        "policy_digest": POLICY, "run_id": "RUN-1", "claims": [{"gate": "targeted_tests"}, {"acceptance_criterion": "AC-001"}],
        "execution": {"argv": ["pytest"], "exit_code": 0}, "recorded_at": "2026-07-17T00:00:00Z",
        "validity": {"status": "valid", "invalidated_by": []},
    }


def test_invalidation_is_append_only_and_change_matrix_is_selective() -> None:
    invalid = invalidate_evidence(item(), event_id="EVT-1", reason="changed")
    invalid = invalidate_evidence(invalid, event_id="EVT-2", reason="changed again")
    assert invalid["validity"]["invalidated_by"] == ["EVT-1", "EVT-2"]
    assert {"targeted_tests", "negative_security_tests"} <= claims_invalidated(["local_implementation", "auth_security"])
    values = invalidate_for_changes([item()], ["local_implementation"], event_id="EVT-3")
    assert values[0]["validity"]["status"] == "invalid"
    untouched = invalidate_for_changes([item()], ["documentation"], event_id="EVT-4")
    assert untouched[0]["validity"]["status"] == "valid"


def test_workspace_evidence_promotion_requires_exact_verified_workspace() -> None:
    target = {"type": "commit", "commit_sha": "b" * 40, "tree_sha": "c" * 40}
    checks = {
        "source_subject_bound": True,
        "target_commit_resolved": True,
        "effective_tree_matches": True,
        "index_matches": True,
        "untracked_empty": True,
        "special_paths_match": True,
        "lfs_verified": True,
    }
    proof = WorkspaceEquivalenceProof.verified(
        source_workspace_subject=WORKSPACE,
        observed_workspace_subject=WORKSPACE,
        target_commit_subject=target,
        checks=checks,
        verifier="test-git-adapter",
    )
    promoted = promote_evidence(item(), current_workspace_subject=WORKSPACE, target_commit_subject=target, equivalence_proof=proof)
    assert promoted.evidence["subject"]["type"] == "commit"
    assert promoted.evidence["id"] != item()["id"]
    assert promoted.event_payload["source_evidence_id"] == item()["id"]
    with pytest.raises(ValueError):
        promote_evidence(item(), current_workspace_subject=WORKSPACE, target_commit_subject=target, workspace_equivalent=True)
    with pytest.raises(ValueError, match="observed workspace"):
        promote_evidence(item(), current_workspace_subject={**WORKSPACE, "head_commit": "d" * 40}, target_commit_subject=target, equivalence_proof=proof)


def test_gate_coverage_uses_only_current_valid_evidence() -> None:
    task = {"required_gates": ["targeted_tests"], "acceptance_criteria": [{"id": "AC-001", "required": True}, {"id": "AC-OPT", "required": False}]}
    coverage = gate_coverage(task, [item()], current_subject=WORKSPACE, policy_digest=POLICY, runs={"RUN-1": {"status": "succeeded"}})
    assert coverage.complete
    assert coverage.covered_gates == ("targeted_tests",)
    stale = deepcopy(item()); stale["policy_digest"] = "sha256:" + "b" * 64
    missing = gate_coverage(task, [stale], current_subject=WORKSPACE, policy_digest=POLICY, runs={"RUN-1": {"status": "succeeded"}})
    assert not missing.complete
    assert missing.missing_acceptance == ("AC-001",)
