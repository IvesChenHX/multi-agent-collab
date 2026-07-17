from __future__ import annotations

from datetime import datetime, timedelta, timezone

from mac.application.governance import evaluate_close, evaluate_evidence, evaluate_review_independence


def evidence(*, kind: str = "command", gate: str = "targeted_tests") -> dict[str, object]:
    return {
        "id": "EVD-01K0W4Z36K3W5C2R0A3M8N9P7Q", "kind": kind,
        "subject": {"type": "commit", "commit_sha": "a" * 40, "tree_sha": "b" * 40},
        "policy_digest": "sha256:" + "1" * 64, "run_id": "RUN-1",
        "claims": [{"gate": gate}], "execution": {"argv": ["pytest"], "exit_code": 0},
        "validity": {"status": "valid", "invalidated_by": []},
        "review": {"independence_level": "L2", "reviewed_diff_digest": "sha256:" + "2" * 64},
    }


def test_evidence_requires_current_subject_policy_successful_run_and_claim() -> None:
    item = evidence()
    decision = evaluate_evidence(
        item, current_subject=item["subject"], policy_digest=item["policy_digest"],
        runs={"RUN-1": {"status": "succeeded", "independence_level": "L1"}}, applicable_claims={"targeted_tests"},
    )
    assert decision.ok
    assert "EVIDENCE_SUBJECT_MISMATCH" in evaluate_evidence(item, current_subject={"type": "commit"}, policy_digest=item["policy_digest"]).codes


def test_review_independence_uses_run_metadata_not_role_name() -> None:
    item = evidence(kind="review")
    reviewer = {"id": "RUN-R", "status": "succeeded", "actor": {"id": "reviewer", "kind": "agent"}, "independence_level": "L2", "runtime": {"profile": "review-readonly", "provider": "other", "model": "review-model", "execution_context_id": "review"}}
    implementer = {"id": "RUN-I", "actor": {"id": "executor", "kind": "agent"}, "runtime": {"profile": "implementation", "provider": "codex", "model": "gpt-5", "execution_context_id": "impl"}}
    profiles = {"review-readonly": {"capabilities": {"read_only_run": "native"}}, "implementation": {"capabilities": {"read_only_run": "unavailable"}}}
    assert evaluate_review_independence(item, reviewer, [implementer], current_diff_digest="sha256:" + "2" * 64, minimum_level="L2", runtime_profiles=profiles).ok
    reviewer["runtime"]["profile"] = "implementation"
    assert "REVIEW_WRITE_CAPABILITY" in evaluate_review_independence(item, reviewer, [implementer], current_diff_digest="sha256:" + "2" * 64, minimum_level="L2", runtime_profiles=profiles).codes


def test_close_is_gate_coverage_not_natural_language_summary() -> None:
    item = evidence()
    item["claims"] = [{"gate": "targeted_tests"}, {"acceptance_criterion": "AC-001"}]
    task = {"mode": "standard", "required_gates": ["targeted_tests"], "acceptance_criteria": [{"id": "AC-001", "required": True}], "work_units_complete": True}
    decision = evaluate_close(
        task, {"status": "approved"}, [item], [], {"RUN-1": {"status": "succeeded", "independence_level": "L1"}}, [],
        current_subject=item["subject"], policy_digest=item["policy_digest"], close_actor="closer",
        authorized_closers={"closer"}, non_waivable_gates={"approved_scope", "evidence_matches_current_commit", "independent_review"},
    )
    assert decision.ok
    task["required_gates"] = ["targeted_tests", "rollback_plan"]
    assert "CLOSE_GATE_MISSING" in evaluate_close(
        task, {"status": "approved"}, [item], [], {"RUN-1": {"status": "succeeded"}}, [],
        current_subject=item["subject"], policy_digest=item["policy_digest"], close_actor="closer",
        authorized_closers={"closer"}, non_waivable_gates=set(),
    ).codes
