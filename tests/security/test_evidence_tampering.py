from __future__ import annotations

from copy import deepcopy

from mac.application.governance import evaluate_evidence


DIGEST_A = "sha256:" + ("a" * 64)
DIGEST_B = "sha256:" + ("b" * 64)
COMMIT_A = "a" * 40
COMMIT_B = "b" * 40


def commit_subject(commit: str) -> dict[str, str]:
    return {"type": "commit", "commit_sha": commit, "tree_sha": commit}


def valid_evidence() -> dict[str, object]:
    return {
        "id": "EVD-01K0W4Z36K3W5C2R0A3M8N9P7X",
        "kind": "command",
        "subject": commit_subject(COMMIT_A),
        "policy_digest": DIGEST_A,
        "run_id": "RUN-01K0W4Z36K3W5C2R0A3M8N9P7T",
        "claims": [{"gate": "targeted_tests"}],
        "execution": {"argv": ["pytest", "tests/security"], "exit_code": 0},
        "validity": {"status": "valid", "invalidated_by": []},
    }


def succeeded_run() -> dict[str, object]:
    return {
        "id": "RUN-01K0W4Z36K3W5C2R0A3M8N9P7T",
        "status": "succeeded",
        "independence_level": "L0",
    }


def test_old_evidence_cannot_cover_current_commit() -> None:
    decision = evaluate_evidence(
        valid_evidence(),
        current_subject=commit_subject(COMMIT_B),
        policy_digest=DIGEST_A,
        runs={succeeded_run()["id"]: succeeded_run()},
        applicable_claims={"targeted_tests"},
    )

    assert not decision.ok
    assert "EVIDENCE_SUBJECT_MISMATCH" in decision.codes


def test_evidence_bound_to_changed_policy_digest_is_invalid() -> None:
    decision = evaluate_evidence(
        valid_evidence(),
        current_subject=commit_subject(COMMIT_A),
        policy_digest=DIGEST_B,
        runs={succeeded_run()["id"]: succeeded_run()},
        applicable_claims={"targeted_tests"},
    )

    assert not decision.ok
    assert "EVIDENCE_POLICY_MISMATCH" in decision.codes


def test_failed_run_cannot_be_relabelled_as_valid_evidence() -> None:
    run = succeeded_run()
    run["status"] = "failed"
    evidence = valid_evidence()
    evidence["execution"] = {"argv": ["pytest"], "exit_code": 1}

    decision = evaluate_evidence(
        evidence,
        current_subject=commit_subject(COMMIT_A),
        policy_digest=DIGEST_A,
        runs={run["id"]: run},
        applicable_claims={"targeted_tests"},
    )

    assert not decision.ok
    assert "EVIDENCE_RUN_INVALID" in decision.codes


def test_invalidated_evidence_never_becomes_valid_by_reusing_the_record() -> None:
    evidence = deepcopy(valid_evidence())
    evidence["validity"] = {
        "status": "invalid",
        "invalidated_by": ["EVT-01K0W4Z36K3W5C2R0A3M8N9P81"],
        "reason": "scope amended",
    }

    decision = evaluate_evidence(
        evidence,
        current_subject=commit_subject(COMMIT_A),
        policy_digest=DIGEST_A,
        runs={succeeded_run()["id"]: succeeded_run()},
        applicable_claims={"targeted_tests"},
    )

    assert not decision.ok
    assert "EVIDENCE_STATUS_INVALID" in decision.codes
