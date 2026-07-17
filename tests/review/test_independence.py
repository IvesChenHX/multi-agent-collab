from __future__ import annotations

import pytest

from mac.application.governance import evaluate_review_independence


DIFF_A = "sha256:" + ("a" * 64)
DIFF_B = "sha256:" + ("b" * 64)
RUNTIME_PROFILES = {
    "review-readonly": {"capabilities": {"read_only_run": "native"}},
    "implementation": {"capabilities": {"read_only_run": "unavailable"}},
}


def run(
    run_id: str,
    *,
    context: str,
    level: str,
    actor_kind: str = "agent",
    provider: str = "codex",
    model: str = "gpt-5",
    can_write: bool = False,
) -> dict[str, object]:
    return {
        "id": run_id,
        "status": "succeeded",
        "actor": {"id": f"ACTOR-{run_id[-4:]}", "kind": actor_kind},
        "runtime": {
            "profile": "review-readonly" if not can_write else "implementation",
            "provider": provider,
            "model": model,
            "execution_context_id": context,
        },
        "independence_level": level,
        "can_write_business_code": can_write,
    }


def review_evidence(*, run_id: str, level: str, diff: str = DIFF_A) -> dict[str, object]:
    return {
        "kind": "review",
        "run_id": run_id,
        "review": {
            "independence_level": level,
            "reviewed_diff_digest": diff,
        },
        "validity": {"status": "valid", "invalidated_by": []},
    }


def implementer_run() -> dict[str, object]:
    return run(
        "RUN-01K0W4Z36K3W5C2R0A3M8N9P7T",
        context="context-implementation",
        level="L0",
        provider="codex",
        model="gpt-5",
        can_write=True,
    )


def independent_reviewer(level: str) -> dict[str, object]:
    if level == "L1":
        return run(
            "RUN-01K0W4Z36K3W5C2R0A3M8N9P7V",
            context="context-review",
            level=level,
        )
    if level == "L2":
        return run(
            "RUN-01K0W4Z36K3W5C2R0A3M8N9P7V",
            context="context-review",
            level=level,
            provider="other-runtime",
            model="review-model",
        )
    if level == "L3":
        return run(
            "RUN-01K0W4Z36K3W5C2R0A3M8N9P7V",
            context="context-review",
            level=level,
            actor_kind="human",
            provider="human",
            model="domain-reviewer",
        )
    return run(
        "RUN-01K0W4Z36K3W5C2R0A3M8N9P7V",
        context="context-self-check",
        level=level,
    )


@pytest.mark.parametrize(
    ("actual", "minimum"),
    [
        ("L0", "L0"),
        ("L1", "L1"),
        ("L2", "L1"),
        ("L2", "L2"),
        ("L3", "L2"),
        ("L3", "L3"),
    ],
)
def test_independence_levels_l0_through_l3_satisfy_only_equal_or_lower_policy(
    actual: str,
    minimum: str,
) -> None:
    reviewer = independent_reviewer(actual)
    implementers = [] if actual == "L0" else [implementer_run()]

    decision = evaluate_review_independence(
        review_evidence(run_id=str(reviewer["id"]), level=actual),
        reviewer_run=reviewer,
        implementer_runs=implementers,
        current_diff_digest=DIFF_A,
        minimum_level=minimum,
        runtime_profiles=RUNTIME_PROFILES,
    )

    assert decision.ok, decision.codes


@pytest.mark.parametrize(("actual", "minimum"), [("L0", "L1"), ("L1", "L2"), ("L2", "L3")])
def test_independence_levels_cannot_be_claimed_above_their_actual_level(actual: str, minimum: str) -> None:
    reviewer = independent_reviewer(actual)

    decision = evaluate_review_independence(
        review_evidence(run_id=str(reviewer["id"]), level=actual),
        reviewer_run=reviewer,
        implementer_runs=[] if actual == "L0" else [implementer_run()],
        current_diff_digest=DIFF_A,
        minimum_level=minimum,
        runtime_profiles=RUNTIME_PROFILES,
    )

    assert not decision.ok
    assert "REVIEW_LEVEL_INSUFFICIENT" in decision.codes


def test_reviewer_and_implementer_cannot_be_the_same_run() -> None:
    implementer = implementer_run()

    decision = evaluate_review_independence(
        review_evidence(run_id=str(implementer["id"]), level="L2"),
        reviewer_run=implementer,
        implementer_runs=[implementer],
        current_diff_digest=DIFF_A,
        minimum_level="L2",
        runtime_profiles=RUNTIME_PROFILES,
    )

    assert not decision.ok
    assert "REVIEW_SAME_RUN" in decision.codes


def test_new_run_in_same_execution_context_is_not_independent() -> None:
    implementer = implementer_run()
    reviewer = independent_reviewer("L1")
    reviewer["runtime"]["execution_context_id"] = implementer["runtime"]["execution_context_id"]

    decision = evaluate_review_independence(
        review_evidence(run_id=str(reviewer["id"]), level="L1"),
        reviewer_run=reviewer,
        implementer_runs=[implementer],
        current_diff_digest=DIFF_A,
        minimum_level="L1",
        runtime_profiles=RUNTIME_PROFILES,
    )

    assert not decision.ok
    assert "REVIEW_SAME_CONTEXT" in decision.codes


def test_l2_reviewer_with_business_write_capability_is_rejected() -> None:
    reviewer = independent_reviewer("L2")
    reviewer["runtime"]["profile"] = "implementation"

    decision = evaluate_review_independence(
        review_evidence(run_id=str(reviewer["id"]), level="L2"),
        reviewer_run=reviewer,
        implementer_runs=[implementer_run()],
        current_diff_digest=DIFF_A,
        minimum_level="L2",
        runtime_profiles=RUNTIME_PROFILES,
    )

    assert not decision.ok
    assert "REVIEW_WRITE_CAPABILITY" in decision.codes


def test_l2_policy_only_read_only_claim_fails_closed() -> None:
    reviewer = independent_reviewer("L2")
    profiles = {**RUNTIME_PROFILES, "review-readonly": {"capabilities": {"read_only_run": "policy_only"}}}

    decision = evaluate_review_independence(
        review_evidence(run_id=str(reviewer["id"]), level="L2"),
        reviewer_run=reviewer,
        implementer_runs=[implementer_run()],
        current_diff_digest=DIFF_A,
        minimum_level="L2",
        runtime_profiles=profiles,
    )

    assert "REVIEW_WRITE_CAPABILITY" in decision.codes


def test_reviewer_that_contributed_to_reviewed_commit_is_rejected() -> None:
    reviewer = independent_reviewer("L2")
    reviewer["actor"] = implementer_run()["actor"]

    decision = evaluate_review_independence(
        review_evidence(run_id=str(reviewer["id"]), level="L2"),
        reviewer_run=reviewer,
        implementer_runs=[implementer_run()],
        current_diff_digest=DIFF_A,
        minimum_level="L2",
        runtime_profiles=RUNTIME_PROFILES,
    )

    assert not decision.ok
    assert "REVIEW_COMMIT_PARTICIPATION" in decision.codes


def test_review_becomes_stale_when_diff_changes_after_review_started() -> None:
    reviewer = independent_reviewer("L2")

    decision = evaluate_review_independence(
        review_evidence(run_id=str(reviewer["id"]), level="L2", diff=DIFF_A),
        reviewer_run=reviewer,
        implementer_runs=[implementer_run()],
        current_diff_digest=DIFF_B,
        minimum_level="L2",
        runtime_profiles=RUNTIME_PROFILES,
    )

    assert not decision.ok
    assert "REVIEW_DIFF_STALE" in decision.codes
