from __future__ import annotations

from mac.application.governance import evaluate_close


DIGEST_A = "sha256:" + ("a" * 64)
DIGEST_B = "sha256:" + ("b" * 64)


def workspace_subject(*, diff_digest: str = DIGEST_A) -> dict[str, str]:
    return {
        "type": "workspace",
        "head_commit": "a" * 40,
        "index_digest": DIGEST_A,
        "worktree_diff_digest": diff_digest,
        "untracked_manifest_digest": DIGEST_A,
    }


def task() -> dict[str, object]:
    return {
        "id": "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        "mode": "high_risk",
        "state": "reviewing",
        "acceptance_criteria": [{"id": "AC-001", "text": "secure", "required": True}],
        "required_gates": ["targeted_tests", "independent_review"],
    }


def scope() -> dict[str, object]:
    return {
        "status": "approved",
        "allowed_paths": ["src/**", "tests/**"],
        "allowed_operations": ["write", "execute_tests"],
        "required_gates": ["targeted_tests", "independent_review"],
    }


def run(run_id: str, *, context: str, level: str, can_write: bool) -> dict[str, object]:
    return {
        "id": run_id,
        "status": "succeeded",
        "actor": {"id": f"ACTOR-{run_id[-2:]}", "kind": "agent"},
        "runtime": {
            "profile": "implementation" if can_write else "review-readonly",
            "provider": "codex" if can_write else "independent-runtime",
            "model": "gpt-5" if can_write else "review-model",
            "execution_context_id": context,
        },
        "independence_level": level,
        "can_write_business_code": can_write,
    }


def runs() -> dict[str, dict[str, object]]:
    implementer = run(
        "RUN-01K0W4Z36K3W5C2R0A3M8N9P7T",
        context="implementation",
        level="L0",
        can_write=True,
    )
    reviewer = run(
        "RUN-01K0W4Z36K3W5C2R0A3M8N9P7V",
        context="review",
        level="L2",
        can_write=False,
    )
    return {str(implementer["id"]): implementer, str(reviewer["id"]): reviewer}


def evidence() -> list[dict[str, object]]:
    subject = workspace_subject()
    return [
        {
            "id": "EVD-01K0W4Z36K3W5C2R0A3M8N9P7X",
            "kind": "command",
            "subject": subject,
            "policy_digest": DIGEST_A,
            "run_id": "RUN-01K0W4Z36K3W5C2R0A3M8N9P7T",
            "claims": [{"acceptance_criterion": "AC-001"}, {"gate": "targeted_tests"}],
            "execution": {"argv": ["pytest", "tests/security"], "exit_code": 0},
            "validity": {"status": "valid", "invalidated_by": []},
        },
        {
            "id": "EVD-01K0W4Z36K3W5C2R0A3M8N9P7Y",
            "kind": "review",
            "subject": subject,
            "policy_digest": DIGEST_A,
            "run_id": "RUN-01K0W4Z36K3W5C2R0A3M8N9P7V",
            "claims": [{"gate": "independent_review"}],
            "review": {"independence_level": "L2", "reviewed_diff_digest": DIGEST_A},
            "validity": {"status": "valid", "invalidated_by": []},
        },
    ]


def close(
    *,
    evidence_records: list[dict[str, object]] | None = None,
    run_records: dict[str, dict[str, object]] | None = None,
    findings: list[dict[str, object]] | None = None,
    acceptances: list[dict[str, object]] | None = None,
):
    return evaluate_close(
        task(),
        scope(),
        evidence_records if evidence_records is not None else evidence(),
        findings if findings is not None else [],
        run_records if run_records is not None else runs(),
        acceptances if acceptances is not None else [],
        current_subject=workspace_subject(),
        policy_digest=DIGEST_A,
        close_actor="ACTOR-closer",
        authorized_closers={"ACTOR-closer"},
        non_waivable_gates={"scope_approved", "data_integrity", "independent_review"},
        runtime_profiles={
            "review-readonly": {"capabilities": {"read_only_run": "native"}},
            "implementation": {"capabilities": {"read_only_run": "unavailable"}},
        },
    )


def test_close_engine_rejects_evidence_for_old_workspace() -> None:
    records = evidence()
    records[0]["subject"] = workspace_subject(diff_digest=DIGEST_B)

    decision = close(evidence_records=records)

    assert not decision.ok
    assert "EVIDENCE_SUBJECT_MISMATCH" in decision.codes


def test_close_engine_rejects_evidence_from_old_policy_snapshot() -> None:
    records = evidence()
    records[0]["policy_digest"] = DIGEST_B

    decision = close(evidence_records=records)

    assert not decision.ok
    assert "EVIDENCE_POLICY_MISMATCH" in decision.codes


def test_close_engine_rejects_review_performed_by_implementer_run() -> None:
    records = evidence()
    run_records = runs()
    implementer_id = "RUN-01K0W4Z36K3W5C2R0A3M8N9P7T"
    records[1]["run_id"] = implementer_id
    records[1]["review"]["independence_level"] = "L2"

    decision = close(evidence_records=records, run_records=run_records)

    assert not decision.ok
    assert "REVIEW_SAME_RUN" in decision.codes


def test_close_engine_rejects_risk_acceptance_for_non_waivable_gate() -> None:
    finding = {
        "id": "FND-01K0W4Z36K3W5C2R0A3M8N9P7Z",
        "severity": "major",
        "category": "policy",
        "blocking_effect": "waiver_allowed",
        "status": "open",
        "invalidates": ["scope_approved"],
    }
    acceptance = {
        "id": "RISK-01K0W4Z36K3W5C2R0A3M8N9P90",
        "finding_ids": [finding["id"]],
        "accepted_by": {"id": "ACTOR-product-owner", "kind": "human"},
        "accepted_at": "2026-07-17T07:00:00Z",
        "rationale": "attempted override",
        "compensating_controls": ["none can replace approved scope"],
        "expires_at": "2099-07-18T08:00:00Z",
        "scope": {"environments": ["staging"]},
    }

    decision = close(findings=[finding], acceptances=[acceptance])

    assert not decision.ok
    assert "RISK_NON_WAIVABLE" in decision.codes
