from __future__ import annotations

from mac.application.governance import evaluate_close
from mac.authority import scope_binding
from mac.repository import _close_transition_facts


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
    evidence_revisions: dict[str, int] | None = None,
    minimum_evidence_revision: int | None = None,
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
        evidence_revisions=evidence_revisions,
        minimum_evidence_revision=minimum_evidence_revision,
    )


def test_close_engine_rejects_evidence_for_old_workspace() -> None:
    records = evidence()
    records[0]["subject"] = workspace_subject(diff_digest=DIGEST_B)

    decision = close(evidence_records=records)

    assert not decision.ok
    assert "EVIDENCE_SUBJECT_MISMATCH" in decision.codes


def test_review_entry_requires_all_non_review_evidence_but_not_the_review_itself() -> None:
    missing = close(evidence_records=[], run_records={})
    assert not _close_transition_facts(
        missing,
        "reviewing",
        actor_authorized=True,
    )["evidence_complete"]

    implementation_only = close(
        evidence_records=evidence()[:1],
        run_records={next(iter(runs())): next(iter(runs().values()))},
    )
    facts = _close_transition_facts(
        implementation_only,
        "reviewing",
        actor_authorized=True,
    )
    assert facts["evidence_complete"]
    assert not facts["review_complete"]


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
        "scope": scope_binding(scope()),
    }

    decision = close(findings=[finding], acceptances=[acceptance])

    assert not decision.ok
    assert "RISK_NON_WAIVABLE" in decision.codes


def test_close_engine_rejects_risk_acceptance_from_an_old_scope() -> None:
    finding = {
        "id": "FND-01K0W4Z36K3W5C2R0A3M8N9P7Z",
        "severity": "major",
        "category": "maintainability",
        "blocking_effect": "waiver_allowed",
        "status": "open",
        "invalidates": [],
    }
    acceptance = {
        "id": "RISK-01K0W4Z36K3W5C2R0A3M8N9P90",
        "finding_ids": [finding["id"]],
        "accepted_by": {"id": "ACTOR-product-owner", "kind": "human"},
        "accepted_at": "2026-07-17T07:00:00Z",
        "rationale": "accepted before amendment",
        "compensating_controls": ["manual review"],
        "expires_at": "2099-07-18T08:00:00Z",
        "scope": {"paths": ["src/**"]},
    }

    decision = close(findings=[finding], acceptances=[acceptance])

    assert not decision.ok
    assert "RISK_SCOPE_STALE" in decision.codes


def test_close_independence_uses_only_runs_bound_to_implementation_evidence() -> None:
    run_records = runs()
    unrelated = run(
        "RUN-01K0W4Z36K3W5C2R0A3M8N9P8A",
        context="review",
        level="L0",
        can_write=True,
    )
    unrelated["actor"] = run_records["RUN-01K0W4Z36K3W5C2R0A3M8N9P7V"]["actor"]
    run_records[str(unrelated["id"])] = unrelated

    decision = close(run_records=run_records)

    assert decision.ok, decision.codes


def test_close_inherits_required_gates_from_scope_and_mode_policy() -> None:
    scoped = scope()
    scoped["required_gates"] = [*scoped["required_gates"], "scope_guard"]

    decision = evaluate_close(
        task(),
        scoped,
        evidence(),
        [],
        runs(),
        [],
        current_subject=workspace_subject(),
        policy_digest=DIGEST_A,
        close_actor="ACTOR-closer",
        authorized_closers={"ACTOR-closer"},
        non_waivable_gates={"scope_approved", "data_integrity", "independent_review"},
        runtime_profiles={
            "review-readonly": {"capabilities": {"read_only_run": "native"}},
            "implementation": {"capabilities": {"read_only_run": "unavailable"}},
        },
        mode_required_gates={"negative_security_tests"},
    )

    assert not decision.ok
    assert "CLOSE_GATE_MISSING" in decision.codes
    missing = next(issue.details["gates"] for issue in decision.issues if issue.code == "CLOSE_GATE_MISSING")
    assert {"scope_guard", "negative_security_tests"} <= set(missing)


def test_current_evidence_replaces_an_invalid_historical_attempt() -> None:
    records = evidence()
    invalid = dict(records[0])
    invalid["id"] = "EVD-01K0W4Z36K3W5C2R0A3M8N9P80"
    invalid["validity"] = {"status": "invalid", "invalidated_by": ["workspace_change"]}

    decision = close(evidence_records=[invalid, *records])

    assert decision.ok, decision.codes
    assert "EVIDENCE_STATUS_INVALID" not in decision.codes


def test_scope_revision_invalidates_only_evidence_recorded_before_the_amendment() -> None:
    records = evidence()
    old = dict(records[0])
    old["id"] = "EVD-01K0W4Z36K3W5C2R0A3M8N9P80"
    current = dict(records[0])
    current["id"] = "EVD-01K0W4Z36K3W5C2R0A3M8N9P81"
    revisions = {
        str(old["id"]): 4,
        str(current["id"]): 8,
        str(records[1]["id"]): 8,
    }

    decision = close(
        evidence_records=[old, current, records[1]],
        evidence_revisions=revisions,
        minimum_evidence_revision=6,
    )

    assert decision.ok, decision.codes
    assert "EVIDENCE_SCOPE_STALE" not in decision.codes


def test_current_risk_acceptance_replaces_an_expired_historical_acceptance() -> None:
    finding = {
        "id": "FND-01K0W4Z36K3W5C2R0A3M8N9P7Z",
        "severity": "major",
        "category": "maintainability",
        "blocking_effect": "waiver_allowed",
        "confidence": "probable",
        "status": "open",
        "invalidates": [],
    }
    base = {
        "finding_ids": [finding["id"]],
        "accepted_by": {"id": "ACTOR-closer", "kind": "human"},
        "accepted_at": "2026-07-17T07:00:00Z",
        "rationale": "bounded operational risk",
        "compensating_controls": ["manual review"],
        "scope": scope_binding(scope()),
    }
    expired = {
        **base,
        "id": "RISK-01K0W4Z36K3W5C2R0A3M8N9P90",
        "expires_at": "2026-07-18T08:00:00Z",
    }
    current = {
        **base,
        "id": "RISK-01K0W4Z36K3W5C2R0A3M8N9P91",
        "expires_at": "2099-07-18T08:00:00Z",
    }

    decision = close(findings=[finding], acceptances=[expired, current])

    assert decision.ok, decision.codes
    assert "RISK_EXPIRED" not in decision.codes


def test_resolved_finding_does_not_keep_an_expired_waiver_on_the_close_frontier() -> None:
    finding = {
        "id": "FND-01K0W4Z36K3W5C2R0A3M8N9P7Z",
        "severity": "major",
        "category": "maintainability",
        "blocking_effect": "waiver_allowed",
        "confidence": "probable",
        "status": "resolved",
        "invalidates": [],
    }
    expired = {
        "id": "RISK-01K0W4Z36K3W5C2R0A3M8N9P90",
        "finding_ids": [finding["id"]],
        "accepted_by": {"id": "ACTOR-closer", "kind": "human"},
        "accepted_at": "2026-07-17T07:00:00Z",
        "rationale": "historical waiver",
        "compensating_controls": ["manual review"],
        "expires_at": "2026-07-18T08:00:00Z",
        "scope": scope_binding(scope()),
    }

    decision = close(findings=[finding], acceptances=[expired])

    assert decision.ok, decision.codes
    assert "RISK_EXPIRED" not in decision.codes
