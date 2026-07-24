from __future__ import annotations

from datetime import datetime, timezone

from mac.application.governance import validate_risk_acceptance


NOW = datetime(2026, 7, 17, 8, 0, tzinfo=timezone.utc)
FINDING_ID = "FND-01K0W4Z36K3W5C2R0A3M8N9P7Z"


def waiver_allowed_finding() -> dict[str, object]:
    return {
        "id": FINDING_ID,
        "severity": "major",
        "category": "operations",
        "blocking_effect": "waiver_allowed",
        "status": "open",
        "invalidates": ["staging_smoke"],
    }


def valid_acceptance() -> dict[str, object]:
    return {
        "id": "RISK-01K0W4Z36K3W5C2R0A3M8N9P90",
        "finding_ids": [FINDING_ID],
        "accepted_by": {"id": "ACTOR-product-owner", "kind": "human"},
        "accepted_at": "2026-07-17T07:00:00Z",
        "rationale": "staging-only exposure is bounded",
        "compensating_controls": ["feature flag remains disabled by default"],
        "expires_at": "2026-07-18T08:00:00Z",
        "scope": {"environments": ["staging"], "versions": ["v1.2.0"]},
    }


def validate(acceptance: dict[str, object], finding: dict[str, object]):
    return validate_risk_acceptance(
        acceptance,
        findings=[finding],
        authorized_actor_ids={"ACTOR-product-owner"},
        non_waivable_gates={"scope_approved", "data_integrity", "independent_review"},
        now=NOW,
    )


def test_risk_acceptance_requires_authorized_actor_identity() -> None:
    acceptance = valid_acceptance()
    acceptance["accepted_by"] = {"id": "ACTOR-implementer", "kind": "agent"}

    decision = validate(acceptance, waiver_allowed_finding())

    assert not decision.ok
    assert "RISK_ACTOR_UNAUTHORIZED" in decision.codes


def test_expired_risk_acceptance_cannot_cover_a_finding() -> None:
    acceptance = valid_acceptance()
    acceptance["expires_at"] = "2026-07-17T08:00:00Z"

    decision = validate(acceptance, waiver_allowed_finding())

    assert not decision.ok
    assert "RISK_EXPIRED" in decision.codes


def test_risk_acceptance_cannot_waive_non_waivable_gate() -> None:
    finding = waiver_allowed_finding()
    finding["invalidates"] = ["scope_approved"]

    decision = validate(valid_acceptance(), finding)

    assert not decision.ok
    assert "RISK_NON_WAIVABLE" in decision.codes


def test_block_close_finding_cannot_be_converted_to_waiver() -> None:
    finding = waiver_allowed_finding()
    finding["blocking_effect"] = "block_close"

    decision = validate(valid_acceptance(), finding)

    assert not decision.ok
    assert "RISK_FINDING_NOT_WAIVABLE" in decision.codes


def test_confirmed_security_or_data_finding_is_never_waivable() -> None:
    for category in ("security", "data"):
        finding = waiver_allowed_finding()
        finding.update({"category": category, "confidence": "confirmed", "severity": "minor"})

        decision = validate(valid_acceptance(), finding)

        assert not decision.ok
        assert "RISK_CATEGORY_NON_WAIVABLE" in decision.codes
