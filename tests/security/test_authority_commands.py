from __future__ import annotations

import pytest

from mac.authority import AuthorityDecision, governance_sensitive, require_authority
from mac.cli import result_submit
from mac.errors import MacError
from mac.io import atomic_write_json


def test_governance_sensitive_paths_use_gitignore_semantics() -> None:
    config = {
        "security": {
            "governance_sensitive_paths": ["AGENTS.md", ".agents/**", "schemas/**"],
        }
    }

    assert governance_sensitive({"allowed_paths": [".agents/config.yaml"]}, config)
    assert governance_sensitive({"allowed_paths": ["schemas/task.schema.json"]}, config)
    assert not governance_sensitive({"allowed_paths": ["src/mac/policy.py"]}, config)
    assert not governance_sensitive({"allowed_paths": ["agentz/config.yaml"]}, config)


class _Verifier:
    def __init__(self, decision: AuthorityDecision) -> None:
        self.decision = decision

    def authorize(self, **_: object) -> AuthorityDecision:
        return self.decision


def test_authority_decision_must_bind_actor_operation_and_task() -> None:
    decision = AuthorityDecision(
        allowed=True,
        actor_id="platform-owner",
        operation="scope.approve",
        task_id="TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        authenticated=True,
        issuer="local-broker",
    )
    assert require_authority(
        _Verifier(decision),
        actor_claim={"id": "platform-owner", "kind": "human"},
        operation="scope.approve",
        task_id=decision.task_id,
    ) == decision

    with pytest.raises(MacError) as captured:
        require_authority(
            _Verifier(decision),
            actor_claim={"id": "attacker", "kind": "agent"},
            operation="scope.approve",
            task_id=decision.task_id,
        )
    assert captured.value.code == "ACTOR_AUTHORITY_DENIED"

    with pytest.raises(MacError) as missing:
        require_authority(
            None,
            actor_claim={"id": "platform-owner", "kind": "human"},
            operation="scope.approve",
            task_id=decision.task_id,
        )
    assert missing.value.code == "AUTHORITY_VERIFIER_REQUIRED"


def test_result_submit_rejects_untrusted_identifiers_before_path_construction(tmp_path) -> None:
    task_id = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    result_path = tmp_path / "untrusted-result.json"
    atomic_write_json(
        result_path,
        {
            "task_id": task_id,
            "run_id": "../private/secret",
            "work_unit_id": "WU-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        },
    )

    with pytest.raises(MacError) as captured:
        result_submit(
            task_id,
            result_path,
            expected_revision=0,
            idempotency_key="unsafe-result",
            actor="executor",
            repo=tmp_path,
            json_output=True,
        )

    assert captured.value.code == "RESULT_RUN_ID_UNSAFE"
