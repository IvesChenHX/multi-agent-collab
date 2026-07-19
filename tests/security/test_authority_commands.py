from __future__ import annotations

import pytest

from mac.authority import (
    AuthorityDecision,
    governance_sensitive,
    require_authority,
    trusted_authority_verifier,
)
from mac.application.task_service import TaskService
from mac.cli import (
    approval_record,
    finding_waive,
    init_command,
    result_submit,
    run_register,
    scope_approve,
    scope_propose,
    task_cancel,
    task_new,
    task_supersede,
    task_transition,
)
from mac.errors import MacError
from mac.io import atomic_write_json
from mac.repository import FilesystemTaskRepository


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
        actor_kind="human",
        independence_level="L2",
        attestation_id="broker-attestation-001",
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


def test_scope_approve_rejects_self_reported_actor_without_trusted_verifier(tmp_path) -> None:
    init_command(repo=tmp_path, project="authority-regression", json_output=True)
    created = TaskService(tmp_path).create(
        title="authority regression",
        mode="high_risk",
        objective="prove scope approval authority",
        acceptance=["trusted approval"],
        allowed_paths=["AGENTS.md"],
        owners=["governance"],
        runtime_profile="local-single",
        required_gates=["targeted_tests", "independent_review"],
        actor={"id": "proposer", "kind": "human"},
        idempotency_key="authority-task",
    )

    with pytest.raises(MacError) as captured:
        scope_approve(
            str(created["task"]["id"]),
            expected_revision=0,
            idempotency_key="self-reported-scope-approval",
            actor="governance-owner",
            independence_level="L2",
            repo=tmp_path,
            json_output=True,
        )

    assert captured.value.code == "AUTHORITY_VERIFIER_REQUIRED"


def test_task_new_requires_trusted_proposer_and_persists_initial_authority(tmp_path) -> None:
    init_command(repo=tmp_path, project="trusted-task-create", json_output=True)

    with pytest.raises(MacError) as missing:
        task_new(
            title="untrusted task",
            objective="must not be created",
            mode="standard",
            allow=["src/**"],
            owner=["backend"],
            acceptance=["not created"],
            runtime_profile="local-single",
            gate=["targeted_tests"],
            parent_task=None,
            supersedes=[],
            actor="proposer",
            idempotency_key="untrusted-task-create",
            repo=tmp_path,
            json_output=True,
        )
    assert missing.value.code == "AUTHORITY_VERIFIER_REQUIRED"
    assert not list((tmp_path / "tasks").glob("TASK-*"))

    decision = AuthorityDecision(
        allowed=True,
        actor_id="proposer",
        actor_kind="human",
        operation="task.create",
        task_id=None,
        authenticated=True,
        issuer="runtime-broker",
        independence_level="L1",
        attestation_id="attestation-task-create-001",
    )
    with trusted_authority_verifier(_Verifier(decision)):
        task_new(
            title="trusted task",
            objective="bind its proposer",
            mode="standard",
            allow=["src/**"],
            owner=["backend"],
            acceptance=["created by trusted proposer"],
            runtime_profile="local-single",
            gate=["targeted_tests"],
            parent_task=None,
            supersedes=[],
            actor="proposer",
            idempotency_key="trusted-task-create",
            repo=tmp_path,
            json_output=True,
        )

    task_dir = next((tmp_path / "tasks").glob("TASK-*"))
    event = FilesystemTaskRepository(tmp_path).list_events(task_dir.name)[0]
    assert event["event_type"] == "task_created"
    assert event["payload"]["authority"] == {
        "allowed": True,
        "authenticated": True,
        "issuer": "runtime-broker",
        "attestation_id": "attestation-task-create-001",
        "actor_id": "proposer",
        "actor_kind": "human",
        "operation": "task.create",
        "task_id": None,
        "independence_level": "L1",
    }


def test_scope_proposer_cannot_be_spoofed(tmp_path) -> None:
    init_command(repo=tmp_path, project="trusted-scope-proposer", json_output=True)
    created = TaskService(tmp_path).create(
        title="scope binding",
        mode="standard",
        objective="prevent separation-of-duty spoofing",
        acceptance=["proposer is authenticated"],
        allowed_paths=["src/**"],
        owners=["governance"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "initial-proposer", "kind": "human"},
        idempotency_key="scope-proposer-task",
    )
    task_id = str(created["task"]["id"])

    with pytest.raises(MacError) as missing:
        scope_propose(
            task_id,
            allow=["src/**"],
            deny=[],
            owner=["governance"],
            expected_revision=0,
            idempotency_key="spoofed-scope-proposer",
            actor="someone-else",
            repo=tmp_path,
            json_output=True,
        )
    assert missing.value.code == "AUTHORITY_VERIFIER_REQUIRED"

    proposal_decision = AuthorityDecision(
        allowed=True,
        actor_id="governance-owner",
        actor_kind="human",
        operation="scope.propose",
        task_id=task_id,
        authenticated=True,
        issuer="runtime-broker",
        independence_level="L1",
        attestation_id="attestation-scope-propose-001",
    )
    with trusted_authority_verifier(_Verifier(proposal_decision)):
        scope_propose(
            task_id,
            allow=["src/**"],
            deny=[],
            owner=["governance"],
            expected_revision=0,
            idempotency_key="trusted-scope-proposer",
            actor="governance-owner",
            repo=tmp_path,
            json_output=True,
        )

    approval_decision = AuthorityDecision(
        allowed=True,
        actor_id="governance-owner",
        actor_kind="human",
        operation="scope.approve",
        task_id=task_id,
        authenticated=True,
        issuer="runtime-broker",
        independence_level="L1",
        attestation_id="attestation-scope-approve-same-actor",
    )
    with trusted_authority_verifier(_Verifier(approval_decision)):
        with pytest.raises(MacError) as same_actor:
            scope_approve(
                task_id,
                expected_revision=1,
                idempotency_key="same-actor-approval",
                actor="governance-owner",
                independence_level="L1",
                repo=tmp_path,
                json_output=True,
            )
    assert same_actor.value.code == "SCOPE_APPROVER_UNAUTHORIZED"

    proposal_event = FilesystemTaskRepository(tmp_path).list_events(task_id)[-1]
    assert proposal_event["payload"]["authority"]["operation"] == "scope.propose"
    assert proposal_event["payload"]["authority"]["authenticated"] is True


def test_scope_approve_persists_authenticated_issuer_and_attested_independence(tmp_path) -> None:
    init_command(repo=tmp_path, project="authority-audit", json_output=True)
    created = TaskService(tmp_path).create(
        title="authority audit",
        mode="high_risk",
        objective="persist trusted authority",
        acceptance=["auditable approval"],
        allowed_paths=["AGENTS.md"],
        owners=["governance"],
        runtime_profile="local-single",
        required_gates=["targeted_tests", "independent_review"],
        actor={"id": "proposer", "kind": "human"},
        idempotency_key="authority-audit-task",
    )
    task_id = str(created["task"]["id"])
    decision = AuthorityDecision(
        allowed=True,
        actor_id="governance-owner",
        actor_kind="human",
        operation="scope.approve",
        task_id=task_id,
        authenticated=True,
        issuer="runtime-broker",
        independence_level="L2",
        attestation_id="attestation-scope-001",
    )

    with trusted_authority_verifier(_Verifier(decision)):
        scope_approve(
            task_id,
            expected_revision=0,
            idempotency_key="trusted-scope-approval",
            actor="governance-owner",
            independence_level="L1",
            repo=tmp_path,
            json_output=True,
        )

    event = FilesystemTaskRepository(tmp_path).list_events(task_id)[-1]
    assert event["payload"]["authority"] == {
        "allowed": True,
        "authenticated": True,
        "issuer": "runtime-broker",
        "attestation_id": "attestation-scope-001",
        "actor_id": "governance-owner",
        "actor_kind": "human",
        "operation": "scope.approve",
        "task_id": task_id,
        "independence_level": "L2",
    }
    assert event["payload"]["approval"]["independence_level"] == "L2"


def test_authority_sensitive_cli_mutations_all_fail_closed_without_runtime_verifier(tmp_path) -> None:
    init_command(repo=tmp_path, project="authority-boundary", json_output=True)
    created = TaskService(tmp_path).create(
        title="boundary",
        mode="standard",
        objective="exercise authority-sensitive commands",
        acceptance=["commands fail closed"],
        allowed_paths=["AGENTS.md"],
        owners=["governance"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "proposer", "kind": "human"},
        idempotency_key="authority-boundary-task",
    )
    task_id = str(created["task"]["id"])
    repository = FilesystemTaskRepository(tmp_path)
    repository.append_event(
        task_id,
        "state_transitioned",
        {"from": "triage", "to": "verifying", "transition_id": "fixture", "terminal_state": False},
        actor={"id": "fixture", "kind": "automation"},
        expected_revision=0,
        idempotency_key="authority-boundary-state",
    )

    commands = [
        lambda: task_transition(task_id, "completed", 1, "close-without-verifier", "governance-owner", [], None, None, tmp_path, True),
        lambda: task_cancel(task_id, 1, "cancel-without-verifier", "governance-owner", tmp_path, True),
        lambda: task_supersede(task_id, "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q", 1, "supersede-without-verifier", "governance-owner", tmp_path, True),
        lambda: finding_waive(task_id, "FND-01K0W4Z36K3W5C2R0A3M8N9P7Q", "risk", ["control"], "2099-01-01T00:00:00Z", 1, "risk-without-verifier", "governance-owner", tmp_path, True),
        lambda: approval_record(task_id, "close", "approved", "HEAD", "governance-owner", "L1", 1, "approval-without-verifier", tmp_path, True),
        lambda: run_register(task_id, "WU-01K0W4Z36K3W5C2R0A3M8N9P7Q", "local-single", "context", None, None, None, None, "reviewer", "agent", "L2", 1, "run-without-verifier", tmp_path, True),
    ]
    for command in commands:
        with pytest.raises(MacError) as captured:
            command()
        assert captured.value.code == "AUTHORITY_VERIFIER_REQUIRED"


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
