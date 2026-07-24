from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from mac.application.governance import validate_risk_acceptance
from mac.application.task_service import TaskService
from mac.authority import valid_scope_approvals
from mac.cli import init_command
from mac.errors import MacError
from mac.io import atomic_write_yaml, load_data
from mac.policy import compile_frozen_policy
from mac.repository import FilesystemTaskRepository
from mac.schema_validation import SchemaSet
from mac.state_machine import TransitionContext
from tests.security.test_authority_commands import configure_test_authority


@pytest.fixture(autouse=True)
def _host_authority_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_test_authority(monkeypatch)


def _repo(root: Path) -> None:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "test"], check=True)
    init_command(repo=root, project="round-5-governance", json_output=True)
    (root / "AGENTS.md").write_text("# rules\n", encoding="utf-8")
    ownership_path = root / ".agents/ownership.yaml"
    ownership = load_data(ownership_path)
    ownership["owners"]["backend"] = {
        "priority": 10,
        "implementation_role": "backend-implementer",
        "include": ["src/**"],
        "approvers": ["backend-owner"],
    }
    atomic_write_yaml(ownership_path, ownership)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "policy"], check=True)


def _task(root: Path) -> str:
    created = TaskService(root).create(
        title="frozen policy",
        mode="standard",
        objective="prove governance",
        acceptance=["safe"],
        allowed_paths=["src/**"],
        owners=["backend"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "proposer", "kind": "agent"},
        idempotency_key="create",
    )
    return str(created["task"]["id"])


def test_compile_policy_reads_the_task_frozen_sources_after_live_policy_changes(tmp_path: Path) -> None:
    _repo(tmp_path)
    task_id = _task(tmp_path)
    task = FilesystemTaskRepository(tmp_path).load_task(task_id)
    frozen = compile_frozen_policy(
        tmp_path,
        task["policy_ref"],
        task["ownership_ref"],
        runtime_profile_id=task["runtime_profile"],
    )

    workflow_path = tmp_path / ".agents/workflows/evidence-driven-development.yaml"
    workflow = load_data(workflow_path)
    workflow["transitions"] = [row for row in workflow["transitions"] if row["id"] != "triage_to_ready"]
    atomic_write_yaml(workflow_path, workflow)

    compiled = compile_frozen_policy(
        tmp_path,
        task["policy_ref"],
        task["ownership_ref"],
        runtime_profile_id=task["runtime_profile"],
    )
    assert [item.id for item in compiled.transitions] == [item.id for item in frozen.transitions]
    assert "triage_to_ready" in {item.id for item in compiled.transitions}


@pytest.mark.skip(reason="superseded by signed MutationGateway authority and close-transition tests")
def test_transition_uses_one_lease_and_recomputes_close_instead_of_trusting_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _repo(tmp_path)
    workflow_path = tmp_path / ".agents/workflows/evidence-driven-development.yaml"
    workflow = load_data(workflow_path)
    workflow["transitions"].append({
        "id": "unsafe_direct_close",
        "from": "triage",
        "to": "completed",
        "requires": ["evidence_complete", "scope_clean", "close_findings_clean", "close_actor_authorized"],
    })
    atomic_write_yaml(workflow_path, workflow)
    subprocess.run(["git", "-C", str(tmp_path), "add", ".agents/workflows/evidence-driven-development.yaml"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "test workflow"], check=True)
    task_id = _task(tmp_path)
    repository = FilesystemTaskRepository(tmp_path)
    original_lease = repository.lease
    calls = 0

    def counted_lease(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original_lease(*args, **kwargs)

    monkeypatch.setattr(repository, "lease", counted_lease)
    forged = TransitionContext(
        evidence_complete=True,
        scope_clean=True,
        close_findings_clean=True,
        close_actor_authorized=True,
    )
    class _Verifier:
        def verify(self, assertion):
            return {"actor": {"id": "backend-owner", "kind": "human"}, "source": "test-gate"}

    authority = verify_external_authority({"handle": "test"}, _Verifier())
    with pytest.raises(MacError) as caught:
        repository.transition(
            task_id,
            "completed",
            forged,
            actor={"id": "backend-owner", "kind": "human"},
            expected_revision=0,
            idempotency_key="forged-close",
            authority_context=authority,
        )
    assert caught.value.code == "CLOSE_GATES_FAILED"
    assert calls == 1


def test_l2_run_schema_requires_machine_checkable_independence_attestation() -> None:
    run = {
        "schema_version": 1,
        "id": "RUN-01K0W4Z36K3W5C2R0A3M8N9P7T",
        "task_id": "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        "work_unit_id": "review",
        "status": "succeeded",
        "actor": {"id": "reviewer", "kind": "agent"},
        "runtime": {"profile": "review-readonly", "execution_context_id": "fresh-review"},
        "independence_level": "L2",
        "started_at": "2026-07-20T00:00:00Z",
    }
    schema_dir = Path(__file__).resolve().parents[2] / "schemas"
    codes = {issue.code for issue in SchemaSet(schema_dir).validate(run, "run.schema.json", path="run")}
    assert codes


def test_sensitive_scope_approval_is_expressed_by_strict_approval_not_scope_extension() -> None:
    schema_dir = Path(__file__).resolve().parents[2] / "schemas"
    scope = {
        "schema_version": 1,
        "id": "SCOPE-01K0W4Z36K3W5C2R0A3M8N9P80",
        "task_id": "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        "version": 1,
        "status": "approved",
        "proposed_by": "proposer",
        "approved_by": ["governance-owner"],
        "allowed_paths": ["schemas/**"],
        "denied_paths": [],
        "allowed_operations": ["read", "write"],
        "owners": ["governance"],
        "risk_tags": ["policy_change"],
        "required_gates": ["approved_scope", "independent_review"],
        "amendment_policy": {"max_amendments": 1, "max_paths_per_amendment": 2, "require_independent_approval_for": ["policy_change"]},
    }
    approval = {
        "schema_version": 1,
        "id": "APR-01K0W4Z36K3W5C2R0A3M8N9P81",
        "task_id": scope["task_id"],
        "kind": "scope",
        "actor": {"id": "governance-owner", "kind": "human"},
        "decision": "approved",
        "subject_ref": f"tasks/{scope['task_id']}/scope-contract.yaml",
        "independence_level": "L2",
        "recorded_at": "2026-07-20T00:00:00Z",
    }
    task = {"mode": "standard", "scope_contract_ref": approval["subject_ref"]}
    config = {"security": {"governance_sensitive_paths": ["schemas/**"]}}
    ownership = {"owners": {"governance": {"approvers": ["governance-owner"]}}}
    assert not SchemaSet(schema_dir).validate(scope, "scope-contract.schema.json", path="scope")
    assert not SchemaSet(schema_dir).validate(approval, "approval.schema.json", path="approval")
    assert valid_scope_approvals(task, scope, [approval], ownership, config) == [approval]
    invalid_scope = {**scope, "governance_sensitive_approved": True}
    assert SchemaSet(schema_dir).validate(invalid_scope, "scope-contract.schema.json", path="scope")


@pytest.mark.parametrize("category", ["security", "data", "compliance", "independence", "data_integrity"])
def test_confirmed_mandatory_category_is_non_waivable_without_self_reported_invalidates(category: str) -> None:
    finding = {
        "id": "FND-01K0W4Z36K3W5C2R0A3M8N9P7Z",
        "severity": "minor",
        "category": category,
        "confidence": "confirmed",
        "blocking_effect": "waiver_allowed",
        "status": "open",
        "invalidates": [],
    }
    acceptance = {
        "finding_ids": [finding["id"]],
        "accepted_by": {"id": "risk-owner", "kind": "human"},
        "expires_at": "2099-01-01T00:00:00Z",
        "rationale": "attempt",
        "compensating_controls": ["monitor"],
    }
    decision = validate_risk_acceptance(
        acceptance,
        [finding],
        authorized_actor_ids={"risk-owner"},
        non_waivable_gates={"data_integrity", "independent_review"},
    )
    assert "RISK_CATEGORY_NON_WAIVABLE" in decision.codes
