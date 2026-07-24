from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import subprocess
import sys
import time

import pytest

from mac.errors import ExitCode, MacError
from mac.events import replay_entity_snapshots, replay_events
from mac.cli import (
    init_command,
    scope_approve,
    task_transition,
    work_unit_new,
    work_unit_ready,
)
from mac.application.task_service import TaskService
from mac.git import GitRepository
import mac.repository as repository_module
from mac.repository import (
    AppendEvent,
    CreateTask,
    FilesystemTaskRepository,
    MutationGateway,
    RecordCommandEvidence,
    Rebuild,
    Transition,
    _assess_repair_round,
    _enforce_operation_independence,
    _results_complete_after_latest_repair,
    resolve_transition_context,
    utc_now,
)
from mac.repository import build_policy_ref
from mac.io import atomic_write_json, load_data
from mac.policy import ownership_source_path, policy_source_paths
from mac.state_machine import TransitionContext
from tests.security.test_authority_commands import (
    _configure_sigstore_authority,
    configure_test_authority,
    remove_test_authority,
)


@pytest.fixture(autouse=True)
def _host_authority_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_test_authority(monkeypatch)


def init_governance_repo(tmp_path: Path, *, project: str = "event-store") -> None:
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    init_command(repo=tmp_path, project=project, json_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-m", "init"], check=True, capture_output=True)


def create_governed_task(tmp_path: Path, *, key: str = "create-task") -> tuple[FilesystemTaskRepository, dict[str, object]]:
    init_governance_repo(tmp_path)
    service = TaskService(tmp_path)
    created = service.create(
        title="event store",
        mode="standard",
        objective="prove recovery",
        acceptance=["replay works"],
        allowed_paths=["AGENTS.md"],
        owners=["governance"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "a", "kind": "agent"},
        idempotency_key=key,
    )
    return service.repository, created


def approve_and_ready_task(root: Path, task_id: str) -> None:
    scope_approve(
        task_id=task_id,
        expected_revision=0,
        idempotency_key=f"approve-{task_id}",
        actor="governance-owner",
        independence_level="L1",
        repo=root,
        json_output=True,
    )
    task_transition(
        task_id=task_id,
        target="ready",
        expected_revision=1,
        idempotency_key=f"ready-{task_id}",
        actor="controller",
        condition=[],
        fact_id=None,
        reason=None,
        repo=root,
        json_output=True,
    )


def finding_snapshot(task_id: str, finding_id: str) -> dict[str, object]:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": 1,
        "id": finding_id,
        "task_id": task_id,
        "severity": "minor",
        "category": "maintainability",
        "blocking_effect": "advisory",
        "confidence": "confirmed",
        "status": "open",
        "title": "bounded",
        "risk": "none",
        "owner": "governance",
        "evidence_refs": [],
        "invalidates": [],
        "opened_at": now,
        "resolved_at": None,
    }


def task(task_id: str) -> dict[str, object]:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    digest = "sha256:" + "1" * 64
    return {
        "schema_version": 6,
        "id": task_id,
        "title": "event store",
        "mode": "standard",
        "state": "triage",
        "revision": 0,
        "created_at": now,
        "updated_at": now,
        "objective": "prove recovery",
        "acceptance_criteria": [{"id": "AC-001", "text": "replay works", "required": True}],
        "policy_ref": {"combined_digest": digest},
        "ownership_ref": {"combined_digest": digest},
        "scope_contract_ref": f"tasks/{task_id}/scope-contract.yaml",
        "runtime_profile": "local-single",
        "required_gates": ["targeted_tests"],
        "active_controller": None,
        "relationships": {"parent_task": None, "supersedes": [], "superseded_by": None},
        "legacy_integrity": "full",
        "terminal": None,
    }


def test_event_is_durable_before_projection_and_rebuild_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    gateway = MutationGateway(tmp_path, repository=repository)
    original_writer = repository_module.atomic_write_yaml

    def crash_projection(path: Path, value: dict[str, object]) -> None:
        if path == repository.task_dir(task_id) / "task.yaml" and value.get("revision") == 1:
            raise RuntimeError("power loss")
        original_writer(path, value)

    monkeypatch.setattr(repository_module, "atomic_write_yaml", crash_projection)
    with pytest.raises(RuntimeError, match="power loss"):
        gateway.execute(Transition(
            task_id=task_id,
            target="cancelled",
            context=resolve_transition_context(tmp_path, task_id, "cancelled", "governance-owner"),
            actor_claim={"id": "governance-owner", "kind": "human"},
            expected_revision=0,
            idempotency_key="cancel",
            operation="task.cancel",
            replay_intent={"target": "cancelled"},
        ))

    monkeypatch.setattr(repository_module, "atomic_write_yaml", original_writer)
    assert repository.load_task(task_id)["revision"] == 0
    assert len(repository.list_events(task_id)) == 2
    rebuilt = gateway.execute(Rebuild(
        task_id=task_id,
        actor_claim={"id": "a", "kind": "agent"},
        expected_revision=1,
        idempotency_key="rebuild-ready",
    )).projection
    assert rebuilt["state"] == "cancelled"
    assert rebuilt["revision"] == 1


def test_scope_event_interruption_is_repaired_from_scope_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    scope_path = repository.task_dir(task_id) / "scope-contract.yaml"
    original_scope = load_data(scope_path)
    updated_scope = dict(original_scope)
    updated_scope["allowed_paths"] = ["src/**"]
    gateway = MutationGateway(tmp_path, repository=repository)
    original_writer = repository_module.atomic_write_yaml

    def crash_scope(path: Path, value: dict[str, object]) -> None:
        if path == scope_path and value.get("allowed_paths") == ["src/**"]:
            raise RuntimeError("scope projection loss")
        original_writer(path, value)

    monkeypatch.setattr(repository_module, "atomic_write_yaml", crash_scope)
    with pytest.raises(RuntimeError, match="scope projection loss"):
        gateway.execute(AppendEvent(
            task_id=task_id,
            event_type="scope_proposed",
            payload={"scope_id": updated_scope["id"], "version": updated_scope["version"], "scope": updated_scope},
            actor_claim={"id": "a", "kind": "agent"},
            expected_revision=0,
            idempotency_key="scope-propose-interrupted",
            operation="scope.propose",
            materializations=((scope_path, updated_scope),),
            replace_existing=frozenset({scope_path}),
            replay_intent={"allowed_paths": ["src/**"]},
        ))
    monkeypatch.setattr(repository_module, "atomic_write_yaml", original_writer)
    assert load_data(scope_path) == original_scope
    assert len(repository.list_events(task_id)) == 2

    gateway.execute(Rebuild(
        task_id=task_id,
        actor_claim={"id": "a", "kind": "agent"},
        expected_revision=1,
        idempotency_key="scope-rebuild",
    ))
    assert load_data(scope_path) == updated_scope


def test_idempotency_and_revision_conflict_are_deterministic(tmp_path: Path) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    gateway = MutationGateway(tmp_path, repository=repository)
    command = Transition(
        task_id=task_id,
        target="cancelled",
        context=resolve_transition_context(tmp_path, task_id, "cancelled", "governance-owner"),
        actor_claim={"id": "governance-owner", "kind": "human"},
        expected_revision=0,
        idempotency_key="same",
        operation="task.cancel",
        replay_intent={"target": "cancelled"},
    )
    first = gateway.execute(command)
    retried = gateway.execute(command)
    assert retried.event == first.event
    assert len(repository.list_events(task_id)) == 2

    with pytest.raises(MacError) as caught:
        gateway.execute(Transition(
            task_id=task_id,
            target="cancelled",
            context=resolve_transition_context(tmp_path, task_id, "cancelled", "governance-owner"),
            actor_claim={"id": "governance-owner", "kind": "human"},
            expected_revision=0,
            idempotency_key="stale",
            operation="task.cancel",
        ))
    assert caught.value.exit_code == ExitCode.CONFLICT
    assert caught.value.code == "REVISION_CONFLICT"


def test_replay_rejects_revision_gap_and_rollback() -> None:
    base = {"event_id": "EVT-01K0W4Z36K3W5C2R0A3M8N9P7Q", "idempotency_key": "a", "expected_revision": -1, "new_revision": 0, "event_type": "task_created", "payload": {"task": task("TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q")}}
    gap = {**base, "event_id": "EVT-01K0W4Z36K3W5C2R0A3M8N9P7R", "idempotency_key": "b", "expected_revision": 0, "new_revision": 2}
    with pytest.raises(MacError, match="revision gap") as gap_error:
        replay_events([base, gap])
    assert gap_error.value.code == "EVENT_REVISION_GAP"

    rollback = {**base, "event_id": "EVT-01K0W4Z36K3W5C2R0A3M8N9P7R", "idempotency_key": "b", "expected_revision": 0, "new_revision": 0}
    with pytest.raises(MacError) as rollback_error:
        replay_events([base, rollback])
    assert rollback_error.value.code == "EVENT_REVISION_ROLLBACK"


def test_entity_replay_with_current_initial_projection_does_not_skip_events(tmp_path: Path) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    snapshots = replay_entity_snapshots(
        repository.list_events(task_id),
        initial_projection=repository.load_task(task_id),
    )
    assert snapshots == {
        "work-units": {},
        "runs": {},
        "results": {},
        "evidence": {},
        "findings": {},
        "approvals": {},
        "risk-acceptances": {},
    }


def test_expired_record_cannot_be_stolen_while_controller_holds_lock(tmp_path: Path) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])

    with repository.lease(task_id, "first", ttl_seconds=0.01):
        time.sleep(0.02)
        with pytest.raises(MacError) as captured:
            with FilesystemTaskRepository(tmp_path).lease(task_id, "second"):
                pass

    assert captured.value.code == "LEASE_CONFLICT"


def test_task_service_freezes_safe_lineage_in_creation_event(tmp_path: Path) -> None:
    parent = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    predecessor = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7R"
    init_governance_repo(tmp_path, project="lineage")
    service = TaskService(tmp_path)

    created = service.create(
        title="successor",
        mode="standard",
        objective="continue predecessor",
        acceptance=["lineage is immutable"],
        allowed_paths=["src/**"],
        owners=["platform"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "a", "kind": "agent"},
        idempotency_key="create-successor",
        parent_task=parent,
        supersedes=[predecessor, predecessor],
    )

    event = service.repository.list_events(str(created["task"]["id"]))[0]
    expected = {"parent_task": parent, "supersedes": [predecessor], "superseded_by": None}
    assert created["task"]["relationships"] == expected
    assert event["payload"]["task"]["relationships"] == expected

    with pytest.raises(ValueError, match="safe TASK identifier"):
        service.create(
            title="unsafe",
            mode="standard",
            objective="reject traversal",
            acceptance=["rejected"],
            allowed_paths=["src/**"],
            owners=["platform"],
            runtime_profile="local-single",
            required_gates=[],
            actor={"id": "a", "kind": "agent"},
            idempotency_key="unsafe-successor",
            parent_task="../../TASK-escape",
        )


def test_public_repository_writers_fail_closed_without_creating_files(tmp_path: Path) -> None:
    repository = FilesystemTaskRepository(tmp_path)
    task_id = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    calls = [
        lambda: repository.create_task(task(task_id), actor={"id": "a", "kind": "agent"}, idempotency_key="create"),
        lambda: repository.append_event(task_id, "finding_opened", {}, actor={"id": "a", "kind": "agent"}, expected_revision=0, idempotency_key="append"),
        lambda: repository.transition(task_id, "ready", TransitionContext(), actor={"id": "a", "kind": "agent"}, expected_revision=0, idempotency_key="transition"),
        lambda: repository.rebuild_task(task_id),
    ]
    for call in calls:
        with pytest.raises(MacError) as captured:
            call()
        assert captured.value.code == "MUTATION_GATEWAY_REQUIRED"
    assert not (tmp_path / "tasks").exists()


def test_gateway_rejects_illegal_create_work_unit_and_run_initial_states(tmp_path: Path) -> None:
    bad_task = task("TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q")
    bad_task["state"] = "completed"
    scope = {
        "task_id": bad_task["id"],
        "status": "proposed",
        "approved_by": [],
    }
    with pytest.raises(MacError) as create_error:
        MutationGateway(tmp_path).execute(CreateTask(
            task=bad_task,
            initial_entities=(("scope-contract.yaml", scope),),
            actor_claim={"id": "a", "kind": "agent"},
            idempotency_key="illegal-create-state",
        ))
    assert create_error.value.code == "MUTATION_CREATE_STATE_INVALID"
    assert not (tmp_path / "tasks").exists()

    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    gateway = MutationGateway(tmp_path, repository=repository)
    work_unit = {
        "schema_version": 1,
        "id": "WU-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        "task_id": task_id,
        "title": "cannot skip lifecycle",
        "status": "completed",
        "owner": "governance",
        "allowed_paths": ["AGENTS.md"],
        "depends_on": [],
        "acceptance_criteria": [],
        "expected_result": f"tasks/{task_id}/results/RESULT-01K0W4Z36K3W5C2R0A3M8N9P7Q.json",
    }
    work_unit_path = repository.task_dir(task_id) / "work-units" / f"{work_unit['id']}.yaml"
    with pytest.raises(MacError) as work_unit_error:
        gateway.execute(AppendEvent(
            task_id=task_id,
            event_type="work_unit_created",
            payload={"work_unit_id": work_unit["id"], "work_unit": work_unit},
            actor_claim={"id": "a", "kind": "agent"},
            expected_revision=0,
            idempotency_key="illegal-work-unit-state",
            operation="work_unit.create",
            materializations=((work_unit_path, work_unit),),
        ))
    assert work_unit_error.value.code == "MUTATION_WORK_UNIT_STATE_INVALID"

    running_unit = dict(work_unit)
    running_unit["status"] = "running"
    run = {
        "schema_version": 1,
        "id": "RUN-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        "task_id": task_id,
        "work_unit_id": running_unit["id"],
        "status": "succeeded",
        "actor": {"id": "a", "kind": "agent"},
        "runtime": {"profile": "local-single", "execution_context_id": "illegal-run"},
        "independence_level": "L3",
        "started_at": "2026-07-20T00:00:00Z",
        "finished_at": "2026-07-20T00:01:00Z",
        "exit_code": 0,
    }
    run_path = repository.task_dir(task_id) / "runs" / f"{run['id']}.json"
    with pytest.raises(MacError) as run_error:
        gateway.execute(AppendEvent(
            task_id=task_id,
            event_type="run_started",
            payload={
                "run_id": run["id"],
                "work_unit_id": running_unit["id"],
                "run": run,
                "work_unit": running_unit,
                "baseline_subject": {},
                "worktree_identity": {},
                "repository_binding": {},
            },
            actor_claim={"id": "a", "kind": "agent"},
            expected_revision=0,
            idempotency_key="illegal-run-state",
            operation="run.register",
            run_id=run["id"],
            materializations=((run_path, run), (work_unit_path, running_unit)),
        ))
    assert run_error.value.code == "MUTATION_RUN_REGISTER_INVALID"
    assert len(repository.list_events(task_id)) == 1
    assert not work_unit_path.exists()
    assert not run_path.exists()


def test_internal_writer_has_no_importable_permit_and_cannot_write(tmp_path: Path) -> None:
    repository = FilesystemTaskRepository(tmp_path)
    task_id = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    command = CreateTask(
        task=task(task_id),
        initial_entities=(),
        actor_claim={"id": "a", "kind": "agent"},
        idempotency_key="raw-create",
    )
    assert not hasattr(repository_module, "_MUTATION_PERMIT")
    with pytest.raises(MacError) as captured:
        repository._create_task(command, _permit=object())
    assert captured.value.code == "MUTATION_GATEWAY_REQUIRED"
    assert not (tmp_path / "tasks").exists()


def test_task_directory_symlink_cannot_redirect_governed_writes(tmp_path: Path) -> None:
    task_id = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    outside = tmp_path / "outside"
    outside.mkdir()
    tasks = tmp_path / "tasks"
    tasks.mkdir()
    try:
        os.symlink(outside, tasks / task_id, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")

    repository = FilesystemTaskRepository(tmp_path)
    with pytest.raises(MacError) as captured:
        repository.task_dir(task_id)

    assert captured.value.code == "TASK_PATH_UNSAFE"
    assert list(outside.iterdir()) == []


def test_entity_prefix_is_rejected_before_an_immutable_event_is_written(tmp_path: Path) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    wrong_id = "RUN-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    finding = finding_snapshot(task_id, wrong_id)
    path = repository.task_dir(task_id) / "findings" / f"{wrong_id}.json"

    with pytest.raises(MacError) as captured:
        MutationGateway(tmp_path, repository=repository).execute(AppendEvent(
            task_id=task_id,
            event_type="finding_opened",
            payload={"finding_id": wrong_id, "finding": finding},
            actor_claim={"id": "a", "kind": "agent"},
            expected_revision=0,
            idempotency_key="wrong-finding-prefix",
            operation="finding.open",
            materializations=((path, finding),),
        ))

    assert captured.value.code == "MUTATION_ENTITY_ID_INVALID"
    assert len(repository.list_events(task_id)) == 1
    assert not path.exists()


def test_full_integrity_event_cannot_drop_its_authority_fact(tmp_path: Path) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    event = repository.list_events(task_id)[0]
    event["payload"].pop("authority")
    event["payload"]["task"]["legacy_integrity"] = "metadata_only"
    event_path = repository.task_dir(task_id) / "events" / f"{event['event_id']}.json"
    atomic_write_json(event_path, event)

    with pytest.raises(MacError) as captured:
        repository.list_events(task_id)

    assert captured.value.code == "EVENT_AUTHORITY_MISSING"


def test_transition_event_cannot_change_the_authorized_target(tmp_path: Path) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    approve_and_ready_task(tmp_path, task_id)
    event = repository.list_events(task_id)[-1]
    event["payload"]["to"] = "completed"
    event_path = repository.task_dir(task_id) / "events" / f"{event['event_id']}.json"
    atomic_write_json(event_path, event)

    with pytest.raises(MacError) as captured:
        repository.list_events(task_id)

    assert captured.value.code == "EVENT_SEMANTIC_TAMPERED"


@pytest.mark.parametrize("tampered", ["false", 1, None])
def test_transition_terminal_flag_requires_an_exact_boolean(
    tmp_path: Path,
    tampered: object,
) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    approve_and_ready_task(tmp_path, task_id)
    event = repository.list_events(task_id)[-1]
    event["payload"]["terminal_state"] = tampered
    atomic_write_json(
        repository.task_dir(task_id) / "events" / f"{event['event_id']}.json",
        event,
    )

    with pytest.raises(MacError) as captured:
        repository.list_events(task_id)

    assert captured.value.code == "EVENT_SEMANTIC_TAMPERED"


def test_transition_payload_cannot_inject_replay_only_terminal_fields(tmp_path: Path) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    approve_and_ready_task(tmp_path, task_id)
    event = repository.list_events(task_id)[-1]
    event["payload"]["summary"] = "attacker-controlled close summary"
    atomic_write_json(
        repository.task_dir(task_id) / "events" / f"{event['event_id']}.json",
        event,
    )

    with pytest.raises(MacError) as captured:
        repository.list_events(task_id)

    assert captured.value.code == "EVENT_PAYLOAD_CONTRACT_TAMPERED"


def test_append_payload_rejects_unknown_audit_keys_before_event_write(tmp_path: Path) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    finding = finding_snapshot(task_id, "FND-01K0W4Z36K3W5C2R0A3M8N9P7W")
    target = repository.task_dir(task_id) / "findings" / f"{finding['id']}.json"
    before = repository.list_events(task_id)

    with pytest.raises(MacError) as captured:
        MutationGateway(tmp_path, repository=repository).execute(AppendEvent(
            task_id=task_id,
            event_type="finding_opened",
            payload={
                "finding_id": finding["id"],
                "finding": finding,
                "summary": "not part of the finding Event contract",
            },
            actor_claim={"id": "a", "kind": "agent"},
            expected_revision=0,
            idempotency_key="finding-extra-audit-key",
            operation="finding.open",
            materializations=((target, finding),),
            replay_intent={"title": "bounded"},
        ))

    assert captured.value.code == "MUTATION_PAYLOAD_CONTRACT_INVALID"
    assert repository.list_events(task_id) == before
    assert not target.exists()


def test_signed_authority_binds_entity_semantics_and_prevents_contract_downgrade(
    tmp_path: Path,
) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    finding = finding_snapshot(task_id, "FND-01K0W4Z36K3W5C2R0A3M8N9P7W")
    target = repository.task_dir(task_id) / "findings" / f"{finding['id']}.json"
    MutationGateway(tmp_path, repository=repository).execute(AppendEvent(
        task_id=task_id,
        event_type="finding_opened",
        payload={"finding_id": finding["id"], "finding": finding},
        actor_claim={"id": "a", "kind": "agent"},
        expected_revision=0,
        idempotency_key="signed-finding",
        operation="finding.open",
        materializations=((target, finding),),
        replay_intent={"title": "bounded"},
    ))
    original = repository.list_events(task_id)[-1]
    event_path = repository.task_dir(task_id) / "events" / f"{original['event_id']}.json"

    semantic_tamper = json.loads(json.dumps(original))
    semantic_tamper["payload"]["finding"]["title"] = "tampered after authorization"
    projection_tamper = dict(finding)
    projection_tamper["title"] = "tampered after authorization"
    atomic_write_json(event_path, semantic_tamper)
    atomic_write_json(target, projection_tamper)
    with pytest.raises(MacError) as semantic_error:
        repository.load_verified_aggregate(task_id)
    assert semantic_error.value.code == "EVENT_SEMANTIC_TAMPERED"

    atomic_write_json(event_path, original)
    atomic_write_json(target, finding)
    intent_tamper = json.loads(json.dumps(original))
    intent_tamper["payload"]["authority"]["authorized_intent"]["payload"]["finding"]["title"] = "rewritten intent"
    atomic_write_json(event_path, intent_tamper)
    with pytest.raises(MacError) as intent_error:
        repository.list_events(task_id)
    assert intent_error.value.code == "EVENT_AUTHORITY_INTENT_TAMPERED"

    time_tamper = json.loads(json.dumps(original))
    time_tamper["occurred_at"] = "2099-01-01T00:00:00Z"
    time_tamper["payload"]["finding"]["opened_at"] = "2099-01-01T00:00:00Z"
    atomic_write_json(event_path, time_tamper)
    with pytest.raises(MacError) as time_error:
        repository.list_events(task_id)
    assert time_error.value.code == "EVENT_STORE_FACT_TAMPERED"

    downgrade = json.loads(json.dumps(original))
    downgrade["payload"]["authority"].pop("signed_envelope")
    downgrade["payload"]["authority"]["store_contract_version"] = 1
    atomic_write_json(event_path, downgrade)
    with pytest.raises(MacError) as downgrade_error:
        repository.list_events(task_id)
    assert downgrade_error.value.code == "EVENT_AUTHORITY_VERSION_UNSUPPORTED"

    atomic_write_json(event_path, original)
    creation = repository.list_events(task_id)[0]
    creation_downgrade = json.loads(json.dumps(creation))
    creation_downgrade["event_type"] = "legacy_imported"
    creation_downgrade["payload"].pop("authority")
    creation_path = repository.task_dir(task_id) / "events" / f"{creation['event_id']}.json"
    atomic_write_json(creation_path, creation_downgrade)
    with pytest.raises(MacError) as legacy_error:
        repository.list_events(task_id)
    assert legacy_error.value.code == "EVENT_LEGACY_IMPORT_INVALID"


def test_schema_valid_event_state_tamper_is_rejected_before_replay(tmp_path: Path) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    finding_id = "FND-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    finding = finding_snapshot(task_id, finding_id)
    finding_path = repository.task_dir(task_id) / "findings" / f"{finding_id}.json"
    MutationGateway(tmp_path, repository=repository).execute(AppendEvent(
        task_id=task_id,
        event_type="finding_opened",
        payload={"finding_id": finding_id, "finding": finding},
        actor_claim={"id": "a", "kind": "agent"},
        expected_revision=0,
        idempotency_key="open-finding-before-tamper",
        operation="finding.open",
        materializations=((finding_path, finding),),
    ))
    event = repository.list_events(task_id)[-1]
    event["payload"]["finding"]["status"] = "resolved"
    event["payload"]["finding"]["resolved_at"] = utc_now()
    atomic_write_json(
        repository.task_dir(task_id) / "events" / f"{event['event_id']}.json",
        event,
    )

    with pytest.raises(MacError) as captured:
        repository.list_events(task_id)

    assert captured.value.code == "EVENT_SEMANTIC_TAMPERED"


def test_verified_aggregate_reports_extra_projection_entities(tmp_path: Path) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    approval_id = "APR-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    approval_path = repository.task_dir(task_id) / "approvals" / f"{approval_id}.json"
    atomic_write_json(approval_path, {
        "schema_version": 1,
        "id": approval_id,
        "task_id": task_id,
        "kind": "scope",
        "actor": {"id": "attacker", "kind": "human"},
        "decision": "approved",
        "subject_ref": "scope-contract.yaml",
        "independence_level": "L3",
        "recorded_at": utc_now(),
    })

    aggregate = repository.load_verified_aggregate(task_id)

    assert approval_path.relative_to(tmp_path).as_posix() in aggregate.projection_drift
    wrong_extension = approval_path.with_suffix(".yaml")
    wrong_extension.write_text("unexpected: true\n", encoding="utf-8")
    aggregate = repository.load_verified_aggregate(task_id)
    assert wrong_extension.relative_to(tmp_path).as_posix() in aggregate.projection_drift


def test_verified_aggregate_rejects_an_event_stream_change_during_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    frozen_events = repository.list_events(task_id)
    calls = 0

    def changing_events(requested_task_id: str) -> list[dict[str, object]]:
        nonlocal calls
        assert requested_task_id == task_id
        calls += 1
        if calls == 1:
            return frozen_events
        return [*frozen_events, {"event_id": "EVT-concurrent-change"}]

    monkeypatch.setattr(repository, "list_events", changing_events)
    with pytest.raises(MacError) as captured:
        repository.load_verified_aggregate(task_id)

    assert captured.value.code == "AGGREGATE_EVENT_STREAM_CHANGED"


def test_event_stream_computes_repository_identity_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        repository_module.AUTHORITY_REPOSITORY_IDENTITY_ENV,
        "github:repository-id:1290429577",
    )
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    original = repository_module._repository_identity
    calls = 0

    def counted(repo: Path) -> str:
        nonlocal calls
        calls += 1
        return original(repo)

    monkeypatch.setattr(repository_module, "_repository_identity", counted)
    assert repository.list_events(task_id)
    assert calls == 1


def test_event_stream_rejects_a_different_trusted_github_repository_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        repository_module.AUTHORITY_REPOSITORY_IDENTITY_ENV,
        "github:repository-id:1290429577",
    )
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    monkeypatch.setenv(
        repository_module.AUTHORITY_REPOSITORY_IDENTITY_ENV,
        "github:repository-id:1290429578",
    )

    with pytest.raises(MacError) as captured:
        repository.list_events(task_id)

    assert captured.value.code == "EVENT_AUTHORITY_TAMPERED"


def test_event_stream_prefers_an_explicit_verified_repository_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        repository_module.AUTHORITY_REPOSITORY_IDENTITY_ENV,
        "github:repository-id:1290429577",
    )
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    _, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    repository = FilesystemTaskRepository(
        tmp_path,
        repository_identity="repo:explicit-verified-identity",
    )

    with pytest.raises(MacError) as captured:
        repository.list_events(task_id)

    assert captured.value.code == "EVENT_AUTHORITY_TAMPERED"


def _scope_proposal_command(
    repository: FilesystemTaskRepository,
    task_id: str,
    *,
    key: str,
) -> AppendEvent:
    path = repository.task_dir(task_id) / "scope-contract.yaml"
    scope = load_data(path)
    return AppendEvent(
        task_id=task_id,
        event_type="scope_proposed",
        payload={"scope_id": scope["id"], "version": scope["version"], "scope": scope},
        actor_claim={"id": "a", "kind": "agent"},
        expected_revision=0,
        idempotency_key=key,
        operation="scope.propose",
        materializations=((path, scope),),
        replace_existing=frozenset({path}),
        replay_intent={
            "allow": list(scope["allowed_paths"]),
            "deny": list(scope["denied_paths"]),
            "operation": list(scope["allowed_operations"]),
            "owner": list(scope["owners"]),
        },
    )


def test_append_mutation_validates_the_event_stream_only_twice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    command = _scope_proposal_command(repository, task_id, key="counted-scope-proposal")
    original = repository.list_events
    calls = 0

    def counted(requested_task_id: str) -> list[dict[str, object]]:
        nonlocal calls
        calls += 1
        return original(requested_task_id)

    monkeypatch.setattr(repository, "list_events", counted)
    MutationGateway(tmp_path, repository=repository).execute(command)

    assert calls == 2


def test_idempotent_append_reuses_one_snapshot_and_one_prewrite_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    command = _scope_proposal_command(repository, task_id, key="retry-scope-proposal")
    gateway = MutationGateway(tmp_path, repository=repository)
    first = gateway.execute(command)
    original = repository.list_events
    calls = 0

    def counted(requested_task_id: str) -> list[dict[str, object]]:
        nonlocal calls
        calls += 1
        return original(requested_task_id)

    monkeypatch.setattr(repository, "list_events", counted)
    replayed = gateway.execute(command)

    assert replayed.idempotent_replay
    assert replayed.event == first.event
    assert calls == 2


def test_append_mutation_rejects_event_stream_change_before_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    command = _scope_proposal_command(repository, task_id, key="raced-scope-proposal")
    frozen_events = repository.list_events(task_id)
    calls = 0

    def changing_events(requested_task_id: str) -> list[dict[str, object]]:
        nonlocal calls
        assert requested_task_id == task_id
        calls += 1
        if calls == 1:
            return frozen_events
        return [*frozen_events, {"event_id": "EVT-concurrent-change"}]

    monkeypatch.setattr(repository, "list_events", changing_events)
    with pytest.raises(MacError) as captured:
        MutationGateway(tmp_path, repository=repository).execute(command)

    assert captured.value.code == "MUTATION_EVENT_STREAM_CHANGED"
    assert len(list((repository.task_dir(task_id) / "events").glob("EVT-*.json"))) == 1


def test_policy_independence_floor_does_not_rewrite_the_signed_intent() -> None:
    audit = {
        "independence_level": "L3",
        "minimum_independence": None,
    }
    task = {"mode": "standard"}
    scope = {"allowed_paths": ["src/**"], "risk_tags": []}
    config = {
        "modes": {"standard": {"minimum_review_independence": "L1"}},
        "security": {"governance_sensitive_paths": []},
    }

    _enforce_operation_independence(
        audit,
        task,
        scope,
        config,
        operation="scope.approve",
        task_id="TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q",
    )

    assert audit["minimum_independence"] is None
    assert audit["policy_minimum_independence"] == "L1"


def test_event_replay_rejects_a_tampered_policy_independence_floor(
    tmp_path: Path,
) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    scope_approve(
        task_id=task_id,
        expected_revision=0,
        idempotency_key="approve-policy-floor",
        actor="governance-owner",
        independence_level="L1",
        repo=tmp_path,
        json_output=True,
    )
    event = repository.list_events(task_id)[-1]
    event["payload"]["authority"]["policy_minimum_independence"] = "L1"
    atomic_write_json(
        repository.task_dir(task_id) / "events" / f"{event['event_id']}.json",
        event,
    )

    with pytest.raises(MacError) as captured:
        repository.list_events(task_id)

    assert captured.value.code == "EVENT_POLICY_GUARD_INVALID"


def test_transition_mutation_validates_the_event_stream_only_twice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    scope_approve(
        task_id=task_id,
        expected_revision=0,
        idempotency_key="approve-counted-transition",
        actor="governance-owner",
        independence_level="L1",
        repo=tmp_path,
        json_output=True,
    )
    actor = {"id": "controller", "kind": "human"}
    context = resolve_transition_context(tmp_path, task_id, "ready", actor)
    command = Transition(
        task_id=task_id,
        target="ready",
        context=context,
        actor_claim=actor,
        expected_revision=1,
        idempotency_key="counted-ready-transition",
        operation="task.transition.ready",
    )
    original = repository.list_events
    calls = 0

    def counted(requested_task_id: str) -> list[dict[str, object]]:
        nonlocal calls
        calls += 1
        return original(requested_task_id)

    monkeypatch.setattr(repository, "list_events", counted)
    MutationGateway(tmp_path, repository=repository).execute(command)

    assert calls == 2


def test_portable_run_event_replays_after_head_moves_and_in_another_worktree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_identity = "github:repository-id:1290429577"
    monkeypatch.setenv(
        repository_module.AUTHORITY_REPOSITORY_IDENTITY_ENV,
        repository_identity,
    )
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    approve_and_ready_task(tmp_path, task_id)
    work_unit_new(
        task_id,
        title="portable execution",
        owner="governance",
        allow=["AGENTS.md"],
        depends_on=[],
        expected_revision=2,
        idempotency_key="portable-work-unit",
        actor="a",
        repo=tmp_path,
        json_output=True,
    )
    work_unit_id = next(
        (repository.task_dir(task_id) / "work-units").glob("*.yaml")
    ).stem
    work_unit_ready(
        task_id,
        work_unit_id,
        expected_revision=3,
        idempotency_key="portable-work-unit-ready",
        actor="a",
        repo=tmp_path,
        json_output=True,
    )
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-m", "ready portable run"],
        check=True,
        capture_output=True,
    )

    source_ref = "refs/heads/codex/portable-run"
    git = GitRepository(tmp_path)
    baseline_subject = git.commit_subject("HEAD")
    scope = load_data(repository.task_dir(task_id) / "scope-contract.yaml")
    binding_checks = git.portable_run_binding_checks(
        approved_base=str(scope["base_commit"]),
        baseline_subject=baseline_subject,
        source_ref_subject=baseline_subject,
    )
    work_unit_path = (
        repository.task_dir(task_id) / "work-units" / f"{work_unit_id}.yaml"
    )
    work_unit = load_data(work_unit_path)
    running_work_unit = deepcopy(work_unit)
    running_work_unit["status"] = "running"
    run_id = "RUN-01K0W4Z36K3W5C2R0A3M8N9P7V"
    run = {
        "schema_version": 1,
        "id": run_id,
        "task_id": task_id,
        "work_unit_id": work_unit_id,
        "status": "running",
        "actor": {"id": "a", "kind": "agent"},
        "runtime": {
            "profile": "local-single",
            "execution_context_id": "portable-run",
        },
        "independence_level": "L0",
        "started_at": utc_now(),
        "finished_at": None,
        "exit_code": None,
    }
    worktree_identity = {
        "kind": "portable",
        "repository_identity": repository_identity,
        "source_ref": source_ref,
    }
    repository_binding = {
        "kind": "portable",
        "repository_identity": repository_identity,
        "source_ref": source_ref,
        "source_digest": baseline_subject["commit_sha"],
        **binding_checks,
    }
    run_path = repository.task_dir(task_id) / "runs" / f"{run_id}.json"
    command = AppendEvent(
        task_id=task_id,
        event_type="run_started",
        payload={
            "run_id": run_id,
            "work_unit_id": work_unit_id,
            "run": run,
            "work_unit": running_work_unit,
            "baseline_subject": baseline_subject,
            "worktree_identity": worktree_identity,
            "repository_binding": repository_binding,
        },
        actor_claim={"id": "a", "kind": "agent"},
        expected_revision=4,
        idempotency_key="portable-run-register",
        operation="run.register",
        run_id=run_id,
        materializations=(
            (run_path, run),
            (work_unit_path, running_work_unit),
        ),
        replace_existing=frozenset({work_unit_path}),
        replay_intent={
            "work_unit_id": work_unit_id,
            "profile": "local-single",
            "context_id": "portable-run",
            "provider": None,
            "model": None,
            "worktree": None,
            "branch": None,
            "actor_kind": "agent",
            "independence_level": "L0",
        },
    )

    gateway = MutationGateway(tmp_path, repository=repository)
    with pytest.raises(MacError) as unsigned:
        gateway.execute(command)
    assert unsigned.value.code == "MUTATION_RUN_PORTABLE_BINDING_INVALID"

    revision_payload = deepcopy(command.payload)
    revision_source_ref = f"{source_ref}~0"
    revision_payload["worktree_identity"]["source_ref"] = revision_source_ref
    revision_payload["repository_binding"]["source_ref"] = revision_source_ref
    revision_command = replace(command, payload=revision_payload)
    revision_prepared = gateway.prepare(revision_command)
    authority_dir = tmp_path.parent / f"{tmp_path.name}-authority"
    authority_dir.mkdir()
    _configure_sigstore_authority(
        authority_dir,
        monkeypatch,
        revision_prepared.request,
        source_ref=revision_source_ref,
        source_digest=str(baseline_subject["commit_sha"]),
    )
    with pytest.raises(MacError) as revision_expression:
        gateway.execute(revision_command)
    assert (
        revision_expression.value.code
        == "MUTATION_RUN_PORTABLE_BINDING_INVALID"
    )

    prepared = gateway.prepare(command)
    _configure_sigstore_authority(
        authority_dir,
        monkeypatch,
        prepared.request,
        source_ref=source_ref,
        source_digest=str(baseline_subject["commit_sha"]),
        repository_identity="github:repository-id:1",
    )
    with pytest.raises(MacError) as repository_mismatch:
        gateway.execute(command)
    assert (
        repository_mismatch.value.code
        == "AUTHORITY_BINDING_MISMATCH"
    )

    _configure_sigstore_authority(
        authority_dir,
        monkeypatch,
        prepared.request,
        source_ref=source_ref,
        source_digest=str(baseline_subject["commit_sha"]),
    )
    gateway.execute(command)
    for name in (
        "MAC_AUTHORITY_SIGSTORE_BUNDLE",
        "MAC_AUTHORITY_SIGSTORE_PREDICATE",
        "MAC_AUTHORITY_SIGSTORE_SOURCE_REF",
        "MAC_AUTHORITY_SIGSTORE_SOURCE_DIGEST",
    ):
        monkeypatch.delenv(name)
    actor = {"id": "a", "kind": "agent"}
    context = resolve_transition_context(
        tmp_path,
        task_id,
        "executing",
        actor,
    )
    assert context.executor_run_created
    assert context.work_unit_dependencies_complete
    assert context.dependencies_complete
    gateway.execute(
        Transition(
            task_id=task_id,
            target="executing",
            context=context,
            actor_claim=actor,
            expected_revision=5,
            idempotency_key="portable-task-executing",
            operation="task.transition.executing",
            replay_intent={"target": "executing"},
        )
    )
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-m", "record portable run"],
        check=True,
        capture_output=True,
    )
    (tmp_path / "later.txt").write_text("later\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "later.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-m", "move head"],
        check=True,
        capture_output=True,
    )
    monkeypatch.delenv(
        repository_module.AUTHORITY_REPOSITORY_IDENTITY_ENV,
    )
    monkeypatch.delenv("GITHUB_ACTIONS")

    run_event = next(
        event
        for event in repository.list_events(task_id)
        if event["event_type"] == "run_started"
    )
    assert run_event["payload"]["worktree_identity"] == worktree_identity
    linked = tmp_path.parent / f"{tmp_path.name}-portable-replay"
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "worktree",
            "add",
            "--detach",
            str(linked),
            "HEAD",
        ],
        check=True,
        capture_output=True,
    )
    replayed = FilesystemTaskRepository(linked).list_events(task_id)
    assert replayed[-1]["event_type"] == "state_transitioned"
    assert replayed[-1]["payload"]["to"] == "executing"


def test_raw_event_writer_cannot_be_called_with_a_forged_capability(tmp_path: Path) -> None:
    repository = FilesystemTaskRepository(tmp_path)
    task_id = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    with pytest.raises(MacError) as captured:
        repository._append_event_locked(
            task_id,
            "state_transitioned",
            {"from": "triage", "to": "completed"},
            actor={"id": "attacker", "kind": "agent"},
            expected_revision=0,
            idempotency_key="raw-terminal-write",
            _permit=object(),
        )
    assert captured.value.code == "MUTATION_GATEWAY_REQUIRED"
    assert not (tmp_path / "tasks").exists()


def test_missing_authority_host_fails_before_first_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    init_governance_repo(tmp_path, project="missing-authority")
    remove_test_authority(monkeypatch)
    with pytest.raises(MacError) as captured:
        TaskService(tmp_path).create(
            title="denied",
            mode="standard",
            objective="no mutation",
            acceptance=["zero writes"],
            allowed_paths=["AGENTS.md"],
            owners=["governance"],
            runtime_profile="local-single",
            required_gates=["targeted_tests"],
            actor={"id": "a", "kind": "agent"},
            idempotency_key="missing-authority",
        )
    assert captured.value.code == "AUTHORITY_CONFIGURATION_MISSING"
    assert not list((tmp_path / "tasks").glob("TASK-*"))


def test_evidence_command_requires_an_attested_isolated_executor_before_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    approve_and_ready_task(tmp_path, task_id)
    monkeypatch.setenv("MAC_UNDECLARED_TEST_SECRET", "must-not-reach-command")
    marker = tmp_path / "unisolated-command-ran"
    script = f"from pathlib import Path; Path({str(marker)!r}).write_text('bad', encoding='utf-8')"

    with pytest.raises(MacError) as captured:
        MutationGateway(tmp_path, repository=repository).execute(RecordCommandEvidence(
            task_id=task_id,
            claim="authority_env_isolated",
            argv=(sys.executable, "-c", script),
            actor_claim={"id": "a", "kind": "automation"},
            expected_revision=2,
            idempotency_key="evidence-env-isolated",
            replay_intent={"claim": "authority_env_isolated"},
        ))

    assert captured.value.code == "EVIDENCE_ISOLATED_EXECUTOR_REQUIRED"
    assert not marker.exists()
    assert len(repository.list_events(task_id)) == 3


def test_evidence_rejects_dynamic_shell_through_env_wrapper(tmp_path: Path) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    approve_and_ready_task(tmp_path, task_id)
    marker = tmp_path / "dynamic-shell-ran"

    with pytest.raises(MacError) as captured:
        MutationGateway(tmp_path, repository=repository).execute(RecordCommandEvidence(
            task_id=task_id,
            claim="must-not-run",
            argv=("env", "bash", "-c", f"echo bad > {marker}"),
            actor_claim={"id": "a", "kind": "automation"},
            expected_revision=2,
            idempotency_key="reject-env-shell",
            replay_intent={"claim": "must-not-run"},
        ))

    assert captured.value.code == "EVIDENCE_DYNAMIC_SHELL_FORBIDDEN"
    assert not marker.exists()
    assert len(repository.list_events(task_id)) == 3


def test_event_actor_is_derived_from_verified_authority(tmp_path: Path) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    event = repository.list_events(task_id)[0]
    authority = event["payload"]["authority"]
    assert event["actor"] == {"id": authority["actor_id"], "kind": authority["actor_kind"]}
    assert authority["request_digest"].startswith("sha256:")
    assert authority["binding_digest"].startswith("sha256:")
    assert authority["replay_digest"].startswith("sha256:")


def test_stable_replay_reauthorizes_original_and_rejects_independence_downgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    init_governance_repo(tmp_path, project="stable-replay")
    kwargs = {
        "title": "same intent",
        "mode": "standard",
        "objective": "retry safely",
        "acceptance": ["one event"],
        "allowed_paths": ["AGENTS.md"],
        "owners": ["governance"],
        "runtime_profile": "local-single",
        "required_gates": ["targeted_tests"],
        "actor": {"id": "a", "kind": "agent"},
        "idempotency_key": "stable-create",
    }
    service = TaskService(tmp_path)
    first = service.create(**kwargs)
    retry = service.create(**kwargs)
    assert retry["idempotent_replay"] is True
    assert retry["task"]["id"] == first["task"]["id"]
    assert len(service.repository.list_events(str(first["task"]["id"]))) == 1

    monkeypatch.setenv("MAC_AUTHORITY_BROKER_CONTEXT_TEST_INDEPENDENCE", "L0")
    with pytest.raises(MacError) as captured:
        service.create(**kwargs)
    assert captured.value.code == "MUTATION_REPLAY_INDEPENDENCE_DOWNGRADE"
    assert len(service.repository.list_events(str(first["task"]["id"]))) == 1


@pytest.mark.parametrize("relative", ["scope-contract.yaml", "events/EVT-malicious.json"])
def test_finding_authority_cannot_materialize_scope_or_events(tmp_path: Path, relative: str) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    before_events = repository.list_events(task_id)
    scope_path = repository.task_dir(task_id) / "scope-contract.yaml"
    before_scope = scope_path.read_bytes()
    target = repository.task_dir(task_id) / Path(relative)
    finding = {
        "schema_version": 1,
        "id": "FND-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        "task_id": task_id,
    }
    with pytest.raises(MacError) as captured:
        MutationGateway(tmp_path, repository=repository).execute(AppendEvent(
            task_id=task_id,
            event_type="finding_opened",
            payload={"finding_id": finding["id"], "finding": finding},
            actor_claim={"id": "a", "kind": "agent"},
            expected_revision=0,
            idempotency_key=f"malicious-{target.name}",
            operation="finding.open",
            materializations=((target, finding),),
            replace_existing=frozenset({target}),
            replay_intent={"title": "malicious"},
        ))
    assert captured.value.code == "MUTATION_MATERIALIZATION_FORBIDDEN"
    assert repository.list_events(task_id) == before_events
    assert scope_path.read_bytes() == before_scope
    if relative.startswith("events/"):
        assert not target.exists()


def test_caller_event_id_cannot_escape_or_overwrite_event_store(tmp_path: Path) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    finding = finding_snapshot(task_id, "FND-01K0W4Z36K3W5C2R0A3M8N9P7T")
    target = repository.task_dir(task_id) / "findings" / f"{finding['id']}.json"
    before_events = repository.list_events(task_id)
    with pytest.raises(MacError) as captured:
        MutationGateway(tmp_path, repository=repository).execute(AppendEvent(
            task_id=task_id,
            event_type="finding_opened",
            payload={"finding_id": finding["id"], "finding": finding},
            actor_claim={"id": "a", "kind": "agent"},
            expected_revision=0,
            idempotency_key="unsafe-event-id",
            operation="finding.open",
            event_id="../outside",
            materializations=((target, finding),),
            replay_intent={"title": "bounded"},
        ))
    assert captured.value.code == "EVENT_ID_UNSAFE"
    assert repository.list_events(task_id) == before_events
    assert not target.exists()
    assert not (tmp_path / "tasks" / "outside.json").exists()


def test_tampered_event_entity_id_fails_before_replay_materialization(tmp_path: Path) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    finding = finding_snapshot(task_id, "FND-01K0W4Z36K3W5C2R0A3M8N9P7V")
    target = repository.task_dir(task_id) / "findings" / f"{finding['id']}.json"
    command = AppendEvent(
        task_id=task_id,
        event_type="finding_opened",
        payload={"finding_id": finding["id"], "finding": finding},
        actor_claim={"id": "a", "kind": "agent"},
        expected_revision=0,
        idempotency_key="tampered-replay-entity",
        operation="finding.open",
        materializations=((target, finding),),
        replay_intent={"title": "bounded"},
    )
    result = MutationGateway(tmp_path, repository=repository).execute(command)
    event_path = repository.task_dir(task_id) / "events" / f"{result.event['event_id']}.json"
    event = dict(load_data(event_path))
    event["payload"]["finding"]["id"] = "../../../.agents/config"
    atomic_write_json(event_path, event)
    projection_path = repository.task_dir(task_id) / "task.yaml"
    before_projection = projection_path.read_bytes()

    with pytest.raises(MacError) as captured:
        MutationGateway(tmp_path, repository=repository).execute(command)

    assert captured.value.code == "EVENT_ENTITY_ID_INVALID"
    assert projection_path.read_bytes() == before_projection
    assert not (tmp_path / ".agents" / "config.json").exists()


def test_finding_payload_cannot_inject_or_omit_authoritative_snapshot(tmp_path: Path) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    finding = {
        "schema_version": 1,
        "id": "FND-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        "task_id": task_id,
        "severity": "minor",
        "category": "maintainability",
        "blocking_effect": "advisory",
        "confidence": "confirmed",
        "status": "open",
        "title": "bounded",
        "risk": "none",
        "owner": "governance",
        "evidence_refs": [],
        "invalidates": [],
        "opened_at": now,
        "resolved_at": None,
    }
    target = repository.task_dir(task_id) / "findings" / f"{finding['id']}.json"
    gateway = MutationGateway(tmp_path, repository=repository)
    before = repository.list_events(task_id)
    with pytest.raises(MacError) as injected:
        gateway.execute(AppendEvent(
            task_id=task_id,
            event_type="finding_opened",
            payload={"finding_id": finding["id"], "finding": finding, "work_unit": {"id": "WU-injected"}},
            actor_claim={"id": "a", "kind": "agent"},
            expected_revision=0,
            idempotency_key="finding-injected-snapshot",
            operation="finding.open",
            materializations=((target, finding),),
            replay_intent={"title": "bounded"},
        ))
    assert injected.value.code == "MUTATION_PAYLOAD_CONTRACT_INVALID"

    with pytest.raises(MacError) as omitted:
        gateway.execute(AppendEvent(
            task_id=task_id,
            event_type="finding_opened",
            payload={"finding_id": finding["id"], "finding": finding},
            actor_claim={"id": "a", "kind": "agent"},
            expected_revision=0,
            idempotency_key="finding-omitted-materialization",
            operation="finding.open",
            replay_intent={"title": "bounded"},
        ))
    assert omitted.value.code == "MUTATION_PAYLOAD_MATERIALIZATION_MISMATCH"

    extra = dict(finding)
    extra["id"] = "FND-01K0W4Z36K3W5C2R0A3M8N9P7R"
    extra_target = repository.task_dir(task_id) / "findings" / f"{extra['id']}.json"
    with pytest.raises(MacError) as extra_materialization:
        gateway.execute(AppendEvent(
            task_id=task_id,
            event_type="finding_opened",
            payload={"finding_id": finding["id"], "finding": finding},
            actor_claim={"id": "a", "kind": "agent"},
            expected_revision=0,
            idempotency_key="finding-extra-materialization",
            operation="finding.open",
            materializations=((target, finding), (extra_target, extra)),
            replay_intent={"title": "bounded"},
        ))
    assert extra_materialization.value.code in {
        "MUTATION_ENTITY_PAYLOAD_MISMATCH",
        "MUTATION_MATERIALIZATION_PAYLOAD_MISMATCH",
    }
    assert repository.list_events(task_id) == before
    assert not target.exists()
    assert not extra_target.exists()


def test_gateway_json_snapshots_nested_mutable_mappings_before_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EvilDict(dict[str, object]):
        def __deepcopy__(self, memo: dict[int, object]) -> "EvilDict":
            return self

    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    finding = EvilDict({
        "schema_version": 1,
        "id": "FND-01K0W4Z36K3W5C2R0A3M8N9P7S",
        "task_id": task_id,
        "severity": "minor",
        "category": "maintainability",
        "blocking_effect": "advisory",
        "confidence": "confirmed",
        "status": "open",
        "title": "captured-before-authority",
        "risk": "none",
        "owner": "governance",
        "evidence_refs": [],
        "invalidates": [],
        "opened_at": now,
        "resolved_at": None,
    })
    target = repository.task_dir(task_id) / "findings" / f"{finding['id']}.json"
    original_require = repository_module.require_authority

    def mutate_after_snapshot(*args: object, **kwargs: object):
        finding["title"] = "mutated-after-authority-request"
        return original_require(*args, **kwargs)

    monkeypatch.setattr(repository_module, "require_authority", mutate_after_snapshot)
    result = MutationGateway(tmp_path, repository=repository).execute(AppendEvent(
        task_id=task_id,
        event_type="finding_opened",
        payload={"finding_id": finding["id"], "finding": finding},
        actor_claim={"id": "a", "kind": "agent"},
        expected_revision=0,
        idempotency_key="nested-mapping-snapshot",
        operation="finding.open",
        materializations=((target, finding),),
        replay_intent={"title": "captured-before-authority"},
    ))
    assert ((result.event or {}).get("payload") or {})["finding"]["title"] == "captured-before-authority"
    assert load_data(target)["title"] == "captured-before-authority"
    assert finding["title"] == "mutated-after-authority-request"


def test_transition_cannot_assert_machine_guards(tmp_path: Path) -> None:
    repository, created = create_governed_task(tmp_path)
    task_id = str(created["task"]["id"])
    fake = TransitionContext(triage_complete=True, scope_approved=True, gates_selected=True)
    with pytest.raises(MacError) as captured:
        MutationGateway(tmp_path, repository=repository).execute(Transition(
            task_id=task_id,
            target="ready",
            context=fake,
            actor_claim={"id": "a", "kind": "agent"},
            expected_revision=0,
            idempotency_key="fake-ready-context",
            operation="task.transition.ready",
            replay_intent={"target": "ready"},
        ))
    assert captured.value.code == "AUTHORITY_CONTEXT_INVALID"
    assert len(repository.list_events(task_id)) == 1
    assert repository.load_task(task_id)["state"] == "triage"


def _repair_events(*, rounds: int, actor_kind: str = "automation", root: str | None = "parser-timeout") -> list[dict[str, object]]:
    finding: dict[str, object] = {
        "id": "FND-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        "status": "open",
        "blocking_effect": "block_close",
    }
    if root is not None:
        finding["root_cause_key"] = root
    events: list[dict[str, object]] = [{
        "event_id": "EVT-FINDING",
        "new_revision": 0,
        "event_type": "finding_opened",
        "payload": {"finding": finding},
    }]
    for index in range(rounds):
        events.extend([
            {
                "event_id": f"EVT-REPAIR-{index}",
                "new_revision": index * 2 + 1,
                "event_type": "state_transitioned",
                "actor": {"id": "controller", "kind": actor_kind},
                "payload": {"to": "repairing"},
            },
            {
                "event_id": f"EVT-VERIFY-{index}",
                "new_revision": index * 2 + 2,
                "event_type": "state_transitioned",
                "actor": {"id": "controller", "kind": actor_kind},
                "payload": {"to": "verifying"},
            },
        ])
    return events


def test_automatic_repair_budget_allows_two_rounds_and_rejects_the_third() -> None:
    config = {"repair_policy": {"max_automatic_rounds_per_root_cause": 2}}
    second = _assess_repair_round(
        _repair_events(rounds=1),
        config,
        actor_kind="automation",
        task_id="TASK-TEST",
    )
    assert second["counts"] == {"parser-timeout": 1}

    with pytest.raises(MacError) as captured:
        _assess_repair_round(
            _repair_events(rounds=2),
            config,
            actor_kind="automation",
            task_id="TASK-TEST",
        )
    assert captured.value.code == "REPAIR_ROUND_LIMIT_EXHAUSTED"
    assert captured.value.issue.details["next_targets"] == ["waiting_input", "failed"]


def test_human_repair_does_not_consume_budget_and_automatic_repair_requires_a_root() -> None:
    config = {"repair_policy": {"max_automatic_rounds_per_root_cause": 2}}
    human_history = _assess_repair_round(
        _repair_events(rounds=3, actor_kind="human"),
        config,
        actor_kind="automation",
        task_id="TASK-TEST",
    )
    assert human_history["counts"] == {"parser-timeout": 0}

    with pytest.raises(MacError) as captured:
        _assess_repair_round(
            _repair_events(rounds=0, root=None),
            config,
            actor_kind="agent",
            task_id="TASK-TEST",
        )
    assert captured.value.code == "REPAIR_ROOT_CAUSE_REQUIRED"


def test_repair_to_verifying_requires_a_result_from_the_current_round() -> None:
    events = [
        {"new_revision": 2, "event_type": "result_submitted", "payload": {}},
        {"new_revision": 3, "event_type": "state_transitioned", "payload": {"to": "repairing"}},
    ]
    assert not _results_complete_after_latest_repair(
        events,
        results_present=True,
        work_units_complete=True,
    )
    events.append({"new_revision": 4, "event_type": "result_submitted", "payload": {}})
    assert _results_complete_after_latest_repair(
        events,
        results_present=True,
        work_units_complete=True,
    )


def test_legacy_event_without_authority_remains_readable(tmp_path: Path) -> None:
    task_id = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    legacy_task = task(task_id)
    legacy_task["legacy_id"] = "legacy-7"
    legacy_task["legacy_integrity"] = "metadata_only"
    event = {
        "schema_version": 1,
        "event_id": "EVT-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        "task_id": task_id,
        "event_type": "legacy_imported",
        "occurred_at": "2026-07-17T00:00:00Z",
        "actor": {"id": "migration-automation", "kind": "automation"},
        "run_id": None,
        "expected_revision": -1,
        "new_revision": 0,
        "idempotency_key": "legacy-import:legacy-7",
        "payload": {
            "task": legacy_task,
            "legacy_id": "legacy-7",
            "legacy_status": "complete",
            "integrity": "metadata_only",
            "verification_status": "unverifiable",
            "source_path": "tasks/index.yaml",
            "source_digest": "sha256:" + ("a" * 64),
        },
    }
    path = tmp_path / "tasks" / task_id / "events" / f"{event['event_id']}.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(event), encoding="utf-8")
    assert FilesystemTaskRepository(tmp_path).list_events(task_id) == [event]
