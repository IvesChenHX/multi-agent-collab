from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import time

import pytest

from mac.errors import ExitCode, MacError
from mac.events import replay_events
from mac.cli import init_command
from mac.application.task_service import TaskService
from mac.repository import FilesystemTaskRepository
from mac.repository import build_policy_ref
from mac.io import load_data
from mac.policy import ownership_source_path, policy_source_paths
from mac.state_machine import TransitionContext


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


def test_event_is_durable_before_projection_and_rebuild_recovers(tmp_path: Path) -> None:
    repository = FilesystemTaskRepository(tmp_path)
    created = repository.create_task(task("TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"), actor={"id": "a", "kind": "agent"}, idempotency_key="create")

    def crash(stage: str) -> None:
        if stage == "after_event":
            raise RuntimeError("power loss")

    with pytest.raises(RuntimeError):
        repository.append_event(
            created.projection["id"], "state_transitioned", {"from": "triage", "to": "ready"},
            actor={"id": "a", "kind": "agent"}, expected_revision=0, idempotency_key="ready", fault_hook=crash,
        )

    assert repository.load_task(created.projection["id"])["revision"] == 0
    rebuilt = repository.rebuild_task(created.projection["id"])
    assert rebuilt["state"] == "ready"
    assert rebuilt["revision"] == 1


def test_idempotency_and_revision_conflict_are_deterministic(tmp_path: Path) -> None:
    init_command(repo=tmp_path, project="event-store", json_output=True)
    (tmp_path / "AGENTS.md").write_text("# rules\n", encoding="utf-8")
    repository = FilesystemTaskRepository(tmp_path)
    task_id = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    value = task(task_id)
    config = load_data(tmp_path / ".agents/config.yaml")
    value["policy_ref"] = build_policy_ref(tmp_path, list(policy_source_paths(config, "local-single")))
    value["ownership_ref"] = build_policy_ref(tmp_path, [ownership_source_path(config)])
    repository.create_task(value, actor={"id": "a", "kind": "agent"}, idempotency_key="create")
    first = repository.transition(task_id, "ready", TransitionContext(triage_complete=True, scope_approved=True, gates_selected=True), actor={"id": "a", "kind": "agent"}, expected_revision=0, idempotency_key="same")
    retried = repository.transition(task_id, "ready", TransitionContext(triage_complete=True, scope_approved=True, gates_selected=True), actor={"id": "a", "kind": "agent"}, expected_revision=0, idempotency_key="same")
    assert retried.event == first.event
    assert len(repository.list_events(task_id)) == 2

    with pytest.raises(MacError) as caught:
        repository.append_event(task_id, "finding_opened", {}, actor={"id": "a", "kind": "agent"}, expected_revision=0, idempotency_key="stale")
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


def test_expired_record_cannot_be_stolen_while_controller_holds_lock(tmp_path: Path) -> None:
    repository = FilesystemTaskRepository(tmp_path)
    task_id = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    repository.create_task(task(task_id), actor={"id": "a", "kind": "agent"}, idempotency_key="create")

    with repository.lease(task_id, "first", ttl_seconds=0.01):
        time.sleep(0.02)
        with pytest.raises(MacError) as captured:
            with FilesystemTaskRepository(tmp_path).lease(task_id, "second"):
                pass

    assert captured.value.code == "LEASE_CONFLICT"


def test_task_service_freezes_safe_lineage_in_creation_event(tmp_path: Path) -> None:
    parent = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    predecessor = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7R"
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
