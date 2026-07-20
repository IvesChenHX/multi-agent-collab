from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mac.errors import ExitCode, MacError
from mac.events import replay_events
from mac.cli import init_command
from mac.repository import FilesystemTaskRepository
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
    repository.create_task(task(task_id), actor={"id": "a", "kind": "agent"}, idempotency_key="create")
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


def test_controller_lease_recovers_an_old_legacy_cas_guard_but_not_a_fresh_one(tmp_path: Path) -> None:
    task_id = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    private = tmp_path / "tasks" / task_id / "private"
    private.mkdir(parents=True)
    guard = private / ".controller.lease.cas"
    guard.write_text("12345\n", encoding="ascii")
    old = time.time() - 301
    os.utime(guard, (old, old))
    repository = FilesystemTaskRepository(tmp_path)

    with repository.lease(task_id, "recovery-agent"):
        assert (private / "controller.lease").is_file()

    guard.write_text("12345\n", encoding="ascii")
    with pytest.raises(MacError) as caught:
        with repository.lease(task_id, "competing-agent"):
            pass
    assert caught.value.code == "LEASE_CONFLICT"


def test_controller_lease_recovers_a_well_formed_guard_owned_by_a_dead_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mac.repository as repository_module

    monkeypatch.setattr(repository_module, "_process_is_alive", lambda pid: False)
    task_id = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    private = tmp_path / "tasks" / task_id / "private"
    private.mkdir(parents=True)
    guard = private / ".controller.lease.cas"
    guard.write_text(json.dumps({
        "token": "CAS-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        "owner": "crashed-agent",
        "pid": 424242,
        "created_at": "2026-07-20T00:00:00Z",
        "expires_unix": time.time() + 60,
    }), encoding="utf-8")
    repository = FilesystemTaskRepository(tmp_path)

    with repository.lease(task_id, "recovery-agent") as token:
        payload = json.loads((private / "controller.lease").read_text(encoding="utf-8"))
        assert payload["token"] == token

    assert not guard.exists()


def test_controller_lease_cannot_take_over_an_active_cas_guard(tmp_path: Path) -> None:
    task_id = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    (tmp_path / "tasks" / task_id).mkdir(parents=True)
    repository = FilesystemTaskRepository(tmp_path)
    entered = threading.Event()
    release = threading.Event()

    def hold_guard() -> None:
        with repository._lease_cas_guard(task_id, "active-agent"):
            entered.set()
            release.wait(timeout=2)

    worker = threading.Thread(target=hold_guard)
    worker.start()
    assert entered.wait(timeout=2)
    guard_payload = json.loads(
        (tmp_path / "tasks" / task_id / "private" / ".controller.lease.cas").read_text(encoding="utf-8")
    )
    assert set(guard_payload) == {"token", "owner", "pid", "created_at", "expires_unix"}
    assert guard_payload["owner"] == "active-agent"
    assert guard_payload["pid"] == os.getpid()
    assert guard_payload["expires_unix"] > time.time()
    try:
        with pytest.raises(MacError) as caught:
            with repository.lease(task_id, "competing-agent"):
                pass
        assert caught.value.code == "LEASE_CONFLICT"
    finally:
        release.set()
        worker.join(timeout=2)
    assert not worker.is_alive()


def test_stale_cas_takeover_fails_closed_if_the_observed_guard_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mac.repository as repository_module

    monkeypatch.setattr(repository_module, "_process_is_alive", lambda pid: True)
    task_id = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    private = tmp_path / "tasks" / task_id / "private"
    private.mkdir(parents=True)
    guard = private / ".controller.lease.cas"
    guard.write_text(json.dumps({
        "token": "CAS-STALE",
        "owner": "stale-agent",
        "pid": 111,
        "created_at": "2026-07-20T00:00:00Z",
        "expires_unix": 0,
    }), encoding="utf-8")
    fresh = {
        "token": "CAS-FRESH",
        "owner": "fresh-agent",
        "pid": 222,
        "created_at": "2026-07-20T00:00:01Z",
        "expires_unix": time.time() + 300,
    }
    real_replace = os.replace

    def raced_replace(source: str | os.PathLike[str], target: str | os.PathLike[str]) -> None:
        if Path(source) == guard:
            guard.write_text(json.dumps(fresh), encoding="utf-8")
        real_replace(source, target)

    monkeypatch.setattr(repository_module.os, "replace", raced_replace)
    repository = FilesystemTaskRepository(tmp_path)
    with pytest.raises(MacError) as caught:
        with repository.lease(task_id, "recovery-agent"):
            pass

    assert caught.value.code == "LEASE_CONFLICT"
    assert json.loads(guard.read_text(encoding="utf-8"))["token"] == "CAS-FRESH"
