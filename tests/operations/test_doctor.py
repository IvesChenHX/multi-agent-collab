from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from mac.application.task_service import TaskService
from mac.cli import init_command, scope_amend, scope_approve
from mac.doctor import repair_safe, run_doctor
from mac.errors import MacError
from mac.io import load_data
from tests.security.test_authority_commands import configure_test_authority


TASK_ID = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"


@pytest.fixture(autouse=True)
def _host_authority_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_test_authority(monkeypatch)


def _signed_task(root: Path) -> str:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "test"], check=True)
    init_command(repo=root, project="doctor-recovery", json_output=True)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "freeze governance"], check=True)
    created = TaskService(root).create(
        title="doctor",
        mode="standard",
        objective="Prove safe recovery.",
        acceptance=["Recover"],
        allowed_paths=["src/**"],
        owners=["governance"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "proposer", "kind": "human"},
        idempotency_key="doctor-fixture",
    )
    return str(created["task"]["id"])


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _task_event() -> dict[str, object]:
    projection = {
        "schema_version": 6,
        "id": TASK_ID,
        "title": "Doctor recovery fixture",
        "mode": "standard",
        "state": "ready",
        "revision": 0,
        "created_at": "2026-07-17T00:00:00Z",
        "updated_at": "2026-07-17T00:00:00Z",
        "objective": "Prove safe recovery.",
        "acceptance_criteria": [{"id": "AC-001", "text": "Recover", "required": True}],
        "policy_ref": {"path": ".agents/policy.lock.json", "digest": "sha256:" + "a" * 64},
        "ownership_ref": {"path": ".agents/ownership.yaml", "digest": "sha256:" + "b" * 64},
        "scope_contract_ref": f"tasks/{TASK_ID}/scope-contract.yaml",
        "required_gates": ["approved_scope"],
    }
    return {
        "schema_version": 1,
        "event_id": "EVT-01K0W4Z36K3W5C2R0A3M8N9P81",
        "task_id": TASK_ID,
        "event_type": "task_created",
        "occurred_at": "2026-07-17T00:00:00Z",
        "actor": {"id": "tester", "type": "human"},
        "run_id": None,
        "expected_revision": -1,
        "new_revision": 0,
        "idempotency_key": "doctor-fixture",
        "payload": {"task": projection},
    }


def _scope_event(
    revision: int,
    scope: dict[str, object],
    *,
    event_type: str,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "event_id": f"EVT-{revision:026d}",
        "task_id": TASK_ID,
        "event_type": event_type,
        "occurred_at": f"2026-07-17T00:00:0{revision}Z",
        "actor": {"id": "tester", "type": "human"},
        "run_id": None,
        "expected_revision": revision - 1,
        "new_revision": revision,
        "idempotency_key": f"scope-{revision}",
        "payload": {"scope": scope},
    }


def test_doctor_is_read_only(tmp_path):
    config = tmp_path / ".agents" / "config.yaml"
    config.parent.mkdir(parents=True)
    config.write_text("schema_version: 6\ngovernance_level: advisory\n", encoding="utf-8")
    before = _snapshot(tmp_path)

    run_doctor(tmp_path)

    assert _snapshot(tmp_path) == before


def test_repair_safe_only_repairs_derived_or_temporary_state(tmp_path):
    task_id = _signed_task(tmp_path)
    task_dir = tmp_path / "tasks" / task_id
    (task_dir / "task.yaml").unlink()
    scope = task_dir / "scope-contract.yaml"
    expected_scope = load_data(scope)
    scope.unlink()
    risk = task_dir / "risk-acceptance.json"
    risk.write_text('{"status":"active"}\n', encoding="utf-8")
    approval = task_dir / "approvals" / "APR.json"
    approval.parent.mkdir()
    approval.write_text('{"decision":"approved"}\n', encoding="utf-8")
    temporary = task_dir / ".task.yaml.abcd1234.tmp"
    temporary.write_text("partial", encoding="utf-8")
    arbitrary = task_dir / "artifact.tmp"
    arbitrary.write_text("business artifact", encoding="utf-8")
    lookalike = task_dir / ".task.yaml.interrupted.tmp"
    lookalike.write_text("business artifact", encoding="utf-8")
    old = time.time() - 120
    os.utime(temporary, (old, old))
    lease = task_dir / "private" / "controller.lease"
    lease.parent.mkdir()
    lease.write_text(
        json.dumps(
            {
                "token": "LEASE-01K0W4Z36K3W5C2R0A3M8N9P82",
                "owner": "tester",
                "acquired_at": "2026-07-17T00:00:00Z",
                "expires_unix": 0,
            }
        ),
        encoding="utf-8",
    )
    protected = {path: path.read_bytes() for path in (risk, approval)}

    preview = repair_safe(tmp_path)

    assert preview.applied is False
    assert preview.plan_digest.startswith("sha256:")
    assert temporary.exists() and lease.exists()

    repair_safe(tmp_path, apply=True, expected_plan_digest=preview.plan_digest)

    assert not temporary.exists()
    assert not lease.exists()
    assert arbitrary.exists()
    assert lookalike.exists()
    assert (task_dir / "task.yaml").is_file()
    assert load_data(scope) == expected_scope
    assert (tmp_path / "tasks" / "INDEX.generated.json").is_file()
    assert {path: path.read_bytes() for path in protected} == protected


def test_repair_safe_refuses_a_changed_preview_plan(tmp_path):
    task_dir = tmp_path / "tasks" / TASK_ID
    task_dir.mkdir(parents=True)
    temporary = task_dir / ".task.yaml.abcd1234.tmp"
    temporary.write_text("partial", encoding="utf-8")
    old = time.time() - 120
    os.utime(temporary, (old, old))
    preview = repair_safe(tmp_path)
    temporary.write_text("changed", encoding="utf-8")
    os.utime(temporary, (old, old))

    with pytest.raises(MacError) as caught:
        repair_safe(tmp_path, apply=True, expected_plan_digest=preview.plan_digest)

    assert caught.value.code == "DOCTOR_REPAIR_PLAN_CHANGED"
    assert temporary.exists()


def test_repair_safe_apply_requires_the_preview_plan_digest(tmp_path):
    with pytest.raises(MacError) as caught:
        repair_safe(tmp_path, apply=True)

    assert caught.value.code == "DOCTOR_REPAIR_PLAN_DIGEST_REQUIRED"


def test_repair_safe_rejects_non_replayable_event_inputs(tmp_path):
    task_dir = tmp_path / "tasks" / TASK_ID
    events = task_dir / "events"
    events.mkdir(parents=True)
    event = _task_event()
    event["task_id"] = "TASK-01K0W4Z36K3W5C2R0A3M8N9P99"
    (events / "EVT-01K0W4Z36K3W5C2R0A3M8N9P81.json").write_text(
        json.dumps(event), encoding="utf-8"
    )

    with pytest.raises(MacError) as caught:
        repair_safe(tmp_path)

    assert caught.value.code == "DOCTOR_REPLAY_INPUT_INVALID"


def test_repair_safe_rejects_unsigned_modern_event_stream(tmp_path: Path) -> None:
    task_dir = tmp_path / "tasks" / TASK_ID
    events = task_dir / "events"
    events.mkdir(parents=True)
    event = _task_event()
    event["actor"] = {"id": "tester", "kind": "human"}
    (events / f"{event['event_id']}.json").write_text(json.dumps(event), encoding="utf-8")

    with pytest.raises(MacError) as caught:
        repair_safe(tmp_path)

    assert caught.value.code == "DOCTOR_REPLAY_INPUT_INVALID"
    assert (caught.value.issue.details or {})["cause"] == "EVENT_AUTHORITY_MISSING"


def test_repair_safe_rejects_event_replacement_during_plan_capture(tmp_path, monkeypatch):
    task_dir = tmp_path / "tasks" / TASK_ID
    events = task_dir / "events"
    events.mkdir(parents=True)
    event_path = events / "EVT-01K0W4Z36K3W5C2R0A3M8N9P81.json"
    event_path.write_text(json.dumps(_task_event()), encoding="utf-8")
    original_read_bytes = Path.read_bytes
    replaced = False

    def racing_read(path: Path) -> bytes:
        nonlocal replaced
        content = original_read_bytes(path)
        if path == event_path and not replaced:
            replaced = True
            changed = _task_event()
            changed["payload"]["task"]["title"] = "replacement with a different size"
            path.write_text(json.dumps(changed), encoding="utf-8")
        return content

    monkeypatch.setattr(Path, "read_bytes", racing_read)

    with pytest.raises(MacError) as caught:
        repair_safe(tmp_path)

    assert replaced is True
    assert caught.value.code == "DOCTOR_REPLAY_INPUT_INVALID"


def test_repair_safe_restores_scope_contract_and_history_from_events(tmp_path: Path) -> None:
    task_id = _signed_task(tmp_path)
    task_dir = tmp_path / "tasks" / task_id
    scope_approve(
        task_id,
        expected_revision=0,
        idempotency_key="doctor-scope-v1",
        actor="governance-owner",
        independence_level="L1",
        repo=tmp_path,
        json_output=True,
    )
    scope_amend(
        task_id,
        add=["tests/**"],
        add_operation=[],
        expected_revision=1,
        idempotency_key="doctor-scope-amend",
        actor="proposer",
        approver=["governance-owner"],
        risk_tag=[],
        independent=False,
        repo=tmp_path,
        json_output=True,
    )
    scope_approve(
        task_id,
        expected_revision=2,
        idempotency_key="doctor-scope-v2",
        actor="governance-owner",
        independence_level="L1",
        repo=tmp_path,
        json_output=True,
    )
    scope_path = task_dir / "scope-contract.yaml"
    history_path = task_dir / "scope-history" / "scope-contract.v1.yaml"
    approved = load_data(scope_path)
    base = load_data(history_path)
    scope_path.unlink()
    history_path.unlink()

    preview = repair_safe(tmp_path)

    assert f"tasks/{task_id}/scope-contract.yaml" in preview.projections
    assert f"tasks/{task_id}/scope-history/scope-contract.v1.yaml" in preview.projections
    repair_safe(tmp_path, apply=True, expected_plan_digest=preview.plan_digest)

    assert load_data(task_dir / "scope-contract.yaml") == approved
    assert load_data(task_dir / "scope-history" / "scope-contract.v1.yaml") == base
