from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import pytest

from mac.doctor import repair_safe, run_doctor
from mac.repository import FilesystemTaskRepository


TASK_ID = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"


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


def test_doctor_is_read_only(tmp_path):
    config = tmp_path / ".agents" / "config.yaml"
    config.parent.mkdir(parents=True)
    config.write_text("schema_version: 6\ngovernance_level: advisory\n", encoding="utf-8")
    before = _snapshot(tmp_path)

    run_doctor(tmp_path)

    assert _snapshot(tmp_path) == before


def test_repair_safe_only_repairs_derived_or_temporary_state(tmp_path):
    task_dir = tmp_path / "tasks" / TASK_ID
    events = task_dir / "events"
    events.mkdir(parents=True)
    (events / "EVT-01K0W4Z36K3W5C2R0A3M8N9P81.json").write_text(
        json.dumps(_task_event()), encoding="utf-8"
    )
    scope = task_dir / "scope-contract.yaml"
    scope.write_text("status: approved\nallowed_paths:\n  - src/**\n", encoding="utf-8")
    risk = task_dir / "risk-acceptance.json"
    risk.write_text('{"status":"active"}\n', encoding="utf-8")
    approval = task_dir / "approvals" / "APR.json"
    approval.parent.mkdir()
    approval.write_text('{"decision":"approved"}\n', encoding="utf-8")
    temporary = task_dir / ".task.yaml.interrupted.tmp"
    temporary.write_text("partial", encoding="utf-8")
    arbitrary = task_dir / "artifact.tmp"
    arbitrary.write_text("business artifact", encoding="utf-8")
    old = time.time() - 120
    os.utime(temporary, (old, old))
    lease = task_dir / "private" / "controller.lease"
    lease.parent.mkdir()
    lease.write_text('{"token":"old","expires_unix":0}\n', encoding="utf-8")
    protected = {path: path.read_bytes() for path in (scope, risk, approval)}

    preview = repair_safe(tmp_path)

    assert preview.applied is False
    assert temporary.exists() and lease.exists()

    repair_safe(tmp_path, apply=True)

    assert not temporary.exists()
    assert not lease.exists()
    assert arbitrary.exists()
    assert (task_dir / "task.yaml").is_file()
    assert (tmp_path / "tasks" / "INDEX.generated.json").is_file()
    assert {path: path.read_bytes() for path in protected} == protected


def test_repair_safe_never_classifies_hidden_business_tmp_as_atomic_output(tmp_path):
    task_dir = tmp_path / "tasks" / TASK_ID
    task_dir.mkdir(parents=True)
    known_atomic = task_dir / ".task.yaml.interrupted.tmp"
    known_atomic.write_text("partial projection", encoding="utf-8")
    business_file = task_dir / ".customer.invoice.ABCDEF.tmp"
    business_file.write_text("business data", encoding="utf-8")
    old = time.time() - 120
    os.utime(known_atomic, (old, old))
    os.utime(business_file, (old, old))

    report = repair_safe(tmp_path)

    assert known_atomic.relative_to(tmp_path).as_posix() in report.temporary_files
    assert business_file.relative_to(tmp_path).as_posix() not in report.temporary_files


def test_doctor_reports_config_schema_version_as_an_explicit_check(tmp_path):
    agents = tmp_path / ".agents"
    agents.mkdir()
    (agents / "config.yaml").write_text("schema_version: 5\n", encoding="utf-8")

    report = run_doctor(tmp_path)
    checks = {check.name: check for check in report.checks}

    assert "config_schema_version" in checks
    assert checks["config_schema_version"].required is True
    assert checks["config_schema_version"].ok is False


def _cas_payload(*, expires_unix: float, pid: int = 424242) -> str:
    return json.dumps({
        "token": "CAS-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        "owner": "controller",
        "pid": pid,
        "created_at": "2026-07-20T00:00:00Z",
        "expires_unix": expires_unix,
    })


def test_repair_safe_only_recovers_stale_cas_in_the_exact_task_private_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mac.repository as repository_module

    monkeypatch.setattr(repository_module, "_process_is_alive", lambda pid: True)
    task_private = tmp_path / "tasks" / TASK_ID / "private"
    task_private.mkdir(parents=True)
    stale = task_private / ".controller.lease.cas"
    stale.write_text(_cas_payload(expires_unix=0), encoding="utf-8")
    nested = task_private / "business" / ".controller.lease.cas"
    nested.parent.mkdir()
    nested.write_text(_cas_payload(expires_unix=0), encoding="utf-8")

    preview = repair_safe(tmp_path)

    assert stale.relative_to(tmp_path).as_posix() in preview.expired_leases
    assert nested.relative_to(tmp_path).as_posix() not in preview.expired_leases
    applied = repair_safe(tmp_path, apply=True)
    assert stale.relative_to(tmp_path).as_posix() in applied.expired_leases
    assert not stale.exists()
    assert nested.exists()


def test_repair_safe_does_not_list_an_expired_cas_guard_while_its_owner_is_active(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mac.doctor as doctor_module

    task_dir = tmp_path / "tasks" / TASK_ID
    task_dir.mkdir(parents=True)
    repository = FilesystemTaskRepository(tmp_path)
    entered = threading.Event()
    release = threading.Event()

    def hold_guard() -> None:
        with repository._lease_cas_guard(TASK_ID, "active-controller"):
            entered.set()
            release.wait(timeout=2)

    worker = threading.Thread(target=hold_guard)
    worker.start()
    assert entered.wait(timeout=2)
    real_time = time.time
    monkeypatch.setattr(doctor_module.time, "time", lambda: real_time() + 3600)
    try:
        report = repair_safe(tmp_path)
        assert not any(path.endswith("/.controller.lease.cas") for path in report.expired_leases)
    finally:
        release.set()
        worker.join(timeout=2)
    assert not worker.is_alive()


def test_repair_safe_apply_revalidates_a_cas_candidate_before_removing_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mac.doctor as doctor_module
    import mac.repository as repository_module

    monkeypatch.setattr(repository_module, "_process_is_alive", lambda pid: True)
    private = tmp_path / "tasks" / TASK_ID / "private"
    private.mkdir(parents=True)
    guard = private / ".controller.lease.cas"
    guard.write_text(_cas_payload(expires_unix=0), encoding="utf-8")

    def raced_candidates(tasks: Path, *, now: float | None = None) -> list[Path]:
        guard.write_text(_cas_payload(expires_unix=time.time() + 300), encoding="utf-8")
        return [guard]

    monkeypatch.setattr(doctor_module, "_expired_leases", raced_candidates)
    report = repair_safe(tmp_path, apply=True)

    assert guard.exists()
    assert guard.relative_to(tmp_path).as_posix() not in report.expired_leases


def test_repair_safe_uses_a_conservative_age_threshold_for_legacy_cas_guards(tmp_path: Path) -> None:
    old_private = tmp_path / "tasks" / TASK_ID / "private"
    fresh_private = tmp_path / "tasks" / "TASK-01K0W4Z36K3W5C2R0A3M8N9P80" / "private"
    old_private.mkdir(parents=True)
    fresh_private.mkdir(parents=True)
    old_guard = old_private / ".controller.lease.cas"
    fresh_guard = fresh_private / ".controller.lease.cas"
    old_guard.write_text("legacy-pid-only\n", encoding="utf-8")
    fresh_guard.write_text("legacy-pid-only\n", encoding="utf-8")
    old = time.time() - 301
    os.utime(old_guard, (old, old))

    report = repair_safe(tmp_path)

    assert old_guard.relative_to(tmp_path).as_posix() in report.expired_leases
    assert fresh_guard.relative_to(tmp_path).as_posix() not in report.expired_leases
