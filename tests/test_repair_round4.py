from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mac.application.task_service import TaskService
from mac.cli import _close_decision, _write_entity, init_command, run_register, scope_approve
from mac.io import atomic_write_yaml, load_data
from mac.repository import FilesystemTaskRepository, utc_now, validate_task_invariants
from mac.result import ResultService


WORK_UNIT_ID = "WU-01K0W4Z36K3W5C2R0A3M8N9P7Q"
RESULT_ID = "RESULT-01K0W4Z36K3W5C2R0A3M8N9P7Q"


def _git_init(root: Path) -> None:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "test"], check=True)


def _initialized_repo(root: Path) -> None:
    _git_init(root)
    init_command(repo=root, project="round-4", json_output=True)
    (root / "AGENTS.md").write_text("# rules\n", encoding="utf-8")
    ownership_path = root / ".agents/ownership.yaml"
    ownership = load_data(ownership_path)
    ownership["owners"]["backend"] = {"priority": 10, "implementation_role": "backend-implementer", "include": ["src/**"], "approvers": ["backend-owner"]}
    atomic_write_yaml(ownership_path, ownership)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "init"], check=True)


def _task(root: Path) -> str:
    created = TaskService(root).create(
        title="round 4",
        mode="standard",
        objective="repair lifecycle",
        acceptance=["works"],
        allowed_paths=["src/**"],
        owners=["backend"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "test", "kind": "agent"},
        idempotency_key="create-round-4",
    )
    task_id = str(created["task"]["id"])
    scope_approve(task_id, expected_revision=0, idempotency_key="approve-round-4", actor="backend-owner", independence_level="L1", repo=root, json_output=True)
    return task_id


def _work_unit(task_id: str, *, status: str = "ready") -> dict[str, object]:
    return {
        "schema_version": 1,
        "id": WORK_UNIT_ID,
        "task_id": task_id,
        "title": "implement",
        "status": status,
        "owner": "backend",
        "allowed_paths": ["src/**"],
        "depends_on": [],
        "acceptance_criteria": [],
        "expected_result": f"tasks/{task_id}/results/{RESULT_ID}.json",
    }


def _run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": str(root / "src")}
    return subprocess.run(
        [sys.executable, "-m", "mac.cli", *args],
        cwd=cwd or root,
        env=env,
        text=True,
        capture_output=True,
    )


def test_cli_propagates_stable_business_exit_codes_without_tracebacks(tmp_path: Path) -> None:
    invalid_repo = tmp_path / "invalid"
    invalid_repo.mkdir()
    invalid = _run_cli("validate", "--repo", str(invalid_repo), "--json")
    assert invalid.returncode == 3
    assert json.loads(invalid.stdout)["ok"] is False

    repo = tmp_path / "repo"
    repo.mkdir()
    _initialized_repo(repo)
    task_id = _task(repo)

    invalid_transition = _run_cli(
        "task", "transition", task_id, "executing",
        "--expected-revision", "0", "--idempotency-key", "invalid-transition",
        "--repo", str(repo), "--json",
    )
    assert invalid_transition.returncode == 4
    assert json.loads(invalid_transition.stderr)["ok"] is False

    (repo / "outside.txt").write_text("outside scope\n", encoding="utf-8")
    scope = _run_cli("scope", "check", task_id, "--workspace", "--repo", str(repo), "--json")
    assert scope.returncode == 6
    assert json.loads(scope.stdout)["ok"] is False

    evidence = _run_cli(
        "evidence", "record", task_id, "--claim", "targeted_tests",
        "--expected-revision", "1", "--idempotency-key", "failed-evidence",
        "--repo", str(repo), "--json", "--", sys.executable, "-c", "raise SystemExit(1)",
    )
    assert evidence.returncode == 7
    assert json.loads(evidence.stdout)["ok"] is False

    success_repo = tmp_path / "success"
    success_repo.mkdir()
    _initialized_repo(success_repo)
    success = _run_cli("validate", "--repo", str(success_repo), "--json")
    assert success.returncode == 0
    assert json.loads(success.stdout)["ok"] is True

    for completed in (invalid, invalid_transition, scope, evidence, success):
        assert "Traceback" not in completed.stdout
        assert "Traceback" not in completed.stderr


def test_run_and_result_events_project_and_rebuild_work_unit_lifecycle(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _initialized_repo(tmp_path)
    task_id = _task(tmp_path)
    work_unit = _work_unit(task_id)
    _write_entity(
        tmp_path,
        task_id,
        "work-units",
        work_unit,
        "work-unit.schema.json",
        "work_unit_created",
        expected_revision=1,
        idempotency_key="work-unit",
        actor="test",
    )

    run_register(
        task_id,
        work_unit_id=WORK_UNIT_ID,
        profile="local-single",
        context_id="executor-context",
        provider=None,
        model=None,
        worktree=None,
        branch=None,
        actor="executor",
        actor_kind="agent",
        independence_level="L0",
        expected_revision=2,
        idempotency_key="run-start",
        repo=tmp_path,
        json_output=True,
    )
    run_payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    run_id = str(run_payload["run"]["id"])
    work_unit_path = tmp_path / "tasks" / task_id / "work-units" / f"{WORK_UNIT_ID}.yaml"
    assert load_data(work_unit_path)["status"] == "running"

    result = {
        "schema_version": 1,
        "id": RESULT_ID,
        "task_id": task_id,
        "work_unit_id": WORK_UNIT_ID,
        "run_id": run_id,
        "outcome": "succeeded",
        "summary": "implemented",
        "changed_files": ["src/app.py"],
        "commands": [{"argv": ["pytest"], "exit_code": 0}],
        "submitted_at": utc_now(),
    }
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.py").write_text("implemented\n", encoding="utf-8")
    ResultService(tmp_path).submit(
        task_id,
        result,
        expected_revision=3,
        idempotency_key="result-submit",
        actor={"id": "executor", "kind": "agent"},
    )
    assert load_data(work_unit_path)["status"] == "completed"

    work_unit_path.unlink()
    FilesystemTaskRepository(tmp_path).rebuild_task(task_id)
    assert load_data(work_unit_path)["status"] == "completed"


def test_close_and_validator_fail_closed_for_incomplete_required_work_unit(tmp_path: Path) -> None:
    _initialized_repo(tmp_path)
    task_id = _task(tmp_path)
    work_unit = _work_unit(task_id)
    _write_entity(
        tmp_path,
        task_id,
        "work-units",
        work_unit,
        "work-unit.schema.json",
        "work_unit_created",
        expected_revision=1,
        idempotency_key="work-unit",
        actor="test",
    )

    close = _close_decision(tmp_path, task_id, "closer")
    assert "CLOSE_WORK_UNITS_INCOMPLETE" in close.codes

    close_cli = _run_cli(
        "task", "transition", task_id, "completed",
        "--expected-revision", "2", "--idempotency-key", "rejected-close",
        "--actor", "closer", "--repo", str(tmp_path), "--json",
    )
    assert close_cli.returncode == 7
    close_error = json.loads(close_cli.stderr)
    assert close_error["error"]["code"] == "CLOSE_GATES_FAILED"
    assert "CLOSE_WORK_UNITS_INCOMPLETE" in {
        issue["code"] for issue in close_error["error"]["details"]["issues"]
    }

    repository = FilesystemTaskRepository(tmp_path)
    repository.append_event(
        task_id,
        "task_completed",
        {"state": "completed"},
        actor={"id": "closer", "kind": "human"},
        expected_revision=2,
        idempotency_key="corrupt-close",
    )
    codes = {
        issue.code
        for issue in validate_task_invariants(tmp_path, repository.task_dir(task_id))
    }
    assert "TASK_REQUIRED_WORK_UNITS_INCOMPLETE" in codes


def test_cancel_and_supersede_require_scope_owner_and_existing_successor(tmp_path: Path) -> None:
    _initialized_repo(tmp_path)
    task_id = _task(tmp_path)
    successor = TaskService(tmp_path).create(
        title="successor",
        mode="standard",
        objective="continue work",
        acceptance=["works"],
        allowed_paths=["src/**"],
        owners=["backend"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "test", "kind": "agent"},
        idempotency_key="create-successor",
    )["task"]["id"]

    unauthorized = _run_cli(
        "task", "cancel", task_id,
        "--expected-revision", "1", "--idempotency-key", "mallory-cancel",
        "--actor", "mallory", "--repo", str(tmp_path), "--json",
    )
    assert unauthorized.returncode == 9
    assert json.loads(unauthorized.stderr)["error"]["code"] == "ACTOR_SCOPE_UNAUTHORIZED"

    missing = _run_cli(
        "task", "supersede", task_id,
        "--successor", "TASK-01K0W4Z36K3W5C2R0A3M8N9P7R",
        "--expected-revision", "1", "--idempotency-key", "missing-successor",
        "--actor", "backend-owner", "--repo", str(tmp_path), "--json",
    )
    assert missing.returncode == 3
    assert json.loads(missing.stderr)["error"]["code"] == "TASK_NOT_FOUND"

    superseded = _run_cli(
        "task", "supersede", task_id,
        "--successor", str(successor),
        "--expected-revision", "1", "--idempotency-key", "valid-successor",
        "--actor", "backend-owner", "--repo", str(tmp_path), "--json",
    )
    assert superseded.returncode == 0, superseded.stderr
    assert json.loads(superseded.stdout)["task"]["state"] == "superseded"
