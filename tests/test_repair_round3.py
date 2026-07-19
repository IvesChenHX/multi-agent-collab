from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mac.application.task_service import TaskService
from mac.cli import _transition_context, _write_entity, init_command
from mac.errors import MacError
from mac.git import GitRepository
from mac.io import atomic_write_json, atomic_write_yaml, load_data
from mac.repository import FilesystemTaskRepository, utc_now, validate_repository, validate_task_invariants
from mac.scope import Change, check_changes
from mac.state_machine import DEFAULT_TRANSITIONS, parse_transitions, validate_workflow_invariants


TASK_ID = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
WORK_UNIT_ID = "WU-01K0W4Z36K3W5C2R0A3M8N9P7Q"
RUN_ID = "RUN-01K0W4Z36K3W5C2R0A3M8N9P7Q"
RESULT_ID = "RESULT-01K0W4Z36K3W5C2R0A3M8N9P7Q"
EVIDENCE_ID = "EVD-01K0W4Z36K3W5C2R0A3M8N9P7Q"


def _git_init(root: Path) -> None:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "test"], check=True)


def _initialized_repo(root: Path) -> None:
    _git_init(root)
    init_command(repo=root, project="test", json_output=True)
    (root / "AGENTS.md").write_text("# rules\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "init"], check=True)


def _task(root: Path) -> tuple[str, dict[str, object]]:
    created = TaskService(root).create(
        title="round 3",
        mode="standard",
        objective="repair",
        acceptance=["works"],
        allowed_paths=["src/**"],
        owners=["backend"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "test", "kind": "agent"},
        idempotency_key="create-round-3",
    )
    task_id = str(created["task"]["id"])
    scope = dict(created["scope"])
    scope["status"] = "approved"
    scope["approved_by"] = ["owner"]
    atomic_write_yaml(root / "tasks" / task_id / "scope-contract.yaml", scope)
    return task_id, created["task"]


def _work_unit(task_id: str, *, status: str = "ready", depends_on: list[str] | None = None) -> dict[str, object]:
    return {
        "schema_version": 1,
        "id": WORK_UNIT_ID,
        "task_id": task_id,
        "title": "implement",
        "status": status,
        "owner": "backend",
        "allowed_paths": ["src/**"],
        "depends_on": depends_on or [],
        "acceptance_criteria": [],
        "expected_result": f"tasks/{task_id}/results/{RESULT_ID}.json",
    }


def _run(task_id: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "id": RUN_ID,
        "task_id": task_id,
        "work_unit_id": WORK_UNIT_ID,
        "status": "running",
        "actor": {"id": "executor", "kind": "agent"},
        "runtime": {"profile": "local-single", "execution_context_id": "ctx-1"},
        "independence_level": "L0",
        "started_at": utc_now(),
        "finished_at": None,
        "exit_code": None,
    }


def test_ready_work_unit_only_requires_its_declared_dependencies(tmp_path: Path) -> None:
    _initialized_repo(tmp_path)
    task_id, _ = _task(tmp_path)
    directory = tmp_path / "tasks" / task_id
    atomic_write_yaml(directory / "work-units" / f"{WORK_UNIT_ID}.yaml", _work_unit(task_id))
    atomic_write_json(directory / "runs" / f"{RUN_ID}.json", _run(task_id))

    context = _transition_context(tmp_path, task_id, "executing")

    assert context.executor_run_created
    assert context.dependencies_complete


def test_scope_and_workspace_digest_ignore_only_current_task_machine_metadata(tmp_path: Path) -> None:
    _git_init(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.py").write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "base"], check=True)
    contract = {"allowed_paths": ["src/**"], "denied_paths": [], "owners": ["backend"]}
    ownership = {"owners": {"backend": {"priority": 1, "include": ["src/**"]}}}
    own_event = f"tasks/{TASK_ID}/events/EVT-1.json"
    other_event = "tasks/TASK-OTHER/events/EVT-2.json"
    disguised_business_file = f"tasks/{TASK_ID}/source.py"

    result = check_changes(
        [Change("add", own_event), Change("add", other_event), Change("add", disguised_business_file), Change("modify", "src/app.py")],
        contract,
        ownership=ownership,
        repo_root=tmp_path,
        task_id=TASK_ID,
    )

    issue_paths = {issue.path for issue in result.issues}
    assert own_event not in issue_paths
    assert other_event in issue_paths
    assert disguised_business_file in issue_paths
    assert "src/app.py" in result.allowed

    (tmp_path / "src/app.py").write_text("after\n", encoding="utf-8")
    own_path = tmp_path / own_event
    own_path.parent.mkdir(parents=True)
    own_path.write_text("one\n", encoding="utf-8")
    git = GitRepository(tmp_path)
    first = git.workspace_subject(task_id=TASK_ID)
    own_path.write_text("two\n", encoding="utf-8")
    assert git.workspace_subject(task_id=TASK_ID) == first
    other_path = tmp_path / other_event
    other_path.parent.mkdir(parents=True)
    other_path.write_text("other\n", encoding="utf-8")
    assert git.workspace_subject(task_id=TASK_ID) != first


def test_revision_conflict_does_not_leave_run_and_validator_rejects_orphans(tmp_path: Path) -> None:
    _initialized_repo(tmp_path)
    task_id, task = _task(tmp_path)
    directory = tmp_path / "tasks" / task_id
    run = _run(task_id)

    with pytest.raises(MacError, match="expected 99"):
        _write_entity(
            tmp_path,
            task_id,
            "runs",
            run,
            "run.schema.json",
            "run_started",
            expected_revision=99,
            idempotency_key="stale-run",
            actor="executor",
        )

    assert not (directory / "runs" / f"{RUN_ID}.json").exists()
    assert len(FilesystemTaskRepository(tmp_path).list_events(task_id)) == 1

    atomic_write_yaml(directory / "work-units" / f"{WORK_UNIT_ID}.yaml", _work_unit(task_id))
    atomic_write_json(directory / "runs" / f"{RUN_ID}.json", run)
    atomic_write_json(
        directory / "results" / f"{RESULT_ID}.json",
        {
            "schema_version": 1,
            "id": RESULT_ID,
            "task_id": task_id,
            "work_unit_id": WORK_UNIT_ID,
            "run_id": RUN_ID,
            "outcome": "succeeded",
            "summary": "done",
            "changed_files": ["src/app.py"],
            "commands": [{"argv": ["pytest"], "exit_code": 0}],
            "submitted_at": utc_now(),
        },
    )
    atomic_write_json(
        directory / "evidence" / f"{EVIDENCE_ID}.json",
        {
            "schema_version": 1,
            "id": EVIDENCE_ID,
            "task_id": task_id,
            "kind": "manual",
            "subject": {"type": "commit", "commit_sha": "1" * 40, "tree_sha": "2" * 40},
            "policy_digest": task["policy_ref"]["combined_digest"],
            "run_id": RUN_ID,
            "claims": [{"gate": "targeted_tests"}],
            "recorded_at": utc_now(),
            "validity": {"status": "valid", "invalidated_by": []},
        },
    )

    codes = {issue.code for issue in validate_task_invariants(tmp_path, directory)}
    assert {"RUN_EVENT_MISSING", "RESULT_EVENT_MISSING", "EVIDENCE_EVENT_MISSING"} <= codes


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": str(root / "src")}
    return subprocess.run([sys.executable, "-m", "mac.cli", *args], cwd=root, env=env, text=True, capture_output=True)


def test_json_leaf_errors_are_stable_and_never_render_rich_tracebacks(tmp_path: Path) -> None:
    missing_task = _run_cli("task", "show", "TASK-NOT-THERE", "--repo", str(tmp_path), "--json")
    assert missing_task.returncode == 3
    payload = json.loads(missing_task.stderr)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "TASK_NOT_FOUND"
    assert "Traceback" not in missing_task.stderr

    missing_argument = _run_cli("run", "register", "--json")
    assert missing_argument.returncode == 2
    payload = json.loads(missing_argument.stderr)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "CLI_USAGE_ERROR"
    assert "Usage:" not in missing_argument.stderr


def test_init_emits_complete_reachable_workflow_and_valid_repository(tmp_path: Path) -> None:
    _git_init(tmp_path)
    init_command(repo=tmp_path, project="initialized", json_output=True)
    workflow_path = tmp_path / ".agents/workflows/evidence-driven-development.yaml"
    workflow = load_data(workflow_path)

    assert validate_workflow_invariants(workflow, workflow_path.as_posix()) == []
    actual_pairs = {(source, transition.target) for transition in parse_transitions(workflow) for source in transition.sources}
    expected_pairs = {(source, transition.target) for transition in DEFAULT_TRANSITIONS for source in transition.sources}
    assert actual_pairs == expected_pairs
    assert not [issue for issue in validate_repository(tmp_path) if issue.severity == "error"]


def test_standard_cli_lifecycle_reaches_close_with_task_metadata_present(tmp_path: Path) -> None:
    _initialized_repo(tmp_path)
    ownership_path = tmp_path / ".agents/ownership.yaml"
    ownership = load_data(ownership_path)
    ownership["owners"]["backend"] = {"priority": 10, "implementation_role": "backend-implementer", "include": ["src/**"], "approvers": ["backend-owner"]}
    atomic_write_yaml(ownership_path, ownership)
    subprocess.run(["git", "-C", str(tmp_path), "add", ".agents/ownership.yaml"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "add backend owner"], check=True)

    def invoke(*args: str) -> dict[str, object]:
        completed = _run_cli(*args, "--repo", str(tmp_path), "--json")
        assert completed.returncode == 0, completed.stderr
        return json.loads(completed.stdout)

    created = invoke(
        "task", "new", "--title", "lifecycle", "--objective", "close normally",
        "--allow", "src/**", "--owner", "backend", "--accept", "lifecycle closes",
        "--parent-task", TASK_ID, "--supersedes", TASK_ID,
        "--idempotency-key", "lifecycle-create",
    )
    task_id = str(created["task_id"])
    assert created["task"]["relationships"] == {
        "parent_task": TASK_ID,
        "supersedes": [TASK_ID],
        "superseded_by": None,
    }
    invoke("scope", "approve", task_id, "--expected-revision", "0", "--idempotency-key", "scope-approve", "--actor", "backend-owner")
    invoke("task", "transition", task_id, "ready", "--expected-revision", "1", "--idempotency-key", "ready")
    work_unit = invoke(
        "work-unit", "new", task_id, "--title", "implement", "--owner", "backend", "--allow", "src/**",
        "--expected-revision", "2", "--idempotency-key", "work-unit",
    )["work_unit"]
    work_unit_id = str(work_unit["id"])
    invoke("work-unit", "ready", task_id, work_unit_id, "--expected-revision", "3", "--idempotency-key", "work-unit-ready")
    run = invoke(
        "run", "register", task_id, "--work-unit-id", work_unit_id, "--context-id", "executor-context",
        "--expected-revision", "4", "--idempotency-key", "run-register",
    )["run"]
    run_id = str(run["id"])
    actual_branch = subprocess.run(
        ["git", "-C", str(tmp_path), "rev-parse", "--abbrev-ref", "HEAD"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()
    assert run["runtime"]["worktree"] == str(tmp_path.resolve())
    assert run["runtime"]["branch"] == actual_branch
    run_started = next(
        event
        for event in FilesystemTaskRepository(tmp_path).list_events(task_id)
        if event["event_type"] == "run_started"
    )
    assert run_started["payload"]["baseline_subject"]["type"] == "commit"
    assert run_started["payload"]["worktree_identity"] == {
        "path": str(tmp_path.resolve()),
        "branch": actual_branch,
    }
    invoke("task", "transition", task_id, "executing", "--expected-revision", "5", "--idempotency-key", "executing")

    source = tmp_path / "src/app.py"
    source.parent.mkdir()
    source.write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "src/app.py"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "implementation"], check=True)
    result_path = tmp_path / "tasks" / task_id / "private" / "result.json"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(
        json.dumps({
            "schema_version": 1,
            "id": RESULT_ID,
            "task_id": task_id,
            "work_unit_id": work_unit_id,
            "run_id": run_id,
            "outcome": "succeeded",
            "summary": "implemented",
            "changed_files": ["src/app.py"],
            "commands": [{"argv": ["python", "-c", "pass"], "exit_code": 0}],
            "submitted_at": utc_now(),
        }),
        encoding="utf-8",
    )
    submitted = invoke("result", "submit", task_id, str(result_path), "--expected-revision", "6", "--idempotency-key", "result-submit")
    assert submitted["intake_proof"]["checks"] == {
        "run_baseline_bound": True,
        "worktree_identity_bound": True,
        "diff_recomputed": True,
        "paths_exact": True,
    }
    invoke("task", "transition", task_id, "verifying", "--expected-revision", "7", "--idempotency-key", "verifying")

    for revision, claim in enumerate(("approved_scope", "targeted_tests", "AC-001"), start=8):
        completed = _run_cli(
            "evidence", "record", task_id, "--claim", claim, "--expected-revision", str(revision),
            "--idempotency-key", f"evidence-{claim}", "--repo", str(tmp_path), "--commit", "--json",
            "--", sys.executable, "-c", "pass",
        )
        assert completed.returncode == 0, completed.stderr

    closed = invoke("task", "transition", task_id, "completed", "--expected-revision", "11", "--idempotency-key", "completed", "--actor", "backend-owner")
    assert closed["task"]["state"] == "completed"
    assert not [issue for issue in validate_repository(tmp_path) if issue.severity == "error"]


def test_repository_gitignore_keeps_user_idea_metadata_ignored() -> None:
    root = Path(__file__).resolve().parents[1]
    patterns = (root / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".idea/" in patterns
