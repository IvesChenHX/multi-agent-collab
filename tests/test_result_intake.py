from __future__ import annotations

import os
import subprocess
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from mac.application.task_service import TaskService
from mac.cli import init_command, scope_amend, scope_approve, task_transition
from mac.errors import MacError
from mac.git import GitRepository
from mac.io import atomic_write_yaml, load_data
from mac.repository import AppendEvent, FilesystemTaskRepository, MutationGateway, utc_now
from mac.result import ResultIntakeProof, ResultService
from tests.security.test_authority_commands import configure_test_authority


@pytest.fixture(autouse=True)
def _host_authority_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_test_authority(monkeypatch)


def _assert_store_timestamped_result(
    root: Path,
    submitted: dict[str, object],
    original: dict[str, object],
) -> None:
    assert {key: value for key, value in submitted.items() if key != "submitted_at"} == {
        key: value for key, value in original.items() if key != "submitted_at"
    }
    repository = FilesystemTaskRepository(root)
    event = next(
        event
        for event in reversed(repository.list_events(str(submitted["task_id"])))
        if event.get("event_type") == "result_submitted"
    )
    assert submitted["submitted_at"] == event["occurred_at"]
    task_dir = repository.task_dir(str(submitted["task_id"]))
    stored_result = load_data(task_dir / "results" / f"{submitted['id']}.json")
    stored_run = load_data(task_dir / "runs" / f"{submitted['run_id']}.json")
    assert stored_result["submitted_at"] == event["occurred_at"]
    assert stored_run["finished_at"] == event["occurred_at"]


def _proof() -> ResultIntakeProof:
    return ResultIntakeProof.verified(
        task_id="TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        work_unit_id="WU-01K0W4Z36K3W5C2R0A3M8N9P7R",
        run_id="RUN-01K0W4Z36K3W5C2R0A3M8N9P7S",
        baseline_subject={"type": "commit", "commit_sha": "a" * 40, "tree_sha": "b" * 40},
        worktree_identity={"path": "C:/worktrees/run", "branch": "codex/run"},
        result_subject={"type": "commit", "commit_sha": "c" * 40, "tree_sha": "d" * 40},
        changes=[{"operation": "rename", "old_path": "src/old.py", "path": "src/new.py", "submodule": False}],
        checks={"run_baseline_bound": True, "worktree_identity_bound": True, "diff_recomputed": True, "paths_exact": True},
        verifier="test-git-adapter",
    )


def test_result_intake_proof_binds_run_and_exact_rename_paths() -> None:
    proof = _proof()
    result = {
        "task_id": proof.task_id,
        "work_unit_id": proof.work_unit_id,
        "run_id": proof.run_id,
        "changed_files": ["src/old.py", "src/new.py"],
    }

    assert proof.valid()
    assert proof.binds(result)
    assert {change.path for change in proof.scope_changes()} == {"src/new.py"}
    assert not replace(proof, digest="sha256:" + "0" * 64).valid()
    assert not proof.binds({**result, "run_id": "RUN-01K0W4Z36K3W5C2R0A3M8N9P8X"})


def _git(root: Path, *argv: str, input_text: str | None = None) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *argv],
        check=True,
        capture_output=True,
        text=True,
        input=input_text,
    )
    return completed.stdout.strip()


def _scope_approve_with_authority(*, independence_level: str, **kwargs: object) -> None:
    with patch.dict(os.environ, {"MAC_AUTHORITY_BROKER_CONTEXT_TEST_INDEPENDENCE": independence_level}):
        scope_approve(independence_level=independence_level, **kwargs)


def _transition_task_ready(root: Path, task_id: str, expected_revision: int) -> int:
    task_transition(
        task_id=task_id,
        target="ready",
        expected_revision=expected_revision,
        idempotency_key=f"ready-{task_id}",
        actor="controller",
        condition=[],
        fact_id=None,
        reason=None,
        repo=root,
        json_output=True,
    )
    return expected_revision + 1


def _run_bound_result_case(
    root: Path,
    execution_root: Path,
    *,
    execution_kind: str,
) -> tuple[str, dict[str, object], ResultIntakeProof]:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "test")
    init_command(repo=root, project="run-bound-result", json_output=True)
    (root / "AGENTS.md").write_text("# rules\n", encoding="utf-8")
    ownership_path = root / ".agents/ownership.yaml"
    ownership = load_data(ownership_path)
    ownership["owners"]["backend"] = {
        "priority": 20,
        "implementation_role": "backend-implementer",
        "include": ["src/**"],
        "approvers": ["backend-owner"],
    }
    atomic_write_yaml(ownership_path, ownership)
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "init")

    created = TaskService(root).create(
        title="run-bound result",
        mode="standard",
        objective="bind result to the approved repository",
        acceptance=["src change is accepted"],
        allowed_paths=["src/**"],
        owners=["backend"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "proposer", "kind": "agent"},
        idempotency_key="create-run-bound",
    )
    task_id = str(created["task"]["id"])
    repository = FilesystemTaskRepository(root)
    task_dir = repository.task_dir(task_id)
    scope_path = task_dir / "scope-contract.yaml"
    scope = dict(load_data(scope_path))
    scope["status"] = "approved"
    scope["approved_by"] = ["backend-owner"]
    approval_id = "APR-01K0W4Z36K3W5C2R0A3M8N9P8M"
    approval = {
        "schema_version": 1,
        "id": approval_id,
        "task_id": task_id,
        "kind": "scope",
        "actor": {"id": "backend-owner", "kind": "human"},
        "decision": "approved",
        "subject_ref": str(created["task"]["scope_contract_ref"]),
        "independence_level": "L1",
        "recorded_at": utc_now(),
    }
    MutationGateway(root, repository=repository).execute(AppendEvent(
        task_id=task_id,
        event_type="scope_approved",
        payload={
            "scope_id": scope["id"],
            "version": scope["version"],
            "approval_id": approval_id,
            "approval": approval,
            "scope": scope,
        },
        actor_claim={"id": "backend-owner", "kind": "human"},
        expected_revision=0,
        idempotency_key="approve-run-bound",
        operation="scope.approve",
        materializations=(
            (task_dir / "approvals" / f"{approval_id}.json", approval),
            (scope_path, scope),
        ),
        replace_existing=frozenset({scope_path}),
    ))
    _transition_task_ready(root, task_id, 1)

    if execution_kind == "worktree":
        _git(root, "worktree", "add", "-q", "-b", "codex/run-bound", str(execution_root), "HEAD")
    elif execution_kind == "external":
        # Reproduce a local ``clone --shared`` without depending on platform
        # clone-path parsing: a separate repository reads the Task object's
        # store through Git's alternates mechanism.  It is still not a Task
        # worktree and must be rejected.
        execution_root.mkdir()
        _git(execution_root, "init", "-q")
        alternate = execution_root / ".git" / "objects" / "info" / "alternates"
        alternate.parent.mkdir(parents=True, exist_ok=True)
        source_objects = Path(GitRepository(root).storage_identity()["object_dir"])
        alternate.write_bytes(source_objects.as_posix().encode("utf-8") + b"\n")
        head = _git(root, "rev-parse", "HEAD")
        _git(execution_root, "symbolic-ref", "HEAD", "refs/heads/codex/external")
        _git(execution_root, "update-ref", "refs/heads/codex/external", head)
        _git(execution_root, "reset", "--hard", "-q", head)
    elif execution_kind == "unrelated-worktree":
        tree = _git(root, "mktree", input_text="")
        unrelated = _git(root, "commit-tree", tree, "-m", "unrelated baseline")
        _git(root, "worktree", "add", "-q", "--detach", str(execution_root), unrelated)
    else:
        raise AssertionError(execution_kind)

    execution_git = GitRepository(execution_root)
    baseline = execution_git.commit_subject("HEAD")
    branch = _git(execution_root, "rev-parse", "--abbrev-ref", "HEAD")
    identity = {"path": str(execution_root.resolve()), "branch": branch}
    work_unit_id = "WU-01K0W4Z36K3W5C2R0A3M8N9P8H"
    run_id = "RUN-01K0W4Z36K3W5C2R0A3M8N9P8J"
    result_id = "RESULT-01K0W4Z36K3W5C2R0A3M8N9P8K"
    pending_work_unit = {
        "schema_version": 1,
        "id": work_unit_id,
        "task_id": task_id,
        "title": "change src",
        "status": "pending",
        "owner": "backend",
        "allowed_paths": ["src/**"],
        "depends_on": [],
        "acceptance_criteria": [],
        "expected_result": f"tasks/{task_id}/results/{result_id}.json",
    }
    work_unit_path = task_dir / "work-units" / f"{work_unit_id}.yaml"
    gateway = MutationGateway(root, repository=repository)
    gateway.execute(AppendEvent(
        task_id=task_id,
        event_type="work_unit_created",
        payload={"work_unit_id": work_unit_id, "work_unit": pending_work_unit},
        actor_claim={"id": "controller", "kind": "agent"},
        expected_revision=2,
        idempotency_key="create-run-bound-work-unit",
        operation="work_unit.create",
        materializations=((work_unit_path, pending_work_unit),),
    ))
    ready_work_unit = {**pending_work_unit, "status": "ready"}
    gateway.execute(AppendEvent(
        task_id=task_id,
        event_type="work_unit_created",
        payload={"work_unit_id": work_unit_id, "work_unit": ready_work_unit},
        actor_claim={"id": "controller", "kind": "agent"},
        expected_revision=3,
        idempotency_key="ready-run-bound-work-unit",
        operation="work_unit.ready",
        materializations=((work_unit_path, ready_work_unit),),
        replace_existing=frozenset({work_unit_path}),
    ))
    work_unit = {**ready_work_unit, "status": "running"}
    run = {
        "schema_version": 1,
        "id": run_id,
        "task_id": task_id,
        "work_unit_id": work_unit_id,
        "status": "running",
        "actor": {"id": "executor", "kind": "agent"},
        "runtime": {
            "profile": "local-single",
            "execution_context_id": "run-bound-result",
            "worktree": str(execution_root.resolve()),
            "branch": branch,
        },
        "independence_level": "L0",
        "started_at": "2026-07-01T00:00:00Z",
        "finished_at": None,
        "exit_code": None,
    }
    run_payload = {
            "run_id": run_id,
            "work_unit_id": work_unit_id,
            "work_unit": work_unit,
            "run": run,
            "baseline_subject": baseline,
            "worktree_identity": identity,
    }
    gateway.execute(AppendEvent(
        task_id=task_id,
        event_type="run_started",
        payload=run_payload,
        actor_claim={"id": "executor", "kind": "agent"},
        expected_revision=4,
        idempotency_key="run-bound-start",
        operation="run.register",
        run_id=run_id,
        materializations=(
            (work_unit_path, work_unit),
            (task_dir / "runs" / f"{run_id}.json", run),
        ),
        replace_existing=frozenset({work_unit_path}),
    ))

    (execution_root / "src").mkdir(exist_ok=True)
    (execution_root / "src/app.py").write_text("VALUE = 1\n", encoding="utf-8")
    changes = execution_git.changes_since(str(baseline["commit_sha"]), task_id=task_id)
    serialized = [
        {
            "operation": change.operation,
            "path": change.path,
            **({"old_path": change.old_path} if change.old_path else {}),
            "submodule": change.submodule,
        }
        for change in changes
    ]
    subject = execution_git.workspace_subject(task_id=task_id)
    result: dict[str, object] = {
        "schema_version": 1,
        "id": result_id,
        "task_id": task_id,
        "work_unit_id": work_unit_id,
        "run_id": run_id,
        "outcome": "succeeded",
        "summary": "src changed",
        "changed_files": ["src/app.py"],
        "commands": [{"argv": ["pytest"], "exit_code": 0}],
        "submitted_at": utc_now(),
    }
    proof = ResultIntakeProof.verified(
        task_id=task_id,
        work_unit_id=work_unit_id,
        run_id=run_id,
        baseline_subject=baseline,
        worktree_identity=identity,
        result_subject=subject,
        changes=serialized,
        checks={
            "run_baseline_bound": True,
            "worktree_identity_bound": True,
            "diff_recomputed": True,
            "paths_exact": True,
        },
        verifier="test/run-bound-result",
    )
    return task_id, result, proof


def test_result_accepts_linked_worktree_from_same_repository(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    task_root = tmp_path_factory.mktemp("ri")
    run_root = task_root.parent / "linked worktree"
    task_id, result, proof = _run_bound_result_case(
        task_root, run_root, execution_kind="worktree"
    )

    assert GitRepository(task_root).shares_storage_with(GitRepository(task_root))
    assert GitRepository(task_root).shares_storage_with(GitRepository(run_root))

    submitted = ResultService(task_root).submit(
        task_id,
        result,
        expected_revision=5,
        idempotency_key="submit-linked-worktree",
        actor={"id": "executor", "kind": "agent"},
        intake_proof=proof,
    )

    _assert_store_timestamped_result(task_root, submitted, result)


def test_result_store_time_replaces_a_caller_reported_future_timestamp(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    task_root = tmp_path_factory.mktemp("ri-store-time")
    run_root = task_root.parent / "linked store-time worktree"
    task_id, result, proof = _run_bound_result_case(
        task_root,
        run_root,
        execution_kind="worktree",
    )
    result["submitted_at"] = "2099-01-01T00:00:00Z"

    submitted = ResultService(task_root).submit(
        task_id,
        result,
        expected_revision=5,
        idempotency_key="submit-store-time",
        actor={"id": "executor", "kind": "agent"},
        intake_proof=proof,
    )
    replayed = ResultService(task_root).submit(
        task_id,
        result,
        expected_revision=5,
        idempotency_key="submit-store-time",
        actor={"id": "executor", "kind": "agent"},
        intake_proof=proof,
    )

    assert submitted["submitted_at"] != result["submitted_at"]
    assert replayed == submitted
    _assert_store_timestamped_result(task_root, submitted, result)


def test_result_retry_requires_the_exact_authorized_payload(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    task_root = tmp_path_factory.mktemp("ri-replay")
    run_root = task_root.parent / "linked replay worktree"
    task_id, result, proof = _run_bound_result_case(
        task_root,
        run_root,
        execution_kind="worktree",
    )
    service = ResultService(task_root)
    first = service.submit(
        task_id,
        result,
        expected_revision=5,
        idempotency_key="submit-result-replay",
        actor={"id": "executor", "kind": "agent"},
        intake_proof=proof,
    )
    retry = service.submit(
        task_id,
        result,
        expected_revision=5,
        idempotency_key="submit-result-replay",
        actor={"id": "executor", "kind": "agent"},
        intake_proof=proof,
    )
    assert retry == first

    with pytest.raises(MacError) as caught:
        service.submit(
            task_id,
            {**result, "summary": "different payload"},
            expected_revision=5,
            idempotency_key="submit-result-replay",
            actor={"id": "executor", "kind": "agent"},
            intake_proof=proof,
        )
    assert caught.value.code == "MUTATION_IDEMPOTENCY_CONFLICT"
    events = FilesystemTaskRepository(task_root).list_events(task_id)
    assert sum(event.get("event_type") == "result_submitted" for event in events) == 1


def test_run_registration_rejects_self_consistent_external_repository(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    task_root = tmp_path_factory.mktemp("re")
    run_root = task_root.parent / "external clone"
    with pytest.raises(MacError) as caught:
        _run_bound_result_case(
            task_root, run_root, execution_kind="external"
        )

    assert caught.value.code == "MUTATION_RUN_REPOSITORY_INVALID"


def test_run_registration_rejects_external_repository_before_result_proof(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    task_root = tmp_path_factory.mktemp("ri-no-proof")
    run_root = task_root.parent / "external no proof"
    with pytest.raises(MacError) as caught:
        _run_bound_result_case(
            task_root,
            run_root,
            execution_kind="external",
        )

    assert caught.value.code == "MUTATION_RUN_REPOSITORY_INVALID"


def test_run_registration_rejects_baseline_outside_approved_base_history(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    task_root = tmp_path_factory.mktemp("rb")
    run_root = task_root.parent / "unrelated worktree"
    with pytest.raises(MacError) as caught:
        _run_bound_result_case(
            task_root, run_root, execution_kind="unrelated-worktree"
        )

    assert caught.value.code == "MUTATION_RUN_REPOSITORY_INVALID"


def _multi_owner_result_case(root: Path, *, work_unit_owner: str) -> tuple[str, dict[str, object]]:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "test"], check=True)
    init_command(repo=root, project="result-intake", json_output=True)
    (root / "AGENTS.md").write_text("# rules\n", encoding="utf-8")
    ownership_path = root / ".agents/ownership.yaml"
    ownership = load_data(ownership_path)
    ownership["owners"].update({
        "backend": {
            "priority": 20,
            "implementation_role": "backend-implementer",
            "include": ["src/**"],
            "approvers": ["backend-owner"],
        },
        "tests": {
            "priority": 20,
            "implementation_role": "test-implementer",
            "include": ["tests/**"],
            "approvers": ["tests-owner"],
        },
    })
    atomic_write_yaml(ownership_path, ownership)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "init"], check=True)

    created = TaskService(root).create(
        title="multi-owner result",
        mode="standard",
        objective="allow a concern-based work unit",
        acceptance=["backend and tests are changed"],
        allowed_paths=["src/**", "tests/**"],
        owners=["backend", "tests"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "proposer", "kind": "agent"},
        idempotency_key="create-multi-owner",
    )
    task_id = str(created["task"]["id"])
    _scope_approve_with_authority(
        task_id=task_id,
        expected_revision=0,
        idempotency_key="approve-multi-owner",
        actor="backend-owner",
        independence_level="L1",
        repo=root,
        json_output=True,
    )
    _transition_task_ready(root, task_id, 1)
    task_dir = FilesystemTaskRepository(root).task_dir(task_id)
    work_unit_id = "WU-01K0W4Z36K3W5C2R0A3M8N9P8A"
    run_id = "RUN-01K0W4Z36K3W5C2R0A3M8N9P8B"
    result_id = "RESULT-01K0W4Z36K3W5C2R0A3M8N9P8C"
    pending_work_unit = {
        "schema_version": 1,
        "id": work_unit_id,
        "task_id": task_id,
        "title": "implementation and tests",
        "status": "pending",
        "owner": work_unit_owner,
        "allowed_paths": ["src/**", "tests/**"],
        "depends_on": [],
        "acceptance_criteria": [],
        "expected_result": f"tasks/{task_id}/results/{result_id}.json",
    }
    work_unit_path = task_dir / "work-units" / f"{work_unit_id}.yaml"
    gateway = MutationGateway(root)
    gateway.execute(AppendEvent(
        task_id=task_id,
        event_type="work_unit_created",
        payload={"work_unit_id": work_unit_id, "work_unit": pending_work_unit},
        actor_claim={"id": "controller", "kind": "agent"},
        expected_revision=2,
        idempotency_key="create-multi-owner-work-unit",
        operation="work_unit.create",
        materializations=((work_unit_path, pending_work_unit),),
    ))
    ready_work_unit = {**pending_work_unit, "status": "ready"}
    gateway.execute(AppendEvent(
        task_id=task_id,
        event_type="work_unit_created",
        payload={"work_unit_id": work_unit_id, "work_unit": ready_work_unit},
        actor_claim={"id": "controller", "kind": "agent"},
        expected_revision=3,
        idempotency_key="ready-multi-owner-work-unit",
        operation="work_unit.ready",
        materializations=((work_unit_path, ready_work_unit),),
        replace_existing=frozenset({work_unit_path}),
    ))
    work_unit = {**ready_work_unit, "status": "running"}
    run = {
        "schema_version": 1,
        "id": run_id,
        "task_id": task_id,
        "work_unit_id": work_unit_id,
        "status": "running",
        "actor": {"id": "executor", "kind": "agent"},
        "runtime": {"profile": "local-single", "execution_context_id": "result-intake"},
        "independence_level": "L0",
        "started_at": "2026-07-01T00:00:00Z",
        "finished_at": None,
        "exit_code": None,
    }
    gateway.execute(AppendEvent(
        task_id=task_id,
        event_type="run_started",
        payload={"run_id": run_id, "work_unit_id": work_unit_id, "work_unit": work_unit, "run": run},
        actor_claim={"id": "executor", "kind": "agent"},
        expected_revision=4,
        idempotency_key="run-multi-owner",
        operation="run.register",
        run_id=run_id,
        materializations=(
            (work_unit_path, work_unit),
            (task_dir / "runs" / f"{run_id}.json", run),
        ),
        replace_existing=frozenset({work_unit_path}),
    ))
    (root / "src").mkdir()
    (root / "tests").mkdir()
    (root / "src/app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "tests/test_app.py").write_text("def test_app(): pass\n", encoding="utf-8")
    result: dict[str, object] = {
        "schema_version": 1,
        "id": result_id,
        "task_id": task_id,
        "work_unit_id": work_unit_id,
        "run_id": run_id,
        "outcome": "succeeded",
        "summary": "implementation and tests completed",
        "changed_files": ["src/app.py", "tests/test_app.py"],
        "commands": [{"argv": ["pytest"], "exit_code": 0}],
        "submitted_at": utc_now(),
    }
    return task_id, result


def test_result_uses_task_scope_path_owners_for_multi_owner_work_unit(tmp_path: Path) -> None:
    task_id, result = _multi_owner_result_case(tmp_path, work_unit_owner="backend")

    submitted = ResultService(tmp_path).submit(
        task_id,
        result,
        expected_revision=5,
        idempotency_key="submit-multi-owner",
        actor={"id": "executor", "kind": "agent"},
    )

    _assert_store_timestamped_result(tmp_path, submitted, result)


def test_result_rejects_work_unit_owner_outside_task_scope(tmp_path: Path) -> None:
    with pytest.raises(MacError) as caught:
        _multi_owner_result_case(tmp_path, work_unit_owner="security")

    assert caught.value.code == "MUTATION_WORK_UNIT_STATE_INVALID"


def _governance_result_case(root: Path, *, approval_level: str | None) -> tuple[str, dict[str, object], int]:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "test"], check=True)
    init_command(repo=root, project="governance-result", json_output=True)
    (root / "AGENTS.md").write_text("# rules\n", encoding="utf-8")
    ownership_path = root / ".agents/ownership.yaml"
    ownership = load_data(ownership_path)
    ownership["owners"]["governance"]["include"].append(".github/workflows/*governance*")
    atomic_write_yaml(ownership_path, ownership)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "init"], check=True)

    created = TaskService(root).create(
        title="governance workflow",
        mode="standard",
        objective="update governance CI",
        acceptance=["governance workflow is updated"],
        allowed_paths=[".github/workflows/governance-pr.yml"],
        owners=["governance"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "proposer", "kind": "agent"},
        idempotency_key="create-governance-result",
    )
    task_id = str(created["task"]["id"])
    repository = FilesystemTaskRepository(root)
    task_dir = repository.task_dir(task_id)
    revision = 0
    if approval_level is not None:
        _scope_approve_with_authority(
            task_id=task_id,
            expected_revision=revision,
            idempotency_key="approve-governance-result",
            actor="governance-owner",
            independence_level=approval_level,
            repo=root,
            json_output=True,
        )
        revision += 1
        revision = _transition_task_ready(root, task_id, revision)

    work_unit_id = "WU-01K0W4Z36K3W5C2R0A3M8N9P8E"
    run_id = "RUN-01K0W4Z36K3W5C2R0A3M8N9P8F"
    result_id = "RESULT-01K0W4Z36K3W5C2R0A3M8N9P8G"
    pending_work_unit = {
        "schema_version": 1,
        "id": work_unit_id,
        "task_id": task_id,
        "title": "governance CI",
        "status": "pending",
        "owner": "governance",
        "allowed_paths": [".github/workflows/governance-pr.yml"],
        "depends_on": [],
        "acceptance_criteria": [],
        "expected_result": f"tasks/{task_id}/results/{result_id}.json",
    }
    work_unit_path = task_dir / "work-units" / f"{work_unit_id}.yaml"
    gateway = MutationGateway(root, repository=repository)
    gateway.execute(AppendEvent(
        task_id=task_id,
        event_type="work_unit_created",
        payload={"work_unit_id": work_unit_id, "work_unit": pending_work_unit},
        actor_claim={"id": "controller", "kind": "agent"},
        expected_revision=revision,
        idempotency_key="create-governance-work-unit",
        operation="work_unit.create",
        materializations=((work_unit_path, pending_work_unit),),
    ))
    revision += 1
    ready_work_unit = {**pending_work_unit, "status": "ready"}
    gateway.execute(AppendEvent(
        task_id=task_id,
        event_type="work_unit_created",
        payload={"work_unit_id": work_unit_id, "work_unit": ready_work_unit},
        actor_claim={"id": "controller", "kind": "agent"},
        expected_revision=revision,
        idempotency_key="ready-governance-work-unit",
        operation="work_unit.ready",
        materializations=((work_unit_path, ready_work_unit),),
        replace_existing=frozenset({work_unit_path}),
    ))
    revision += 1
    work_unit = {**ready_work_unit, "status": "running"}
    run = {
        "schema_version": 1,
        "id": run_id,
        "task_id": task_id,
        "work_unit_id": work_unit_id,
        "status": "running",
        "actor": {"id": "executor", "kind": "agent"},
        "runtime": {"profile": "local-single", "execution_context_id": "governance-result"},
        "independence_level": "L0",
        "started_at": "2026-07-01T00:00:00Z",
        "finished_at": None,
        "exit_code": None,
    }
    gateway.execute(AppendEvent(
        task_id=task_id,
        event_type="run_started",
        payload={"run_id": run_id, "work_unit_id": work_unit_id, "work_unit": work_unit, "run": run},
        actor_claim={"id": "executor", "kind": "agent"},
        expected_revision=revision,
        idempotency_key="run-governance-result",
        operation="run.register",
        run_id=run_id,
        materializations=(
            (work_unit_path, work_unit),
            (task_dir / "runs" / f"{run_id}.json", run),
        ),
        replace_existing=frozenset({work_unit_path}),
    ))
    revision += 1
    workflow = root / ".github/workflows/governance-pr.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: governance\n", encoding="utf-8")
    result: dict[str, object] = {
        "schema_version": 1,
        "id": result_id,
        "task_id": task_id,
        "work_unit_id": work_unit_id,
        "run_id": run_id,
        "outcome": "succeeded",
        "summary": "governance workflow updated",
        "changed_files": [".github/workflows/governance-pr.yml"],
        "commands": [{"argv": ["pytest"], "exit_code": 0}],
        "submitted_at": utc_now(),
    }
    return task_id, result, revision


def test_governance_sensitive_result_accepts_valid_l2_scope_approval(tmp_path: Path) -> None:
    task_id, result, revision = _governance_result_case(tmp_path, approval_level="L2")

    submitted = ResultService(tmp_path).submit(
        task_id,
        result,
        expected_revision=revision,
        idempotency_key="submit-governance-result",
        actor={"id": "executor", "kind": "agent"},
    )

    _assert_store_timestamped_result(tmp_path, submitted, result)


def test_result_does_not_reuse_scope_approval_after_amendment(tmp_path: Path) -> None:
    task_id, result, revision = _governance_result_case(tmp_path, approval_level="L2")
    scope_amend(
        task_id=task_id,
        add=["docs/**"],
        expected_revision=revision,
        idempotency_key="amend-governance-result",
        actor="executor",
        approver=["governance-owner"],
        risk_tag=[],
        independent=False,
        repo=tmp_path,
        json_output=True,
    )
    revision += 1

    with pytest.raises(MacError) as caught:
        ResultService(tmp_path).submit(
            task_id,
            result,
            expected_revision=revision,
            idempotency_key="submit-after-unbound-v2-approval",
            actor={"id": "executor", "kind": "agent"},
        )

    issue_codes = {
        str(issue["code"])
        for issue in (caught.value.issue.details or {}).get("issues", [])
    }
    assert "RESULT_SCOPE_APPROVAL_INVALID" in issue_codes


@pytest.mark.parametrize("approval_level", ["L0", None])
def test_governance_sensitive_result_rejects_insufficient_scope_approval(
    tmp_path: Path,
    approval_level: str | None,
) -> None:
    with pytest.raises(MacError) as caught:
        _governance_result_case(tmp_path, approval_level=approval_level)

    assert caught.value.code == (
        "ACTOR_AUTHORITY_DENIED"
        if approval_level == "L0"
        else "MUTATION_WORK_UNIT_STATE_INVALID"
    )
