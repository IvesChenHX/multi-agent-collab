from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from mac.application.task_service import TaskService
from mac.cli import init_command, scope_approve
from mac.errors import MacError
from mac.io import atomic_write_yaml, load_data
from mac.repository import FilesystemTaskRepository, utc_now
from mac.result import ResultIntakeProof, ResultService


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
    scope_approve(
        task_id,
        expected_revision=0,
        idempotency_key="approve-multi-owner",
        actor="backend-owner",
        independence_level="L1",
        repo=root,
        json_output=True,
    )
    task_dir = FilesystemTaskRepository(root).task_dir(task_id)
    work_unit_id = "WU-01K0W4Z36K3W5C2R0A3M8N9P8A"
    run_id = "RUN-01K0W4Z36K3W5C2R0A3M8N9P8B"
    result_id = "RESULT-01K0W4Z36K3W5C2R0A3M8N9P8C"
    work_unit = {
        "schema_version": 1,
        "id": work_unit_id,
        "task_id": task_id,
        "title": "implementation and tests",
        "status": "running",
        "owner": work_unit_owner,
        "allowed_paths": ["src/**", "tests/**"],
        "depends_on": [],
        "acceptance_criteria": [],
        "expected_result": f"tasks/{task_id}/results/{result_id}.json",
    }
    run = {
        "schema_version": 1,
        "id": run_id,
        "task_id": task_id,
        "work_unit_id": work_unit_id,
        "status": "running",
        "actor": {"id": "executor", "kind": "agent"},
        "runtime": {"profile": "local-single", "execution_context_id": "result-intake"},
        "independence_level": "L0",
        "started_at": "2026-07-20T00:00:00Z",
        "finished_at": None,
        "exit_code": None,
    }
    FilesystemTaskRepository(root).append_event(
        task_id,
        "run_started",
        {"run_id": run_id, "work_unit_id": work_unit_id, "work_unit": work_unit, "run": run},
        actor={"id": "executor", "kind": "agent"},
        expected_revision=1,
        idempotency_key="run-multi-owner",
        run_id=run_id,
        materializations=[
            (task_dir / "work-units" / f"{work_unit_id}.yaml", work_unit),
            (task_dir / "runs" / f"{run_id}.json", run),
        ],
    )
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
        expected_revision=2,
        idempotency_key="submit-multi-owner",
        actor={"id": "executor", "kind": "agent"},
    )

    assert submitted == result


def test_result_rejects_work_unit_owner_outside_task_scope(tmp_path: Path) -> None:
    task_id, result = _multi_owner_result_case(tmp_path, work_unit_owner="security")

    with pytest.raises(MacError) as caught:
        ResultService(tmp_path).submit(
            task_id,
            result,
            expected_revision=2,
            idempotency_key="submit-owner-outside",
            actor={"id": "executor", "kind": "agent"},
        )

    assert caught.value.code == "RESULT_WORK_UNIT_OWNER_OUTSIDE"


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
    if approval_level == "L2":
        scope_approve(
            task_id,
            expected_revision=revision,
            idempotency_key="approve-governance-result",
            actor="governance-owner",
            independence_level="L2",
            repo=root,
            json_output=True,
        )
        revision += 1
    elif approval_level == "L0":
        scope_path = task_dir / "scope-contract.yaml"
        scope = dict(load_data(scope_path))
        scope["status"] = "approved"
        scope["approved_by"] = ["governance-owner"]
        approval_id = "APR-01K0W4Z36K3W5C2R0A3M8N9P8D"
        approval = {
            "schema_version": 1,
            "id": approval_id,
            "task_id": task_id,
            "kind": "scope",
            "actor": {"id": "governance-owner", "kind": "human"},
            "decision": "approved",
            "subject_ref": str(created["task"]["scope_contract_ref"]),
            "independence_level": "L0",
            "recorded_at": utc_now(),
        }
        repository.append_event(
            task_id,
            "scope_approved",
            {
                "scope_id": scope["id"],
                "version": scope["version"],
                "approval_id": approval_id,
                "approval": approval,
                "scope": scope,
            },
            actor={"id": "governance-owner", "kind": "human"},
            expected_revision=revision,
            idempotency_key="record-l0-governance-approval",
            materializations=[
                (task_dir / "approvals" / f"{approval_id}.json", approval),
                (scope_path, scope),
            ],
            replace_existing={scope_path},
        )
        revision += 1

    work_unit_id = "WU-01K0W4Z36K3W5C2R0A3M8N9P8E"
    run_id = "RUN-01K0W4Z36K3W5C2R0A3M8N9P8F"
    result_id = "RESULT-01K0W4Z36K3W5C2R0A3M8N9P8G"
    work_unit = {
        "schema_version": 1,
        "id": work_unit_id,
        "task_id": task_id,
        "title": "governance CI",
        "status": "running",
        "owner": "governance",
        "allowed_paths": [".github/workflows/governance-pr.yml"],
        "depends_on": [],
        "acceptance_criteria": [],
        "expected_result": f"tasks/{task_id}/results/{result_id}.json",
    }
    run = {
        "schema_version": 1,
        "id": run_id,
        "task_id": task_id,
        "work_unit_id": work_unit_id,
        "status": "running",
        "actor": {"id": "executor", "kind": "agent"},
        "runtime": {"profile": "local-single", "execution_context_id": "governance-result"},
        "independence_level": "L0",
        "started_at": "2026-07-20T00:00:00Z",
        "finished_at": None,
        "exit_code": None,
    }
    repository.append_event(
        task_id,
        "run_started",
        {"run_id": run_id, "work_unit_id": work_unit_id, "work_unit": work_unit, "run": run},
        actor={"id": "executor", "kind": "agent"},
        expected_revision=revision,
        idempotency_key="run-governance-result",
        run_id=run_id,
        materializations=[
            (task_dir / "work-units" / f"{work_unit_id}.yaml", work_unit),
            (task_dir / "runs" / f"{run_id}.json", run),
        ],
    )
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

    assert submitted == result


@pytest.mark.parametrize("approval_level", ["L0", None])
def test_governance_sensitive_result_rejects_insufficient_scope_approval(
    tmp_path: Path,
    approval_level: str | None,
) -> None:
    task_id, result, revision = _governance_result_case(tmp_path, approval_level=approval_level)

    with pytest.raises(MacError) as caught:
        ResultService(tmp_path).submit(
            task_id,
            result,
            expected_revision=revision,
            idempotency_key="submit-unapproved-governance-result",
            actor={"id": "executor", "kind": "agent"},
        )

    assert caught.value.code == "SCOPE_GOVERNANCE_SENSITIVE"
    issue_codes = {
        str(issue["code"])
        for issue in (caught.value.issue.details or {}).get("issues", [])
    }
    assert "RESULT_SCOPE_APPROVAL_INVALID" in issue_codes
