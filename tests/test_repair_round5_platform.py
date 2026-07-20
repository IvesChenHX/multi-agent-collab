from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import yaml

from mac.application.task_service import TaskService
from mac.cli import init_command, scope_approve
from mac.errors import MacError
from mac.events import replay_events
from mac.git import GitRepository
from mac.io import load_data
from mac.migration import convert_v5, scan_v5
from mac.policy import compile_policy
from mac.repository import FilesystemTaskRepository, validate_repository
from mac.schema_validation import SchemaSet, install_schema_bundle
import mac.schema_validation as schema_validation
from mac.scope import Change, check_changes
from mac.security import parse_yaml_safely


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_TASK_ID = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q-refund-auth"


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, text=True, capture_output=True
    )


def _git_repo(root: Path) -> None:
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "test")


def _commit_all(root: Path, message: str) -> str:
    _git(root, "add", ".")
    _git(root, "commit", "-qm", message)
    return _git(root, "rev-parse", "HEAD").stdout.strip()


def _initialized_v6_repo(root: Path) -> None:
    _git_repo(root)
    init_command(repo=root, project="round-5", json_output=True)
    (root / "AGENTS.md").write_text("# rules\n", encoding="utf-8")
    ownership_path = root / ".agents/ownership.yaml"
    ownership = load_data(ownership_path)
    ownership["owners"]["backend"] = {
        "priority": 10,
        "implementation_role": "backend-implementer",
        "include": ["src/**"],
        "approvers": ["backend-owner"],
    }
    from mac.io import atomic_write_yaml

    atomic_write_yaml(ownership_path, ownership)
    _commit_all(root, "init")


def _temporary_executable_schema_bundle(root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    install_schema_bundle(root)
    schema_dir = root / "schemas"
    monkeypatch.setattr(schema_validation, "_default_schema_dir", lambda: schema_dir)
    return schema_dir


def _sha(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _write_v5_repo(root: Path) -> dict[str, object]:
    entry = {
        "id": "TASK-0001-legacy",
        "title": "legacy",
        "status": "blocked",
        "summary": "waiting for an unknown dependency",
    }
    (root / "tasks/TASK-0001-legacy").mkdir(parents=True)
    (root / "tasks/index.yaml").write_text(
        yaml.safe_dump({"schema_version": 1, "tasks": [entry]}), encoding="utf-8"
    )
    (root / "tasks/TASK-0001-legacy/task.md").write_text("# legacy\n", encoding="utf-8")
    (root / ".agents/workflows").mkdir(parents=True)
    (root / ".agents/agents").mkdir(parents=True)
    (root / "AGENTS.md").write_text("# policy\n", encoding="utf-8")
    (root / ".agents/config.yaml").write_text(
        yaml.safe_dump({"schema_version": 5, "default_workflow": "missing-flow"}),
        encoding="utf-8",
    )
    ownership = {
        "owners": {
            "a": {"priority": 1, "implementation_role": "missing-role", "include": ["src/**"]},
            "b": {"priority": 1, "implementation_role": "missing-role", "include": ["src/**"]},
        }
    }
    (root / ".agents/ownership.yaml").write_text(yaml.safe_dump(ownership), encoding="utf-8")
    return entry


def test_authoritative_examples_validate_and_replay_without_modification() -> None:
    example = ROOT / "examples/v6"
    package_example = ROOT / "multi-agent-collab-v6-design-package/examples/v6"
    for packaged in sorted(path for path in package_example.rglob("*") if path.is_file()):
        relative = packaged.relative_to(package_example)
        assert (example / relative).read_bytes() == packaged.read_bytes()

    errors = [issue for issue in validate_repository(example) if issue.severity == "error"]
    assert errors == []
    repository = FilesystemTaskRepository(example)
    assert repository.projection_drift(EXAMPLE_TASK_ID) == []
    assert repository._replayed_state(EXAMPLE_TASK_ID)[0] == repository.load_task(EXAMPLE_TASK_ID)


def test_compile_policy_falls_back_to_locked_executable_schemas_without_a_repo_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    executable = tmp_path / "executable"
    init_command(repo=repo, project="schema-fallback", json_output=True)
    _temporary_executable_schema_bundle(executable, monkeypatch)
    shutil.rmtree(repo / "schemas")
    (repo / ".agents/schemas.lock.json").unlink()

    compiled = compile_policy(repo)

    assert compiled.config["project"] == "schema-fallback"


def test_compile_policy_rejects_a_stale_repo_lock_before_loading_local_schemas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    executable = tmp_path / "executable"
    init_command(repo=repo, project="schema-stale-lock", json_output=True)
    _temporary_executable_schema_bundle(executable, monkeypatch)
    (repo / "schemas/config.schema.json").write_text("{", encoding="utf-8")

    with pytest.raises(MacError) as caught:
        compile_policy(repo)

    assert caught.value.code == "POLICY_COMPILE_FAILED"
    assert {issue["code"] for issue in caught.value.issue.details["issues"]} == {
        "SCHEMA_LOCK_MISMATCH"
    }


def test_v5_converter_outputs_schema_valid_replayable_task_and_scope(tmp_path: Path) -> None:
    _write_v5_repo(tmp_path)
    converted = convert_v5(
        tmp_path,
        dry_run=False,
        blocked_classification={"TASK-0001-legacy": "external"},
    )
    task_dir = Path(converted["output"]) / converted["actions"][0]["task_id"]
    task = load_data(task_dir / "task.yaml")
    scope = load_data(task_dir / "scope-contract.yaml")
    events = [load_data(path) for path in (task_dir / "events").glob("*.json")]
    schemas = SchemaSet()

    assert schemas.validate(task, "task.schema.json", path="task.yaml") == []
    assert schemas.validate(scope, "scope-contract.schema.json", path="scope-contract.yaml") == []
    assert replay_events(events) == task
    assert scope["task_id"] == task["id"]
    assert converted["generated_entities"]
    assert converted["rollback"]["generated_entities"] == converted["generated_entities"]
    assert all(item["digest"].startswith("sha256:") for item in converted["generated_entities"])
    assert converted["actions"][0]["source_entities"]


def test_v5_scan_records_each_source_entity_reference_and_rollback_check(tmp_path: Path) -> None:
    entry = _write_v5_repo(tmp_path)
    report = scan_v5(tmp_path)
    task = report["tasks"][0]

    registry_source = next(source for source in task["sources"] if source["kind"] == "registry_entry")
    assert registry_source == {
        "kind": "registry_entry",
        "path": "tasks/index.yaml",
        "pointer": "/tasks/0",
        "digest": _sha(entry),
    }
    assert any(source["kind"] == "task_detail" for source in task["sources"])
    assert {item["reference"] for item in report["reference_checks"] if not item["exists"]} == {
        "role:missing-role",
        "workflow:missing-flow",
    }
    assert report["ownership_ambiguities"] == [{"path": "src/probe", "owners": ["a", "b"]}]
    assert report["status_inventory"] == {"blocked": 1}
    assert task["mapped_state"] == "failed" and task["status_class"] == "manual"
    assert report["rollback"]["matrix"]
    assert all({"mutation", "rollback_action", "verification"} <= set(row) for row in report["rollback"]["matrix"])


def test_workspace_subject_separates_index_from_unstaged_diff_and_promotion_rejects_drift(tmp_path: Path) -> None:
    _git_repo(tmp_path)
    (tmp_path / "src").mkdir()
    source = tmp_path / "src/app.py"
    source.write_text("base\n", encoding="utf-8")
    _commit_all(tmp_path, "base")
    git = GitRepository(tmp_path)
    clean_worktree_digest = git.workspace_subject()["worktree_diff_digest"]

    source.write_text("staged\n", encoding="utf-8")
    _git(tmp_path, "add", "src/app.py")
    staged_subject = git.workspace_subject()
    assert staged_subject["worktree_diff_digest"] == clean_worktree_digest

    source.write_text("unverified unstaged overlay\n", encoding="utf-8")
    drifted_subject = git.workspace_subject()
    assert drifted_subject["worktree_diff_digest"] != clean_worktree_digest
    _git(tmp_path, "commit", "-qm", "staged only")
    _git(tmp_path, "restore", "src/app.py")
    assert not git.workspace_equivalent_to_commit(
        "HEAD", source_workspace_subject=drifted_subject
    )
    assert git.workspace_equivalent_to_commit(
        "HEAD", source_workspace_subject=staged_subject
    )


def test_command_evidence_rejects_a_command_that_mutates_the_bound_workspace(tmp_path: Path) -> None:
    _initialized_v6_repo(tmp_path)
    created = TaskService(tmp_path).create(
        title="evidence subject",
        mode="standard",
        objective="bind the exact tested workspace",
        acceptance=["subject is stable"],
        allowed_paths=["src/**"],
        owners=["backend"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "agent", "kind": "agent"},
        idempotency_key="create-evidence-task",
    )
    task_id = str(created["task"]["id"])
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    command = subprocess.run(
        [
            sys.executable, "-m", "mac.cli", "evidence", "record", task_id,
            "--claim", "targeted_tests", "--expected-revision", "0",
            "--idempotency-key", "mutating-command", "--repo", str(tmp_path), "--json", "--",
            sys.executable, "-c",
            "from pathlib import Path; Path('src').mkdir(exist_ok=True); Path('src/mutated.py').write_text('x')",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
    )
    assert command.returncode == 7
    assert "EVIDENCE_COMMAND_CHANGED_WORKSPACE" in command.stderr
    task_dir = tmp_path / "tasks" / task_id
    assert not list((task_dir / "evidence").glob("*.json"))
    assert len(list((task_dir / "events").glob("*.json"))) == 1


def test_task_scope_creation_is_atomic_when_projection_write_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _git_repo(tmp_path)
    (tmp_path / "AGENTS.md").write_text("# policy\n", encoding="utf-8")
    (tmp_path / ".agents/workflows").mkdir(parents=True)
    (tmp_path / ".agents/workflows/evidence-driven-development.yaml").write_text("name: flow\n", encoding="utf-8")
    (tmp_path / ".agents").mkdir(exist_ok=True)
    (tmp_path / ".agents/config.yaml").write_text("schema_version: 6\n", encoding="utf-8")
    (tmp_path / ".agents/ownership.yaml").write_text("schema_version: 6\n", encoding="utf-8")
    _commit_all(tmp_path, "policy")

    import mac.repository as repository_module

    real_write = repository_module.atomic_write_yaml

    def fail_projection(path: Path, value: dict[str, object]) -> None:
        if path.name == "task.yaml":
            raise OSError("injected projection failure")
        real_write(path, value)

    monkeypatch.setattr(repository_module, "atomic_write_yaml", fail_projection)
    with pytest.raises(OSError, match="injected"):
        TaskService(tmp_path).create(
            title="atomic",
            mode="standard",
            objective="atomic create",
            acceptance=["all or nothing"],
            allowed_paths=["src/**"],
            owners=["platform"],
            runtime_profile="local-single",
            required_gates=["targeted_tests"],
            actor={"id": "agent", "kind": "agent"},
            idempotency_key="atomic-create",
        )
    assert not list((tmp_path / "tasks").glob("TASK-*"))
    assert not list((tmp_path / "tasks").glob(".*.tmp"))


def test_expired_lease_takeover_cannot_steal_a_fresh_competing_lease(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    task_id = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    task_dir = tmp_path / "tasks" / task_id
    lease_path = task_dir / "private/controller.lease"
    lease_path.parent.mkdir(parents=True)
    lease_path.write_text(json.dumps({"token": "expired", "expires_unix": 0}), encoding="utf-8")
    repository = FilesystemTaskRepository(tmp_path)
    real_rename = os.rename
    rename_barrier = threading.Barrier(2)
    first_renamed = threading.Event()
    calls_lock = threading.Lock()
    rename_calls = 0

    def raced_rename(source: str | os.PathLike[str], target: str | os.PathLike[str]) -> None:
        nonlocal rename_calls
        if Path(source) != lease_path:
            real_rename(source, target)
            return
        with calls_lock:
            rename_calls += 1
            order = rename_calls
        rename_barrier.wait(timeout=2)
        if order == 1:
            real_rename(source, target)
            first_renamed.set()
            return
        first_renamed.wait(timeout=2)
        deadline = time.time() + 2
        while time.time() < deadline:
            try:
                current = json.loads(lease_path.read_text(encoding="utf-8"))
            except (FileNotFoundError, json.JSONDecodeError):
                time.sleep(0.005)
                continue
            if float(current.get("expires_unix", 0)) > time.time():
                break
            time.sleep(0.005)
        real_rename(source, target)

    monkeypatch.setattr(os, "rename", raced_rename)
    acquired: list[str] = []
    release = threading.Event()

    def contender(owner: str) -> str:
        try:
            with repository.lease(task_id, owner, ttl_seconds=5) as token:
                acquired.append(token)
                release.wait(timeout=2)
            return "acquired"
        except MacError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(contender, owner) for owner in ("one", "two")]
        deadline = time.time() + 1
        while time.time() < deadline and len(acquired) < 2 and not all(item.done() for item in futures):
            time.sleep(0.01)
        release.set()
        results = [item.result(timeout=3) for item in futures]
    assert results.count("acquired") == 1
    assert results.count("LEASE_CONFLICT") == 1


def test_changes_since_is_effective_base_to_workspace_diff_not_union(tmp_path: Path) -> None:
    _git_repo(tmp_path)
    path = tmp_path / "src/app.py"
    path.parent.mkdir()
    path.write_text("base\n", encoding="utf-8")
    base = _commit_all(tmp_path, "base")
    path.write_text("committed change\n", encoding="utf-8")
    _commit_all(tmp_path, "intermediate")
    path.write_text("base\n", encoding="utf-8")

    assert GitRepository(tmp_path).changes_since(base) == []


def test_result_submission_uses_effective_diff_and_binds_task_work_unit_and_owner(tmp_path: Path) -> None:
    _initialized_v6_repo(tmp_path)
    created = TaskService(tmp_path).create(
        title="result binding",
        mode="standard",
        objective="validate result provenance",
        acceptance=["result matches diff"],
        allowed_paths=["src/**"],
        owners=["backend"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "controller", "kind": "agent"},
        idempotency_key="create-result-task",
    )
    task_id = str(created["task"]["id"])
    scope_approve(
        task_id, expected_revision=0, idempotency_key="approve-result-task",
        actor="backend-owner", independence_level="L1", repo=tmp_path, json_output=True,
    )
    repository = FilesystemTaskRepository(tmp_path)
    task_dir = repository.task_dir(task_id)
    work_unit_id = "WU-01K0W4Z36K3W5C2R0A3M8N9P7S"
    run_id = "RUN-01K0W4Z36K3W5C2R0A3M8N9P7T"
    work_unit = {
        "schema_version": 1, "id": work_unit_id, "task_id": task_id, "title": "work",
        "status": "running", "owner": "backend", "allowed_paths": ["src/**"],
        "depends_on": [], "expected_result": f"tasks/{task_id}/results/RESULT-01K0W4Z36K3W5C2R0A3M8N9P7W.json",
    }
    run = {
        "schema_version": 1, "id": run_id, "task_id": task_id, "work_unit_id": work_unit_id,
        "status": "running", "actor": {"id": "executor", "kind": "agent"},
        "runtime": {"profile": "local-single", "execution_context_id": "ctx-result"},
        "independence_level": "L0", "started_at": "2026-07-17T00:00:00Z",
        "finished_at": None, "exit_code": None,
    }
    repository.append_event(
        task_id, "run_started", {"run_id": run_id, "work_unit_id": work_unit_id, "work_unit": work_unit},
        actor={"id": "executor", "kind": "agent"}, expected_revision=1,
        idempotency_key="start-result-run", run_id=run_id,
        materializations=[
            (task_dir / "work-units" / f"{work_unit_id}.yaml", work_unit),
            (task_dir / "runs" / f"{run_id}.json", run),
        ],
    )
    source = tmp_path / "src/app.py"
    source.parent.mkdir()
    source.write_text("intermediate\n", encoding="utf-8")
    _commit_all(tmp_path, "intermediate implementation")
    source.unlink()
    result = {
        "schema_version": 1, "id": "RESULT-01K0W4Z36K3W5C2R0A3M8N9P7W", "task_id": task_id,
        "work_unit_id": work_unit_id, "run_id": run_id, "outcome": "succeeded",
        "summary": "effective workspace equals base", "changed_files": [],
        "commands": [{"argv": ["pytest"], "exit_code": 0}], "submitted_at": "2026-07-17T00:01:00Z",
    }
    from mac.result import ResultService

    assert ResultService(tmp_path).submit(
        task_id, result, expected_revision=2, idempotency_key="submit-effective-result",
        actor={"id": "executor", "kind": "agent"},
    ) == result


@pytest.mark.parametrize(
    ("existing", "incoming", "code"),
    [
        ("Auth.py", "auth.py", "SCOPE_CASE_COLLISION"),
        ("caf\u00e9.py", "cafe\u0301.py", "SCOPE_UNICODE_COLLISION"),
    ],
)
def test_scope_detects_case_and_unicode_collisions_with_existing_siblings(
    tmp_path: Path, existing: str, incoming: str, code: str
) -> None:
    directory = tmp_path / "src"
    directory.mkdir()
    (directory / existing).write_text("existing\n", encoding="utf-8")
    result = check_changes(
        [Change("add", f"src/{incoming}", display_path=f"src/{incoming}")],
        {"allowed_paths": ["src/**"], "denied_paths": [], "owners": []},
        repo_root=tmp_path,
    )
    assert code in {issue.code for issue in result.issues}


def test_yaml_rejects_duplicate_keys_and_excessive_nesting() -> None:
    with pytest.raises(MacError) as duplicate:
        parse_yaml_safely("owner: platform\nowner: attacker\n")
    assert duplicate.value.code == "YAML_DUPLICATE_KEY"

    nested = "value: leaf\n"
    for _ in range(12):
        nested = "node:\n" + "\n".join("  " + line for line in nested.splitlines()) + "\n"
    with pytest.raises(MacError) as complex_input:
        parse_yaml_safely(nested, max_depth=8)
    assert complex_input.value.code == "YAML_COMPLEXITY_LIMIT"


def test_lfs_pointer_subject_does_not_require_optional_local_object(tmp_path: Path) -> None:
    _git_repo(tmp_path)
    pointer = tmp_path / "asset.bin"
    pointer.write_text(
        "version https://git-lfs.github.com/spec/v1\n"
        f"oid sha256:{'a' * 64}\n"
        "size 123\n",
        encoding="ascii",
    )
    _commit_all(tmp_path, "lfs pointer")

    subject = GitRepository(tmp_path).workspace_subject()
    assert subject["type"] == "workspace"
