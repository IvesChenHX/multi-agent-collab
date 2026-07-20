from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

import mac.cli as cli_module
import mac.repository as repository_module
from mac.application.task_service import TaskService
from mac.cli import init_command, run_finish, run_register, scope_approve, task_transition, work_unit_new, work_unit_ready
from mac.doctor import run_doctor
from mac.errors import MacError
from mac.events import replay_entity_snapshots
from mac.ids import prefixed
from mac.io import atomic_write_json, load_data
from mac.repository import FilesystemTaskRepository, utc_now
from tests.security.test_authority_commands import configure_test_authority


@pytest.fixture(autouse=True)
def _host_authority_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_test_authority(monkeypatch)


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": str(root / "src")}
    return subprocess.run(
        [sys.executable, "-m", "mac.cli", *args],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
    )


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        capture_output=True,
        check=True,
    )
    return completed.stdout.strip()


def _registered_run(root: Path) -> tuple[str, str, str, FilesystemTaskRepository]:
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "tests@example.invalid")
    _git(root, "config", "user.name", "Tests")
    init_command(repo=root, project="run-finish-replay", json_output=True)
    source_agents = Path(__file__).resolve().parents[1] / "AGENTS.md"
    (root / "AGENTS.md").write_bytes(source_agents.read_bytes())
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "baseline")
    created = TaskService(root).create(
        title="run replay",
        mode="standard",
        objective="keep terminal Run projections replayable",
        acceptance=["terminal Run replays exactly"],
        allowed_paths=["src/**"],
        owners=["governance"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "proposer", "kind": "human"},
        idempotency_key="create-run-replay",
    )
    task_id = str(created["task"]["id"])
    scope_approve(
        task_id=task_id,
        expected_revision=0,
        idempotency_key="approve-run-replay-scope",
        actor="governance-owner",
        independence_level="L1",
        repo=root,
        json_output=True,
    )
    task_transition(
        task_id=task_id,
        target="ready",
        expected_revision=1,
        idempotency_key="ready-run-replay-task",
        actor="controller",
        condition=[],
        fact_id=None,
        reason=None,
        repo=root,
        json_output=True,
    )
    work_unit_new(
        task_id,
        title="implementation",
        owner="governance",
        allow=["src/**"],
        depends_on=[],
        expected_revision=2,
        idempotency_key="create-run-replay-unit",
        actor="controller",
        repo=root,
        json_output=True,
    )
    work_unit_path = next((root / "tasks" / task_id / "work-units").glob("*.yaml"))
    work_unit_id = work_unit_path.stem
    work_unit_ready(
        task_id,
        work_unit_id,
        expected_revision=3,
        idempotency_key="ready-run-replay-unit",
        actor="controller",
        repo=root,
        json_output=True,
    )
    run_register(
        task_id,
        work_unit_id=work_unit_id,
        profile="local-single",
        context_id="run-replay-context",
        provider="test-provider",
        model="test-model",
        worktree=root,
        branch=None,
        actor="executor",
        actor_kind="agent",
        independence_level="L0",
        expected_revision=4,
        idempotency_key="register-run-replay",
        repo=root,
        json_output=True,
    )
    run_id = next((root / "tasks" / task_id / "runs").glob("*.json")).stem
    return task_id, work_unit_id, run_id, FilesystemTaskRepository(root)


def test_cli_requires_frozen_repair_plan_and_explicit_run_finish_metadata(tmp_path: Path) -> None:
    repair = _run_cli(
        "doctor", "--repair-safe", "--apply", "--repo", str(tmp_path), "--json",
    )
    assert repair.returncode == 2
    assert json.loads(repair.stderr)["error"]["code"] == "DOCTOR_PLAN_DIGEST_REQUIRED"

    finish = _run_cli(
        "run", "finish", "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        "RUN-01K0W4Z36K3W5C2R0A3M8N9P7Q", "--status", "succeeded", "--json",
    )
    assert finish.returncode == 2
    assert json.loads(finish.stderr)["error"]["code"] == "CLI_USAGE_ERROR"


def test_cli_bundle_verification_requires_external_trust_anchor(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.zip"
    bundle.write_bytes(b"not trusted")

    verified = _run_cli("report", "verify-bundle", str(bundle), "--json")

    assert verified.returncode == 9
    assert json.loads(verified.stderr)["error"]["code"] == "AUDIT_BUNDLE_TRUST_ANCHOR_REQUIRED"


def test_policy_compile_binds_the_selected_runtime_profile(tmp_path: Path) -> None:
    initialized = _run_cli("init", "--repo", str(tmp_path), "--json")
    assert initialized.returncode == 0, initialized.stderr
    profiles = tmp_path / ".agents/runtime-profiles"
    source = (profiles / "local-single.yaml").read_text(encoding="utf-8")
    (profiles / "isolated.yaml").write_text(
        source.replace("id: local-single", "id: isolated", 1),
        encoding="utf-8",
    )

    compiled = _run_cli(
        "policy", "compile", "--runtime-profile", "isolated",
        "--repo", str(tmp_path), "--json",
    )

    assert compiled.returncode == 0, compiled.stderr
    payload = json.loads(compiled.stdout)
    assert payload["runtime_profile"] == "isolated"
    assert ".agents/runtime-profiles/isolated.yaml" in {
        item["path"] for item in payload["policy_ref"]["files"]
    }


def test_run_register_rejects_an_independent_repository(tmp_path: Path) -> None:
    root = tmp_path / "task-repo"
    external = tmp_path / "external-repo"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "tests@example.invalid")
    _git(root, "config", "user.name", "Tests")
    init_command(repo=root, project="run-binding", json_output=True)
    source_agents = Path(__file__).resolve().parents[1] / "AGENTS.md"
    (root / "AGENTS.md").write_bytes(source_agents.read_bytes())
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "baseline")
    created = TaskService(root).create(
        title="run binding",
        mode="standard",
        objective="reject another repository",
        acceptance=["run stays in the task repository"],
        allowed_paths=["src/**"],
        owners=["governance"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "proposer", "kind": "human"},
        idempotency_key="create-run-binding",
    )
    task_id = str(created["task"]["id"])
    work_unit_new(
        task_id,
        title="implementation",
        owner="governance",
        allow=["src/**"],
        depends_on=[],
        expected_revision=0,
        idempotency_key="create-work-unit",
        actor="controller",
        repo=root,
        json_output=True,
    )
    work_unit_path = next((root / "tasks" / task_id / "work-units").glob("*.yaml"))
    work_unit_id = work_unit_path.stem
    work_unit_ready(
        task_id,
        work_unit_id,
        expected_revision=1,
        idempotency_key="ready-work-unit",
        actor="controller",
        repo=root,
        json_output=True,
    )
    shutil.copytree(root, external)

    with pytest.raises(MacError) as captured:
        run_register(
            task_id,
            work_unit_id=work_unit_id,
            profile="local-single",
            context_id="external-context",
            provider=None,
            model=None,
            worktree=external,
            branch=None,
            actor="executor",
            actor_kind="agent",
            independence_level="L0",
            expected_revision=2,
            idempotency_key="external-run",
            repo=root,
            json_output=True,
        )

    assert captured.value.code == "RUN_WORKTREE_REPOSITORY_MISMATCH"


def test_run_finish_records_a_replayable_terminal_run_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "task-repo"
    task_id, _, run_id, repository = _registered_run(root)
    started = load_data(root / "tasks" / task_id / "runs" / f"{run_id}.json")
    start_event = next(
        event for event in repository.list_events(task_id) if event["event_type"] == "run_started"
    )
    assert started["started_at"] == start_event["occurred_at"]

    store_time = "2026-07-21T00:00:00Z"
    monkeypatch.setattr(cli_module, "utc_now", lambda: "2099-01-01T00:00:00Z")
    monkeypatch.setattr(repository_module, "utc_now", lambda: store_time)

    run_finish(
        task_id,
        run_id,
        status="cancelled",
        exit_code=None,
        expected_revision=5,
        idempotency_key="finish-run-replay",
        actor="controller",
        repo=root,
        json_output=True,
    )

    run = load_data(root / "tasks" / task_id / "runs" / f"{run_id}.json")
    finish_event = repository.list_events(task_id)[-1]
    assert finish_event["occurred_at"] == store_time
    assert run["finished_at"] == store_time
    assert finish_event["payload"]["run"] == run
    assert replay_entity_snapshots(repository.list_events(task_id))["runs"][run_id] == run
    projection_check = next(check for check in run_doctor(root).checks if check.name == "projection_drift")
    assert projection_check.ok


def test_run_finish_rejects_success_without_structured_result(tmp_path: Path) -> None:
    root = tmp_path / "task-repo"
    task_id, work_unit_id, run_id, repository = _registered_run(root)
    before_events = repository.list_events(task_id)
    before_run = load_data(root / "tasks" / task_id / "runs" / f"{run_id}.json")
    before_unit = load_data(root / "tasks" / task_id / "work-units" / f"{work_unit_id}.yaml")

    with pytest.raises(MacError) as captured:
        run_finish(
            task_id,
            run_id,
            status="succeeded",
            exit_code=0,
            expected_revision=5,
            idempotency_key="finish-success-without-result",
            actor="executor",
            repo=root,
            json_output=True,
        )

    assert captured.value.code == "RUN_SUCCESS_REQUIRES_RESULT"
    assert repository.list_events(task_id) == before_events
    assert load_data(root / "tasks" / task_id / "runs" / f"{run_id}.json") == before_run
    assert load_data(root / "tasks" / task_id / "work-units" / f"{work_unit_id}.yaml") == before_unit


def test_run_finish_same_key_retry_recovers_an_event_first_interruption(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "task-repo"
    task_id, work_unit_id, run_id, repository = _registered_run(root)
    original_atomic_write_json = repository_module.atomic_write_json

    def interrupted_atomic_write_json(path: Path, value: object) -> None:
        original_atomic_write_json(path, value)
        if (
            path.parent.name == "events"
            and isinstance(value, dict)
            and value.get("idempotency_key") == "finish-after-event-interruption"
        ):
            raise RuntimeError("simulated event-first interruption")

    monkeypatch.setattr(repository_module, "atomic_write_json", interrupted_atomic_write_json)
    with pytest.raises(RuntimeError, match="event-first interruption"):
        run_finish(
            task_id,
            run_id,
            status="cancelled",
            exit_code=None,
            expected_revision=5,
            idempotency_key="finish-after-event-interruption",
            actor="controller",
            repo=root,
            json_output=True,
        )
    event_count = len(repository.list_events(task_id))
    assert repository.load_task(task_id)["revision"] == 5
    assert load_data(root / "tasks" / task_id / "runs" / f"{run_id}.json")["status"] == "running"

    monkeypatch.setattr(repository_module, "atomic_write_json", original_atomic_write_json)
    run_finish(
        task_id,
        run_id,
        status="cancelled",
        exit_code=None,
        expected_revision=5,
        idempotency_key="finish-after-event-interruption",
        actor="controller",
        repo=root,
        json_output=True,
    )

    assert len(repository.list_events(task_id)) == event_count
    assert repository.load_task(task_id)["revision"] == 6
    assert load_data(root / "tasks" / task_id / "runs" / f"{run_id}.json")["status"] == "cancelled"
    assert load_data(root / "tasks" / task_id / "work-units" / f"{work_unit_id}.yaml")["status"] == "cancelled"
    assert next(check for check in run_doctor(root).checks if check.name == "projection_drift").ok


def test_modern_run_stream_rejects_authorityless_legacy_compensation(tmp_path: Path) -> None:
    root = tmp_path / "task-repo"
    task_id, work_unit_id, run_id, repository = _registered_run(root)
    task_dir = root / "tasks" / task_id
    cancelled_unit = deepcopy(load_data(task_dir / "work-units" / f"{work_unit_id}.yaml"))
    cancelled_unit["status"] = "cancelled"
    legacy_event = {
        "schema_version": 1,
        "event_id": prefixed("EVT"),
        "task_id": task_id,
        "event_type": "run_finished",
        "occurred_at": utc_now(),
        "actor": {"id": "legacy-controller", "kind": "agent"},
        "run_id": run_id,
        "expected_revision": 5,
        "new_revision": 6,
        "idempotency_key": "legacy-run-finish-without-snapshot",
        "payload": {"run_id": run_id, "status": "cancelled", "work_unit_id": work_unit_id, "work_unit": cancelled_unit},
    }
    atomic_write_json(task_dir / "events" / f"{legacy_event['event_id']}.json", legacy_event)
    with pytest.raises(MacError) as captured:
        repository.list_events(task_id)
    assert captured.value.code == "EVENT_AUTHORITY_MISSING"
    assert repository.load_task(task_id)["revision"] == 5


@pytest.mark.parametrize(
    ("source", "target", "conditions"),
    [
        ("executing", "waiting_external", ["external_dependency_pending"]),
        ("executing", "waiting_input", ["human_input_required"]),
        ("executing", "failed", ["unrecoverable_failure"]),
        ("waiting_external", "verifying", ["external_evidence_received"]),
        ("waiting_external", "executing", ["external_dependency_recovered"]),
        ("waiting_input", "executing", ["input_received", "risk_surface_unchanged"]),
        ("waiting_input", "triage", ["input_received", "risk_surface_changed"]),
    ],
)
def test_conditional_cli_transitions_require_and_canonicalize_exact_facts(
    source: str,
    target: str,
    conditions: list[str],
) -> None:
    with pytest.raises(MacError) as missing:
        cli_module._transition_fact(
            source=source,
            target=target,
            expected_conditions=set(conditions),
            supplied_conditions=[],
            fact_id=None,
            reason=None,
        )
    assert missing.value.code == "TRANSITION_FACT_MISMATCH"

    fact_id = "FACT-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    fact = cli_module._transition_fact(
        source=source,
        target=target,
        expected_conditions=set(conditions),
        supplied_conditions=list(reversed(conditions)),
        fact_id=fact_id,
        reason="external or human dependency fact recorded by the controller",
    )

    assert fact == {
        "id": fact_id,
        "source": source,
        "target": target,
        "conditions": sorted(conditions),
        "reason": "external or human dependency fact recorded by the controller",
    }


_GOVERNED_MUTATION_COMMANDS = frozenset(
    {
        "task_new",
        "task_transition",
        "task_cancel",
        "task_supersede",
        "task_rebuild",
        "scope_propose",
        "scope_approve",
        "scope_amend",
        "work_unit_new",
        "work_unit_ready",
        "run_register",
        "run_finish",
        "result_submit",
        "handoff_collect",
        "evidence_record",
        "evidence_promote",
        "evidence_invalidate",
        "finding_open",
        "finding_resolve",
        "finding_waive",
        "approval_record",
    }
)


# These persistent writers are deliberately outside the governed-entity gateway
# in the current alpha. Keeping the exclusions explicit makes adding another
# uncovered writer a test-reviewed, fail-closed decision rather than an accident.
_MUTATION_GATEWAY_UNCOVERED_FAIL_CLOSED = {
    "init_command": "repository bootstrap and schema installation",
    "doctor_command": "explicit doctor --repair-safe application",
    "migrate_v5": "legacy migration application and report output",
    "handoff_build": "derived handoff artifact writer",
    "report_render": "derived human report writer",
    "report_bundle": "derived audit bundle writer",
    "index_build": "derived index writer",
}


def test_governed_cli_writers_reach_only_gateway_or_converged_services() -> None:
    import ast

    import mac.cli as cli_module

    module = ast.parse(Path(cli_module.__file__).read_text(encoding="utf-8"))
    functions = {
        node.name: node
        for node in module.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert _GOVERNED_MUTATION_COMMANDS <= functions.keys()
    assert _MUTATION_GATEWAY_UNCOVERED_FAIL_CLOSED.keys() <= functions.keys()

    direct_writer_calls = {
        "atomic_write_json",
        "atomic_write_text",
        "atomic_write_yaml",
        "install_schema_bundle",
        "repair_safe",
        "write_handoff_packet",
        "build_audit_bundle",
        "convert_v5",
    }
    detected_uncovered: set[str] = set()
    for function_name, function in functions.items():
        for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
            if (
                isinstance(call.func, ast.Name)
                and call.func.id in direct_writer_calls
            ) or (
                isinstance(call.func, ast.Attribute)
                and call.func.attr in {"write_text", "mkdir"}
            ):
                detected_uncovered.add(function_name)
    assert detected_uncovered == _MUTATION_GATEWAY_UNCOVERED_FAIL_CLOSED.keys()

    typed_gateway_commands = {
        "AppendEvent",
        "Transition",
        "Rebuild",
        "RecordCommandEvidence",
    }
    for call in (node for node in ast.walk(module) if isinstance(node, ast.Call)):
        if isinstance(call.func, ast.Name) and call.func.id in typed_gateway_commands:
            assert any(keyword.arg == "replay_intent" for keyword in call.keywords), (
                f"CLI {call.func.id} at line {call.lineno} lacks a stable replay_intent"
            )

    forbidden_attributes = {"append_event", "transition", "rebuild_task"}
    forbidden_names = {
        "trusted_authority_verifier",
        "current_authority_verifier",
        "_authority",
        "_operation_replay",
        "_authorized_operation_replay",
        "_transition_context",
        "_context_with_transition_fact",
        "_require_scope_owner",
    }

    for command_name in {"task_transition", "task_cancel", "task_supersede"}:
        assert any(
            isinstance(node, ast.Name) and node.id == "resolve_transition_context"
            for node in ast.walk(functions[command_name])
        ), f"{command_name} must preview the repository-derived transition context"

    for command_name in sorted(_GOVERNED_MUTATION_COMMANDS):
        pending = [command_name]
        visited: set[str] = set()
        terminal_calls: set[str] = set()
        while pending:
            function_name = pending.pop()
            if function_name in visited:
                continue
            visited.add(function_name)
            node = functions[function_name]
            for descendant in ast.walk(node):
                if isinstance(descendant, ast.Attribute):
                    assert descendant.attr not in forbidden_attributes, (
                        f"{command_name} reaches direct repository write "
                        f"{function_name}.{descendant.attr}"
                    )
                    if descendant.attr in {"execute", "create", "submit"}:
                        terminal_calls.add(descendant.attr)
                elif isinstance(descendant, ast.Name):
                    assert descendant.id not in forbidden_names, (
                        f"{command_name} reaches deprecated authority/replay path "
                        f"{function_name}.{descendant.id}"
                    )
                    if descendant.id in functions and descendant.id not in visited:
                        pending.append(descendant.id)

        assert terminal_calls & {"execute", "create", "submit"}, (
            f"{command_name} does not reach MutationGateway.execute, "
            "TaskService.create, or ResultService.submit"
        )


def test_evidence_record_sends_exact_argv_to_gateway_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from types import SimpleNamespace

    import mac.cli as cli_module
    from mac.repository import RecordCommandEvidence

    commands: list[RecordCommandEvidence] = []

    class RecordingGateway:
        def execute(self, command: RecordCommandEvidence) -> object:
            commands.append(command)
            return SimpleNamespace(
                value={
                    "id": "EVD-01K0W4Z36K3W5C2R0A3M8N9P7Q",
                    "execution": {"exit_code": 0},
                },
                event=None,
                idempotent_replay=False,
            )

    monkeypatch.setattr(cli_module, "_mutation_gateway", lambda _repo: RecordingGateway())

    def unexpected_subprocess(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the CLI must not execute evidence argv before gateway authorization")

    monkeypatch.setattr(cli_module.subprocess, "run", unexpected_subprocess)
    argv = ("python", "-c", "print('exact argv')", "--flag", "value with spaces")
    cli_module.evidence_record(
        SimpleNamespace(args=list(argv)),
        "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        claim="the exact command succeeds",
        expected_revision=4,
        idempotency_key="record-evidence-exact-argv",
        actor="automation-claim",
        repo=tmp_path,
        commit=False,
        json_output=True,
    )

    capsys.readouterr()
    assert len(commands) == 1
    command = commands[0]
    assert isinstance(command, RecordCommandEvidence)
    assert command.argv == argv
    assert command.operation == "evidence.record"
    assert command.actor_claim == {"id": "automation-claim", "kind": "automation"}


def test_init_installs_agents_boundary_without_overwriting_existing(tmp_path: Path) -> None:
    fresh = tmp_path / "fresh"
    init_command(repo=fresh, project="fresh-boundary", json_output=True)
    installed = (fresh / "AGENTS.md").read_text(encoding="utf-8")
    assert ".agents/config.yaml" in installed
    assert "human-readable" in installed

    existing = tmp_path / "existing"
    existing.mkdir()
    custom = "# Existing project boundary\n\nKeep this exact content.\n"
    (existing / "AGENTS.md").write_text(custom, encoding="utf-8")
    init_command(repo=existing, project="preserve-boundary", json_output=True)
    assert (existing / "AGENTS.md").read_text(encoding="utf-8") == custom


def test_generated_entity_and_post_state_retries_still_enter_gateway(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "tests@example.invalid")
    _git(tmp_path, "config", "user.name", "Tests")
    init_command(repo=tmp_path, project="stable-cli-retry", json_output=True)
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "freeze governance")
    created = TaskService(tmp_path).create(
        title="stable CLI retry",
        mode="standard",
        objective="bind retry semantics to user input",
        acceptance=["same-key retry replays the original entity"],
        allowed_paths=["src/**"],
        owners=["governance"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "proposer", "kind": "human"},
        idempotency_key="stable-cli-retry-task",
    )
    task_id = str(created["task"]["id"])
    repository = FilesystemTaskRepository(tmp_path)
    scope_approve(
        task_id,
        expected_revision=0,
        idempotency_key="stable-scope-approval",
        actor="governance-owner",
        independence_level="L1",
        repo=tmp_path,
        json_output=True,
    )

    for _ in range(2):
        work_unit_new(
            task_id,
            title="stable work unit",
            owner="governance",
            allow=["src/**"],
            depends_on=[],
            expected_revision=1,
            idempotency_key="stable-work-unit-create",
            actor="proposer",
            repo=tmp_path,
            json_output=True,
        )

    work_units = list((repository.task_dir(task_id) / "work-units").glob("*.yaml"))
    assert len(work_units) == 1
    work_unit_id = work_units[0].stem
    assert repository.load_task(task_id)["revision"] == 2

    for _ in range(2):
        work_unit_ready(
            task_id,
            work_unit_id,
            expected_revision=2,
            idempotency_key="stable-work-unit-ready",
            actor="proposer",
            repo=tmp_path,
            json_output=True,
        )

    assert load_data(work_units[0])["status"] == "ready"
    assert repository.load_task(task_id)["revision"] == 3
    assert len(repository.list_events(task_id)) == 4

    with pytest.raises(MacError) as changed:
        work_unit_new(
            task_id,
            title="changed retry intent",
            owner="governance",
            allow=["src/**"],
            depends_on=[],
            expected_revision=1,
            idempotency_key="stable-work-unit-create",
            actor="proposer",
            repo=tmp_path,
            json_output=True,
        )
    assert changed.value.code == "MUTATION_IDEMPOTENCY_CONFLICT"
