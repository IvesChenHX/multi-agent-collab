from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from mac.application.task_service import TaskService
from mac.authority import AuthorityDecision, trusted_authority_verifier
from mac.cli import init_command, run_finish, run_register, task_transition, work_unit_new, work_unit_ready
from mac.doctor import run_doctor
from mac.errors import MacError
from mac.events import replay_entity_snapshots
from mac.io import load_data
from mac.repository import FilesystemTaskRepository


class _RuntimeVerifier:
    def authorize(self, *, actor_claim: dict[str, object], operation: str, task_id: str | None) -> AuthorityDecision:
        return AuthorityDecision(
            allowed=True,
            actor_id=str(actor_claim["id"]),
            actor_kind=str(actor_claim["kind"]),
            operation=operation,
            task_id=task_id,
            authenticated=True,
            issuer="test-runtime-broker",
            independence_level="L2",
            attestation_id=f"attestation-{operation.replace('.', '-')}",
        )


def _task_in_state(tmp_path: Path, state: str) -> tuple[str, FilesystemTaskRepository]:
    init_command(repo=tmp_path, project="transition-facts", json_output=True)
    source_agents = Path(__file__).resolve().parents[1] / "AGENTS.md"
    (tmp_path / "AGENTS.md").write_bytes(source_agents.read_bytes())
    created = TaskService(tmp_path).create(
        title="fact",
        mode="standard",
        objective="exercise an audited transition fact",
        acceptance=["transition is audited"],
        allowed_paths=["src/**"],
        owners=["governance"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "proposer", "kind": "human"},
        idempotency_key=f"create-{state}",
    )
    task_id = str(created["task"]["id"])
    repository = FilesystemTaskRepository(tmp_path)
    repository.append_event(
        task_id,
        "state_transitioned",
        {"from": "triage", "to": state, "transition_id": "fixture", "terminal_state": False},
        actor={"id": "fixture", "kind": "automation"},
        expected_revision=0,
        idempotency_key=f"fixture-{state}",
    )
    return task_id, repository

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
    work_unit_new(
        task_id,
        title="implementation",
        owner="governance",
        allow=["src/**"],
        depends_on=[],
        expected_revision=0,
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
        expected_revision=1,
        idempotency_key="ready-run-replay-unit",
        actor="controller",
        repo=root,
        json_output=True,
    )
    with trusted_authority_verifier(_RuntimeVerifier()):
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
            expected_revision=2,
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

    with trusted_authority_verifier(_RuntimeVerifier()), pytest.raises(MacError) as captured:
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


def test_run_finish_records_a_replayable_terminal_run_snapshot(tmp_path: Path) -> None:
    root = tmp_path / "task-repo"
    task_id, _, run_id, repository = _registered_run(root)

    run_finish(
        task_id,
        run_id,
        status="cancelled",
        exit_code=None,
        expected_revision=3,
        idempotency_key="finish-run-replay",
        actor="controller",
        repo=root,
        json_output=True,
    )

    run = load_data(root / "tasks" / task_id / "runs" / f"{run_id}.json")
    finish_event = repository.list_events(task_id)[-1]
    assert finish_event["payload"]["run"] == run
    assert replay_entity_snapshots(repository.list_events(task_id))["runs"][run_id] == run
    projection_check = next(check for check in run_doctor(root).checks if check.name == "projection_drift")
    assert projection_check.ok


def test_run_finish_same_key_retry_recovers_an_event_first_interruption(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "task-repo"
    task_id, work_unit_id, run_id, repository = _registered_run(root)
    original_append = FilesystemTaskRepository.append_event

    def interrupted_append(self: FilesystemTaskRepository, *args: object, **kwargs: object):
        if kwargs.get("idempotency_key") == "finish-after-event-interruption":
            def fail_after_event(stage: str) -> None:
                if stage == "after_event":
                    raise RuntimeError("simulated event-first interruption")

            kwargs["fault_hook"] = fail_after_event
        return original_append(self, *args, **kwargs)

    monkeypatch.setattr(FilesystemTaskRepository, "append_event", interrupted_append)
    with pytest.raises(RuntimeError, match="event-first interruption"):
        run_finish(
            task_id,
            run_id,
            status="cancelled",
            exit_code=None,
            expected_revision=3,
            idempotency_key="finish-after-event-interruption",
            actor="controller",
            repo=root,
            json_output=True,
        )
    event_count = len(repository.list_events(task_id))
    assert repository.load_task(task_id)["revision"] == 3
    assert load_data(root / "tasks" / task_id / "runs" / f"{run_id}.json")["status"] == "running"

    monkeypatch.setattr(FilesystemTaskRepository, "append_event", original_append)
    run_finish(
        task_id,
        run_id,
        status="cancelled",
        exit_code=None,
        expected_revision=3,
        idempotency_key="finish-after-event-interruption",
        actor="controller",
        repo=root,
        json_output=True,
    )

    assert len(repository.list_events(task_id)) == event_count
    assert repository.load_task(task_id)["revision"] == 4
    assert load_data(root / "tasks" / task_id / "runs" / f"{run_id}.json")["status"] == "cancelled"
    assert load_data(root / "tasks" / task_id / "work-units" / f"{work_unit_id}.yaml")["status"] == "cancelled"
    assert next(check for check in run_doctor(root).checks if check.name == "projection_drift").ok


def test_run_finish_appends_a_compensating_snapshot_for_legacy_terminal_events(tmp_path: Path) -> None:
    root = tmp_path / "task-repo"
    task_id, work_unit_id, run_id, repository = _registered_run(root)
    task_dir = root / "tasks" / task_id
    run_path = task_dir / "runs" / f"{run_id}.json"
    work_unit_path = task_dir / "work-units" / f"{work_unit_id}.yaml"
    finished = deepcopy(load_data(run_path))
    finished.update({"status": "cancelled", "finished_at": "2026-07-19T00:00:00Z", "exit_code": None})
    cancelled_unit = deepcopy(load_data(work_unit_path))
    cancelled_unit["status"] = "cancelled"
    legacy = repository.append_event(
        task_id,
        "run_finished",
        {"run_id": run_id, "status": "cancelled", "work_unit_id": work_unit_id, "work_unit": cancelled_unit},
        actor={"id": "legacy-controller", "kind": "agent"},
        expected_revision=3,
        idempotency_key="legacy-run-finish-without-snapshot",
        run_id=run_id,
        materializations=[(run_path, finished), (work_unit_path, cancelled_unit)],
        replace_existing={run_path, work_unit_path},
    )
    assert not next(check for check in run_doctor(root).checks if check.name == "projection_drift").ok
    legacy_event_count = len(repository.list_events(task_id))

    with pytest.raises(MacError) as incomplete_retry:
        run_finish(
            task_id,
            run_id,
            status="cancelled",
            exit_code=None,
            expected_revision=4,
            idempotency_key="legacy-run-finish-without-snapshot",
            actor="controller",
            repo=root,
            json_output=True,
        )
    assert incomplete_retry.value.code == "RUN_FINISH_SNAPSHOT_MISSING"
    assert len(repository.list_events(task_id)) == legacy_event_count

    tampered = deepcopy(finished)
    tampered["actor"] = {"id": "attacker", "kind": "agent"}
    run_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(MacError) as tampered_projection:
        run_finish(
            task_id,
            run_id,
            status="cancelled",
            exit_code=None,
            expected_revision=4,
            idempotency_key="reject-tampered-run-projection",
            actor="controller",
            repo=root,
            json_output=True,
        )
    assert tampered_projection.value.code == "RUN_PROJECTION_TAMPERED"
    assert len(repository.list_events(task_id)) == legacy_event_count
    run_path.write_text(json.dumps(finished), encoding="utf-8")

    run_finish(
        task_id,
        run_id,
        status="cancelled",
        exit_code=None,
        expected_revision=4,
        idempotency_key="compensate-legacy-run-finish",
        actor="controller",
        repo=root,
        json_output=True,
    )

    compensation = repository.list_events(task_id)[-1]
    assert compensation["event_type"] == "run_finished"
    assert compensation["payload"]["run"] == finished
    assert compensation["payload"]["compensates_event_id"] == legacy.event["event_id"]
    assert replay_entity_snapshots(repository.list_events(task_id))["runs"][run_id] == finished
    assert next(check for check in run_doctor(root).checks if check.name == "projection_drift").ok

    revision = repository.load_task(task_id)["revision"]
    event_count = len(repository.list_events(task_id))
    run_finish(
        task_id,
        run_id,
        status="cancelled",
        exit_code=None,
        expected_revision=revision,
        idempotency_key="compensate-legacy-run-finish",
        actor="controller",
        repo=root,
        json_output=True,
    )
    assert repository.load_task(task_id)["revision"] == revision
    assert len(repository.list_events(task_id)) == event_count


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
def test_conditional_cli_transitions_require_and_persist_exact_facts(
    tmp_path: Path,
    source: str,
    target: str,
    conditions: list[str],
) -> None:
    task_id, repository = _task_in_state(tmp_path, source)

    with pytest.raises(MacError) as missing:
        task_transition(
            task_id,
            target,
            expected_revision=1,
            idempotency_key=f"missing-{source}-{target}",
            actor="controller",
            condition=[],
            fact_id=None,
            reason=None,
            repo=tmp_path,
            json_output=True,
        )
    assert missing.value.code == "TRANSITION_FACT_MISMATCH"

    fact_id = "FACT-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    idempotency_key = f"fact-{source}-{target}"
    with trusted_authority_verifier(_RuntimeVerifier()):
        task_transition(
            task_id,
            target,
            expected_revision=1,
            idempotency_key=idempotency_key,
            actor="controller",
            condition=conditions,
            fact_id=fact_id,
            reason="external or human dependency fact recorded by the controller",
            repo=tmp_path,
            json_output=True,
        )
        task_transition(
            task_id,
            target,
            expected_revision=1,
            idempotency_key=idempotency_key,
            actor="controller",
            condition=conditions,
            fact_id=fact_id,
            reason="external or human dependency fact recorded by the controller",
            repo=tmp_path,
            json_output=True,
        )

    event = repository.list_events(task_id)[-1]
    metadata = event["payload"]["transition_metadata"]
    assert metadata["transition_fact"] == {
        "id": fact_id,
        "source": source,
        "target": target,
        "conditions": sorted(conditions),
        "reason": "external or human dependency fact recorded by the controller",
    }
    assert metadata["authority"]["issuer"] == "test-runtime-broker"

    with trusted_authority_verifier(_RuntimeVerifier()), pytest.raises(MacError) as changed:
        task_transition(
            task_id,
            target,
            expected_revision=1,
            idempotency_key=idempotency_key,
            actor="controller",
            condition=conditions,
            fact_id=fact_id,
            reason="different retry fact",
            repo=tmp_path,
            json_output=True,
        )
    assert changed.value.code == "EVENT_IDEMPOTENCY_CONFLICT"
