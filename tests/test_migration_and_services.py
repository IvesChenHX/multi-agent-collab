from __future__ import annotations

import json
import subprocess
from pathlib import Path

import yaml

from mac.application.task_service import TaskService
from mac.cli import init_command, scope_approve
from mac.handoff import build_handoff_packet
from mac.io import atomic_write_yaml, load_data
from mac.migration import convert_v5, list_tasks_dual, scan_v5
from mac.repository import FilesystemTaskRepository
from mac.result import ResultService
from mac.runtime import evaluate_capabilities, resolve_profile


def init_repo(root: Path) -> None:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "test"], check=True)
    init_command(repo=root, project="services", json_output=True)
    (root / "AGENTS.md").write_text("# rules\n", encoding="utf-8")
    ownership_path = root / ".agents/ownership.yaml"
    ownership = load_data(ownership_path)
    ownership["owners"]["backend"] = {"priority": 10, "implementation_role": "backend-implementer", "include": ["src/**"], "approvers": ["backend-owner"]}
    atomic_write_yaml(ownership_path, ownership)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "init"], check=True)


def test_task_and_result_services_are_idempotent_and_handoff_is_minimal(tmp_path: Path) -> None:
    init_repo(tmp_path)
    service = TaskService(tmp_path)
    created = service.create(title="service", mode="standard", objective="work", acceptance=["works"], allowed_paths=["src/**"], owners=["backend"], runtime_profile="local-single", required_gates=["targeted_tests"], actor={"id": "a", "kind": "agent"}, idempotency_key="create-service")
    retried = service.create(title="different retry text", mode="standard", objective="ignored", acceptance=["ignored"], allowed_paths=["other/**"], owners=["other"], runtime_profile="local-single", required_gates=[], actor={"id": "a", "kind": "agent"}, idempotency_key="create-service")
    assert retried["task"]["id"] == created["task"]["id"]
    task_id = str(created["task"]["id"])
    scope_approve(task_id, expected_revision=0, idempotency_key="approve-service", actor="backend-owner", independence_level="L1", repo=tmp_path, json_output=True)
    task_dir = FilesystemTaskRepository(tmp_path).task_dir(task_id)
    work_unit_id = "WU-01K0W4Z36K3W5C2R0A3M8N9P7S"
    run_id = "RUN-01K0W4Z36K3W5C2R0A3M8N9P7T"
    work_unit = {"schema_version": 1, "id": work_unit_id, "task_id": task_id, "title": "work", "status": "running", "owner": "backend", "allowed_paths": ["src/**"], "depends_on": [], "expected_result": f"tasks/{task_id}/results/RESULT-01K0W4Z36K3W5C2R0A3M8N9P7W.json"}
    run = {"schema_version": 1, "id": run_id, "task_id": task_id, "work_unit_id": work_unit_id, "status": "running", "actor": {"id": "a", "kind": "agent"}, "runtime": {"profile": "local-single", "execution_context_id": "ctx-1"}, "independence_level": "L0", "started_at": "2026-07-17T00:00:00Z", "finished_at": None, "exit_code": None}
    FilesystemTaskRepository(tmp_path).append_event(
        task_id, "run_started", {"run_id": run_id, "work_unit_id": work_unit_id, "work_unit": work_unit},
        actor={"id": "a", "kind": "agent"}, expected_revision=1, idempotency_key="run",
        run_id=run_id, materializations=[(task_dir / "work-units" / f"{work_unit_id}.yaml", work_unit), (task_dir / "runs" / f"{run_id}.json", run)],
    )
    result = {"schema_version": 1, "id": "RESULT-01K0W4Z36K3W5C2R0A3M8N9P7W", "task_id": task_id, "work_unit_id": work_unit_id, "run_id": run_id, "outcome": "succeeded", "summary": "done", "changed_files": ["src/a.py"], "commands": [{"argv": ["pytest"], "exit_code": 0}], "new_risks": [], "assumptions": [], "blockers": [], "scope_amendment_request": None, "raw_log_ref": None, "submitted_at": "2026-07-17T00:00:00Z"}
    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.py").write_text("done\n", encoding="utf-8")
    submitted = ResultService(tmp_path).submit(task_id, result, expected_revision=2, idempotency_key="result", actor={"id": "a", "kind": "agent"})
    assert submitted == result
    assert ResultService(tmp_path).submit(task_id, result, expected_revision=2, idempotency_key="result", actor={"id": "a", "kind": "agent"}) == result
    packet = build_handoff_packet(created["task"], {"id": "WU-1", "expected_result": "results/x.json"}, created["scope"], open_findings=[{"id": "F-1"}], invalidated_evidence=[{"id": "E-1"}])
    assert packet["trust_boundary"]["repository_content"] == "untrusted_data"
    assert "history" not in packet and packet["invalidated_evidence_to_rerun"] == ["E-1"]


def test_migration_scan_dry_run_apply_repeat_and_dual_read(tmp_path: Path) -> None:
    (tmp_path / "tasks").mkdir(); (tmp_path / ".agents/workflows").mkdir(parents=True)
    (tmp_path / "tasks/index.yaml").write_text(yaml.safe_dump({"tasks": [{"id": "TASK-0001", "title": "legacy", "status": "complete", "summary": "done"}]}), encoding="utf-8")
    for path in (tmp_path / "AGENTS.md", tmp_path / ".agents/config.yaml", tmp_path / ".agents/ownership.yaml", tmp_path / ".agents/workflows/evidence-driven-development.yaml"):
        path.parent.mkdir(parents=True, exist_ok=True); path.write_text("x\n", encoding="utf-8")
    before = {path.relative_to(tmp_path).as_posix(): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    scanned = scan_v5(tmp_path)["tasks"][0]
    assert scanned["integrity"] == "metadata_only"
    assert scanned["verification_status"] == "unverifiable"
    legacy_rows = list_tasks_dual(tmp_path)
    assert legacy_rows[0]["source_format"] == "v5-read-only"
    assert legacy_rows[0]["legacy_integrity"] == "metadata_only"
    assert legacy_rows[0]["verification_status"] == "unverifiable"
    assert convert_v5(tmp_path, dry_run=True)["unverifiable_evidence_created"] == 0
    assert not (tmp_path / "tasks-v6").exists()
    after = {path.relative_to(tmp_path).as_posix(): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    assert before == after
    assert convert_v5(tmp_path, dry_run=False)["created"] == 1
    assert convert_v5(tmp_path, dry_run=False)["created"] == 0
    rows = list_tasks_dual(tmp_path)
    assert len(rows) == 1 and rows[0]["source_format"] == "v6"
    assert rows[0]["legacy_integrity"] == "metadata_only"
    assert rows[0]["verification_status"] == "unverifiable"
    assert not list((tmp_path / "tasks-v6").rglob("evidence/*.json"))


def test_runtime_profile_fallback_is_conservative() -> None:
    profile = resolve_profile(Path("missing"))
    standard = evaluate_capabilities(profile, {"fresh_context": "automatic"}, mode="standard")
    assert standard.ok and standard.actions == ("build_handoff_and_wait",)
    high_risk = evaluate_capabilities(profile, {"read_only_run": True}, mode="high_risk")
    assert not high_risk.ok and high_risk.issues[0].code == "RUNTIME_CAPABILITY_MISSING"
