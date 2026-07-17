import json
import subprocess
from pathlib import Path

import yaml

from scripts.ci.governance_pr import check_current_evidence, discover_task_ids, evaluate


TASK_ID = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"


def test_discover_task_ids_from_changed_v6_task_metadata():
    paths = [f"tasks/{TASK_ID}-refund-auth/events/EVT-example.json", "src/mac/domain/task.py"]

    assert discover_task_ids(paths, []) == [f"{TASK_ID}-refund-auth"]


def test_explicit_task_id_covers_pr_without_changed_task_metadata():
    assert discover_task_ids(["src/mac/domain/task.py"], [TASK_ID]) == [TASK_ID]


def test_advisory_reports_but_does_not_block():
    ok, exit_code = evaluate("advisory", [{"exit_code": 6}], [])

    assert ok is True
    assert exit_code == 0


def test_enforced_fails_closed_without_task_context():
    ok, exit_code = evaluate("enforced", [{"exit_code": 0}], [])

    assert ok is False
    assert exit_code == 7


def test_enforced_preserves_stable_scope_exit_code():
    ok, exit_code = evaluate("enforced", [{"exit_code": 0}, {"exit_code": 6}], [TASK_ID])

    assert ok is False
    assert exit_code == 6


def test_evidence_gate_accepts_metadata_only_successor_commit_and_rejects_new_code(tmp_path: Path, monkeypatch):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "test"], check=True)
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.py").write_text("v1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "src/app.py"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "code"], check=True)
    commit = subprocess.run(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], check=True, text=True, capture_output=True).stdout.strip()
    tree = subprocess.run(["git", "-C", str(tmp_path), "rev-parse", "HEAD^{tree}"], check=True, text=True, capture_output=True).stdout.strip()
    task_directory = f"{TASK_ID}-refund-auth"
    task_dir = tmp_path / "tasks" / task_directory
    (task_dir / "runs").mkdir(parents=True)
    (task_dir / "evidence").mkdir()
    policy = "sha256:" + "a" * 64
    task = {"id": TASK_ID, "required_gates": ["targeted_tests"], "acceptance_criteria": [{"id": "AC-001", "required": True}], "policy_ref": {"combined_digest": policy}}
    (task_dir / "task.yaml").write_text(yaml.safe_dump(task), encoding="utf-8")
    run_id = "RUN-01K0W4Z36K3W5C2R0A3M8N9P7T"
    (task_dir / "runs" / f"{run_id}.json").write_text(json.dumps({"id": run_id, "status": "succeeded"}), encoding="utf-8")
    evidence = {"id": "EVD-01K0W4Z36K3W5C2R0A3M8N9P7X", "kind": "command", "run_id": run_id, "subject": {"type": "commit", "commit_sha": commit, "tree_sha": tree}, "policy_digest": policy, "claims": [{"gate": "targeted_tests"}, {"acceptance_criterion": "AC-001"}], "execution": {"exit_code": 0}, "validity": {"status": "valid", "invalidated_by": []}}
    (task_dir / "evidence" / f"{evidence['id']}.json").write_text(json.dumps(evidence), encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", f"tasks/{task_directory}"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "evidence metadata"], check=True)
    monkeypatch.chdir(tmp_path)

    accepted = check_current_evidence(Path("."), task_directory, "HEAD")
    assert accepted["exit_code"] == 0

    (tmp_path / "src/app.py").write_text("v2\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "src/app.py"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "new code"], check=True)
    rejected = check_current_evidence(Path("."), task_directory, "HEAD")
    assert rejected["exit_code"] == 7
