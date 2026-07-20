from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess

import yaml


SCRIPT = Path(__file__).parents[2] / "scripts" / "ci" / "governance_pr.py"
SPEC = importlib.util.spec_from_file_location("governance_pr", SCRIPT)
assert SPEC and SPEC.loader
governance_pr = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(governance_pr)

TASK_ID = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q-legal-slug"


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        text=True,
        encoding="utf-8",
        capture_output=True,
    )
    return completed.stdout.strip()


def test_pr_gate_preserves_slug_and_tracks_the_head_current_code_subject(
    tmp_path: Path, monkeypatch
) -> None:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "ci@example.test")
    _git(tmp_path, "config", "user.name", "CI")
    task_dir = tmp_path / "tasks" / TASK_ID
    (task_dir / "runs").mkdir(parents=True)
    (task_dir / "evidence").mkdir()
    (tmp_path / "src.py").write_text("VALUE = 1\n", encoding="utf-8")
    task = {
        "id": TASK_ID,
        "required_gates": ["targeted_tests"],
        "acceptance_criteria": [],
        "policy_ref": {"combined_digest": "sha256:" + "a" * 64},
    }
    (task_dir / "task.yaml").write_text(yaml.safe_dump(task), encoding="utf-8")
    run = {"id": "RUN-01K0W4Z36K3W5C2R0A3M8N9P7T", "status": "succeeded"}
    (task_dir / "runs" / f"{run['id']}.json").write_text(json.dumps(run), encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "code subject")
    old_commit = _git(tmp_path, "rev-parse", "HEAD")
    old_tree = _git(tmp_path, "rev-parse", "HEAD^{tree}")
    evidence = {
        "id": "EVD-01K0W4Z36K3W5C2R0A3M8N9P7X",
        "kind": "command",
        "run_id": run["id"],
        "claims": [{"gate": "targeted_tests"}],
        "subject": {"type": "commit", "commit_sha": old_commit, "tree_sha": old_tree},
        "policy_digest": task["policy_ref"]["combined_digest"],
        "execution": {"exit_code": 0},
        "validity": {"status": "valid", "invalidated_by": []},
    }
    (task_dir / "evidence" / f"{evidence['id']}.json").write_text(
        json.dumps(evidence), encoding="utf-8"
    )
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "record old evidence")
    head = _git(tmp_path, "rev-parse", "HEAD")

    assert governance_pr.discover_task_ids(
        [f"tasks/{TASK_ID}/task.yaml"], []
    ) == [TASK_ID]
    monkeypatch.chdir(tmp_path)
    metadata_only_check = governance_pr.check_current_evidence(tmp_path, TASK_ID, head)

    assert metadata_only_check["exit_code"] == 0
    assert metadata_only_check["output"]["accepted_evidence"] == [evidence["id"]]

    (tmp_path / "src.py").write_text("VALUE = 2\n", encoding="utf-8")
    _git(tmp_path, "add", "src.py")
    _git(tmp_path, "commit", "-qm", "new business subject")
    newer_head = _git(tmp_path, "rev-parse", "HEAD")
    check = governance_pr.check_current_evidence(tmp_path, TASK_ID, newer_head)

    assert check["exit_code"] == 7
    assert check["output"]["accepted_evidence"] == []
    assert "not bound to PR head current code subject" in check["output"]["rejected_evidence"][evidence["id"]]
