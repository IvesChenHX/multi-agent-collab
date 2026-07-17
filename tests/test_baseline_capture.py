from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "capture_v5_baseline.py"
DEFAULT_PATHS = [
    "AGENTS.md",
    ".agents/config.yaml",
    ".agents/ownership.yaml",
    ".agents/workflows/evidence-driven-development.yaml",
]


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
    )


def _commit_policy_files(repo: Path) -> str:
    _git(repo, "init", "-q")
    for relative in DEFAULT_PATHS:
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"committed v5: {relative}\n", encoding="utf-8")
    _git(repo, "add", *DEFAULT_PATHS)
    _git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-q",
        "-m",
        "v5 policy",
    )
    _git(repo, "tag", "v5-base")
    return _git(repo, "rev-parse", "v5-base^{commit}").stdout.decode().strip()


def test_cli_source_ref_reads_committed_files_not_workspace(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    resolved_commit = _commit_policy_files(repo)
    for relative in DEFAULT_PATHS:
        (repo / relative).write_text(f"migrated workspace: {relative}\n", encoding="utf-8")

    output = tmp_path / "baseline.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            str(repo),
            "--out",
            str(output),
            "--source-ref",
            "v5-base",
        ],
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert manifest["requested_ref"] == "v5-base"
    assert manifest["source_commit"] == resolved_commit
    for item in manifest["files"]:
        committed = _git(repo, "show", f"{resolved_commit}:{item['path']}").stdout
        workspace = (repo / item["path"]).read_bytes()
        assert item == {
            "path": item["path"],
            "present": True,
            "digest": "sha256:" + hashlib.sha256(committed).hexdigest(),
        }
        assert item["digest"] != "sha256:" + hashlib.sha256(workspace).hexdigest()

    verified = subprocess.run(
        [sys.executable, str(SCRIPT), str(repo), "--out", str(output), "--verify"],
        capture_output=True,
        text=True,
    )
    assert verified.returncode == 0, verified.stderr


def test_cli_source_ref_does_not_fall_back_when_ref_is_missing(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _commit_policy_files(repo)
    output = tmp_path / "baseline.json"

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), str(repo), "--out", str(output), "--source-ref", "missing-ref"],
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert completed.stderr == "baseline capture failed: source ref does not resolve to a commit: missing-ref\n"
    assert not output.exists()


def test_cli_source_ref_does_not_fall_back_when_commit_file_is_missing(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _commit_policy_files(repo)
    missing_path = repo / DEFAULT_PATHS[-1]
    missing_path.unlink()
    _git(repo, "add", "--", DEFAULT_PATHS[-1])
    _git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-q",
        "-m",
        "remove policy file",
    )
    missing_path.write_text("workspace fallback must not be used\n", encoding="utf-8")
    output = tmp_path / "baseline.json"

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), str(repo), "--out", str(output), "--source-ref", "HEAD"],
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert completed.stderr == f"baseline capture failed: file not found at source commit: {DEFAULT_PATHS[-1]}\n"
    assert not output.exists()


def test_cli_without_source_ref_keeps_workspace_capture_behavior(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    resolved_commit = _commit_policy_files(repo)
    changed_path = repo / DEFAULT_PATHS[0]
    changed_path.write_text("uncommitted workspace policy\n", encoding="utf-8")
    output = tmp_path / "baseline.json"

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), str(repo), "--out", str(output)],
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert "requested_ref" not in manifest
    assert manifest["source_commit"] == resolved_commit
    assert manifest["files"][0]["digest"] == "sha256:" + hashlib.sha256(changed_path.read_bytes()).hexdigest()
