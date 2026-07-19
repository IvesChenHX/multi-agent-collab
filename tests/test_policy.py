from __future__ import annotations

import subprocess
from pathlib import Path

import hashlib
import json

from mac.repository import build_policy_ref, policy_ref_matches_executable
from mac.application.task_service import TaskService


def _git(repo: Path, *argv: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *argv],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_policy_ref_is_stable_across_clean_crlf_worktrees(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "tests@example.invalid")
    _git(tmp_path, "config", "user.name", "Tests")
    _git(tmp_path, "config", "core.autocrlf", "true")
    (tmp_path / ".gitattributes").write_text("*.yaml text\n", encoding="utf-8")
    policy = tmp_path / ".agents" / "config.yaml"
    policy.parent.mkdir(parents=True)
    policy.write_bytes(b"schema_version: 6\nproject: demo\n")
    _git(tmp_path, "add", ".gitattributes", ".agents/config.yaml")
    _git(tmp_path, "commit", "-qm", "policy")

    lf_ref = build_policy_ref(tmp_path, [".agents/config.yaml"])
    policy.write_bytes(b"schema_version: 6\r\nproject: demo\r\n")

    subprocess.run(
        ["git", "-C", str(tmp_path), "diff", "--quiet", "HEAD", "--", ".agents/config.yaml"],
        check=True,
    )
    assert build_policy_ref(tmp_path, [".agents/config.yaml"]) == lf_ref


def test_legacy_crlf_snapshot_requires_exact_source_blob_equivalence(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "tests@example.invalid")
    _git(tmp_path, "config", "user.name", "Tests")
    policy = tmp_path / "AGENTS.md"
    policy.write_bytes(b"alpha\nbeta\n")
    runtime = tmp_path / ".agents" / "runtime-profiles" / "local.yaml"
    runtime.parent.mkdir(parents=True)
    runtime.write_bytes(b"id: local\n")
    _git(tmp_path, "add", "AGENTS.md", ".agents/runtime-profiles/local.yaml")
    _git(tmp_path, "commit", "-qm", "policy")
    source_commit = _git(tmp_path, "rev-parse", "HEAD")
    legacy_content = b"alpha\r\nbeta\r\n"
    rows = [{"path": "AGENTS.md", "digest": "sha256:" + hashlib.sha256(legacy_content).hexdigest()}]
    legacy_ref = {
        "source_commit": source_commit,
        "files": rows,
        "combined_digest": "sha256:" + hashlib.sha256(
            json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }

    required = {"AGENTS.md", ".agents/runtime-profiles/local.yaml"}
    assert policy_ref_matches_executable(tmp_path, legacy_ref, required_paths=required)

    forged = dict(legacy_ref)
    forged_rows = [{"path": "AGENTS.md", "digest": "sha256:" + "0" * 64}]
    forged["files"] = forged_rows
    forged["combined_digest"] = "sha256:" + hashlib.sha256(
        json.dumps(forged_rows, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert not policy_ref_matches_executable(tmp_path, forged, required_paths=required)

    runtime.write_text("id: changed\n", encoding="utf-8")
    assert not policy_ref_matches_executable(tmp_path, legacy_ref, required_paths=required)
    runtime.write_bytes(b"id: local\n")

    policy.write_text("alpha\nchanged\n", encoding="utf-8")
    assert not policy_ref_matches_executable(tmp_path, legacy_ref, required_paths=required)


def test_policy_ref_rejects_non_hex_source_commit_before_git_revision_lookup(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "tests@example.invalid")
    _git(tmp_path, "config", "user.name", "Tests")
    (tmp_path / "AGENTS.md").write_text("policy\n", encoding="utf-8")
    _git(tmp_path, "add", "AGENTS.md")
    _git(tmp_path, "commit", "-qm", "policy")
    reference = build_policy_ref(tmp_path, ["AGENTS.md"])

    reference["source_commit"] = "-" + "a" * 39

    assert not policy_ref_matches_executable(tmp_path, reference, required_paths={"AGENTS.md"})


def test_task_policy_snapshot_binds_selected_runtime_profile(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "tests@example.invalid")
    _git(tmp_path, "config", "user.name", "Tests")
    files = {
        "AGENTS.md": "# policy\n",
        ".agents/config.yaml": (
            "default_workflow: evidence-driven-development\n"
            "default_runtime_profile: local-multi\n"
            "paths:\n"
            "  workflows: .agents/workflows\n"
            "  ownership: .agents/ownership.yaml\n"
            "  runtime_profiles: .agents/runtime-profiles\n"
        ),
        ".agents/workflows/evidence-driven-development.yaml": "name: evidence-driven-development\n",
        ".agents/runtime-profiles/local-multi.yaml": "id: local-multi\n",
        ".agents/ownership.yaml": "owners: {}\n",
    }
    for relative, content in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "governance")

    created = TaskService(tmp_path).create(
        title="runtime-bound",
        mode="standard",
        objective="freeze runtime",
        acceptance=["runtime is frozen"],
        allowed_paths=["src/**"],
        owners=["platform"],
        runtime_profile="local-multi",
        required_gates=[],
        actor={"id": "a", "kind": "agent"},
        idempotency_key="runtime-bound",
    )
    reference = created["task"]["policy_ref"]
    runtime_path = ".agents/runtime-profiles/local-multi.yaml"
    assert runtime_path in {row["path"] for row in reference["files"]}
    assert policy_ref_matches_executable(tmp_path, reference, required_paths={runtime_path})

    (tmp_path / runtime_path).write_text("id: changed\n", encoding="utf-8")
    assert not policy_ref_matches_executable(tmp_path, reference, required_paths={runtime_path})
