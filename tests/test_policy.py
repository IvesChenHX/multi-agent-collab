from __future__ import annotations

import subprocess
from pathlib import Path

import hashlib
import json
import pytest

from mac.repository import build_policy_ref, policy_ref_matches_executable
from mac.application.task_service import TaskService
from mac.cli import init_command
from mac.io import atomic_write_yaml, load_data
from mac.policy import compile_frozen_policy, ownership_source_path, policy_source_paths
from tests.security.test_authority_commands import configure_test_authority


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


def test_frozen_policy_compilation_ignores_later_worktree_policy_drift(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "tests@example.invalid")
    _git(tmp_path, "config", "user.name", "Tests")
    init_command(repo=tmp_path, project="frozen-policy", json_output=True)
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "governance")
    config = load_data(tmp_path / ".agents/config.yaml")
    policy_ref = build_policy_ref(tmp_path, list(policy_source_paths(config, "local-single")))
    ownership_ref = build_policy_ref(tmp_path, [ownership_source_path(config)])

    original = compile_frozen_policy(
        tmp_path,
        policy_ref,
        ownership_ref,
        runtime_profile_id="local-single",
    )
    workflow_path = tmp_path / ".agents/workflows/evidence-driven-development.yaml"
    drifted = load_data(workflow_path)
    drifted["transitions"][0]["id"] = "worktree-only-transition-id"
    atomic_write_yaml(workflow_path, drifted)

    replayed = compile_frozen_policy(
        tmp_path,
        policy_ref,
        ownership_ref,
        runtime_profile_id="local-single",
    )

    assert replayed.workflow == original.workflow
    assert replayed.transitions == original.transitions


def test_task_policy_snapshot_binds_selected_runtime_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_test_authority(monkeypatch)
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "tests@example.invalid")
    _git(tmp_path, "config", "user.name", "Tests")
    init_command(repo=tmp_path, project="runtime-bound", json_output=True)
    source_profile = load_data(tmp_path / ".agents/runtime-profiles/local-single.yaml")
    source_profile["id"] = "local-multi"
    atomic_write_yaml(tmp_path / ".agents/runtime-profiles/local-multi.yaml", source_profile)
    (tmp_path / "AGENTS.md").write_text("# policy\n", encoding="utf-8")
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
