from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import warnings
from pathlib import Path
from types import SimpleNamespace

import pytest

from mac.errors import MacError
from mac.evidence import WORKSPACE_EQUIVALENCE_CHECKS
from mac.git import GitRepository
from mac.ownership import OwnershipResolver
from mac.scope import Change, amend_scope, check_changes, normalize_repo_path


def test_ownership_uses_exclude_specificity_priority_and_reports_ambiguity() -> None:
    ownership = {
        "owners": {
            "web": {"priority": 100, "include": ["apps/**"], "exclude": ["apps/server/**"]},
            "backend": {"priority": 90, "include": ["apps/server/**"]},
            "data-a": {"priority": 100, "include": ["db/**"]},
            "data-b": {"priority": 100, "include": ["db/**"]},
        }
    }
    resolver = OwnershipResolver(ownership)
    assert resolver.resolve("apps/ui/x.ts").owners == ("web",)
    assert resolver.resolve("apps/server/api.py").owners == ("backend",)
    assert resolver.resolve("unknown.txt").status == "unassigned"
    assert resolver.resolve("db/x.sql").status == "ambiguous"


def test_change_guard_checks_both_rename_sides_owner_and_path_collisions(tmp_path: Path) -> None:
    contract = {"allowed_paths": ["backend/**", "tests/**"], "denied_paths": ["backend/private/**"], "owners": ["backend"]}
    ownership = {"owners": {"backend": {"priority": 10, "include": ["backend/**"]}, "tests": {"priority": 10, "include": ["tests/**"]}}}
    result = check_changes(
        [Change("rename", "tests/service.py", old_path="backend/service.py"), Change("add", "backend/A.py"), Change("add", "backend/a.py")],
        contract, ownership=ownership, repo_root=tmp_path,
    )
    assert {issue.code for issue in result.issues} >= {"SCOPE_RENAME_OWNER_CROSS", "SCOPE_CASE_COLLISION"}


def test_change_guard_checks_case_and_nfc_collisions_against_existing_tree(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "test"], check=True)
    source = tmp_path / "src"
    source.mkdir()
    (source / "Auth.py").write_text("existing\n", encoding="utf-8")
    (source / "caf\u00e9.py").write_text("existing\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "src"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "existing tree"], check=True)
    (source / "Auth.py").unlink()
    (source / "caf\u00e9.py").unlink()
    contract = {"allowed_paths": ["src/**"], "denied_paths": [], "owners": []}

    result = check_changes(
        [
            Change("add", "src/auth.py"),
            Change("add", "src/cafe\u0301.py", display_path="src/cafe\u0301.py"),
        ],
        contract,
        repo_root=tmp_path,
    )

    assert {issue.code for issue in result.issues} >= {"SCOPE_CASE_COLLISION", "SCOPE_UNICODE_COLLISION"}


def test_scope_patterns_do_not_use_deprecated_pathspec_factory() -> None:
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        result = check_changes(
            [Change("add", "src/app.py")],
            {"allowed_paths": ["src/**"], "denied_paths": [], "owners": []},
        )

    assert result.ok
    assert not [item for item in captured if issubclass(item.category, DeprecationWarning)]


def test_change_guard_enforces_allowed_operations() -> None:
    result = check_changes(
        [Change("modify", "src/app.py")],
        {
            "allowed_paths": ["src/**"],
            "denied_paths": [],
            "allowed_operations": ["read"],
            "owners": [],
        },
    )

    assert not result.ok
    assert {issue.code for issue in result.issues} == {"SCOPE_OPERATION_DENIED"}


def test_change_guard_requires_delete_and_write_for_destructive_changes() -> None:
    deleted = check_changes(
        [Change("delete", "src/old.py")],
        {
            "allowed_paths": ["src/**"],
            "denied_paths": [],
            "allowed_operations": ["write"],
            "owners": [],
        },
    )
    renamed = check_changes(
        [Change("rename", "src/new.py", old_path="src/old.py")],
        {
            "allowed_paths": ["src/**"],
            "denied_paths": [],
            "allowed_operations": ["write"],
            "owners": [],
        },
    )
    allowed_delete = check_changes(
        [Change("delete", "src/old.py")],
        {
            "allowed_paths": ["src/**"],
            "denied_paths": [],
            "allowed_operations": ["delete"],
            "owners": [],
        },
    )

    assert {issue.details["required_operation"] for issue in deleted.issues} == {"delete"}
    assert {issue.details["required_operation"] for issue in renamed.issues} == {"delete"}
    assert allowed_delete.ok


def test_scope_amendment_can_explicitly_add_delete_authority() -> None:
    contract = {
        "id": "SCOPE-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        "version": 1,
        "status": "approved",
        "allowed_paths": ["src/**"],
        "allowed_operations": ["read", "write"],
        "risk_tags": [],
        "amendment_policy": {"max_amendments": 2, "max_paths_per_amendment": 4},
    }

    amended = amend_scope(
        contract,
        add_paths=[],
        add_operations=["delete"],
        actor="proposer",
        approvers=[],
    )

    assert amended["status"] == "proposed"
    assert amended["version"] == 2
    assert amended["allowed_operations"] == ["read", "write", "delete"]


def test_git_reader_and_workspace_digest_cover_staged_unstaged_untracked_and_delete(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "test"], check=True)
    (tmp_path / "a.txt").write_text("a\n", encoding="utf-8")
    (tmp_path / "gone.txt").write_text("gone\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "base"], check=True)
    (tmp_path / "a.txt").write_text("changed\n", encoding="utf-8")
    (tmp_path / "new.txt").write_text("new\n", encoding="utf-8")
    (tmp_path / "gone.txt").unlink()

    git = GitRepository(tmp_path)
    changes = git.workspace_changes()
    assert {(item.operation, item.path) for item in changes} >= {("modify", "a.txt"), ("add", "new.txt"), ("delete", "gone.txt")}
    first = git.workspace_subject()
    second = git.workspace_subject()
    assert first == second
    assert set(first) == {"type", "head_commit", "index_digest", "worktree_diff_digest", "untracked_manifest_digest"}


def test_workspace_promotion_equivalence_proves_staged_tree_and_ignores_only_current_task_metadata(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "test"], check=True)
    (tmp_path / "base.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "base.txt"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "base"], check=True)
    task_id = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    metadata = tmp_path / "tasks" / task_id / "task.yaml"
    metadata.parent.mkdir(parents=True)
    metadata.write_text("state: executing\n", encoding="utf-8")
    source = tmp_path / "src/app.py"
    source.parent.mkdir()
    source.write_text("implemented\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "src/app.py"], check=True)
    git = GitRepository(tmp_path)
    workspace = git.workspace_subject(task_id=task_id)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "implementation"], check=True)

    proof = git.workspace_equivalence_proof(workspace, "HEAD", task_id=task_id)
    assert proof.valid()
    assert set(proof.checks) == WORKSPACE_EQUIVALENCE_CHECKS
    assert proof.source_workspace_subject == workspace
    assert proof.observed_workspace_subject["head_commit"] == proof.target_commit_subject["commit_sha"]
    assert git.workspace_equivalent_to_commit("HEAD", task_id=task_id, source_workspace_subject=workspace)
    source.write_text("drift\n", encoding="utf-8")
    drifted = git.workspace_equivalence_proof(workspace, "HEAD", task_id=task_id)
    assert not drifted.valid()
    assert not drifted.checks["effective_tree_matches"]
    assert not git.workspace_equivalent_to_commit("HEAD", task_id=task_id, source_workspace_subject=workspace)


def test_commit_subject_validates_lfs_object_for_requested_ref(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "test"], check=True)
    asset = tmp_path / "asset.bin"
    asset.write_bytes(b"regular content\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "asset.bin"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "regular"], check=True)
    regular_commit = subprocess.run(
        ["git", "-C", str(tmp_path), "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
    ).stdout.strip()
    payload = b"large binary payload"
    oid = hashlib.sha256(payload).hexdigest()
    asset.write_text(
        f"version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize {len(payload)}\n",
        encoding="ascii",
    )
    subprocess.run(["git", "-C", str(tmp_path), "add", "asset.bin"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "lfs pointer"], check=True)
    lfs_commit = subprocess.run(
        ["git", "-C", str(tmp_path), "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
    ).stdout.strip()
    git = GitRepository(tmp_path)

    assert git.commit_subject(regular_commit)["commit_sha"] == regular_commit
    with pytest.raises(MacError, match="unavailable") as missing:
        git.commit_subject(lfs_commit)
    assert missing.value.code == "GIT_LFS_OBJECT_MISSING"

    object_path = tmp_path / ".git" / "lfs" / "objects" / oid[:2] / oid[2:4] / oid
    object_path.parent.mkdir(parents=True)
    object_path.write_bytes(b"tampered")
    with pytest.raises(MacError) as tampered:
        git.commit_subject(lfs_commit)
    assert tampered.value.code == "GIT_LFS_OBJECT_TAMPERED"
    object_path.write_bytes(payload)
    assert git.commit_subject(lfs_commit)["commit_sha"] == lfs_commit


def test_lfs_detection_uses_constant_number_of_cat_file_processes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "test"], check=True)
    for index in range(24):
        (tmp_path / f"file-{index:02}.txt").write_text(f"value {index}\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "many files"], check=True)
    git = GitRepository(tmp_path)
    original_run = git._run
    cat_file_calls: list[tuple[str, ...]] = []

    def counted_run(*argv: str, **kwargs: object) -> bytes | str:
        if argv and argv[0] == "cat-file":
            cat_file_calls.append(argv)
        return original_run(*argv, **kwargs)

    monkeypatch.setattr(git, "_run", counted_run)

    git.workspace_subject()

    assert len(cat_file_calls) == 2


def test_diff_marks_gitlink_from_compared_refs(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "test"], check=True)
    (tmp_path / "base.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "base.txt"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "base"], check=True)
    base_commit = subprocess.run(
        ["git", "-C", str(tmp_path), "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "-C", str(tmp_path), "update-index", "--add", "--cacheinfo", f"160000,{base_commit},vendor/sub"],
        check=True,
    )
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "gitlink"], check=True)

    changes = GitRepository(tmp_path).diff_changes(base_commit)

    assert any(change.path == "vendor/sub" and change.submodule for change in changes)


def test_workspace_subject_rejects_untracked_special_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "test"], check=True)
    (tmp_path / "base.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "base.txt"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "base"], check=True)
    special = tmp_path / "pipe"
    special.write_text("placeholder\n", encoding="utf-8")
    original_lstat = Path.lstat

    def fake_lstat(path: Path) -> object:
        if path == special:
            return SimpleNamespace(st_mode=stat.S_IFIFO)
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    with pytest.raises(MacError) as captured:
        GitRepository(tmp_path).workspace_subject()

    assert captured.value.code == "GIT_SPECIAL_PATH_UNSUPPORTED"


def test_workspace_subject_rejects_untracked_file_replaced_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "test"], check=True)
    (repo / "base.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "base.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)
    target = repo / "payload.txt"
    target.write_text("original\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside secret\n", encoding="utf-8")
    replaced = False
    original_path_read_bytes = Path.read_bytes
    original_os_open = os.open

    def replace_target() -> None:
        nonlocal replaced
        if replaced:
            return
        target.unlink()
        try:
            os.symlink(outside, target)
        except OSError:
            os.link(outside, target)
        replaced = True

    def racing_path_read_bytes(path: Path) -> bytes:
        if path == target:
            replace_target()
        return original_path_read_bytes(path)

    def racing_os_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if dir_fd is None and Path(os.fsdecode(path)) == target:
            replace_target()
        if dir_fd is None:
            return original_os_open(path, flags, mode)
        return original_os_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(Path, "read_bytes", racing_path_read_bytes)
    monkeypatch.setattr(os, "open", racing_os_open)

    with pytest.raises(MacError) as captured:
        GitRepository(repo).workspace_subject()

    assert replaced
    assert captured.value.code == "GIT_PATH_CHANGED_DURING_SCAN"
