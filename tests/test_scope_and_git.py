from __future__ import annotations

import subprocess
from pathlib import Path

from mac.git import GitRepository
from mac.ownership import OwnershipResolver
from mac.scope import Change, check_changes, normalize_repo_path


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

    assert git.workspace_equivalent_to_commit("HEAD", task_id=task_id, source_workspace_subject=workspace)
    source.write_text("drift\n", encoding="utf-8")
    assert not git.workspace_equivalent_to_commit("HEAD", task_id=task_id, source_workspace_subject=workspace)
