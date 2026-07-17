from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from typing import Iterable

from .errors import ExitCode, MacError
from .scope import Change, is_task_governance_metadata, normalize_repo_path, task_governance_metadata_patterns


def _digest(chunks: Iterable[bytes]) -> str:
    hasher = hashlib.sha256()
    for chunk in chunks:
        hasher.update(len(chunk).to_bytes(8, "big"))
        hasher.update(chunk)
    return "sha256:" + hasher.hexdigest()


class GitRepository:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self._run("rev-parse", "--git-dir")

    def _run(self, *argv: str, text: bool = False) -> bytes | str:
        try:
            result = subprocess.run(["git", "-C", str(self.root), *argv], check=True, capture_output=True, text=text)
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            raise MacError("GIT_COMMAND_FAILED", f"git {' '.join(argv)} failed", exit_code=ExitCode.EXTERNAL) from exc
        return result.stdout

    @property
    def head(self) -> str:
        return str(self._run("rev-parse", "HEAD", text=True)).strip()

    def _is_gitlink(self, path: str, refs: tuple[str, ...] = ()) -> bool:
        index = self._as_bytes(self._run("ls-files", "--stage", "--", path))
        if any(line.startswith(b"160000 ") for line in index.splitlines()):
            return True
        for ref in refs:
            value = self._as_bytes(self._run("ls-tree", ref, "--", path))
            if any(line.startswith(b"160000 ") for line in value.splitlines()):
                return True
        return False

    def _parse_name_status(self, data: bytes, *, refs: tuple[str, ...] = ()) -> list[Change]:
        fields = data.split(b"\0")
        changes: list[Change] = []
        index = 0
        while index < len(fields) and fields[index]:
            status = fields[index].decode("ascii", "strict")
            index += 1
            if status.startswith(("R", "C")):
                old_display = os.fsdecode(fields[index]); new_display = os.fsdecode(fields[index + 1]); old_path = normalize_repo_path(old_display); new_path = normalize_repo_path(new_display); index += 2
                changes.append(Change("rename" if status.startswith("R") else "copy", new_path, old_path, self._is_gitlink(new_path, refs) or self._is_gitlink(old_path, refs), new_display, old_display))
                continue
            display = os.fsdecode(fields[index]); path = normalize_repo_path(display); index += 1
            operation = {"A": "add", "M": "modify", "D": "delete", "T": "modify"}.get(status[0], "modify")
            changes.append(Change(operation, path, submodule=self._is_gitlink(path, refs), display_path=display))
        return changes

    def diff_changes(self, base: str, head: str = "HEAD") -> list[Change]:
        data = self._run("diff", "--name-status", "-z", "--find-renames", base, head)
        return self._parse_name_status(data if isinstance(data, bytes) else data.encode(), refs=(base, head))

    def workspace_changes(self, task_id: str | None = None) -> list[Change]:
        staged = self._parse_name_status(self._as_bytes(self._run("diff", "--cached", "--name-status", "-z", "--find-renames")), refs=("HEAD",))
        unstaged = self._parse_name_status(self._as_bytes(self._run("diff", "--name-status", "-z", "--find-renames")), refs=("HEAD",))
        untracked_raw = self._as_bytes(self._run("ls-files", "--others", "--exclude-standard", "-z"))
        untracked = [Change("add", normalize_repo_path(os.fsdecode(value)), display_path=os.fsdecode(value)) for value in untracked_raw.split(b"\0") if value]
        deduplicated: dict[tuple[str | None, str, str | None, str | None], Change] = {}
        for change in [*staged, *unstaged, *untracked]:
            deduplicated[(change.old_path, change.path, change.old_display_path, change.display_path)] = change
        changes = sorted(deduplicated.values(), key=lambda item: (item.path, item.old_path or ""))
        if task_id:
            changes = [
                change for change in changes
                if not is_task_governance_metadata(change.path, task_id)
                or bool(change.old_path and not is_task_governance_metadata(change.old_path, task_id))
            ]
        return changes

    def changes_since(self, base: str | None, *, head: str = "HEAD", task_id: str | None = None) -> list[Change]:
        committed = self.diff_changes(base, head) if base else []
        current = self.workspace_changes(task_id=task_id)
        combined: dict[tuple[str | None, str, str | None, str | None], Change] = {}
        for change in [*committed, *current]:
            if task_id and is_task_governance_metadata(change.path, task_id) and not (change.old_path and not is_task_governance_metadata(change.old_path, task_id)):
                continue
            combined[(change.old_path, change.path, change.old_display_path, change.display_path)] = change
        return sorted(combined.values(), key=lambda item: (item.path, item.old_path or ""))

    @staticmethod
    def _as_bytes(value: bytes | str) -> bytes:
        return value if isinstance(value, bytes) else value.encode()

    def commit_subject(self, commit: str = "HEAD") -> dict[str, str]:
        self._lfs_manifest()
        commit_sha = str(self._run("rev-parse", commit, text=True)).strip()
        tree_sha = str(self._run("rev-parse", f"{commit}^{{tree}}", text=True)).strip()
        return {"type": "commit", "commit_sha": commit_sha, "tree_sha": tree_sha}

    def current_code_subject(self, task_id: str, commit: str = "HEAD") -> dict[str, str]:
        """Return the latest commit that changed code/policy outside this Task's derived metadata."""
        cursor = str(self._run("rev-parse", f"{commit}^{{commit}}", text=True)).strip()
        while True:
            ancestry = str(self._run("rev-list", "--parents", "-n", "1", cursor, text=True)).strip().split()
            if len(ancestry) < 2:
                return self.commit_subject(cursor)
            parent = ancestry[1]
            raw = self._as_bytes(self._run("diff", "--name-status", "-z", "--find-renames", parent, cursor))
            changes = self._parse_name_status(raw, refs=(parent, cursor))
            business = [
                change for change in changes
                if not is_task_governance_metadata(change.path, task_id)
                or bool(change.old_path and not is_task_governance_metadata(change.old_path, task_id))
            ]
            if business:
                return self.commit_subject(cursor)
            cursor = parent

    def workspace_subject(self, task_id: str | None = None) -> dict[str, str]:
        pathspecs: tuple[str, ...] = ()
        if task_id:
            pathspecs = (".", *(f":(exclude){pattern}" for pattern in task_governance_metadata_patterns(task_id)))
        path_args = ("--", *pathspecs) if pathspecs else ()
        index = self._as_bytes(self._run("ls-files", "--stage", "-z", *path_args))
        lfs = self._lfs_manifest()
        diff = self._as_bytes(self._run("diff", "--binary", *path_args)) + self._as_bytes(self._run("diff", "--cached", "--binary", *path_args))
        manifest: list[bytes] = []
        untracked = self._as_bytes(self._run("ls-files", "--others", "--exclude-standard", "-z"))
        for raw_path in untracked.split(b"\0"):
            if not raw_path:
                continue
            relative = normalize_repo_path(os.fsdecode(raw_path))
            if task_id and is_task_governance_metadata(relative, task_id):
                continue
            path = self.root / relative
            if path.is_symlink():
                manifest.append(relative.encode("utf-8") + b"\0" + b"120000" + b"\0" + os.readlink(path).encode("utf-8"))
            elif path.is_file():
                mode = oct(path.stat().st_mode & 0o777).encode()
                manifest.append(relative.encode("utf-8") + b"\0" + mode + b"\0" + hashlib.sha256(path.read_bytes()).digest())
        return {
            "type": "workspace", "head_commit": self.head, "index_digest": _digest([index, lfs]),
            "worktree_diff_digest": _digest([diff]), "untracked_manifest_digest": _digest(sorted(manifest)),
        }

    def _commit_index_digest(self, commit: str, task_id: str | None = None) -> str:
        # `git ls-tree` does not consistently support exclusion pathspecs on all
        # Git versions.  Read the immutable tree and apply the same narrow Task
        # metadata filter used for workspace subjects in process.
        tree = self._as_bytes(self._run("ls-tree", "-r", "-z", "--full-tree", commit))
        index_rows: list[bytes] = []
        for row in tree.split(b"\0"):
            if not row:
                continue
            metadata, path = row.split(b"\t", 1)
            normalized = normalize_repo_path(os.fsdecode(path))
            if task_id and is_task_governance_metadata(normalized, task_id):
                continue
            mode, _kind, object_id = metadata.split(b" ", 2)
            index_rows.append(mode + b" " + object_id + b" 0\t" + path + b"\0")
        return _digest([b"".join(index_rows), self._lfs_manifest()])

    def review_diff_digest(self, base: str | None, *, head: str = "HEAD", task_id: str | None = None) -> str:
        pathspecs: tuple[str, ...] = ()
        if task_id:
            pathspecs = (".", *(f":(exclude){pattern}" for pattern in task_governance_metadata_patterns(task_id)))
        path_args = ("--", *pathspecs) if pathspecs else ()
        committed = self._as_bytes(self._run("diff", "--binary", base, head, *path_args)) if base else b""
        current = self._as_bytes(self._run("diff", "--binary", *path_args)) + self._as_bytes(self._run("diff", "--cached", "--binary", *path_args))
        return _digest([committed, current])

    def workspace_equivalent_to_commit(
        self, commit: str = "HEAD", *, task_id: str | None = None,
        source_workspace_subject: dict[str, str] | None = None,
    ) -> bool:
        target = self.commit_subject(commit)
        if self.head != target["commit_sha"] or self.workspace_changes(task_id=task_id):
            return False
        if source_workspace_subject is None:
            return True
        if source_workspace_subject.get("type") != "workspace":
            return False
        return (
            source_workspace_subject.get("index_digest") == self._commit_index_digest(commit, task_id)
            and source_workspace_subject.get("untracked_manifest_digest") == _digest([])
        )

    def _lfs_manifest(self) -> bytes:
        manifest: list[bytes] = []
        git_dir = Path(str(self._run("rev-parse", "--git-common-dir", text=True)).strip())
        if not git_dir.is_absolute():
            git_dir = (self.root / git_dir).resolve()
        tracked = self._as_bytes(self._run("ls-files", "-z"))
        for raw in tracked.split(b"\0"):
            if not raw:
                continue
            relative = normalize_repo_path(os.fsdecode(raw)); path = self.root / relative
            if not path.is_file() or path.is_symlink():
                continue
            try:
                with path.open("rb") as handle:
                    prefix = handle.read(256)
            except OSError:
                continue
            if not prefix.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
                continue
            oid = next((line[11:].decode("ascii") for line in prefix.splitlines() if line.startswith(b"oid sha256:")), "")
            if len(oid) != 64:
                raise MacError("GIT_LFS_POINTER_INVALID", f"invalid LFS pointer: {relative}", exit_code=ExitCode.CORRUPTION, path=relative)
            object_path = git_dir / "lfs" / "objects" / oid[:2] / oid[2:4] / oid
            if not object_path.is_file():
                raise MacError("GIT_LFS_OBJECT_MISSING", f"LFS object is unavailable for {relative}", exit_code=ExitCode.CORRUPTION, path=relative)
            manifest.append(relative.encode("utf-8") + b"\0" + oid.encode("ascii") + b"\0" + hashlib.sha256(object_path.read_bytes()).digest())
        return b"".join(sorted(manifest))
