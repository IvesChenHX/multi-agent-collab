from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Iterable

from .errors import ExitCode, MacError
from .scope import Change, is_task_governance_metadata, normalize_repo_path, task_governance_metadata_patterns


_LFS_POINTER_LIMIT = 1024
_LFS_POINTER = re.compile(
    rb"\Aversion https://git-lfs.github.com/spec/v1\n"
    rb"oid sha256:([0-9a-f]{64})\n"
    rb"size ([0-9]+)\n?\Z"
)
_SUPPORTED_INDEX_MODES = {b"100644", b"100755", b"120000", b"160000"}


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

    def _run(self, *argv: str, text: bool = False, input_data: bytes | None = None) -> bytes | str:
        try:
            result = subprocess.run(
                ["git", "-C", str(self.root), *argv],
                check=True,
                capture_output=True,
                text=text,
                input=input_data,
            )
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            raise MacError("GIT_COMMAND_FAILED", f"git {' '.join(argv)} failed", exit_code=ExitCode.EXTERNAL) from exc
        return result.stdout

    def _git_common_dir(self) -> Path:
        git_dir = Path(str(self._run("rev-parse", "--git-common-dir", text=True)).strip())
        return git_dir if git_dir.is_absolute() else (self.root / git_dir).resolve()

    @staticmethod
    def _canonical_storage_path(path: Path) -> str:
        """Return a comparison key that is stable for Windows paths and symlinks."""
        return os.path.normcase(os.path.realpath(path.resolve()))

    def storage_identity(self) -> dict[str, str]:
        """Identify the shared Git storage behind this working tree.

        Linked worktrees have different per-worktree git dirs, but must resolve
        to the same common dir and object directory.  Callers must compare both:
        an unrelated clone can contain byte-identical commits without belonging
        to the Task repository.
        """
        common_dir = self._git_common_dir()
        object_dir = Path(str(self._run("rev-parse", "--git-path", "objects", text=True)).strip())
        if not object_dir.is_absolute():
            object_dir = (self.root / object_dir).resolve()
        return {
            "common_dir": self._canonical_storage_path(common_dir),
            "object_dir": self._canonical_storage_path(object_dir),
        }

    def shares_storage_with(self, other: "GitRepository") -> bool:
        """Return true only for worktrees backed by the same Git repository."""
        return self.storage_identity() == other.storage_identity()

    def commit_is_ancestor(self, ancestor: str, descendant: str) -> bool:
        result = subprocess.run(
            ["git", "-C", str(self.root), "merge-base", "--is-ancestor", ancestor, descendant],
            shell=False,
            capture_output=True,
        )
        if result.returncode == 0:
            return True
        if result.returncode == 1:
            return False
        raise MacError(
            "GIT_COMMAND_FAILED",
            "git merge-base --is-ancestor failed",
            exit_code=ExitCode.EXTERNAL,
        )

    def run_worktree_binding_checks(
        self,
        run_repository: "GitRepository",
        *,
        approved_base: str,
        baseline_subject: dict[str, str],
    ) -> dict[str, bool]:
        """Verify a run worktree before its baseline is trusted or frozen.

        This is the public seam for `run register` and Result intake.  The Task
        repository is `self`; the run repository may be its main worktree or a
        linked worktree, but never an independent clone.  The frozen baseline
        must resolve identically through both worktrees and descend from the
        approved Scope base.
        """
        task_storage = self.storage_identity()
        run_storage = run_repository.storage_identity()
        checks = {
            "same_common_dir": task_storage["common_dir"] == run_storage["common_dir"],
            "same_object_dir": task_storage["object_dir"] == run_storage["object_dir"],
            "approved_base_resolved": False,
            "baseline_subject_bound": False,
            "baseline_descends_from_approved_base": False,
        }
        try:
            task_base = self.commit_subject(approved_base)
            task_baseline = self.commit_subject(str(baseline_subject.get("commit_sha", "")))
            run_baseline = run_repository.commit_subject(str(baseline_subject.get("commit_sha", "")))
            checks["approved_base_resolved"] = task_base["commit_sha"] == approved_base
            checks["baseline_subject_bound"] = (
                baseline_subject == task_baseline == run_baseline
            )
            checks["baseline_descends_from_approved_base"] = self.commit_is_ancestor(
                task_base["commit_sha"], task_baseline["commit_sha"]
            )
        except (MacError, KeyError, TypeError, ValueError):
            pass
        return checks

    def portable_run_binding_checks(
        self,
        *,
        approved_base: str,
        baseline_subject: dict[str, str],
        source_ref: str | None = None,
        source_ref_subject: dict[str, str] | None = None,
    ) -> dict[str, bool | str]:
        """Verify immutable Run Git facts without binding a host worktree path.

        Portable Run Events identify a repository through their verified
        mutation authority.  Historical validation therefore needs only the
        frozen commit/tree pair and its ancestry from the approved Scope base;
        it must not depend on the machine or worktree where the Event was
        created.
        """

        checks = {
            "approved_base_resolved": False,
            "baseline_subject_bound": False,
            "baseline_descends_from_approved_base": False,
        }
        try:
            approved = self.commit_subject(approved_base)
            baseline = self.commit_subject(
                str(baseline_subject.get("commit_sha", ""))
            )
            checks["approved_base_resolved"] = (
                approved["commit_sha"] == approved_base
            )
            checks["baseline_subject_bound"] = baseline_subject == baseline
            checks["baseline_descends_from_approved_base"] = (
                self.commit_is_ancestor(
                    approved["commit_sha"],
                    baseline["commit_sha"],
                )
            )
            if source_ref is not None or source_ref_subject is not None:
                checks["source_ref_resolved"] = False
                checks["baseline_reachable_from_source_ref"] = False
                if source_ref is not None:
                    self._run("check-ref-format", source_ref)
                    source = self.commit_subject(source_ref)
                else:
                    source = self.commit_subject(
                        str((source_ref_subject or {}).get("commit_sha", ""))
                    )
                    if source != source_ref_subject:
                        return checks
                checks["source_ref_commit_sha"] = source["commit_sha"]
                checks["source_ref_tree_sha"] = source["tree_sha"]
                checks["source_ref_resolved"] = True
                checks["baseline_reachable_from_source_ref"] = (
                    self.commit_is_ancestor(
                        baseline["commit_sha"],
                        source["commit_sha"],
                    )
                )
        except (MacError, KeyError, TypeError, ValueError):
            pass
        return checks

    def _inside_nested_repository(self, relative: str) -> bool:
        candidate = self.root / relative
        for parent in (candidate, *candidate.parents):
            if parent == self.root:
                return False
            if (parent / ".git").exists():
                return True
        return False

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
        untracked = []
        for value in untracked_raw.split(b"\0"):
            if not value:
                continue
            display = os.fsdecode(value)
            path = normalize_repo_path(display)
            untracked.append(
                Change("add", path, submodule=self._inside_nested_repository(path), display_path=display)
            )
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

    def changes_since(
        self,
        base: str | None,
        *,
        head: str = "HEAD",
        task_id: str | None = None,
        include_workspace: bool = True,
    ) -> list[Change]:
        committed = self.diff_changes(base, head) if base else []
        current = self.workspace_changes(task_id=task_id) if include_workspace else []
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
        self._lfs_manifest(commit)
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
        index_entries = self._index_entries(index)
        lfs = self._lfs_manifest_from_entries(index_entries)
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
            manifest.append(self._untracked_manifest_entry(relative, path))
        return {
            "type": "workspace", "head_commit": self.head, "index_digest": _digest([index, lfs]),
            "worktree_diff_digest": _digest([diff]), "untracked_manifest_digest": _digest(sorted(manifest)),
        }

    def _commit_index_digest(self, commit: str, task_id: str | None = None) -> str:
        # `git ls-tree` does not consistently support exclusion pathspecs on all
        # Git versions.  Read the immutable tree and apply the same narrow Task
        # metadata filter used for workspace subjects in process.
        entries = self._tree_entries(commit)
        index_rows: list[bytes] = []
        filtered_entries: list[tuple[bytes, bytes, bytes]] = []
        for mode, object_id, path in entries:
            normalized = normalize_repo_path(os.fsdecode(path))
            if task_id and is_task_governance_metadata(normalized, task_id):
                continue
            index_rows.append(mode + b" " + object_id + b" 0\t" + path + b"\0")
            filtered_entries.append((mode, object_id, path))
        return _digest([b"".join(index_rows), self._lfs_manifest_from_entries(filtered_entries)])

    def review_diff_digest(
        self,
        base: str | None,
        *,
        head: str = "HEAD",
        task_id: str | None = None,
        include_workspace: bool = True,
    ) -> str:
        pathspecs: tuple[str, ...] = ()
        if task_id:
            pathspecs = (".", *(f":(exclude){pattern}" for pattern in task_governance_metadata_patterns(task_id)))
        path_args = ("--", *pathspecs) if pathspecs else ()
        committed = self._as_bytes(self._run("diff", "--binary", base, head, *path_args)) if base else b""
        current = (
            self._as_bytes(self._run("diff", "--binary", *path_args))
            + self._as_bytes(self._run("diff", "--cached", "--binary", *path_args))
            if include_workspace
            else b""
        )
        return _digest([committed, current])

    def _expected_source_diff_digest(
        self, source_head: str, target_commit: str, task_id: str | None,
    ) -> str:
        pathspecs: tuple[str, ...] = ()
        if task_id:
            pathspecs = (
                ".",
                *(f":(exclude){pattern}" for pattern in task_governance_metadata_patterns(task_id)),
            )
        path_args = ("--", *pathspecs) if pathspecs else ()
        diff = self._as_bytes(self._run("diff", "--binary", source_head, target_commit, *path_args))
        return _digest([diff])

    def workspace_equivalence_proof(
        self, source_workspace_subject: dict[str, str], commit: str = "HEAD", *,
        task_id: str | None = None,
    ) -> "WorkspaceEquivalenceProof":
        """Build a fail-closed proof binding source Evidence, observation, and commit.

        The source workspace is promotable only when its staged effective tree
        and recorded diff exactly reconstruct the target commit.  The currently
        observed workspace must independently be a clean materialization of the
        same commit.  Git modes bind symlinks/gitlinks, untracked manifests bind
        special paths, and the index/commit digest routines verify LFS payloads.
        """
        from .evidence import WorkspaceEquivalenceProof

        source = dict(source_workspace_subject)
        observed = self.workspace_subject(task_id=task_id)
        target_commit_sha = str(self._run("rev-parse", f"{commit}^{{commit}}", text=True)).strip()
        target = {
            "type": "commit",
            "commit_sha": target_commit_sha,
            "tree_sha": str(self._run("rev-parse", f"{target_commit_sha}^{{tree}}", text=True)).strip(),
        }
        target_index_digest = self._commit_index_digest(target_commit_sha, task_id)
        empty_untracked_digest = _digest([])
        clean_diff_digest = _digest([b""])
        required_source_fields = {
            "type", "head_commit", "index_digest", "worktree_diff_digest", "untracked_manifest_digest",
        }
        source_bound = (
            set(source) == required_source_fields
            and source.get("type") == "workspace"
            and all(isinstance(source.get(name), str) and source.get(name) for name in required_source_fields)
        )
        expected_source_diff: str | None = None
        if source_bound:
            try:
                source_head = str(self._run(
                    "rev-parse", f"{source['head_commit']}^{{commit}}", text=True,
                )).strip()
                source_bound = source_head == source["head_commit"]
                if source_bound:
                    expected_source_diff = self._expected_source_diff_digest(
                        source_head, target["commit_sha"], task_id,
                    )
            except MacError:
                source_bound = False
        source_index_matches = source_bound and source.get("index_digest") == target_index_digest
        observed_index_matches = observed.get("index_digest") == target_index_digest
        untracked_empty = (
            source_bound
            and source.get("untracked_manifest_digest") == empty_untracked_digest
            and observed.get("untracked_manifest_digest") == empty_untracked_digest
        )
        source_tree_matches = (
            source_index_matches
            and expected_source_diff is not None
            and source.get("worktree_diff_digest") == expected_source_diff
        )
        observed_tree_matches = (
            observed.get("head_commit") == target["commit_sha"]
            and observed_index_matches
            and observed.get("worktree_diff_digest") == clean_diff_digest
        )
        effective_tree_matches = bool(source_tree_matches and observed_tree_matches and untracked_empty)
        index_matches = bool(source_index_matches and observed_index_matches)
        checks = {
            "source_subject_bound": bool(source_bound),
            "target_commit_resolved": bool(target.get("commit_sha") and target.get("tree_sha")),
            "effective_tree_matches": effective_tree_matches,
            "index_matches": index_matches,
            "untracked_empty": bool(untracked_empty),
            "special_paths_match": bool(effective_tree_matches and index_matches),
            "lfs_verified": bool(index_matches),
        }
        return WorkspaceEquivalenceProof.verified(
            source_workspace_subject=source,
            observed_workspace_subject=observed,
            target_commit_subject=target,
            checks=checks,
            verifier="mac.git.GitRepository/v1",
        )

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

    def _tree_entries(self, ref: str) -> list[tuple[bytes, bytes, bytes]]:
        raw = self._as_bytes(self._run("ls-tree", "-r", "-z", "--full-tree", ref))
        entries: list[tuple[bytes, bytes, bytes]] = []
        for row in raw.split(b"\0"):
            if not row:
                continue
            metadata, path = row.split(b"\t", 1)
            mode, _kind, object_id = metadata.split(b" ", 2)
            self._validate_index_mode(mode, os.fsdecode(path))
            entries.append((mode, object_id, path))
        return entries

    def _index_entries(self, raw: bytes) -> list[tuple[bytes, bytes, bytes]]:
        entries: list[tuple[bytes, bytes, bytes]] = []
        for row in raw.split(b"\0"):
            if not row:
                continue
            metadata, path = row.split(b"\t", 1)
            mode, object_id, stage = metadata.split(b" ", 2)
            relative = normalize_repo_path(os.fsdecode(path))
            self._validate_index_mode(mode, relative)
            if stage != b"0":
                raise MacError(
                    "GIT_INDEX_UNMERGED", f"unmerged index entry: {relative}", exit_code=ExitCode.CORRUPTION, path=relative,
                )
            entries.append((mode, object_id, path))
        return entries

    @staticmethod
    def _validate_index_mode(mode: bytes, path: str) -> None:
        if mode not in _SUPPORTED_INDEX_MODES:
            raise MacError(
                "GIT_SPECIAL_MODE_UNSUPPORTED",
                f"unsupported Git index mode {mode.decode('ascii', 'replace')}: {path}",
                exit_code=ExitCode.SECURITY,
                path=path,
            )

    def _untracked_manifest_entry(self, relative: str, path: Path) -> bytes:
        is_junction = getattr(os.path, "isjunction", None)
        if is_junction is not None and is_junction(path):
            raise MacError(
                "GIT_SPECIAL_PATH_UNSUPPORTED", f"untracked junction is unsupported: {relative}",
                exit_code=ExitCode.SECURITY, path=relative,
            )
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise MacError(
                "GIT_PATH_CHANGED_DURING_SCAN", f"cannot inspect untracked path: {relative}",
                exit_code=ExitCode.CORRUPTION, path=relative,
            ) from exc
        prefix = relative.encode("utf-8") + b"\0"
        if stat.S_ISLNK(metadata.st_mode):
            return prefix + b"120000\0" + os.fsencode(os.readlink(path))
        if stat.S_ISREG(metadata.st_mode):
            mode = oct(metadata.st_mode & 0o777).encode()
            digest = self._read_stable_untracked_file(relative, path, metadata)
            return prefix + mode + b"\0" + digest
        raise MacError(
            "GIT_SPECIAL_PATH_UNSUPPORTED", f"unsupported untracked path type: {relative}",
            exit_code=ExitCode.SECURITY, path=relative,
        )

    @staticmethod
    def _path_identity(metadata: os.stat_result) -> tuple[int, int] | None:
        device = int(getattr(metadata, "st_dev", 0))
        inode = int(getattr(metadata, "st_ino", 0))
        return (device, inode) if inode else None

    @staticmethod
    def _content_identity(metadata: os.stat_result) -> tuple[int, int | None, int | None, int]:
        return (
            int(metadata.st_size),
            getattr(metadata, "st_mtime_ns", None),
            getattr(metadata, "st_ctime_ns", None),
            stat.S_IMODE(metadata.st_mode),
        )

    def _read_stable_untracked_file(
        self, relative: str, path: Path, expected: os.stat_result,
    ) -> bytes:
        expected_identity = self._path_identity(expected)
        if expected_identity is None:
            raise MacError(
                "GIT_PATH_IDENTITY_UNAVAILABLE",
                f"cannot establish identity for untracked path: {relative}",
                exit_code=ExitCode.SECURITY,
                path=relative,
            )
        flags = os.O_RDONLY
        for name in ("O_BINARY", "O_CLOEXEC", "O_NOINHERIT", "O_NOFOLLOW"):
            flags |= int(getattr(os, name, 0))
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise MacError(
                "GIT_PATH_CHANGED_DURING_SCAN", f"cannot open untracked path safely: {relative}",
                exit_code=ExitCode.CORRUPTION, path=relative,
            ) from exc
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or self._path_identity(opened) != expected_identity:
                raise MacError(
                    "GIT_PATH_CHANGED_DURING_SCAN", f"untracked path changed before read: {relative}",
                    exit_code=ExitCode.CORRUPTION, path=relative,
                )
            expected_content = self._content_identity(expected)
            opened_content = self._content_identity(opened)
            if opened_content != expected_content:
                raise MacError(
                    "GIT_PATH_CHANGED_DURING_SCAN", f"untracked path metadata changed before read: {relative}",
                    exit_code=ExitCode.CORRUPTION, path=relative,
                )
            hasher = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
            finished = os.fstat(descriptor)
        except OSError as exc:
            raise MacError(
                "GIT_PATH_CHANGED_DURING_SCAN", f"cannot read untracked path safely: {relative}",
                exit_code=ExitCode.CORRUPTION, path=relative,
            ) from exc
        finally:
            os.close(descriptor)
        try:
            observed = path.lstat()
        except OSError as exc:
            raise MacError(
                "GIT_PATH_CHANGED_DURING_SCAN", f"untracked path changed after read: {relative}",
                exit_code=ExitCode.CORRUPTION, path=relative,
            ) from exc
        finished_content = self._content_identity(finished)
        observed_content = self._content_identity(observed)
        if (
            not stat.S_ISREG(observed.st_mode)
            or self._path_identity(finished) != expected_identity
            or self._path_identity(observed) != expected_identity
            or opened_content != finished_content
            or finished_content != observed_content
        ):
            raise MacError(
                "GIT_PATH_CHANGED_DURING_SCAN", f"untracked path changed during read: {relative}",
                exit_code=ExitCode.CORRUPTION, path=relative,
            )
        return hasher.digest()

    def _lfs_manifest(self, ref: str = "HEAD") -> bytes:
        return self._lfs_manifest_from_entries(self._tree_entries(ref))

    def _batch_object_metadata(self, object_ids: list[bytes]) -> dict[bytes, tuple[bytes, int]]:
        if not object_ids:
            return {}
        output = self._as_bytes(self._run(
            "cat-file",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
            input_data=b"\n".join(object_ids) + b"\n",
        ))
        result: dict[bytes, tuple[bytes, int]] = {}
        lines = output.splitlines()
        if len(lines) != len(object_ids):
            raise MacError("GIT_OBJECT_INVALID", "Git object metadata response is incomplete", exit_code=ExitCode.CORRUPTION)
        for requested, line in zip(object_ids, lines):
            parts = line.split()
            if len(parts) != 3:
                raise MacError(
                    "GIT_OBJECT_INVALID", f"Git object is unavailable: {requested.decode('ascii', 'replace')}",
                    exit_code=ExitCode.CORRUPTION,
                )
            _resolved, object_type, raw_size = parts
            try:
                size = int(raw_size)
            except ValueError as exc:
                raise MacError("GIT_OBJECT_INVALID", "invalid Git object size", exit_code=ExitCode.CORRUPTION) from exc
            result[requested] = (object_type, size)
        return result

    def _batch_blob_contents(self, object_ids: list[bytes]) -> dict[bytes, bytes]:
        if not object_ids:
            return {}
        output = self._as_bytes(self._run(
            "cat-file", "--batch", input_data=b"\n".join(object_ids) + b"\n",
        ))
        result: dict[bytes, bytes] = {}
        cursor = 0
        for requested in object_ids:
            header_end = output.find(b"\n", cursor)
            if header_end < 0:
                raise MacError("GIT_OBJECT_INVALID", "Git batch response is truncated", exit_code=ExitCode.CORRUPTION)
            header = output[cursor:header_end].split()
            if len(header) != 3 or header[1] != b"blob":
                raise MacError(
                    "GIT_OBJECT_INVALID", f"Git object is not a blob: {requested.decode('ascii', 'replace')}",
                    exit_code=ExitCode.CORRUPTION,
                )
            try:
                size = int(header[2])
            except ValueError as exc:
                raise MacError("GIT_OBJECT_INVALID", "invalid Git blob size", exit_code=ExitCode.CORRUPTION) from exc
            start = header_end + 1
            end = start + size
            if end >= len(output) or output[end:end + 1] != b"\n":
                raise MacError("GIT_OBJECT_INVALID", "Git blob response is truncated", exit_code=ExitCode.CORRUPTION)
            result[requested] = output[start:end]
            cursor = end + 1
        if cursor != len(output):
            raise MacError("GIT_OBJECT_INVALID", "Git batch response has trailing data", exit_code=ExitCode.CORRUPTION)
        return result

    def _lfs_manifest_from_entries(self, entries: Iterable[tuple[bytes, bytes, bytes]]) -> bytes:
        manifest: list[bytes] = []
        object_root: Path | None = None
        regular_entries = [
            (object_id, raw_path)
            for mode, object_id, raw_path in entries
            if mode in {b"100644", b"100755"}
        ]
        object_ids = list(dict.fromkeys(object_id for object_id, _path in regular_entries))
        metadata = self._batch_object_metadata(object_ids)
        for object_id, (_object_type, size) in metadata.items():
            if _object_type != b"blob":
                raise MacError(
                    "GIT_OBJECT_INVALID", f"regular index entry is not a blob: {object_id.decode('ascii', 'replace')}",
                    exit_code=ExitCode.CORRUPTION,
                )
        small_object_ids = [
            object_id for object_id in object_ids if metadata[object_id][1] <= _LFS_POINTER_LIMIT
        ]
        contents = self._batch_blob_contents(small_object_ids)
        for object_id, raw_path in regular_entries:
            content = contents.get(object_id)
            if content is None:
                continue
            relative = normalize_repo_path(os.fsdecode(raw_path))
            if not content.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
                continue
            match = _LFS_POINTER.fullmatch(content)
            if match is None:
                raise MacError("GIT_LFS_POINTER_INVALID", f"invalid LFS pointer: {relative}", exit_code=ExitCode.CORRUPTION, path=relative)
            oid = match.group(1).decode("ascii")
            expected_size = int(match.group(2))
            if object_root is None:
                object_root = self._git_common_dir() / "lfs" / "objects"
            object_path = object_root / oid[:2] / oid[2:4] / oid
            if object_path.is_symlink() or not object_path.is_file():
                raise MacError("GIT_LFS_OBJECT_MISSING", f"LFS object is unavailable for {relative}", exit_code=ExitCode.CORRUPTION, path=relative)
            hasher = hashlib.sha256()
            actual_size = 0
            with object_path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    actual_size += len(chunk)
                    hasher.update(chunk)
            if actual_size != expected_size or hasher.hexdigest() != oid:
                raise MacError(
                    "GIT_LFS_OBJECT_TAMPERED", f"LFS object does not match pointer: {relative}",
                    exit_code=ExitCode.CORRUPTION, path=relative,
                )
            manifest.append(relative.encode("utf-8") + b"\0" + oid.encode("ascii") + b"\0" + str(expected_size).encode())
        return b"".join(sorted(manifest))
