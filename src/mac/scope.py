from __future__ import annotations

import os
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from pathspec import PathSpec

from .errors import MacIssue
from .ownership import OwnershipResolver


@dataclass(frozen=True, slots=True)
class Change:
    operation: str
    path: str
    old_path: str | None = None
    submodule: bool = False
    display_path: str | None = None
    old_display_path: str | None = None


@dataclass(slots=True)
class ScopeCheckResult:
    issues: list[MacIssue]
    allowed: list[str]
    changes: list[Change]

    @property
    def ok(self) -> bool:
        return not any(issue.severity == "error" for issue in self.issues)


_TASK_METADATA_FILES = frozenset({"task.yaml", "scope-contract.yaml", "report.md"})
_TASK_METADATA_DIRECTORIES = frozenset({
    "approvals",
    "events",
    "evidence",
    "findings",
    "private",
    "results",
    "risk-acceptances",
    "runs",
    "scope-history",
    "work-units",
})


def task_governance_metadata_patterns(task_id: str) -> tuple[str, ...]:
    prefix = f"tasks/{task_id}"
    return (
        *(f"{prefix}/{name}" for name in sorted(_TASK_METADATA_FILES)),
        *(f"{prefix}/{name}/**" for name in sorted(_TASK_METADATA_DIRECTORIES)),
    )


def is_task_governance_metadata(path: str, task_id: str) -> bool:
    """Return whether *path* is machine-owned metadata for exactly *task_id*.

    The explicit allowlist prevents a business file placed below a task directory
    from bypassing Scope Guard merely because it shares the task prefix.
    """
    prefix = f"tasks/{task_id}/"
    if not path.startswith(prefix):
        return False
    relative = path[len(prefix):]
    if relative in _TASK_METADATA_FILES:
        return True
    first, separator, remainder = relative.partition("/")
    return bool(separator and remainder and first in _TASK_METADATA_DIRECTORIES)


def normalize_repo_path(path: str) -> str:
    if "\x00" in path:
        raise ValueError("NUL is not allowed in repository paths")
    candidate = path.replace("\\", "/")
    if candidate.startswith("/") or (len(candidate) >= 3 and candidate[0].isalpha() and candidate[1] == ":" and candidate[2] == "/"):
        raise ValueError(f"unsafe repository path: {path}")
    pure = PurePosixPath(candidate)
    if ".." in pure.parts:
        raise ValueError(f"unsafe repository path: {path}")
    normalized = pure.as_posix()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized in {"", "."}:
        raise ValueError("empty repository path")
    return unicodedata.normalize("NFC", normalized)


def validate_patterns(patterns: Iterable[str]) -> list[MacIssue]:
    issues: list[MacIssue] = []
    for raw in patterns:
        try:
            normalized = normalize_repo_path(raw)
            if raw.startswith("!") or normalized.startswith("!"):
                raise ValueError("negated patterns are unsafe in separated allow/deny lists")
            PathSpec.from_lines("gitwildmatch", [normalized])
        except (ValueError, TypeError) as exc:
            issues.append(MacIssue("SCOPE_PATTERN_UNSAFE", str(exc), str(raw)))
    return issues


def _is_within(root: Path, target: Path) -> bool:
    try:
        target.relative_to(root)
        return True
    except ValueError:
        return False


def _existing_path_collision_issues(root: Path, display_path: str) -> list[MacIssue]:
    """Compare every raw path segment with existing siblings.

    Checking only the current diff misses a new spelling that collides with a
    tracked path on case-insensitive or Unicode-normalizing filesystems.  The
    walk deliberately stays inside the repository and never follows an
    escaping symlink/junction while enumerating siblings.
    """
    issues: list[MacIssue] = []
    parent = root
    raw_parts = PurePosixPath(display_path.replace("\\", "/")).parts
    for index, segment in enumerate(raw_parts):
        try:
            resolved_parent = parent.resolve(strict=False)
        except OSError:
            break
        if not _is_within(root, resolved_parent) or not parent.is_dir():
            break
        try:
            sibling_names = [entry.name for entry in parent.iterdir()]
        except OSError:
            break
        normalized_segment = unicodedata.normalize("NFC", segment)
        for sibling in sibling_names:
            if sibling == segment:
                continue
            normalized_sibling = unicodedata.normalize("NFC", sibling)
            relative = "/".join((*raw_parts[:index], segment))
            if normalized_sibling == normalized_segment:
                issues.append(MacIssue(
                    "SCOPE_UNICODE_COLLISION",
                    f"existing path segment {sibling!r} normalizes to {segment!r}",
                    relative,
                ))
            elif normalized_sibling.casefold() == normalized_segment.casefold():
                issues.append(MacIssue(
                    "SCOPE_CASE_COLLISION",
                    f"existing path segment {sibling!r} collides with {segment!r}",
                    relative,
                ))
        parent = parent / segment
    return issues


def check_changes(
    changes: Iterable[Change], contract: dict[str, Any], *, ownership: dict[str, Any] | None = None,
    repo_root: Path | None = None, task_id: str | None = None,
    governance_approval_level: str | None = None, submodule_approved: bool = False,
    governance_sensitive_patterns: Iterable[str] | None = None,
) -> ScopeCheckResult:
    raw_changes = list(changes)
    issues = validate_patterns([*contract.get("allowed_paths", []), *contract.get("denied_paths", [])])
    if issues:
        return ScopeCheckResult(issues, [], raw_changes)
    allow_spec = PathSpec.from_lines("gitwildmatch", contract.get("allowed_paths", []))
    deny_spec = PathSpec.from_lines("gitwildmatch", contract.get("denied_paths", []))
    resolver = OwnershipResolver(ownership) if ownership else None
    contract_owners = set(str(value) for value in contract.get("owners", []))
    allowed: list[str] = []
    normalized_changes: list[Change] = []
    root = repo_root.resolve() if repo_root else None
    path_keys: dict[str, str] = {}
    unicode_keys: dict[str, str] = {}
    governance_patterns = list(governance_sensitive_patterns or ["AGENTS.md", ".agents/**", ".github/workflows/*governance*", "schemas/**"])
    governance_spec = PathSpec.from_lines("gitwildmatch", governance_patterns)
    for change in raw_changes:
        paths = [change.old_path, change.path] if change.old_path else [change.path]
        displays = [change.old_display_path or change.old_path, change.display_path or change.path] if change.old_path else [change.display_path or change.path]
        normalized: list[str] = []
        for raw, raw_display in zip(paths, displays):
            if raw is None:
                continue
            display_path = str(raw_display or raw).replace("\\", "/")
            try:
                path = normalize_repo_path(raw)
            except ValueError as exc:
                issues.append(MacIssue("SCOPE_PATH_UNSAFE", str(exc), raw))
                continue
            if task_id and is_task_governance_metadata(path, task_id):
                continue
            normalized.append(path)
            case_key = unicodedata.normalize("NFC", display_path).casefold()
            if previous := path_keys.get(case_key):
                if previous != display_path and unicodedata.normalize("NFC", previous) != unicodedata.normalize("NFC", display_path):
                    issues.append(MacIssue("SCOPE_CASE_COLLISION", f"{previous!r} collides with {display_path!r}", path))
            else:
                path_keys[case_key] = display_path
            unicode_key = unicodedata.normalize("NFC", display_path)
            if previous := unicode_keys.get(unicode_key):
                if previous != display_path:
                    issues.append(MacIssue("SCOPE_UNICODE_COLLISION", f"{previous!r} normalizes to {display_path!r}", path))
            else:
                unicode_keys[unicode_key] = display_path
            if root is not None:
                issues.extend(_existing_path_collision_issues(root, display_path))
                candidate = root / path
                if not _is_within(root, candidate.resolve(strict=False)):
                    issues.append(MacIssue("SCOPE_SYMLINK_ESCAPE", "symlink resolves outside repository", path))
                    continue
            if governance_spec.match_file(path) and governance_approval_level not in {"L2", "L3"}:
                issues.append(MacIssue("SCOPE_GOVERNANCE_SENSITIVE", "governance-sensitive paths require a dedicated approved task and independent review", path))
            if deny_spec.match_file(path):
                issues.append(MacIssue("SCOPE_PATH_DENIED", "path matches denied_paths", path, details={"operation": change.operation}))
            elif not allow_spec.match_file(path):
                issues.append(MacIssue("SCOPE_PATH_OUTSIDE", "path is outside allowed_paths", path, details={"operation": change.operation}))
            else:
                allowed.append(path)
            if change.submodule and not submodule_approved:
                issues.append(MacIssue("SCOPE_SUBMODULE_SENSITIVE", "submodule pointer changes require explicit sensitive approval", path))
            if resolver:
                match = resolver.resolve(path)
                issues.extend(match.issues)
                if match.status == "resolved" and contract_owners and not set(match.owners).issubset(contract_owners):
                    issues.append(MacIssue("SCOPE_OWNER_OUTSIDE", f"owner {match.owners[0]} is not approved by scope", path))
        if normalized:
            normalized_changes.append(Change(change.operation, normalized[-1], normalized[0] if change.old_path and len(normalized) > 1 else None, change.submodule, change.display_path, change.old_display_path))
        if change.operation == "rename" and len(normalized) == 2 and resolver:
            old_owner, new_owner = resolver.resolve(normalized[0]), resolver.resolve(normalized[1])
            if old_owner.status == new_owner.status == "resolved" and old_owner.owners != new_owner.owners:
                issues.append(MacIssue("SCOPE_RENAME_OWNER_CROSS", f"rename crosses owner boundary {old_owner.owners[0]} -> {new_owner.owners[0]}", normalized[1], details={"old_path": normalized[0]}))
    return ScopeCheckResult(issues, sorted(set(allowed)), normalized_changes)


def check_paths(changed_paths: list[str], contract: dict[str, Any], *, repo_root: Path | None = None) -> ScopeCheckResult:
    return check_changes([Change("modify", path) for path in changed_paths], contract, repo_root=repo_root)


def amend_scope(
    contract: dict[str, Any], *, add_paths: list[str], actor: str, approvers: list[str],
    added_risk_tags: list[str] | None = None, independent_approval: bool = False,
) -> dict[str, Any]:
    policy = contract.get("amendment_policy", {})
    amendment_count = max(0, int(contract.get("version", 1)) - 1)
    if amendment_count >= int(policy.get("max_amendments", 0)):
        raise ValueError("scope amendment budget exhausted")
    if len(add_paths) > int(policy.get("max_paths_per_amendment", 0)):
        raise ValueError("scope amendment path budget exceeded")
    pattern_issues = validate_patterns(add_paths)
    if pattern_issues:
        raise ValueError(pattern_issues[0].message)
    risk_tags = set(str(value) for value in contract.get("risk_tags", [])) | set(added_risk_tags or [])
    result = {**contract}
    result["id"] = contract["id"].split("-")[0] + "-" + contract["id"].split("-", 1)[1]
    result["version"] = int(contract["version"]) + 1
    result["status"] = "proposed"
    result["proposed_by"] = actor
    result["approved_by"] = []
    result["allowed_paths"] = list(dict.fromkeys([*contract.get("allowed_paths", []), *add_paths]))
    result["risk_tags"] = sorted(risk_tags)
    return result
