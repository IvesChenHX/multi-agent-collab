from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from mac.git import GitRepository
from mac.scope import Change, ScopeCheckResult, check_changes


class ScopeService:
    def check(self, repo: Path, contract: dict[str, Any], ownership: dict[str, Any], *, base: str | None = None, head: str = "HEAD") -> ScopeCheckResult:
        git = GitRepository(repo)
        changes = git.diff_changes(base, head) if base else git.workspace_changes()
        return check_changes(changes, contract, ownership=ownership, repo_root=repo)
