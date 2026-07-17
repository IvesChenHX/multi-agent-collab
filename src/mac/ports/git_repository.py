from __future__ import annotations

from typing import Any, Protocol

from mac.scope import Change


class GitRepositoryPort(Protocol):
    def workspace_changes(self) -> list[Change]: ...
    def workspace_subject(self) -> dict[str, str]: ...
    def commit_subject(self, commit: str = "HEAD") -> dict[str, str]: ...
