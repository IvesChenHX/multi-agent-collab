from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import IntEnum
from typing import Any, NoReturn


class ExitCode(IntEnum):
    SUCCESS = 0
    CLI_USAGE = 2
    VALIDATION = 3
    TRANSITION = 4
    CONFLICT = 5
    SCOPE = 6
    EVIDENCE = 7
    RUNTIME = 8
    SECURITY = 9
    EXTERNAL = 10
    CORRUPTION = 11
    INTERNAL = 20


@dataclass(frozen=True, slots=True)
class MacIssue:
    code: str
    message: str
    path: str | None = None
    field: str | None = None
    severity: str = "error"
    suggestion: str | None = None
    task_id: str | None = None
    details: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}


class MacError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        exit_code: int | ExitCode = ExitCode.INTERNAL,
        path: str | None = None,
        field: str | None = None,
        task_id: str | None = None,
        suggestion: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.issue = MacIssue(code, message, path, field, "error", suggestion, task_id, details)
        self.exit_code = int(exit_code)

    @property
    def code(self) -> str:
        return self.issue.code

    def as_dict(self) -> dict[str, Any]:
        return {"ok": False, "error": self.issue.as_dict()}


def fail(code: str, message: str, *, exit_code: int | ExitCode, **context: Any) -> NoReturn:
    raise MacError(code, message, exit_code=exit_code, **context)
