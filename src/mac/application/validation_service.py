from __future__ import annotations

from pathlib import Path

from mac.errors import MacIssue
from mac.repository import validate_repository
from mac.schema_validation import SchemaSet


class ValidationService:
    def __init__(self, schemas: SchemaSet | None = None) -> None:
        self.schemas = schemas or SchemaSet()

    def validate(self, repo: Path) -> list[MacIssue]:
        return validate_repository(repo, self.schemas)
