from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
import yaml

from mac.repository import validate_repository
from mac.cli import init_command
from mac.schema_validation import SCHEMA_NAMES, SchemaSet, schema_lock_issues


DESIGN_SCHEMAS = Path(__file__).parents[1] / "schemas"


class AcceptAllSchemas:
    def validate_file(self, path: Path, name: str, *, root: Path) -> list[Any]:
        return []


def init_validation_repo(root: Path, legacy_tasks: list[dict[str, str]]) -> None:
    (root / ".agents").mkdir()
    (root / ".agents/config.yaml").write_text("{}\n", encoding="utf-8")
    (root / ".agents/ownership.yaml").write_text("{}\n", encoding="utf-8")
    (root / "tasks").mkdir()
    (root / "tasks/index.yaml").write_text(yaml.safe_dump({"tasks": legacy_tasks}), encoding="utf-8")


def test_all_15_root_schemas_are_the_single_valid_2020_12_source() -> None:
    names = {path.name for path in DESIGN_SCHEMAS.glob("*.json")}
    assert names == SCHEMA_NAMES
    for path in DESIGN_SCHEMAS.glob("*.json"):
        Draft202012Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))

    loaded = SchemaSet(DESIGN_SCHEMAS)
    assert set(loaded.schemas) == names


def test_schema_errors_have_stable_code_and_precise_field() -> None:
    issues = SchemaSet(DESIGN_SCHEMAS).validate(
        {"schema_version": 6, "id": "not-an-id"},
        "task.schema.json",
        path="tasks/x/task.yaml",
    )

    assert issues
    assert {issue.code for issue in issues} == {"SCHEMA_INVALID"}
    assert any(issue.field == "id" for issue in issues)


def test_repository_validation_reports_v5_tasks_as_unverifiable_warnings(tmp_path: Path) -> None:
    init_validation_repo(
        tmp_path,
        [
            {"id": "TASK-0001-metadata", "title": "metadata", "status": "complete"},
            {"id": "TASK-0002-detail", "title": "detail", "status": "complete"},
        ],
    )
    detail_dir = tmp_path / "tasks/TASK-0002-detail"
    detail_dir.mkdir()
    (detail_dir / "task.md").write_text("# legacy detail\n", encoding="utf-8")

    issues = validate_repository(tmp_path, AcceptAllSchemas())  # type: ignore[arg-type]

    assert not [issue for issue in issues if issue.severity == "error"]
    legacy = {issue.task_id: issue for issue in issues if issue.code == "LEGACY_TASK_UNVERIFIABLE"}
    assert set(legacy) == {"TASK-0001-metadata", "TASK-0002-detail"}
    assert legacy["TASK-0001-metadata"].details == {
        "source_format": "v5",
        "legacy_integrity": "metadata_only",
        "verification_status": "unverifiable",
    }
    assert legacy["TASK-0002-detail"].details == {
        "source_format": "v5",
        "legacy_integrity": "partial",
        "verification_status": "unverifiable",
    }


def test_repository_validation_keeps_incomplete_v6_task_as_error(tmp_path: Path) -> None:
    init_validation_repo(
        tmp_path,
        [{"id": "TASK-0003-v6", "title": "v6", "status": "complete"}],
    )
    task_dir = tmp_path / "tasks/TASK-0003-v6"
    task_dir.mkdir()
    (task_dir / "task.yaml").write_text("{}\n", encoding="utf-8")

    issues = validate_repository(tmp_path, AcceptAllSchemas())  # type: ignore[arg-type]

    assert any(
        issue.code == "TASK_FILE_MISSING"
        and issue.path == "tasks/TASK-0003-v6/scope-contract.yaml"
        and issue.severity == "error"
        for issue in issues
    )
    assert not any(issue.code == "LEGACY_TASK_UNVERIFIABLE" for issue in issues)


def test_schema_lock_detects_executable_schema_drift(tmp_path: Path) -> None:
    init_command(repo=tmp_path, project="schema-lock", json_output=True)
    assert schema_lock_issues(tmp_path) == []
    schema = tmp_path / "schemas/task.schema.json"
    schema.write_text(schema.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    issues = schema_lock_issues(tmp_path)

    assert {issue.code for issue in issues} == {"SCHEMA_LOCK_MISMATCH"}
