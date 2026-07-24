from __future__ import annotations

import json
from pathlib import Path
import shutil
from typing import Any

from jsonschema import Draft202012Validator
import pytest
import yaml

import mac.repository as repository_module
import mac.schema_validation as schema_validation_module
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


def test_legacy_only_validation_skips_repository_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    init_validation_repo(
        tmp_path,
        [{"id": "TASK-0001-metadata", "title": "metadata", "status": "complete"}],
    )

    def unexpected_identity(repo: Path) -> str:
        pytest.fail(f"legacy-only validation computed repository identity for {repo}")

    monkeypatch.setattr(repository_module, "_repository_identity", unexpected_identity)

    issues = validate_repository(tmp_path, AcceptAllSchemas())  # type: ignore[arg-type]

    assert any(issue.code == "LEGACY_TASK_UNVERIFIABLE" for issue in issues)


def test_custom_schema_adapter_cannot_bypass_event_schema_validation(tmp_path: Path) -> None:
    init_validation_repo(tmp_path, [])
    task_id = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    task_dir = tmp_path / "tasks" / task_id
    events_dir = task_dir / "events"
    events_dir.mkdir(parents=True)
    (task_dir / "task.yaml").write_text("{}\n", encoding="utf-8")
    (task_dir / "scope-contract.yaml").write_text("{}\n", encoding="utf-8")
    event_id = "EVT-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    (events_dir / f"{event_id}.json").write_text(
        json.dumps({"event_id": event_id, "task_id": task_id}),
        encoding="utf-8",
    )

    issues = validate_repository(tmp_path, AcceptAllSchemas())  # type: ignore[arg-type]

    assert any(issue.code == "EVENT_SCHEMA_INVALID" for issue in issues)


def test_repository_validation_checks_each_event_schema_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    init_validation_repo(tmp_path, [])
    task_id = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    task_dir = tmp_path / "tasks" / task_id
    events_dir = task_dir / "events"
    events_dir.mkdir(parents=True)
    (task_dir / "task.yaml").write_text("{}\n", encoding="utf-8")
    (task_dir / "scope-contract.yaml").write_text("{}\n", encoding="utf-8")
    event_id = "EVT-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    (events_dir / f"{event_id}.json").write_text(
        json.dumps({"event_id": event_id, "task_id": task_id}),
        encoding="utf-8",
    )
    schemas = SchemaSet(DESIGN_SCHEMAS)
    original = schemas.validate
    event_schema_checks = 0

    def count_event_schema_checks(
        data: dict[str, Any], schema_name: str, *, path: str,
    ) -> list[Any]:
        nonlocal event_schema_checks
        if schema_name == "event.schema.json":
            event_schema_checks += 1
        return original(data, schema_name, path=path)

    monkeypatch.setattr(schemas, "validate", count_event_schema_checks)

    issues = validate_repository(tmp_path, schemas)

    assert event_schema_checks == 1
    assert any(issue.code == "EVENT_SCHEMA_INVALID" for issue in issues)


def test_repository_validation_reuses_context_and_parses_task_files_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    init_command(repo=tmp_path, project="validation-context", json_output=True)
    for index in range(2):
        task_dir = tmp_path / "tasks" / f"TASK-{index:010d}"
        task_dir.mkdir()
        for name in ("task.yaml", "scope-contract.yaml"):
            (task_dir / name).write_text("{}\n", encoding="utf-8")
        runs_dir = task_dir / "runs"
        runs_dir.mkdir()
        (runs_dir / f"RUN-{index:010d}.json").write_text("{}\n", encoding="utf-8")
    schemas = SchemaSet(DESIGN_SCHEMAS)
    original = schema_validation_module.load_data
    parsed: list[Path] = []

    def load_once(path: Path) -> dict[str, Any]:
        if path.parent.name.startswith("TASK-") or path.parent.parent.name.startswith("TASK-"):
            parsed.append(path)
        return original(path)

    monkeypatch.setattr(schema_validation_module, "load_data", load_once)
    monkeypatch.setattr(repository_module, "load_data", load_once)
    identities = 0

    def identity(repo: Path) -> str:
        nonlocal identities
        identities += 1
        return "repo:test"

    monkeypatch.setattr(repository_module, "_repository_identity", identity)

    validate_repository(tmp_path, schemas)

    assert identities == 1
    assert [path.name for path in parsed] == [
        "task.yaml", "scope-contract.yaml", "RUN-0000000000.json",
        "task.yaml", "scope-contract.yaml", "RUN-0000000001.json",
    ]


def test_schema_lock_detects_executable_schema_drift(tmp_path: Path) -> None:
    init_command(repo=tmp_path, project="schema-lock", json_output=True)
    assert schema_lock_issues(tmp_path) == []
    schema = tmp_path / "schemas/task.schema.json"
    schema.write_text(schema.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    issues = schema_lock_issues(tmp_path)

    assert {issue.code for issue in issues} == {"SCHEMA_LOCK_MISMATCH"}


def test_schema_lock_digest_is_stable_across_git_line_ending_checkout(tmp_path: Path) -> None:
    init_command(repo=tmp_path, project="schema-lock-crlf", json_output=True)
    schema = tmp_path / "schemas/task.schema.json"
    canonical = schema.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    schema.write_bytes(canonical.replace(b"\n", b"\r\n"))

    assert schema_lock_issues(tmp_path) == []


def test_explicit_schema_set_fails_closed_on_semantic_lock_drift(tmp_path: Path) -> None:
    schemas = tmp_path / "schemas"
    shutil.copytree(DESIGN_SCHEMAS, schemas)
    agents = tmp_path / ".agents"
    agents.mkdir()
    shutil.copy2(DESIGN_SCHEMAS.parent / ".agents/schemas.lock.json", agents / "schemas.lock.json")
    schema = schemas / "task.schema.json"
    canonical = schema.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    schema.write_bytes(canonical.replace(b"\n", b"\r\n"))
    first = SchemaSet(schemas)
    second = SchemaSet(schemas)
    assert second.validators is first.validators
    schema.write_text(schema.read_text(encoding="utf-8") + " ", encoding="utf-8", newline="\n")

    with pytest.raises(ValueError, match="schema lock mismatch"):
        SchemaSet(schemas)


def test_schema_lock_rejects_schema_directory_symlink_outside_repository(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    agents = repo / ".agents"
    agents.mkdir(parents=True)
    shutil.copy2(DESIGN_SCHEMAS.parent / ".agents/schemas.lock.json", agents / "schemas.lock.json")
    outside = tmp_path / "outside-schemas"
    shutil.copytree(DESIGN_SCHEMAS, outside)
    try:
        (repo / "schemas").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    issues = schema_lock_issues(repo)

    assert {issue.code for issue in issues} == {"SCHEMA_PATH_UNSAFE_LINK"}


def test_schema_lock_rejects_schema_file_symlink_even_when_content_matches(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    schemas = repo / "schemas"
    shutil.copytree(DESIGN_SCHEMAS, schemas)
    agents = repo / ".agents"
    agents.mkdir()
    shutil.copy2(DESIGN_SCHEMAS.parent / ".agents/schemas.lock.json", agents / "schemas.lock.json")
    target = schemas / "task.schema.json"
    outside = tmp_path / "task.schema.json"
    shutil.copy2(target, outside)
    target.unlink()
    try:
        target.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")

    issues = schema_lock_issues(repo)

    assert {issue.code for issue in issues} == {"SCHEMA_PATH_UNSAFE_LINK"}
