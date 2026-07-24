from __future__ import annotations

from pathlib import Path

from mac.events import replay_entity_snapshots, replay_events
from mac.io import load_data
from mac.repository import validate_task_invariants
from mac.schema_validation import SchemaSet


REPO_ROOT = Path(__file__).parents[1]
EXAMPLE_ROOT = REPO_ROOT / "examples" / "v6"
TASK_DIR = EXAMPLE_ROOT / "tasks" / "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q-refund-auth"


def _entities(directory: str, suffix: str) -> dict[str, dict[str, object]]:
    return {
        str(item["id"]): item
        for path in sorted((TASK_DIR / directory).glob(f"*{suffix}"))
        if (item := load_data(path))
    }


def test_tracked_example_replays_structurally_but_is_not_full_integrity_evidence() -> None:
    task = load_data(TASK_DIR / "task.yaml")
    events = [load_data(path) for path in sorted((TASK_DIR / "events").glob("*.json"))]

    assert replay_events(events) == task
    snapshots = replay_entity_snapshots(events)
    assert snapshots["work-units"] == _entities("work-units", ".yaml")
    for directory in ("runs", "results", "evidence", "findings", "approvals"):
        assert snapshots[directory] == _entities(directory, ".json")
    assert snapshots["risk-acceptances"] == {}
    issues = validate_task_invariants(EXAMPLE_ROOT, TASK_DIR)
    assert [issue.code for issue in issues] == ["EVENT_AUTHORITY_MISSING"]


def test_tracked_example_entities_conform_to_the_executable_schemas() -> None:
    schemas = SchemaSet(REPO_ROOT / "schemas")
    checks = [
        (TASK_DIR / "task.yaml", "task.schema.json"),
        (TASK_DIR / "scope-contract.yaml", "scope-contract.schema.json"),
        *[(path, "event.schema.json") for path in sorted((TASK_DIR / "events").glob("*.json"))],
        *[(path, "work-unit.schema.json") for path in sorted((TASK_DIR / "work-units").glob("*.yaml"))],
        *[(path, "run.schema.json") for path in sorted((TASK_DIR / "runs").glob("*.json"))],
        *[(path, "result.schema.json") for path in sorted((TASK_DIR / "results").glob("*.json"))],
        *[(path, "evidence.schema.json") for path in sorted((TASK_DIR / "evidence").glob("*.json"))],
        *[(path, "finding.schema.json") for path in sorted((TASK_DIR / "findings").glob("*.json"))],
        *[(path, "approval.schema.json") for path in sorted((TASK_DIR / "approvals").glob("*.json"))],
    ]

    issues = [
        issue
        for path, schema_name in checks
        for issue in schemas.validate_file(path, schema_name, root=EXAMPLE_ROOT)
    ]

    assert issues == []


def test_tracked_workflow_uses_current_nested_scope_command() -> None:
    workflow = (EXAMPLE_ROOT / ".github" / "workflows" / "multi-agent-governance.yml").read_text(encoding="utf-8")

    assert "mac scope check " in workflow
    assert "mac scope-check " not in workflow
