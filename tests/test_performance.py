from __future__ import annotations

import time
from pathlib import Path

from mac.events import replay_events
from mac.schema_validation import SchemaSet


def test_replay_1000_events_under_v1_budget() -> None:
    events = [{"event_id": "EVT-0000", "event_type": "task_created", "expected_revision": -1, "new_revision": 0, "idempotency_key": "k0", "payload": {"task": {"state": "triage", "revision": 0}}}]
    events.extend({"event_id": f"EVT-{index:04d}", "event_type": "finding_opened", "expected_revision": index - 1, "new_revision": index, "idempotency_key": f"k{index}", "payload": {}} for index in range(1, 1000))
    started = time.perf_counter(); projection = replay_events(events); duration = time.perf_counter() - started
    assert projection["revision"] == 999
    assert duration < 0.5


def test_validate_1000_task_metadata_under_v1_budget() -> None:
    schemas = SchemaSet(Path(__file__).parents[1] / "schemas")
    digest = "sha256:" + "a" * 64
    task = {"schema_version": 6, "id": "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q", "title": "x", "mode": "standard", "state": "triage", "revision": 0, "created_at": "2026-07-17T00:00:00Z", "updated_at": "2026-07-17T00:00:00Z", "objective": "x", "acceptance_criteria": [{"id": "AC-001", "text": "x", "required": True}], "policy_ref": {"combined_digest": digest}, "ownership_ref": {"combined_digest": digest}, "scope_contract_ref": "tasks/TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q/scope-contract.yaml", "required_gates": ["targeted_tests"]}
    started = time.perf_counter()
    assert all(not schemas.validate(task, "task.schema.json", path=f"tasks/{index}/task.yaml") for index in range(1000))
    assert time.perf_counter() - started < 2.0
