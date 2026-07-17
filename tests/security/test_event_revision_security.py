from __future__ import annotations

import pytest

from mac.errors import MacError
from mac.events import replay_events


def event(*, event_id: str, expected: int, new: int, key: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "event_id": event_id,
        "task_id": "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        "event_type": "task_created" if new == 0 else "state_transitioned",
        "occurred_at": "2026-07-17T08:00:00Z",
        "actor": {"id": "ACTOR-security", "kind": "agent"},
        "expected_revision": expected,
        "new_revision": new,
        "idempotency_key": key,
        "payload": {"task": {"state": "triage"}} if expected == -1 else {"from": "triage", "to": "ready"},
    }


def test_event_replay_fails_closed_on_revision_rollback() -> None:
    events = [
        event(event_id="EVT-01K0W4Z36K3W5C2R0A3M8N9P81", expected=-1, new=0, key="create"),
        event(event_id="EVT-01K0W4Z36K3W5C2R0A3M8N9P82", expected=0, new=0, key="rollback"),
    ]

    with pytest.raises(MacError) as captured:
        replay_events(events)

    assert captured.value.code == "EVENT_REVISION_ROLLBACK"


def test_event_replay_fails_closed_on_revision_gap() -> None:
    events = [
        event(event_id="EVT-01K0W4Z36K3W5C2R0A3M8N9P81", expected=-1, new=0, key="create"),
        event(event_id="EVT-01K0W4Z36K3W5C2R0A3M8N9P82", expected=0, new=2, key="gap"),
    ]

    with pytest.raises(MacError) as captured:
        replay_events(events)

    assert captured.value.code == "EVENT_REVISION_GAP"
