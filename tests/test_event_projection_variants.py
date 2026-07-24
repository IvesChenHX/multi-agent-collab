from __future__ import annotations

from copy import deepcopy

import pytest

from mac.errors import MacError
from mac.events import replay_events, replay_scope_snapshots


def initial() -> dict[str, object]:
    return {
        "event_id": "EVT-01K0W4Z36K3W5C2R0A3M8N9P81", "event_type": "task_created",
        "expected_revision": -1, "new_revision": 0, "idempotency_key": "create", "occurred_at": "2026-07-17T00:00:00Z",
        "actor": {"id": "a"}, "payload": {"task": {"id": "TASK-1", "state": "triage", "revision": 0, "updated_at": "2026-07-17T00:00:00Z", "policy_ref": {}}},
    }


def event(revision: int, kind: str, payload: dict[str, object]) -> dict[str, object]:
    return {"event_id": f"EVT-{revision:026d}", "event_type": kind, "expected_revision": revision - 1, "new_revision": revision, "idempotency_key": f"k{revision}", "occurred_at": f"2026-07-17T00:00:0{revision}Z", "actor": {"id": "a"}, "payload": payload}


@pytest.mark.parametrize(("kind", "payload", "state"), [
    ("task_cancelled", {}, "cancelled"),
    ("task_completed", {"state": "completed_with_risk"}, "completed_with_risk"),
    ("task_superseded", {"successor_task_id": "TASK-2"}, "superseded"),
])
def test_compensating_terminal_events_project(kind: str, payload: dict[str, object], state: str) -> None:
    projection = replay_events([initial(), event(1, kind, payload)])
    assert projection["state"] == state
    if kind == "task_superseded":
        assert projection["relationships"]["superseded_by"] == "TASK-2"


def test_policy_rebase_and_terminal_transition_project_metadata() -> None:
    policy = {"combined_digest": "sha256:" + "a" * 64}
    projection = replay_events([initial(), event(1, "policy_rebased", {"policy_ref": policy, "ownership_ref": policy}), event(2, "state_transitioned", {"from": "triage", "to": "failed", "summary": "failed"})])
    assert projection["policy_ref"] == policy
    assert projection["terminal"]["summary"] == "failed"


@pytest.mark.parametrize(("events", "code"), [
    ([{"event_id": "x", "event_type": "finding_opened", "expected_revision": -1, "new_revision": 0, "idempotency_key": "x", "payload": {}}], "EVENT_INITIAL_INVALID"),
    ([{**initial(), "payload": {}}], "EVENT_INITIAL_PROJECTION_MISSING"),
    ([initial(), event(1, "state_transitioned", {"from": "ready", "to": "executing"})], "EVENT_STATE_SOURCE_MISMATCH"),
])
def test_projection_fails_closed_on_corrupt_event_history(events: list[dict[str, object]], code: str) -> None:
    with pytest.raises(MacError) as captured:
        replay_events(events)
    assert captured.value.code == code


def test_duplicate_event_id_and_divergent_idempotency_are_corruption() -> None:
    duplicate_id = event(1, "finding_opened", {}); duplicate_id["event_id"] = initial()["event_id"]
    with pytest.raises(MacError) as captured:
        replay_events([initial(), duplicate_id])
    assert captured.value.code == "EVENT_ID_DUPLICATE"
    divergent = event(1, "finding_opened", {}); divergent["idempotency_key"] = "create"
    with pytest.raises(MacError) as captured:
        replay_events([initial(), divergent])
    assert captured.value.code == "EVENT_IDEMPOTENCY_CONFLICT"


def test_scope_snapshots_replay_current_and_version_history() -> None:
    task_id = "TASK-1"
    scope_v1 = {"id": "SCOPE-1", "task_id": task_id, "version": 1, "status": "proposed"}
    approved_v1 = {**scope_v1, "status": "approved"}
    scope_v2 = {**approved_v1, "version": 2, "status": "proposed"}
    approved_v2 = {**scope_v2, "status": "approved"}
    events = [
        initial(),
        event(1, "scope_proposed", {"scope": scope_v1}),
        event(2, "scope_approved", {"approval": {"id": "APR-1"}}),
        event(3, "scope_approved", {"scope": approved_v1}),
        event(4, "scope_proposed", {"scope": scope_v2}),
        event(5, "scope_approved", {"scope": approved_v2}),
    ]

    current, history = replay_scope_snapshots(events)

    assert current == approved_v2
    assert history == {1: approved_v1}


def test_scope_snapshot_replays_from_task_creation_event() -> None:
    scope = {"id": "SCOPE-1", "task_id": "TASK-1", "version": 1, "status": "proposed"}
    created = deepcopy(initial())
    created["payload"]["scope"] = scope

    current, history = replay_scope_snapshots([created])

    assert current == scope
    assert history == {}


def test_scope_replay_rejects_version_rollback_and_identity_change() -> None:
    scope_v2 = {"id": "SCOPE-1", "task_id": "TASK-1", "version": 2, "status": "approved"}
    rolled_back = {**scope_v2, "version": 1}
    with pytest.raises(MacError) as rollback:
        replay_scope_snapshots([
            initial(),
            event(1, "scope_proposed", {"scope": scope_v2}),
            event(2, "scope_approved", {"scope": rolled_back}),
        ])
    assert rollback.value.code == "EVENT_SCOPE_VERSION_ROLLBACK"

    changed_id = {**scope_v2, "id": "SCOPE-2"}
    with pytest.raises(MacError) as identity:
        replay_scope_snapshots([
            initial(),
            event(1, "scope_proposed", {"scope": scope_v2}),
            event(2, "scope_approved", {"scope": changed_id}),
        ])
    assert identity.value.code == "EVENT_SCOPE_ID_CHANGED"
