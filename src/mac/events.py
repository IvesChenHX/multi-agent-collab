from __future__ import annotations

from copy import deepcopy
from typing import Any, Iterable

from .errors import ExitCode, MacError
from .state_machine import TERMINAL_STATES


def _corrupt(code: str, message: str, event: dict[str, Any]) -> MacError:
    return MacError(code, message, exit_code=ExitCode.CORRUPTION, details={"event_id": event.get("event_id")})


def replay_events(events: Iterable[dict[str, Any]], initial_projection: dict[str, Any] | None = None) -> dict[str, Any]:
    """Deterministically project immutable events in revision order.

    Duplicate retries with the same idempotency key and identical event data are
    ignored. Divergent duplicates and any gap/rollback fail closed.
    """
    ordered = sorted((deepcopy(event) for event in events), key=lambda item: (int(item.get("new_revision", -1)), str(item.get("event_id", ""))))
    if not ordered:
        raise MacError("EVENTS_MISSING", "task has no events", exit_code=ExitCode.CORRUPTION)
    projection: dict[str, Any] | None = None
    seeded_projection = False
    revision = -1
    seen_keys: dict[str, dict[str, Any]] = {}
    seen_ids: set[str] = set()
    for event in ordered:
        key = str(event.get("idempotency_key", ""))
        event_id = str(event.get("event_id", ""))
        if event_id in seen_ids:
            raise _corrupt("EVENT_ID_DUPLICATE", f"duplicate event id {event_id}", event)
        if key in seen_keys:
            if event == seen_keys[key]:
                continue
            raise _corrupt("EVENT_IDEMPOTENCY_CONFLICT", f"idempotency key {key!r} has divergent events", event)
        seen_ids.add(event_id)
        seen_keys[key] = event
        expected = int(event.get("expected_revision", -2))
        new = int(event.get("new_revision", -2))
        if new <= revision:
            raise _corrupt("EVENT_REVISION_ROLLBACK", f"revision rollback from {revision} to {new}", event)
        if expected != revision or new != revision + 1:
            raise _corrupt("EVENT_REVISION_GAP", f"revision gap: expected ({revision}, {revision + 1}), got ({expected}, {new})", event)
        event_type = event.get("event_type")
        payload = event.get("payload") or {}
        if revision == -1:
            if event_type not in {"task_created", "legacy_imported"}:
                raise _corrupt("EVENT_INITIAL_INVALID", "first event must create or import a task", event)
            raw_task = payload.get("task")
            if not isinstance(raw_task, dict):
                if not isinstance(initial_projection, dict):
                    raise _corrupt("EVENT_INITIAL_PROJECTION_MISSING", "initial event does not contain a replayable task projection", event)
                projection = deepcopy(initial_projection)
                seeded_projection = True
                if str(projection.get("id")) != str(event.get("task_id")):
                    raise _corrupt("EVENT_INITIAL_TASK_MISMATCH", "seed projection belongs to another task", event)
                if payload.get("state"):
                    projection["state"] = payload["state"]
                projection["terminal"] = None
            else:
                projection = deepcopy(raw_task)
        elif projection is None:
            raise _corrupt("EVENT_PROJECTION_MISSING", "projection could not be initialized", event)
        if event_type == "state_transitioned":
            source = payload.get("from")
            if projection.get("state") != source:
                raise _corrupt("EVENT_STATE_SOURCE_MISMATCH", f"projection is {projection.get('state')!r}, event expects {source!r}", event)
            projection["state"] = payload.get("to")
            terminal_state = payload.get("terminal_state")
            if terminal_state is True or (terminal_state is None and projection["state"] in TERMINAL_STATES):
                projection["terminal"] = payload.get("terminal") or {
                    "closed_at": event.get("occurred_at"), "closed_by": event.get("actor", {}).get("id", "unknown"), "summary": payload.get("summary", f"Transitioned to {projection['state']}")
                }
        elif event_type == "policy_rebased":
            projection["policy_ref"] = deepcopy(payload["policy_ref"])
            if "ownership_ref" in payload:
                projection["ownership_ref"] = deepcopy(payload["ownership_ref"])
        elif event_type == "task_cancelled":
            projection["state"] = "cancelled"
        elif event_type == "task_superseded":
            projection["state"] = "superseded"
            projection.setdefault("relationships", {})["superseded_by"] = payload.get("successor_task_id")
        elif event_type == "task_completed":
            projection["state"] = payload.get("state", "completed")
        projection["revision"] = new
        projection["updated_at"] = event.get("occurred_at", projection.get("updated_at"))
        revision = new
    if projection is None:
        raise MacError("EVENT_PROJECTION_MISSING", "projection could not be initialized", exit_code=ExitCode.CORRUPTION)
    if seeded_projection and initial_projection is not None:
        projection["updated_at"] = initial_projection.get("updated_at", projection.get("updated_at"))
    return projection


_ENTITY_PAYLOADS = {
    "work_unit": "work-units",
    "run": "runs",
    "result": "results",
    "evidence": "evidence",
    "finding": "findings",
    "approval": "approvals",
    "risk_acceptance": "risk-acceptances",
}


def replay_entity_snapshots(events: Iterable[dict[str, Any]], initial_projection: dict[str, Any] | None = None) -> dict[str, dict[str, dict[str, Any]]]:
    event_list = [deepcopy(event) for event in events]
    replay_events(event_list, initial_projection=initial_projection)
    projection = {directory: {} for directory in _ENTITY_PAYLOADS.values()}
    for event in sorted(event_list, key=lambda item: (int(item.get("new_revision", -1)), str(item.get("event_id", "")))):
        payload = event.get("payload") or {}
        for key, directory in _ENTITY_PAYLOADS.items():
            snapshot = payload.get(key)
            if isinstance(snapshot, dict) and snapshot.get("id"):
                projection[directory][str(snapshot["id"])] = deepcopy(snapshot)
    return projection


def replay_scope_snapshots(
    events: Iterable[dict[str, Any]],
    initial_projection: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, dict[int, dict[str, Any]]]:
    """Rebuild the current Scope Contract and its immutable version history.

    Task creation and Scope mutations carry their materialized snapshot in the
    Task event.  Some ``scope_approved`` events only record an approval entity,
    so they are intentionally ignored unless they also contain a ``scope``
    snapshot.  A version may have both proposed and approved snapshots; the
    last committed snapshot for that version is authoritative.
    """

    event_list = [deepcopy(event) for event in events]
    task_projection = replay_events(event_list, initial_projection=initial_projection)
    ordered = sorted(
        event_list,
        key=lambda item: (int(item.get("new_revision", -1)), str(item.get("event_id", ""))),
    )
    task_id = str(task_projection.get("id", ""))
    scope_id: str | None = None
    latest_version = 0
    current: dict[str, Any] | None = None
    versions: dict[int, dict[str, Any]] = {}
    for event in ordered:
        if event.get("event_type") not in {"task_created", "scope_proposed", "scope_approved"}:
            continue
        snapshot = (event.get("payload") or {}).get("scope")
        if snapshot is None:
            continue
        if not isinstance(snapshot, dict):
            raise _corrupt("EVENT_SCOPE_SNAPSHOT_INVALID", "scope snapshot must be an object", event)
        version = snapshot.get("version")
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise _corrupt("EVENT_SCOPE_VERSION_INVALID", "scope snapshot version must be a positive integer", event)
        if version < latest_version:
            raise _corrupt("EVENT_SCOPE_VERSION_ROLLBACK", "scope snapshot version rolled back", event)
        if str(snapshot.get("task_id", "")) != task_id:
            raise _corrupt("EVENT_SCOPE_TASK_MISMATCH", "scope snapshot belongs to another task", event)
        candidate_scope_id = str(snapshot.get("id", ""))
        if not candidate_scope_id:
            raise _corrupt("EVENT_SCOPE_ID_MISSING", "scope snapshot id is missing", event)
        if scope_id is not None and candidate_scope_id != scope_id:
            raise _corrupt("EVENT_SCOPE_ID_CHANGED", "scope identity changed across versions", event)
        scope_id = candidate_scope_id
        latest_version = version
        current = deepcopy(snapshot)
        versions[version] = deepcopy(snapshot)
    if current is None:
        return None, {}
    history = {version: snapshot for version, snapshot in versions.items() if version != latest_version}
    return current, history


def replay_work_units(events: Iterable[dict[str, Any]], initial_projection: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    """Rebuild work-unit snapshots recorded by run/result lifecycle events.

    Task events remain the revision authority.  Run/result events carry the
    resulting work-unit snapshot so an event-first interruption can repair the
    YAML projection without guessing lifecycle state from mutable files.
    """
    event_list = [deepcopy(event) for event in events]
    replay_events(event_list, initial_projection=initial_projection)
    ordered = sorted(
        event_list,
        key=lambda item: (int(item.get("new_revision", -1)), str(item.get("event_id", ""))),
    )
    projection: dict[str, dict[str, Any]] = {}
    for event in ordered:
        if event.get("event_type") not in {"work_unit_created", "run_started", "run_finished", "result_submitted"}:
            continue
        snapshot = (event.get("payload") or {}).get("work_unit")
        if not isinstance(snapshot, dict) or not snapshot.get("id"):
            continue
        projection[str(snapshot["id"])] = deepcopy(snapshot)
    return projection
