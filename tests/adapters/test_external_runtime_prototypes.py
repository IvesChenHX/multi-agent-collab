from __future__ import annotations

import json

import pytest

from mac.adapters.runtime import AgTxPrototypeAdapter, ConductorCompiler, PlainTerminalAdapter


def _task():
    return {
        "id": "TASK-01K00000000000000000000000",
        "title": "Prototype external mappings",
        "state": "ready",
        "objective": "Map governance work without delegating Close.",
        "policy_ref": {"combined_digest": "sha256:" + "a" * 64},
        "acceptance_criteria": [{"id": "AC-001", "text": "Mappings are deterministic", "required": True}],
    }


def _scope():
    return {
        "task_id": _task()["id"],
        "allowed_paths": ["src/**"],
        "denied_paths": ["deploy/production/**"],
    }


def _unit(identifier: str, *, dependencies=()):
    return {
        "id": identifier,
        "task_id": _task()["id"],
        "title": identifier,
        "status": "ready",
        "owner": "platform",
        "depends_on": list(dependencies),
        "expected_result": f"tasks/example/results/{identifier}.json",
    }


def test_agtx_mapping_keeps_runtime_and_governance_ownership_separate():
    task = _task()
    unit = _unit("WU-01K00000000000000000000001")
    packet = PlainTerminalAdapter().prepare(task, unit, _scope())

    mapping = AgTxPrototypeAdapter().map_work_unit(
        task,
        unit,
        packet,
        handoff_path="private/handoffs/work-unit.md",
    )

    assert mapping["adapter"]["stability"] == "experimental"
    assert mapping["session"]["managed_by"] == "agtx"
    assert mapping["governance"]["managed_by"] == "mac"
    assert mapping["governance"]["external_success_is_not_close"] is True
    assert mapping["artifacts"]["handoff"]["digest"] == packet.digest
    assert mapping["mapping_digest"].startswith("sha256:")


def test_conductor_compiler_maps_dependency_layers_and_parallel_work():
    first = _unit("WU-01K00000000000000000000001")
    second = _unit("WU-01K00000000000000000000002", dependencies=[first["id"]])
    third = _unit("WU-01K00000000000000000000003", dependencies=[first["id"]])
    fourth = _unit(
        "WU-01K00000000000000000000004",
        dependencies=[second["id"], third["id"]],
    )
    units = [first, second, third, fourth]
    handoffs = {unit["id"]: f"private/handoffs/{unit['id']}.md" for unit in units}

    document = ConductorCompiler().compile(
        _task(), units, handoff_paths=handoffs, model="explicit-model", provider="copilot"
    )

    assert document["workflow"]["entry_point"].startswith("wu_")
    assert document["workflow"]["runtime"] == {
        "provider": "copilot",
        "default_model": "explicit-model",
    }
    assert document["parallel"][0]["failure_mode"] == "all_or_nothing"
    assert len(document["parallel"][0]["agents"]) == 2
    assert document["output"]["governance_note"].endswith("not Close.")
    assert json.loads(ConductorCompiler.render_yaml(document)) == document


def test_conductor_compiler_refuses_missing_dependency_selection():
    first = _unit("WU-01K00000000000000000000001")
    second = _unit("WU-01K00000000000000000000002", dependencies=[first["id"]])

    with pytest.raises(ValueError, match="omits dependencies"):
        ConductorCompiler().compile(
            _task(),
            [first, second],
            handoff_paths={second["id"]: "private/handoffs/second.md"},
            model="explicit-model",
            selected_work_unit_ids=[second["id"]],
        )


def test_conductor_compiler_refuses_cycle():
    first = _unit("WU-01K00000000000000000000001")
    second = _unit("WU-01K00000000000000000000002", dependencies=[first["id"]])
    first["depends_on"] = [second["id"]]

    with pytest.raises(ValueError, match="cycle"):
        ConductorCompiler().compile(
            _task(),
            [first, second],
            handoff_paths={
                first["id"]: "private/handoffs/first.md",
                second["id"]: "private/handoffs/second.md",
            },
            model="explicit-model",
        )
