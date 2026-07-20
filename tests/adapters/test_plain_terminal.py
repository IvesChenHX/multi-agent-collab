from __future__ import annotations

import json

import pytest

from mac.adapters.runtime import PlainTerminalAdapter, ResultCollectionError
from mac.schema_validation import install_schema_bundle
import mac.schema_validation as schema_validation


@pytest.fixture
def runtime_inputs(tmp_path, monkeypatch):
    schema_repo = tmp_path / "locked-schema-fixture"
    install_schema_bundle(schema_repo)
    monkeypatch.setattr(
        schema_validation, "_default_schema_dir", lambda: schema_repo / "schemas"
    )
    task = {
        "id": "TASK-01K00000000000000000000000",
        "title": "Implement adapter",
        "state": "ready",
        "objective": "Implement only the approved runtime adapter.",
        "acceptance_criteria": [{"id": "AC-001", "text": "Result imports", "required": True}],
        "policy_ref": {"combined_digest": "sha256:" + "a" * 64},
    }
    work_unit = {
        "id": "WU-01K00000000000000000000001",
        "task_id": task["id"],
        "title": "Runtime adapter",
        "status": "ready",
        "expected_result": "tasks/example/results/RESULT-01K00000000000000000000002.json",
    }
    scope = {
        "task_id": task["id"],
        "allowed_paths": ["src/mac/adapters/runtime/**", "tests/adapters/**"],
        "denied_paths": ["src/mac/domain/**"],
    }
    return task, work_unit, scope


def test_plain_terminal_builds_self_contained_packet_without_process_control(tmp_path, runtime_inputs):
    task, work_unit, scope = runtime_inputs
    adapter = PlainTerminalAdapter()

    packet = adapter.build(
        tmp_path,
        "private/handoff.md",
        task,
        work_unit,
        scope,
        decisions_and_contracts=["Runtime adapter must not close the task."],
        open_findings=["FND-01 remains open"],
        invalidated_evidence=["targeted_tests must rerun"],
        run_id="RUN-01K00000000000000000000003",
    )

    rendered = (tmp_path / "private" / "handoff.md").read_text(encoding="utf-8")
    assert "Authoritative governance context" in rendered
    assert "Untrusted task context" in rendered
    assert task["id"] in rendered
    assert work_unit["id"] in rendered
    assert "RUN-01K00000000000000000000003" in rendered
    assert scope["allowed_paths"][0] in rendered
    assert packet.digest.startswith("sha256:")
    assert not hasattr(adapter, "launch")
    assert not hasattr(adapter, "inspect")
    assert not hasattr(adapter, "cancel")


def test_plain_terminal_preserves_the_frozen_policy_reference(tmp_path, runtime_inputs):
    task, work_unit, scope = runtime_inputs
    task["policy_ref"] = {
        "source_commit": "1" * 40,
        "files": [
            {"path": "AGENTS.md", "digest": "sha256:" + "b" * 64},
            {
                "path": ".agents/workflows/evidence-driven-development.yaml",
                "digest": "sha256:" + "c" * 64,
            },
        ],
        "combined_digest": "sha256:" + "d" * 64,
    }

    packet = PlainTerminalAdapter().build(
        tmp_path,
        "private/handoff.md",
        task,
        work_unit,
        scope,
    )

    assert packet.policy_ref == task["policy_ref"]
    assert packet.policy_digest == task["policy_ref"]["combined_digest"]
    rendered = packet.to_markdown()
    assert task["policy_ref"]["source_commit"] in rendered
    assert "AGENTS.md" in rendered


def test_plain_terminal_profile_is_conservative():
    profile = PlainTerminalAdapter().capabilities()
    capabilities = profile["capabilities"]

    assert profile["id"] == "plain-terminal"
    assert capabilities["spawn_agent"] is False
    assert capabilities["parallel_runs"] is False
    assert capabilities["fresh_context"] == "manual"
    assert capabilities["read_only_run"] == "unavailable"
    assert capabilities["network_control"] == "unavailable"
    assert profile["fallback"]["independent_review"] == "wait_for_manual"


def test_plain_terminal_collects_matching_result(tmp_path, runtime_inputs):
    task, work_unit, _ = runtime_inputs
    result = {
        "schema_version": 1,
        "id": "RESULT-01K00000000000000000000002",
        "task_id": task["id"],
        "work_unit_id": work_unit["id"],
        "run_id": "RUN-01K00000000000000000000003",
        "outcome": "succeeded",
        "summary": "Adapter implemented.",
        "changed_files": ["src/mac/adapters/runtime/plain_terminal.py"],
        "commands": [{"argv": ["pytest", "tests/adapters"], "exit_code": 0}],
        "submitted_at": "2026-07-17T00:00:00Z",
    }
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(result), encoding="utf-8")

    collected = PlainTerminalAdapter().collect(
        result_path,
        expected_task_id=task["id"],
        expected_work_unit_id=work_unit["id"],
        expected_run_id=result["run_id"],
    )

    assert collected == result


@pytest.mark.parametrize(
    "change",
    [
        {"outcome": "complete"},
        {"changed_files": ["../escape.py"]},
        {"commands": [{"argv": "pytest tests", "exit_code": 0}]},
    ],
)
def test_plain_terminal_rejects_invalid_result(tmp_path, runtime_inputs, change):
    task, work_unit, _ = runtime_inputs
    result = {
        "schema_version": 1,
        "id": "RESULT-01K00000000000000000000002",
        "task_id": task["id"],
        "work_unit_id": work_unit["id"],
        "run_id": "RUN-01K00000000000000000000003",
        "outcome": "succeeded",
        "summary": "Adapter implemented.",
        "changed_files": [],
        "commands": [],
        "submitted_at": "2026-07-17T00:00:00Z",
    }
    result.update(change)
    path = tmp_path / "result.json"
    path.write_text(json.dumps(result), encoding="utf-8")

    with pytest.raises(ResultCollectionError):
        PlainTerminalAdapter().collect(path)


def test_plain_terminal_rejects_output_escape(tmp_path, runtime_inputs):
    task, work_unit, scope = runtime_inputs

    with pytest.raises(ValueError, match="repository"):
        PlainTerminalAdapter().build(tmp_path, "../handoff.md", task, work_unit, scope)
