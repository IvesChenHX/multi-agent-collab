"""Experimental compiler from selected MAC work units to Conductor YAML data."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
import re
from typing import Any

from .plain_terminal import _as_mapping, _repo_path


_NAME_CHARACTER = re.compile(r"[^a-z0-9_]+")


def _node_name(identifier: str) -> str:
    value = _NAME_CHARACTER.sub("_", identifier.lower()).strip("_")
    if not value or not value[0].isalpha():
        value = "wu_" + value
    return value


def _selected_units(work_units: Sequence[object], selected: Sequence[str] | None) -> list[Mapping[str, Any]]:
    units = [_as_mapping(unit, "work_unit") for unit in work_units]
    by_id = {str(unit.get("id", "")): unit for unit in units}
    if "" in by_id or len(by_id) != len(units):
        raise ValueError("work unit identifiers must be present and unique")
    requested = set(selected or by_id)
    unknown = requested.difference(by_id)
    if unknown:
        raise ValueError(f"selected work units do not exist: {', '.join(sorted(unknown))}")
    result = [by_id[identifier] for identifier in by_id if identifier in requested]
    for unit in result:
        dependencies = {str(item) for item in unit.get("depends_on", [])}
        missing = dependencies.difference(requested)
        if missing:
            raise ValueError(
                f"selected work unit {unit['id']} omits dependencies: {', '.join(sorted(missing))}"
            )
    if not result:
        raise ValueError("at least one work unit must be selected")
    return result


def _topological_layers(units: Sequence[Mapping[str, Any]]) -> list[list[Mapping[str, Any]]]:
    by_id = {str(unit["id"]): unit for unit in units}
    incoming = {
        identifier: {str(dep) for dep in unit.get("depends_on", [])}
        for identifier, unit in by_id.items()
    }
    unknown = {dep for dependencies in incoming.values() for dep in dependencies if dep not in by_id}
    if unknown:
        raise ValueError(f"work unit dependencies do not exist: {', '.join(sorted(unknown))}")
    layers: list[list[Mapping[str, Any]]] = []
    remaining = dict(incoming)
    while remaining:
        ready_ids = sorted(identifier for identifier, deps in remaining.items() if not deps)
        if not ready_ids:
            raise ValueError("work unit dependency graph contains a cycle")
        layers.append([by_id[identifier] for identifier in ready_ids])
        for identifier in ready_ids:
            remaining.pop(identifier)
        for dependencies in remaining.values():
            dependencies.difference_update(ready_ids)
    return layers


class ConductorCompiler:
    """Compile a deterministic DAG subset; execution remains external."""

    profile_id = "conductor"
    stability = "experimental"

    def capabilities(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "id": self.profile_id,
            "description": "Experimental Conductor workflow compiler; no provider launch.",
            "capabilities": {
                "spawn_agent": True,
                "parallel_runs": True,
                "fresh_context": "native",
                "read_only_run": "policy_only",
                "worktree": "external",
                "human_gate": "native",
                "command_execution": True,
                "network_control": "external",
                "secret_broker": "external",
                "artifact_store": "external",
                "tracing": "native",
                "cancellation": "native",
            },
            "fallback": {
                "fresh_context": "build_handoff_and_wait",
                "independent_review": "wait_for_manual",
                "worktree": "serialize_and_lock",
                "artifact_store": "digest_only",
            },
        }

    def compile(
        self,
        task: object,
        work_units: Sequence[object],
        *,
        handoff_paths: Mapping[str, str],
        model: str,
        provider: str | None = None,
        selected_work_unit_ids: Sequence[str] | None = None,
        timeout_seconds: int = 3600,
    ) -> dict[str, Any]:
        """Compile selected nodes into serial layers and static parallel groups."""

        if not model:
            raise ValueError("Conductor model must be explicitly selected")
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")
        task_data = _as_mapping(task, "task")
        task_id = str(task_data.get("id", ""))
        if not task_id:
            raise ValueError("task identifier is required")
        units = _selected_units(work_units, selected_work_unit_ids)
        for unit in units:
            if str(unit.get("task_id", task_id)) != task_id:
                raise ValueError("all work units must belong to the compiled task")
        layers = _topological_layers(units)

        names: dict[str, str] = {}
        for unit in units:
            identifier = str(unit["id"])
            name = _node_name(identifier)
            if name in names.values():
                raise ValueError("work unit identifiers collide after Conductor name normalization")
            names[identifier] = name

        route_nodes: list[str] = []
        parallel: list[dict[str, Any]] = []
        for index, layer in enumerate(layers, start=1):
            if len(layer) == 1:
                route_nodes.append(names[str(layer[0]["id"])])
            else:
                group_name = f"work_units_level_{index}"
                route_nodes.append(group_name)
                parallel.append(
                    {
                        "name": group_name,
                        "description": f"Independent MAC work units at dependency level {index}",
                        "agents": [names[str(unit["id"])] for unit in layer],
                        "failure_mode": "all_or_nothing",
                    }
                )

        next_route = {
            node: (route_nodes[index + 1] if index + 1 < len(route_nodes) else "$end")
            for index, node in enumerate(route_nodes)
        }
        for group in parallel:
            group["routes"] = [{"to": next_route[group["name"]]}]

        agents: list[dict[str, Any]] = []
        parallel_members = {agent for group in parallel for agent in group["agents"]}
        for unit in units:
            identifier = str(unit["id"])
            if identifier not in handoff_paths:
                raise ValueError(f"handoff path missing for work unit {identifier}")
            handoff = _repo_path(handoff_paths[identifier], f"handoff path for {identifier}")
            expected = _repo_path(unit.get("expected_result"), f"expected_result for {identifier}")
            name = names[identifier]
            agent: dict[str, Any] = {
                "name": name,
                "description": str(unit.get("title", identifier)),
                "model": model,
                "prompt": (
                    f"Execute MAC work unit {identifier} for task {task_id}.\n"
                    f"Read the authoritative handoff packet at {handoff}.\n"
                    f"Write the standard MAC Result JSON to {expected}.\n"
                    "Stay within the approved scope. External workflow success is not MAC task Close."
                ),
                "output": {
                    "result_path": {"type": "string", "description": "Path to the MAC Result JSON"},
                    "outcome": {
                        "type": "string",
                        "description": "succeeded, failed, blocked, or partial",
                    },
                },
            }
            if name not in parallel_members:
                agent["routes"] = [{"to": next_route[name]}]
            agents.append(agent)

        workflow: dict[str, Any] = {
            "name": f"mac-{_node_name(task_id)}",
            "description": f"MAC v6 task {task_id}; Close remains governed by MAC.",
            "version": "1.0.0",
            "entry_point": route_nodes[0],
            "context": {"mode": "explicit"},
            "limits": {"max_iterations": max(len(route_nodes), 1), "timeout_seconds": timeout_seconds},
        }
        if provider:
            workflow["runtime"] = {"provider": provider, "default_model": model}
        document: dict[str, Any] = {"workflow": workflow}
        if parallel:
            document["parallel"] = parallel
        document["agents"] = agents
        document["output"] = {
            "task_id": task_id,
            "governance_note": "Import every Result into MAC; Conductor success is not Close.",
        }
        return document

    @staticmethod
    def render_yaml(document: Mapping[str, Any]) -> str:
        """Render JSON, which is valid YAML 1.2, without adding a YAML dependency."""

        return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
