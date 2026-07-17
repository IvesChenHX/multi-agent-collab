"""Experimental agtx mapping for MAC v6 work units.

agtx owns sessions and worktrees.  This adapter only maps a frozen work unit,
handoff, and expected artifacts; governance gates stay in MAC.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import PurePosixPath
from typing import Any

from .plain_terminal import HandoffPacket, PlainTerminalAdapter, _as_mapping, _repo_path


class AgTxPrototypeAdapter:
    """Experimental, process-free mapping to an agtx task/plugin boundary."""

    profile_id = "agtx"
    stability = "experimental"

    def __init__(self, terminal: PlainTerminalAdapter | None = None) -> None:
        self._terminal = terminal or PlainTerminalAdapter()

    def capabilities(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "id": self.profile_id,
            "description": "Experimental mapping to agtx-managed sessions and worktrees.",
            "capabilities": {
                "spawn_agent": True,
                "parallel_runs": True,
                "fresh_context": "native",
                "read_only_run": "policy_only",
                "worktree": "external",
                "human_gate": "interactive",
                "command_execution": True,
                "network_control": "unavailable",
                "secret_broker": "unavailable",
                "artifact_store": "filesystem",
                "tracing": "basic",
                "cancellation": "manual",
            },
            "fallback": {
                "fresh_context": "build_handoff_and_wait",
                "independent_review": "wait_for_manual",
                "worktree": "serialize_and_lock",
                "artifact_store": "digest_only",
            },
        }

    def prepare(self, task: object, work_unit: object, scope: object, **options: object) -> HandoffPacket:
        return self._terminal.prepare(task, work_unit, scope, **options)

    def collect(self, handle_or_path: str, **expected: str) -> dict[str, Any]:
        return self._terminal.collect(handle_or_path, **expected)

    def map_work_unit(
        self,
        task: object,
        work_unit: object,
        packet: HandoffPacket,
        *,
        handoff_path: str,
        worktree_root: str = ".agtx/worktrees",
    ) -> dict[str, Any]:
        task_data = _as_mapping(task, "task")
        unit_data = _as_mapping(work_unit, "work_unit")
        if str(task_data.get("id", "")) != packet.task_id:
            raise ValueError("task does not match handoff packet")
        if str(unit_data.get("id", "")) != packet.work_unit_id:
            raise ValueError("work unit does not match handoff packet")
        handoff = _repo_path(handoff_path, "handoff_path")
        worktree = _repo_path(worktree_root, "worktree_root")
        expected = _repo_path(packet.result_path, "result_path")
        mapping = {
            "schema_version": 1,
            "adapter": {"name": "agtx", "stability": self.stability},
            "task": {
                "id": packet.task_id,
                "title": str(task_data.get("title", packet.task_id)),
                "description": str(task_data.get("objective", "")),
            },
            "work_unit": {
                "id": packet.work_unit_id,
                "owner": str(unit_data.get("owner", "")),
                "depends_on": list(unit_data.get("depends_on", [])),
                "allowed_paths": list(packet.allowed_paths),
                "denied_paths": list(packet.denied_paths),
            },
            "session": {
                "managed_by": "agtx",
                "worktree_root": PurePosixPath(worktree).as_posix(),
                "fresh_context_required": True,
            },
            "artifacts": {
                "handoff": {"path": handoff, "digest": packet.digest},
                "result": {"path": expected, "schema": packet.result_schema},
            },
            "governance": {
                "managed_by": "mac",
                "policy_digest": packet.policy_digest,
                "result_requires_import": True,
                "external_success_is_not_close": True,
            },
        }
        canonical = json.dumps(mapping, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        mapping["mapping_digest"] = "sha256:" + sha256(canonical.encode("utf-8")).hexdigest()
        return mapping
