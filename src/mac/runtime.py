from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .errors import MacIssue
from .io import load_data


@dataclass(frozen=True, slots=True)
class CapabilityDecision:
    ok: bool
    issues: tuple[MacIssue, ...]
    actions: tuple[str, ...]


def resolve_profile(
    profiles_dir: Path, *, explicit: str | None = None, project_default: str | None = None,
    user_default: str | None = None,
) -> dict[str, Any]:
    selected = explicit or project_default or user_default or "local-single"
    path = profiles_dir / f"{selected}.yaml"
    if path.is_file():
        return load_data(path)
    if selected != "local-single":
        raise FileNotFoundError(path)
    return {
        "schema_version": 1, "id": "local-single",
        "capabilities": {"spawn_agent": False, "parallel_runs": False, "fresh_context": "manual", "read_only_run": "policy_only", "worktree": "external", "human_gate": "interactive", "command_execution": True, "network_control": "unavailable", "secret_broker": "unavailable", "artifact_store": "filesystem", "tracing": "basic", "cancellation": "manual"},
        "fallback": {"fresh_context": "build_handoff_and_wait", "independent_review": "wait_for_manual", "worktree": "serialize_and_lock", "artifact_store": "digest_only"},
        "limits": {"max_parallel_runs": 1, "default_timeout_seconds": 3600, "max_output_bytes": 10_485_760},
    }


def evaluate_capabilities(profile: Mapping[str, Any], requirements: Mapping[str, Any], *, mode: str) -> CapabilityDecision:
    capabilities = profile.get("capabilities", {})
    fallback = profile.get("fallback", {})
    issues: list[MacIssue] = []
    actions: list[str] = []
    for name, required in requirements.items():
        actual = capabilities.get(name)
        satisfied = actual is True if required is True else actual == required
        if satisfied:
            continue
        action = fallback.get(name) or fallback.get("independent_review" if name == "read_only_run" else name)
        if action:
            actions.append(str(action))
        if mode in {"high_risk", "audit"} or not action:
            issues.append(MacIssue("RUNTIME_CAPABILITY_MISSING", f"runtime capability {name} does not satisfy {required!r}", details={"actual": actual, "fallback": action}))
    return CapabilityDecision(not issues, tuple(issues), tuple(actions))
