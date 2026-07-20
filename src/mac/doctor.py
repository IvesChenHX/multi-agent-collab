from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ExitCode, MacError
from .events import replay_entity_snapshots, replay_events, replay_scope_snapshots
from .ids import is_identifier
from .io import atomic_write_json, atomic_write_yaml, load_data, normalize_data
from .policy import compile_policy
from .repository import _validate_loaded_event_stream
from .schema_validation import SchemaSet, schema_lock_issues


_ATOMIC_FILE = re.compile(r"^\.(?P<target>.+)\.(?P<token>[a-z0-9_]{8})\.tmp$")
_LEASE_QUARANTINE = re.compile(r"^\.controller\.lease\.(?P<token>LEASE-[0-9A-HJKMNP-TV-Z]{26})\.expired$")
_SCOPE_HISTORY = re.compile(r"^scope-contract\.v[1-9][0-9]*\.yaml$")
_MINIMUM_TEMP_AGE_SECONDS = 60.0
_MAX_RECOVERY_ARTIFACT_BYTES = 16 * 1_048_576
_ENTITY_LAYOUT = {
    "events": ("EVT", ".json"),
    "work-units": ("WU", ".yaml"),
    "runs": ("RUN", ".json"),
    "results": ("RESULT", ".json"),
    "findings": ("FND", ".json"),
    "evidence": ("EVD", ".json"),
    "approvals": ("APR", ".json"),
    "risk-acceptances": ("RISK", ".json"),
}


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    name: str
    ok: bool
    required: bool
    message: str


@dataclass(frozen=True, slots=True)
class DoctorReport:
    ok: bool
    checks: tuple[DoctorCheck, ...]

    def as_dict(self) -> dict[str, object]:
        return {"ok": self.ok, "checks": [{"name": item.name, "ok": item.ok, "required": item.required, "message": item.message} for item in self.checks]}


@dataclass(frozen=True, slots=True)
class RepairReport:
    applied: bool
    plan_digest: str
    temporary_files: tuple[str, ...]
    expired_leases: tuple[str, ...]
    projections: tuple[str, ...]
    index_path: str

    def as_dict(self) -> dict[str, object]:
        action = "removed" if self.applied else "candidate"
        return {
            "ok": True,
            "applied": self.applied,
            "plan_digest": self.plan_digest,
            f"{action}_temporary_files": list(self.temporary_files),
            f"{action}_expired_leases": list(self.expired_leases),
            f"{action}_projections": list(self.projections),
            "index_path": self.index_path,
        }


def _git_available(repo: Path) -> bool:
    try:
        return subprocess.run(["git", "-C", str(repo), "rev-parse", "--git-dir"], capture_output=True).returncode == 0
    except FileNotFoundError:
        return False


def _tracked_private_files(repo: Path) -> list[str]:
    try:
        completed = subprocess.run(["git", "-C", str(repo), "ls-files", "-z"], check=False, capture_output=True)
    except FileNotFoundError:
        return []
    if completed.returncode:
        return []
    return [value.decode("utf-8", errors="surrogateescape") for value in completed.stdout.split(b"\0") if value and (value.startswith(b"private/") or b"/private/" in value)]


def _git_paths(repo: Path, *arguments: str) -> list[str]:
    try:
        completed = subprocess.run(["git", "-C", str(repo), *arguments, "-z"], check=False, capture_output=True)
    except FileNotFoundError:
        return []
    return [value.decode("utf-8", errors="surrogateescape").replace("\\", "/") for value in completed.stdout.split(b"\0") if value] if completed.returncode == 0 else []


def _path_risk_count(repo: Path) -> int:
    import unicodedata

    values = [*_git_paths(repo, "ls-files"), *_git_paths(repo, "ls-files", "--others", "--exclude-standard")]
    case_seen: dict[str, str] = {}
    unicode_seen: dict[str, str] = {}
    risks = 0
    for value in values:
        case_key = unicodedata.normalize("NFC", value).casefold()
        unicode_key = unicodedata.normalize("NFC", value)
        if case_key in case_seen and case_seen[case_key] != value:
            risks += 1
        else:
            case_seen[case_key] = value
        if unicode_key in unicode_seen and unicode_seen[unicode_key] != value:
            risks += 1
        else:
            unicode_seen[unicode_key] = value
        path = repo / value
        if path.is_symlink():
            try:
                path.resolve(strict=False).relative_to(repo)
            except (OSError, ValueError):
                risks += 1
    return risks


def _untracked_sensitive_log_count(repo: Path) -> int:
    return sum(1 for value in _git_paths(repo, "ls-files", "--others", "--exclude-standard") if "/private/" in f"/{value}" or value.lower().endswith((".log", ".trace")))


def _cli_version(repo: Path) -> str | None:
    pyproject = repo / "pyproject.toml"
    if not pyproject.is_file():
        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    if not pyproject.is_file():
        return None
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject.read_text(encoding="utf-8"), re.MULTILINE)
    return match.group(1) if match else None


def _policy_drift_count(repo: Path) -> int:
    from .repository import build_policy_ref

    count = 0
    for task_path in sorted((repo / "tasks").glob("TASK-*/task.yaml")):
        try:
            task = load_data(task_path)
            for key in ("policy_ref", "ownership_ref"):
                reference = task.get(key) or {}
                paths = [str(item.get("path")) for item in reference.get("files", [])]
                if paths and build_policy_ref(repo, paths).get("combined_digest") != reference.get("combined_digest"):
                    count += 1
        except Exception:
            count += 1
    return count


def _migration_incomplete_count(repo: Path) -> int:
    index = repo / "tasks/index.yaml"
    if not index.is_file():
        return 0
    try:
        legacy = {str(item.get("id")) for item in load_data(index).get("tasks", [])}
    except Exception:
        return 1
    imported: set[str] = set()
    for path in (repo / "tasks-v6").glob("TASK-*/task.yaml") if (repo / "tasks-v6").is_dir() else []:
        try:
            if value := load_data(path).get("legacy_id"):
                imported.add(str(value))
        except Exception:
            continue
    return len(legacy - imported)


@dataclass(frozen=True, slots=True)
class _PathSnapshot:
    relative: str
    kind: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class _ProjectionPlan:
    task_id: str
    replay_inputs: tuple[_PathSnapshot, ...]
    task_projection: dict[str, Any]
    outputs: tuple[tuple[str, str, dict[str, Any]], ...]
    drift: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _RepairPlan:
    temporary: tuple[_PathSnapshot, ...]
    leases: tuple[_PathSnapshot, ...]
    projections: tuple[_ProjectionPlan, ...]
    index_inputs: tuple[_PathSnapshot, ...]
    index_rows: tuple[dict[str, Any], ...]
    digest: str


def _capture_regular_file(path: Path, root: Path) -> tuple[_PathSnapshot, bytes]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise MacError("DOCTOR_REPAIR_PLAN_CHANGED", f"repair candidate disappeared: {path}", exit_code=ExitCode.CONFLICT) from exc
    relative = path.relative_to(root).as_posix()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise MacError("DOCTOR_REPAIR_ARTIFACT_UNSAFE", f"repair input is not a regular file: {relative}", exit_code=ExitCode.SECURITY, path=relative)
    if before.st_size > _MAX_RECOVERY_ARTIFACT_BYTES:
        raise MacError("DOCTOR_REPAIR_ARTIFACT_TOO_LARGE", f"repair input exceeds size limit: {relative}", exit_code=ExitCode.SECURITY, path=relative)
    content = path.read_bytes()
    try:
        after = path.lstat()
    except OSError as exc:
        raise MacError("DOCTOR_REPAIR_PLAN_CHANGED", f"repair input disappeared while being frozen: {relative}", exit_code=ExitCode.CONFLICT, path=relative) from exc
    identity_before = (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or len(content) != before.st_size:
        raise MacError("DOCTOR_REPAIR_PLAN_CHANGED", f"repair input changed while being frozen: {relative}", exit_code=ExitCode.CONFLICT, path=relative)
    payload = ["file", *identity_after, hashlib.sha256(content).hexdigest()]
    fingerprint = "sha256:" + hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode("utf-8")).hexdigest()
    return _PathSnapshot(relative, "file", fingerprint), content


def _snapshot(path: Path, root: Path) -> _PathSnapshot:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise MacError("DOCTOR_REPAIR_PLAN_CHANGED", f"repair candidate disappeared: {path}", exit_code=ExitCode.CONFLICT) from exc
    relative = path.relative_to(root).as_posix()
    if stat.S_ISLNK(metadata.st_mode):
        raise MacError("DOCTOR_REPAIR_ARTIFACT_UNSAFE", f"repair candidate is a symlink: {relative}", exit_code=ExitCode.SECURITY, path=relative)
    if stat.S_ISREG(metadata.st_mode):
        return _capture_regular_file(path, root)[0]
    elif stat.S_ISDIR(metadata.st_mode):
        before_identity = (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_mtime_ns)
        rows: list[object] = [[".", "dir", *before_identity]]
        total = 0
        for child in sorted(path.rglob("*"), key=lambda value: value.as_posix()):
            child_metadata = child.lstat()
            child_relative = child.relative_to(path).as_posix()
            if stat.S_ISLNK(child_metadata.st_mode):
                raise MacError("DOCTOR_REPAIR_ARTIFACT_UNSAFE", f"repair directory contains a symlink: {relative}/{child_relative}", exit_code=ExitCode.SECURITY, path=relative)
            if stat.S_ISDIR(child_metadata.st_mode):
                rows.append([child_relative, "dir", child_metadata.st_mtime_ns])
                continue
            if not stat.S_ISREG(child_metadata.st_mode):
                raise MacError("DOCTOR_REPAIR_ARTIFACT_UNSAFE", f"repair directory contains a special file: {relative}/{child_relative}", exit_code=ExitCode.SECURITY, path=relative)
            total += child_metadata.st_size
            if total > _MAX_RECOVERY_ARTIFACT_BYTES:
                raise MacError("DOCTOR_REPAIR_ARTIFACT_TOO_LARGE", f"repair directory exceeds size limit: {relative}", exit_code=ExitCode.SECURITY, path=relative)
            child_snapshot, _ = _capture_regular_file(child, root)
            rows.append([child_relative, child_snapshot.fingerprint])
        after = path.lstat()
        after_identity = (after.st_dev, after.st_ino, after.st_mode, after.st_mtime_ns)
        if before_identity != after_identity:
            raise MacError("DOCTOR_REPAIR_PLAN_CHANGED", f"repair directory changed while being frozen: {relative}", exit_code=ExitCode.CONFLICT, path=relative)
        payload = rows
        kind = "directory"
    else:
        raise MacError("DOCTOR_REPAIR_ARTIFACT_UNSAFE", f"repair candidate is not a regular file or directory: {relative}", exit_code=ExitCode.SECURITY, path=relative)
    fingerprint = "sha256:" + hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode("utf-8")).hexdigest()
    return _PathSnapshot(relative, kind, fingerprint)


def _load_frozen_data(path: Path, root: Path) -> tuple[dict[str, Any], _PathSnapshot]:
    snapshot, content = _capture_regular_file(path, root)
    if len(content) > 1_048_576:
        raise MacError("DOCTOR_REPLAY_INPUT_INVALID", f"replay input exceeds 1 MiB: {snapshot.relative}", exit_code=ExitCode.SECURITY, path=snapshot.relative)
    try:
        if path.suffix.lower() == ".json":
            value = json.loads(content.decode("utf-8"))
        else:
            from .security import parse_yaml_safely

            value = parse_yaml_safely(content)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise MacError("DOCTOR_REPLAY_INPUT_INVALID", f"cannot parse frozen input {snapshot.relative}: {exc}", exit_code=ExitCode.CORRUPTION, path=snapshot.relative) from exc
    if not isinstance(value, dict):
        raise MacError("DOCTOR_REPLAY_INPUT_INVALID", f"frozen input is not an object: {snapshot.relative}", exit_code=ExitCode.CORRUPTION, path=snapshot.relative)
    return normalize_data(value), snapshot


def _validate_snapshot(snapshot: _PathSnapshot, root: Path) -> None:
    current = _snapshot(root / snapshot.relative, root)
    if current != snapshot:
        raise MacError("DOCTOR_REPAIR_PLAN_CHANGED", f"repair candidate changed after preview: {snapshot.relative}", exit_code=ExitCode.CONFLICT, path=snapshot.relative)


def _known_materialization(parts: tuple[str, ...]) -> bool:
    if parts == ("INDEX.generated.json",):
        return True
    if len(parts) < 2 or not is_identifier(parts[0], "TASK"):
        return False
    if len(parts) == 2:
        return parts[1] in {"task.yaml", "scope-contract.yaml"}
    if len(parts) != 3:
        return False
    directory, name = parts[1], parts[2]
    if directory == "scope-history":
        return bool(_SCOPE_HISTORY.fullmatch(name))
    layout = _ENTITY_LAYOUT.get(directory)
    if layout is None:
        return False
    prefix, suffix = layout
    return name.endswith(suffix) and is_identifier(name[: -len(suffix)], prefix)


def _known_atomic_file(tasks: Path, path: Path) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    match = _ATOMIC_FILE.fullmatch(path.name)
    if match is None:
        return False
    destination = path.with_name(match.group("target"))
    try:
        parts = destination.relative_to(tasks).parts
    except ValueError:
        return False
    return _known_materialization(parts)


def _known_staging_directory(tasks: Path, path: Path) -> bool:
    if path.parent != tasks or path.is_symlink() or not path.is_dir():
        return False
    parts = path.name.split(".")
    if len(parts) != 4 or parts[0] or parts[3] != "tmp":
        return False
    task_id, transaction_id = parts[1], parts[2]
    if not is_identifier(task_id, "TASK") or not is_identifier(transaction_id, "TXN"):
        return False
    for child in path.rglob("*"):
        if child.is_symlink():
            return False
        relative = child.relative_to(path)
        if child.is_dir():
            if len(relative.parts) != 1 or relative.parts[0] not in {*_ENTITY_LAYOUT, "scope-history"}:
                return False
            continue
        if not child.is_file():
            return False
        candidate_parts = (task_id, *relative.parts)
        if _known_materialization(candidate_parts):
            continue
        match = _ATOMIC_FILE.fullmatch(child.name)
        if match is None:
            return False
        destination_parts = (task_id, *relative.parent.parts, match.group("target"))
        if not _known_materialization(destination_parts):
            return False
    return True


def _known_temporary_files(tasks: Path, *, now: float | None = None) -> list[Path]:
    if not tasks.is_dir():
        return []
    cutoff = (now if now is not None else time.time()) - _MINIMUM_TEMP_AGE_SECONDS
    staging = [path for path in tasks.glob(".*.tmp") if _known_staging_directory(tasks, path)]
    candidates: list[Path] = []
    for path in sorted([*staging, *(item for item in tasks.rglob("*.tmp") if item.is_file())]):
        if any(parent in staging for parent in path.parents):
            continue
        try:
            old_enough = path.lstat().st_mtime <= cutoff
        except OSError:
            old_enough = False
        if old_enough and (path in staging or _known_atomic_file(tasks, path)):
            candidates.append(path)
    return candidates


def _lease_payload(path: Path) -> dict[str, Any] | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65_536:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        expires = float(data["expires_unix"])
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not is_identifier(str(data.get("token", "")), "LEASE"):
        return None
    if not isinstance(data.get("owner"), str) or not data["owner"] or not isinstance(data.get("acquired_at"), str) or not data["acquired_at"]:
        return None
    if expires != expires or expires in {float("inf"), float("-inf")}:
        return None
    return data


def _lease_artifacts(tasks: Path, *, now: float | None = None) -> tuple[list[Path], int]:
    current = now if now is not None else time.time()
    expired: list[Path] = []
    recognized: set[Path] = set()
    if not tasks.is_dir():
        return expired, 0
    for task_dir in sorted(path for path in tasks.iterdir() if path.is_dir() and is_identifier(path.name, "TASK")):
        private = task_dir / "private"
        active = private / "controller.lease"
        if active.exists():
            data = _lease_payload(active)
            if data is not None:
                recognized.add(active)
                if float(data["expires_unix"]) <= current:
                    expired.append(active)
        if private.is_dir():
            for path in private.glob(".controller.lease.*.expired"):
                match = _LEASE_QUARANTINE.fullmatch(path.name)
                data = _lease_payload(path)
                if match is None or data is None:
                    continue
                recognized.add(path)
                try:
                    if float(data["expires_unix"]) <= current and path.stat().st_mtime <= current - _MINIMUM_TEMP_AGE_SECONDS:
                        expired.append(path)
                except OSError:
                    continue
    lookalikes = set(tasks.rglob("controller.lease")) | set(tasks.rglob(".controller.lease.*.expired"))
    return sorted(expired), len(lookalikes - recognized)


def _expired_leases(tasks: Path, *, now: float | None = None) -> list[Path]:
    return _lease_artifacts(tasks, now=now)[0]


def _replay_error(task_id: str, exc: BaseException) -> MacError:
    code = exc.code if isinstance(exc, MacError) else type(exc).__name__
    return MacError(
        "DOCTOR_REPLAY_INPUT_INVALID",
        f"{task_id} cannot be deterministically replayed ({code}): {exc}",
        exit_code=ExitCode.CORRUPTION,
        task_id=task_id,
        details={"cause": code},
    )


def _projection_plan(root: Path, task_dir: Path) -> _ProjectionPlan:
    task_id = task_dir.name
    if not is_identifier(task_id, "TASK") or task_dir.is_symlink():
        raise _replay_error(task_id, ValueError("task directory identity is invalid"))
    events_dir = task_dir / "events"
    try:
        if events_dir.is_symlink() or not events_dir.is_dir():
            raise ValueError("events directory is missing or unsafe")
        event_paths: list[Path] = []
        for path in sorted(events_dir.iterdir()):
            if _known_atomic_file(root / "tasks", path):
                try:
                    if path.stat().st_mtime <= time.time() - _MINIMUM_TEMP_AGE_SECONDS:
                        continue
                except OSError:
                    pass
                raise ValueError(f"atomic event write is still in progress: {path.name}")
            if path.is_symlink() or not path.is_file() or path.suffix != ".json" or not is_identifier(path.stem, "EVT"):
                raise ValueError(f"unexpected replay input: {path.name}")
            event_paths.append(path)
        if not event_paths:
            raise ValueError("no committed event inputs")
        events: list[dict[str, Any]] = []
        inputs: list[_PathSnapshot] = []
        for path in event_paths:
            event, frozen = _load_frozen_data(path, root)
            if event.get("event_id") != path.stem or event.get("task_id") != task_id:
                raise ValueError(f"event identity does not match path: {path.name}")
            events.append(event)
            inputs.append(frozen)
        events = _validate_loaded_event_stream(
            root,
            task_id,
            events,
            frozen_policy_cache={},
        )
        projection = replay_events(events)
        if projection.get("id") != task_id:
            raise ValueError("replayed task identity does not match directory")
        snapshots = replay_entity_snapshots(events)
        current_scope, scope_history = replay_scope_snapshots(events)
        expected_outputs: list[tuple[str, str, dict[str, Any]]] = [
            ((task_dir / "task.yaml").relative_to(root).as_posix(), "yaml", projection)
        ]
        if current_scope is not None:
            expected_outputs.append(
                ((task_dir / "scope-contract.yaml").relative_to(root).as_posix(), "yaml", current_scope)
            )
            for version, scope_snapshot in sorted(scope_history.items()):
                expected_outputs.append(
                    (
                        (task_dir / "scope-history" / f"scope-contract.v{version}.yaml").relative_to(root).as_posix(),
                        "yaml",
                        scope_snapshot,
                    )
                )
        for directory, entities in snapshots.items():
            prefix, extension = _ENTITY_LAYOUT[directory]
            for entity_id, entity in sorted(entities.items()):
                if not is_identifier(entity_id, prefix) or entity.get("id") != entity_id or entity.get("task_id") != task_id:
                    raise ValueError(f"unsafe replayed {directory} identity: {entity_id}")
                relative = (task_dir / directory / f"{entity_id}{extension}").relative_to(root).as_posix()
                expected_outputs.append((relative, "yaml" if extension == ".yaml" else "json", entity))
        outputs: list[tuple[str, str, dict[str, Any]]] = []
        drift: list[str] = []
        for relative, encoding, expected in expected_outputs:
            try:
                actual = load_data(root / relative)
            except Exception:
                actual = None
            if actual != expected:
                drift.append(relative)
                outputs.append((relative, encoding, expected))
        return _ProjectionPlan(task_id, tuple(inputs), projection, tuple(outputs), tuple(sorted(drift)))
    except MacError as exc:
        if exc.code == "DOCTOR_REPLAY_INPUT_INVALID":
            raise
        raise _replay_error(task_id, exc) from exc
    except Exception as exc:
        raise _replay_error(task_id, exc) from exc


def _index_row(task: dict[str, Any]) -> dict[str, Any]:
    return {key: task.get(key) for key in ("id", "title", "mode", "state", "revision", "updated_at", "legacy_id") if task.get(key) is not None}


def _repair_plan(root: Path) -> _RepairPlan:
    tasks = root / "tasks"
    temporary_paths = _known_temporary_files(tasks)
    lease_paths = _expired_leases(tasks)
    temporary = tuple(_snapshot(path, root) for path in temporary_paths)
    leases = tuple(_snapshot(path, root) for path in lease_paths)
    all_projection_plans: list[_ProjectionPlan] = []
    if tasks.is_dir():
        for task_dir in sorted(path for path in tasks.iterdir() if path.is_dir() and (path / "events").exists()):
            all_projection_plans.append(_projection_plan(root, task_dir))
    # Every replay stream feeds the generated index, even when its materialized
    # task projection is already current, so all event inputs stay frozen.
    projections = tuple(all_projection_plans)
    projected = {plan.task_id: plan.task_projection for plan in all_projection_plans}
    index_inputs: list[_PathSnapshot] = []
    rows: list[dict[str, Any]] = []
    if tasks.is_dir():
        for task_path in sorted(tasks.glob("TASK-*/task.yaml")):
            task_id = task_path.parent.name
            if not is_identifier(task_id, "TASK"):
                raise MacError("DOCTOR_INDEX_INPUT_INVALID", f"invalid task directory in index: {task_id}", exit_code=ExitCode.CORRUPTION)
            if task_id in projected:
                task = projected[task_id]
            else:
                try:
                    task, frozen = _load_frozen_data(task_path, root)
                    index_inputs.append(frozen)
                except Exception as exc:
                    raise MacError("DOCTOR_INDEX_INPUT_INVALID", f"cannot freeze index input {task_id}: {exc}", exit_code=ExitCode.CORRUPTION) from exc
            rows.append(_index_row(task))
    rows.sort(key=lambda row: str(row.get("id", "")))
    plan_payload = {
        "temporary": [[snapshot.relative, snapshot.kind, snapshot.fingerprint] for snapshot in temporary],
        "leases": [[snapshot.relative, snapshot.kind, snapshot.fingerprint] for snapshot in leases],
        "projections": [
            {
                "task_id": plan.task_id,
                "inputs": [[item.relative, item.kind, item.fingerprint] for item in plan.replay_inputs],
                "drift": list(plan.drift),
                "outputs": [[relative, encoding, value] for relative, encoding, value in plan.outputs],
            }
            for plan in projections
        ],
        "index_inputs": [[item.relative, item.kind, item.fingerprint] for item in index_inputs],
        "index_rows": rows,
    }
    digest = "sha256:" + hashlib.sha256(json.dumps(plan_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return _RepairPlan(temporary, leases, projections, tuple(index_inputs), tuple(rows), digest)


def _validate_repair_plan(plan: _RepairPlan, root: Path) -> None:
    for snapshot in (*plan.temporary, *plan.leases, *plan.index_inputs):
        _validate_snapshot(snapshot, root)
    for projection in plan.projections:
        for snapshot in projection.replay_inputs:
            _validate_snapshot(snapshot, root)


def run_doctor(repo: Path) -> DoctorReport:
    """Inspect the repository without creating, deleting, or rewriting files."""
    root = repo.resolve()
    tasks = root / "tasks"
    config = root / ".agents/config.yaml"
    ownership = root / ".agents/ownership.yaml"
    workflows = root / ".agents/workflows"
    profiles = root / ".agents/runtime-profiles"
    temporary = _known_temporary_files(tasks)
    leases, unsafe_leases = _lease_artifacts(tasks)
    temp_lookalikes = 0
    if tasks.is_dir():
        known_temporary = set(temporary)
        temp_lookalikes = sum(1 for path in tasks.rglob("*.tmp") if path not in known_temporary and not any(parent in known_temporary for parent in path.parents))
    tracked_private = _tracked_private_files(root)
    untracked_logs = _untracked_sensitive_log_count(root)
    path_risks = _path_risk_count(root)
    policy_drift = _policy_drift_count(root)
    migration_incomplete = _migration_incomplete_count(root)
    cli_version = _cli_version(root)
    projection_drift = 0
    replay_errors: list[str] = []
    if tasks.is_dir():
        for task_dir in sorted(path for path in tasks.iterdir() if path.is_dir() and (path / "events").exists()):
            try:
                projection_drift += len(_projection_plan(root, task_dir).drift)
            except MacError as exc:
                replay_errors.append(f"{task_dir.name}: {exc}")
    local_schema_bundle = (root / "schemas").is_dir() or (root / ".agents/schemas.lock.json").is_file()
    lock_issues = schema_lock_issues(root, root / "schemas") if local_schema_bundle else []
    schema_message = ("schema lock matches" if local_schema_bundle else "using the executable's locked schema bundle") if not lock_issues else "; ".join(item.message for item in lock_issues)
    try:
        schemas = SchemaSet()
        executable_schema_ok, executable_schema_message = True, "executable schema bundle matches its lock"
    except Exception as exc:
        schemas = None
        executable_schema_ok, executable_schema_message = False, str(exc)
    try:
        if schemas is None:
            raise ValueError(executable_schema_message)
        policy = compile_policy(root, schemas=schemas)
        policy_ok, policy_message = True, f"compiled {policy.workflow.get('name')} with {policy.runtime_profile.get('id')}"
    except Exception as exc:
        policy_ok, policy_message = False, str(exc)
    repository_errors = 0
    repository_message = "repository entities validate"
    try:
        from .repository import validate_repository

        validation = validate_repository(root, schemas) if schemas is not None else []
        repository_errors = sum(1 for issue in validation if issue.severity == "error")
        if repository_errors:
            first = next(issue for issue in validation if issue.severity == "error")
            repository_message = f"{repository_errors} validation errors; first={first.code} at {first.path or '<root>'}"
    except Exception as exc:
        repository_errors = 1
        repository_message = f"repository validation failed: {exc}"
    checks = (
        DoctorCheck("python_runtime", sys.version_info >= (3, 11), True, f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"),
        DoctorCheck("cli_version", bool(cli_version), True, f"multi-agent-collab {cli_version or 'unknown'}"),
        DoctorCheck("git_repository", _git_available(root), False, "Git repository available"),
        DoctorCheck("config", config.is_file(), True, ".agents/config.yaml exists"),
        DoctorCheck("ownership", ownership.is_file(), True, ".agents/ownership.yaml exists"),
        DoctorCheck("workflow", workflows.is_dir() and any(workflows.glob("*.yaml")), True, "at least one workflow exists"),
        DoctorCheck("runtime_profiles", profiles.is_dir() and any(profiles.glob("*.yaml")), True, "at least one runtime profile exists"),
        DoctorCheck("executable_schema_lock", executable_schema_ok, True, executable_schema_message),
        DoctorCheck("schema_lock", not lock_issues, True, schema_message),
        DoctorCheck("compiled_policy", policy_ok, True, policy_message),
        DoctorCheck("repository_validation", repository_errors == 0, True, repository_message),
        DoctorCheck("event_replay_integrity", not replay_errors, True, "all event streams replay deterministically" if not replay_errors else replay_errors[0]),
        DoctorCheck("tracked_private_artifacts", not tracked_private, True, f"{len(tracked_private)} private artifact files are tracked"),
        DoctorCheck("path_case_and_symlink_risk", path_risks == 0, True, f"{path_risks} path collision or symlink escape risks"),
        DoctorCheck("untracked_sensitive_logs", untracked_logs == 0, False, f"{untracked_logs} untracked private/log artifacts"),
        DoctorCheck("policy_drift", policy_drift == 0, False, f"{policy_drift} frozen policy references differ from the current policy"),
        DoctorCheck("projection_drift", projection_drift == 0, False, f"{projection_drift} derived projections require rebuild"),
        DoctorCheck("migration_completion", migration_incomplete == 0, False, f"{migration_incomplete} legacy tasks are not represented in tasks-v6"),
        DoctorCheck("recoverable_temporary_files", not temporary, False, f"{len(temporary)} proven, old interrupted atomic writes"),
        DoctorCheck("expired_controller_leases", not leases, False, f"{len(leases)} proven expired controller lease artifacts"),
        DoctorCheck("unrecognized_recovery_artifacts", temp_lookalikes + unsafe_leases == 0, False, f"{temp_lookalikes} unrecognized temp and {unsafe_leases} invalid lease lookalikes were left untouched"),
    )
    return DoctorReport(all(item.ok for item in checks if item.required), checks)


def repair_safe(repo: Path, *, apply: bool = False, expected_plan_digest: str | None = None) -> RepairReport:
    """Preview or apply a frozen, fingerprinted repair plan for derived state only."""
    from .repository import FilesystemTaskRepository

    root = repo.resolve()
    tasks = root / "tasks"
    plan = _repair_plan(root)
    if apply and expected_plan_digest is None:
        raise MacError(
            "DOCTOR_REPAIR_PLAN_DIGEST_REQUIRED",
            "applying repair-safe requires the exact digest returned by preview",
            exit_code=ExitCode.CLI_USAGE,
        )
    if expected_plan_digest is not None and plan.digest != expected_plan_digest:
        raise MacError("DOCTOR_REPAIR_PLAN_CHANGED", "repair candidate set changed after preview", exit_code=ExitCode.CONFLICT, details={"expected": expected_plan_digest, "actual": plan.digest})
    if apply:
        _validate_repair_plan(plan, root)
        for snapshot in plan.temporary:
            path = root / snapshot.relative
            if snapshot.kind == "directory":
                shutil.rmtree(path)
            else:
                path.unlink()
        for snapshot in plan.leases:
            (root / snapshot.relative).unlink()
        repository = FilesystemTaskRepository(root)
        for projection in plan.projections:
            with repository.lease(projection.task_id, "doctor-repair-safe"):
                for snapshot in projection.replay_inputs:
                    _validate_snapshot(snapshot, root)
                for relative, encoding, value in projection.outputs:
                    writer = atomic_write_yaml if encoding == "yaml" else atomic_write_json
                    writer(root / relative, value)
        atomic_write_json(tasks / "INDEX.generated.json", {"schema_version": 1, "tasks": list(plan.index_rows)})
    projection_paths = tuple(path for projection in plan.projections for path in projection.drift)
    index_path = tasks / "INDEX.generated.json"
    return RepairReport(
        apply,
        plan.digest,
        tuple(snapshot.relative for snapshot in plan.temporary),
        tuple(snapshot.relative for snapshot in plan.leases),
        projection_paths,
        index_path.relative_to(root).as_posix(),
    )
