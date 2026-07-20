from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import subprocess
import time
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from .errors import ExitCode, MacError, MacIssue
from .events import replay_entity_snapshots, replay_events, replay_work_units
from .ids import prefixed
from .io import atomic_write_json, atomic_write_yaml, load_data
from .policy import compile_policy
from .schema_validation import SchemaSet
from .state_machine import TERMINAL_STATES, TransitionContext, evaluate_transition, validate_workflow_invariants

SCHEMA_MAP = {"task.yaml": "task.schema.json", "scope-contract.yaml": "scope-contract.schema.json"}
PATTERN_SCHEMAS = {
    "work-units/*.yaml": "work-unit.schema.json", "runs/*.json": "run.schema.json",
    "results/*.json": "result.schema.json", "findings/*.json": "finding.schema.json",
    "evidence/*.json": "evidence.schema.json", "approvals/*.json": "approval.schema.json",
    "risk-acceptances/*.json": "risk-acceptance.schema.json", "events/*.json": "event.schema.json",
}
V6_TASK_ENTRY_NAMES = frozenset(SCHEMA_MAP) | frozenset(pattern.partition("/")[0] for pattern in PATTERN_SCHEMAS)
CONTROLLER_CAS_FILENAME = ".controller.lease.cas"
CONTROLLER_CAS_LOCK_FILENAME = ".controller.lease.cas.lock"
CONTROLLER_CAS_TTL_SECONDS = 30.0
LEGACY_CONTROLLER_CAS_STALE_SECONDS = 300.0


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _process_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (OSError, OverflowError, ValueError) as exc:
        # Windows reports ERROR_INVALID_PARAMETER as EINVAL for a missing PID.
        return getattr(exc, "errno", None) not in {3, 22}
    return True


def _controller_cas_payload(raw: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(raw.decode("utf-8"))
        created_at = str(value["created_at"])
        datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        expires_unix = float(value["expires_unix"])
        pid = value["pid"]
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("token"), str)
            or not value["token"].startswith("CAS-")
            or not isinstance(value.get("owner"), str)
            or not value["owner"]
            or not isinstance(pid, int)
            or isinstance(pid, bool)
            or pid <= 0
            or not math.isfinite(expires_unix)
        ):
            return None
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value


def controller_cas_recoverable(path: Path, *, now: float | None = None) -> bool:
    """Conservatively classify a regular CAS guard as expired or orphaned."""
    try:
        if path.is_symlink() or not path.is_file():
            return False
        raw = path.read_bytes()
        modified = path.stat().st_mtime
    except OSError:
        return False
    current = time.time() if now is None else now
    payload = _controller_cas_payload(raw)
    if payload is None:
        return modified <= current - LEGACY_CONTROLLER_CAS_STALE_SECONDS
    return float(payload["expires_unix"]) <= current or not _process_is_alive(int(payload["pid"]))


def _lock_descriptor(descriptor: int, *, blocking: bool) -> bool:
    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
    except OSError:
        return False
    return True


def _unlock_descriptor(descriptor: int) -> None:
    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)
    except OSError:
        pass


def controller_cas_coordination_is_active(private: Path) -> bool:
    """Read-only active check used by doctor; absence of a lock file is inactive."""
    lock_path = private / CONTROLLER_CAS_LOCK_FILENAME
    try:
        if lock_path.is_symlink():
            return True
        if not lock_path.exists():
            return False
        if not lock_path.is_file():
            return True
        descriptor = os.open(lock_path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return True
    try:
        if not _lock_descriptor(descriptor, blocking=False):
            return True
        opened = os.fstat(descriptor)
        current = lock_path.stat(follow_symlinks=False)
        if lock_path.is_symlink() or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            _unlock_descriptor(descriptor)
            return True
        _unlock_descriptor(descriptor)
        return False
    except OSError:
        return True
    finally:
        os.close(descriptor)


def git_head(repo: Path) -> str | None:
    try:
        result = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    value = result.stdout.strip().lower()
    return value if len(value) == 40 else None


def build_policy_ref(repo: Path, relative_paths: list[str]) -> dict[str, Any]:
    head = git_head(repo)
    rows = []
    all_from_commit = bool(head)
    for relative in relative_paths:
        path = repo / relative
        if path.is_file():
            raw: bytes | None = None
            if head:
                try:
                    raw = subprocess.run(
                        ["git", "-C", str(repo), "show", f"{head}:{Path(relative).as_posix()}"],
                        check=True, capture_output=True,
                    ).stdout
                except (FileNotFoundError, subprocess.CalledProcessError):
                    all_from_commit = False
            if raw is None:
                raw = path.read_bytes()
            rows.append({"path": Path(relative).as_posix(), "digest": sha256_bytes(raw)})
    rows.sort(key=lambda row: row["path"])
    result: dict[str, Any] = {"combined_digest": sha256_bytes(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()), "files": rows}
    if head and all_from_commit:
        result["source_commit"] = head
    return result


@dataclass(frozen=True, slots=True)
class AppendResult:
    event: dict[str, Any]
    projection: dict[str, Any]
    idempotent_replay: bool = False


class FilesystemTaskRepository:
    def __init__(self, repo: Path) -> None:
        self.repo = repo.resolve()
        self.tasks_root = self.repo / "tasks"

    def task_dir(self, task_id: str) -> Path:
        if "/" in task_id or "\\" in task_id or task_id in {"", ".", ".."}:
            raise MacError("TASK_ID_UNSAFE", "unsafe task id", exit_code=ExitCode.SECURITY)
        return self.tasks_root / task_id

    def list_events(self, task_id: str) -> list[dict[str, Any]]:
        events = []
        for path in sorted((self.task_dir(task_id) / "events").glob("EVT-*.json")):
            events.append(load_data(path))
        return events

    def find_idempotency(self, key: str) -> tuple[str, dict[str, Any]] | None:
        for task_dir in sorted(path for path in self.tasks_root.glob("TASK-*") if path.is_dir()) if self.tasks_root.is_dir() else []:
            for event in self.list_events(task_dir.name):
                if event.get("idempotency_key") == key:
                    return task_dir.name, event
        return None

    def load_task(self, task_id: str) -> dict[str, Any]:
        path = self.task_dir(task_id) / "task.yaml"
        if not path.is_file():
            raise MacError(
                "TASK_NOT_FOUND",
                f"task {task_id} does not exist",
                exit_code=ExitCode.VALIDATION,
                path=path.relative_to(self.repo).as_posix(),
                task_id=task_id,
                suggestion="check the task id with `mac task list`",
            )
        return load_data(path)

    def _replayed_state(self, task_id: str) -> tuple[dict[str, Any], dict[str, dict[str, dict[str, Any]]]]:
        events = self.list_events(task_id)
        try:
            seed = self.load_task(task_id)
        except MacError:
            seed = None
        projection = replay_events(events, initial_projection=seed)
        snapshots = replay_entity_snapshots(events, initial_projection=seed)
        return projection, snapshots

    def projection_drift(self, task_id: str) -> list[str]:
        projection, snapshots = self._replayed_state(task_id)
        drift: list[str] = []
        task_path = self.task_dir(task_id) / "task.yaml"
        try:
            current_task = load_data(task_path)
        except (FileNotFoundError, ValueError):
            current_task = None
        if current_task != projection:
            drift.append(task_path.relative_to(self.repo).as_posix())
        for directory, entities in snapshots.items():
            extension = "yaml" if directory == "work-units" else "json"
            for entity_id, entity in entities.items():
                path = self.task_dir(task_id) / directory / f"{entity_id}.{extension}"
                try:
                    current = load_data(path)
                except (FileNotFoundError, ValueError):
                    current = None
                if current != entity:
                    drift.append(path.relative_to(self.repo).as_posix())
        return sorted(drift)

    def rebuild_task(self, task_id: str) -> dict[str, Any]:
        projection, snapshots = self._replayed_state(task_id)
        atomic_write_yaml(self.task_dir(task_id) / "task.yaml", projection)
        for directory, entities in snapshots.items():
            extension = "yaml" if directory == "work-units" else "json"
            for entity_id, entity in entities.items():
                writer = atomic_write_yaml if extension == "yaml" else atomic_write_json
                writer(self.task_dir(task_id) / directory / f"{entity_id}.{extension}", entity)
        return projection

    def _existing_idempotency(self, task_id: str, key: str) -> dict[str, Any] | None:
        return next((event for event in self.list_events(task_id) if event.get("idempotency_key") == key), None)

    def _lease_private_dir(self, task_id: str) -> Path:
        task = self.task_dir(task_id)
        try:
            tasks_root = self.tasks_root.resolve(strict=True)
            tasks_root.relative_to(self.repo)
            if self.tasks_root.is_symlink() or task.is_symlink() or not task.is_dir():
                raise ValueError
            task_root = task.resolve(strict=True)
            if task_root.parent != tasks_root:
                raise ValueError
            private = task / "private"
            if private.is_symlink():
                raise ValueError
            private.mkdir(parents=False, exist_ok=True)
            if private.resolve(strict=True).parent != task_root:
                raise ValueError
        except (FileNotFoundError, OSError, ValueError) as exc:
            raise MacError(
                "LEASE_PATH_UNSAFE", "controller lease private directory is outside the task",
                exit_code=ExitCode.SECURITY, task_id=task_id,
            ) from exc
        return private

    @contextmanager
    def _lease_coordination_lock(self, task_id: str) -> Iterator[Path]:
        private = self._lease_private_dir(task_id)
        lock_path = private / CONTROLLER_CAS_LOCK_FILENAME
        if lock_path.is_symlink():
            raise MacError(
                "LEASE_PATH_UNSAFE", "lease coordination lock must not be a symlink",
                exit_code=ExitCode.SECURITY, task_id=task_id,
            )
        try:
            descriptor = os.open(
                lock_path,
                os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
        except OSError as exc:
            raise MacError(
                "LEASE_CONFLICT", "cannot open lease coordination lock",
                exit_code=ExitCode.CONFLICT, task_id=task_id,
            ) from exc
        acquired = False
        try:
            for _ in range(50):
                if _lock_descriptor(descriptor, blocking=False):
                    acquired = True
                    break
                time.sleep(0.002)
            if not acquired:
                raise MacError(
                    "LEASE_CONFLICT", "lease compare-and-replace is busy",
                    exit_code=ExitCode.CONFLICT, task_id=task_id,
                )
            opened = os.fstat(descriptor)
            current = lock_path.stat(follow_symlinks=False)
            if lock_path.is_symlink() or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise MacError(
                    "LEASE_PATH_UNSAFE", "lease coordination lock changed while opening",
                    exit_code=ExitCode.SECURITY, task_id=task_id,
                )
            yield private
        finally:
            if acquired:
                _unlock_descriptor(descriptor)
            os.close(descriptor)

    @staticmethod
    def _guard_snapshot(path: Path) -> tuple[tuple[int, int, int, int], bytes]:
        raw = path.read_bytes()
        status = path.stat()
        identity = (status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns)
        return identity, raw

    def _quarantine_recoverable_cas(self, task_id: str, path: Path, *, now: float | None = None) -> Path:
        try:
            observed = self._guard_snapshot(path)
        except OSError as exc:
            raise MacError(
                "LEASE_CONFLICT", "lease compare-and-replace guard changed",
                exit_code=ExitCode.CONFLICT, task_id=task_id,
            ) from exc
        if not controller_cas_recoverable(path, now=now):
            raise MacError(
                "LEASE_CONFLICT", "lease compare-and-replace guard is active or unverifiable",
                exit_code=ExitCode.CONFLICT, task_id=task_id,
            )
        quarantine = path.with_name(f"{CONTROLLER_CAS_FILENAME}.{prefixed('CAS')}.expired")
        try:
            os.replace(path, quarantine)
            moved = self._guard_snapshot(quarantine)
        except OSError as exc:
            raise MacError(
                "LEASE_CONFLICT", "stale guard takeover lost an atomic race",
                exit_code=ExitCode.CONFLICT, task_id=task_id,
            ) from exc
        if moved != observed:
            try:
                os.link(quarantine, path)
                quarantine.unlink()
            except OSError:
                descriptor: int | None = None
                try:
                    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    os.write(descriptor, moved[1])
                    os.fsync(descriptor)
                except OSError:
                    pass
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
            raise MacError(
                "LEASE_CONFLICT", "stale guard changed during atomic quarantine",
                exit_code=ExitCode.CONFLICT, task_id=task_id,
            )
        return quarantine

    @contextmanager
    def _lease_cas_guard(self, task_id: str, owner: str) -> Iterator[None]:
        """Serialize lease read/replace/create as one compare-and-replace step."""
        token = prefixed("CAS")
        quarantine: Path | None = None
        with self._lease_coordination_lock(task_id) as private:
            path = private / CONTROLLER_CAS_FILENAME
            if path.is_symlink():
                raise MacError(
                    "LEASE_PATH_UNSAFE", "lease compare-and-replace guard must not be a symlink",
                    exit_code=ExitCode.SECURITY, task_id=task_id,
                )
            if path.exists():
                quarantine = self._quarantine_recoverable_cas(task_id, path)
            payload = {
                "token": token,
                "owner": owner,
                "pid": os.getpid(),
                "created_at": utc_now(),
                "expires_unix": time.time() + CONTROLLER_CAS_TTL_SECONDS,
            }
            descriptor: int | None = None
            try:
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.write(descriptor, json.dumps(payload, sort_keys=True).encode("utf-8"))
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = None
                if quarantine is not None:
                    try:
                        quarantine.unlink()
                    except OSError:
                        pass
                yield
            except FileExistsError as exc:
                raise MacError(
                    "LEASE_CONFLICT", "lease compare-and-replace lost an atomic race",
                    exit_code=ExitCode.CONFLICT, task_id=task_id,
                ) from exc
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                try:
                    current = _controller_cas_payload(path.read_bytes())
                    if current is not None and current.get("token") == token:
                        path.unlink()
                except FileNotFoundError:
                    pass

    def repair_stale_cas_guard(self, task_id: str, *, now: float | None = None) -> bool:
        """Atomically quarantine and remove one revalidated orphaned CAS guard."""
        try:
            with self._lease_coordination_lock(task_id) as private:
                path = private / CONTROLLER_CAS_FILENAME
                if path.is_symlink() or not path.exists():
                    return False
                try:
                    quarantine = self._quarantine_recoverable_cas(task_id, path, now=now)
                except MacError as exc:
                    if exc.code == "LEASE_CONFLICT":
                        return False
                    raise
                try:
                    quarantine.unlink()
                except OSError:
                    pass
                return True
        except MacError as exc:
            if exc.code == "LEASE_CONFLICT":
                return False
            raise

    @contextmanager
    def lease(self, task_id: str, owner: str, *, ttl_seconds: float = 30.0) -> Iterator[str]:
        private = self._lease_private_dir(task_id)
        path = private / "controller.lease"
        token = prefixed("LEASE")
        payload = {"token": token, "owner": owner, "acquired_at": utc_now(), "expires_unix": time.time() + ttl_seconds}
        quarantined: Path | None = None
        with self._lease_cas_guard(task_id, owner):
            if path.is_symlink():
                raise MacError(
                    "LEASE_PATH_UNSAFE", "controller lease must not be a symlink",
                    exit_code=ExitCode.SECURITY, task_id=task_id,
                )
            if path.exists():
                try:
                    current = json.loads(path.read_text(encoding="utf-8"))
                    expired = float(current.get("expires_unix", 0)) <= time.time()
                except Exception:
                    expired = False
                if not expired:
                    raise MacError("LEASE_CONFLICT", "task controller lease is active", exit_code=ExitCode.CONFLICT, task_id=task_id)
                quarantined = path.with_name(f".{path.name}.{prefixed('LEASE')}.expired")
                try:
                    os.replace(path, quarantined)
                except FileNotFoundError as exc:
                    raise MacError("LEASE_CONFLICT", "expired lease takeover lost an atomic race", exit_code=ExitCode.CONFLICT, task_id=task_id) from exc
            try:
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, sort_keys=True)
                    handle.flush()
                    os.fsync(handle.fileno())
            except FileExistsError as exc:
                raise MacError("LEASE_CONFLICT", "lease compare-and-replace lost an atomic race", exit_code=ExitCode.CONFLICT, task_id=task_id) from exc
            if quarantined is not None:
                try:
                    quarantined.unlink()
                except FileNotFoundError:
                    pass
        try:
            yield token
        finally:
            with self._lease_cas_guard(task_id, owner):
                try:
                    current = json.loads(path.read_text(encoding="utf-8"))
                    if current.get("token") == token:
                        path.unlink()
                except FileNotFoundError:
                    pass

    def create_task(
        self, task: dict[str, Any], *, actor: dict[str, Any], idempotency_key: str,
        initial_entities: list[tuple[str, dict[str, Any]]] | None = None,
    ) -> AppendResult:
        task_id = str(task["id"])
        directory = self.task_dir(task_id)
        if directory.exists():
            existing = self._existing_idempotency(task_id, idempotency_key)
            if existing:
                return AppendResult(existing, self.load_task(task_id), True)
            raise MacError("TASK_EXISTS", f"task {task_id} already exists", exit_code=ExitCode.CONFLICT)
        event = {
            "schema_version": 1, "event_id": prefixed("EVT"), "task_id": task_id,
            "event_type": "task_created", "occurred_at": utc_now(), "actor": actor, "run_id": None,
            "expected_revision": -1, "new_revision": 0, "idempotency_key": idempotency_key,
            "payload": {"task": deepcopy(task)},
        }
        projection = replay_events([event])
        self.tasks_root.mkdir(parents=True, exist_ok=True)
        staging = self.tasks_root / f".{task_id}.{prefixed('TXN')}.tmp"
        staging.mkdir(parents=False, exist_ok=False)
        try:
            atomic_write_json(staging / "events" / f"{event['event_id']}.json", event)
            for relative, value in initial_entities or []:
                target = staging / relative
                resolved = target.resolve(strict=False)
                try:
                    resolved.relative_to(staging.resolve())
                except ValueError as exc:
                    raise MacError("ENTITY_PATH_UNSAFE", "initial entity is outside the task transaction", exit_code=ExitCode.SECURITY, path=relative) from exc
                (atomic_write_yaml if target.suffix.lower() in {".yaml", ".yml"} else atomic_write_json)(target, value)
            atomic_write_yaml(staging / "task.yaml", projection)
            os.replace(staging, directory)
        except BaseException:
            if staging.is_dir():
                shutil.rmtree(staging)
            raise
        return AppendResult(event, projection)

    def append_event(
        self, task_id: str, event_type: str, payload: dict[str, Any], *, actor: dict[str, Any],
        expected_revision: int, idempotency_key: str, run_id: str | None = None,
        event_id: str | None = None,
        fault_hook: Callable[[str], None] | None = None,
        materializations: list[tuple[Path, dict[str, Any]]] | None = None,
        replace_existing: set[Path] | None = None,
        authority_context: Any | None = None,
    ) -> AppendResult:
        with self.lease(task_id, str(actor.get("id", "unknown"))):
            return self._append_event_locked(
                task_id, event_type, payload, actor=actor, expected_revision=expected_revision,
                idempotency_key=idempotency_key, run_id=run_id, event_id=event_id,
                fault_hook=fault_hook, materializations=materializations,
                replace_existing=replace_existing, authority_context=authority_context,
            )

    def _append_event_locked(
        self, task_id: str, event_type: str, payload: dict[str, Any], *, actor: dict[str, Any],
        expected_revision: int, idempotency_key: str, run_id: str | None = None,
        event_id: str | None = None, fault_hook: Callable[[str], None] | None = None,
        materializations: list[tuple[Path, dict[str, Any]]] | None = None,
        replace_existing: set[Path] | None = None,
        authority_context: Any | None = None,
    ) -> AppendResult:
        """Append while the caller holds the task lease: revision, guard, event, materialization."""
        if existing := self._existing_idempotency(task_id, idempotency_key):
            if existing.get("event_type") != event_type:
                raise MacError("EVENT_IDEMPOTENCY_CONFLICT", "idempotency key belongs to another operation", exit_code=ExitCode.CONFLICT, task_id=task_id)
            through_revision = int(existing.get("new_revision", 0))
            original_events = [event for event in self.list_events(task_id) if int(event.get("new_revision", 0)) <= through_revision]
            self.rebuild_task(task_id)
            return AppendResult(existing, replay_events(original_events), True)
        events = self.list_events(task_id)
        projection = replay_events(events)
        current = int(projection["revision"])
        if current != expected_revision:
            raise MacError("REVISION_CONFLICT", f"expected {expected_revision}, current {current}", exit_code=ExitCode.CONFLICT, task_id=task_id)
        pending = list(materializations or [])
        replace_targets = {path.resolve(strict=False) for path in (replace_existing or set())}
        task_root = self.task_dir(task_id).resolve()
        for target, _ in pending:
            resolved_target = target.resolve(strict=False)
            try:
                resolved_target.relative_to(task_root)
            except ValueError as exc:
                raise MacError("ENTITY_PATH_UNSAFE", "entity target is outside the task directory", exit_code=ExitCode.SECURITY, path=str(target), task_id=task_id) from exc
            if target.exists() and resolved_target not in replace_targets:
                raise MacError("ENTITY_ID_CONFLICT", "entity target already exists without a matching idempotency event", exit_code=ExitCode.CONFLICT, path=target.relative_to(self.repo).as_posix(), task_id=task_id)
        self._authorize_governance_write(
            task_id, event_type, payload, actor, projection,
            materializations=pending, authority_context=authority_context,
        )
        event = {
            "schema_version": 1, "event_id": event_id or prefixed("EVT"), "task_id": task_id,
            "event_type": event_type, "occurred_at": utc_now(), "actor": actor, "run_id": run_id,
            "expected_revision": current, "new_revision": current + 1,
            "idempotency_key": idempotency_key, "payload": deepcopy(payload),
        }
        event_path = self.task_dir(task_id) / "events" / f"{event['event_id']}.json"
        atomic_write_json(event_path, event)
        if fault_hook:
            fault_hook("after_event")
        for target, value in pending:
            (atomic_write_yaml if target.suffix.lower() in {".yaml", ".yml"} else atomic_write_json)(target, value)
        projection = replay_events([*events, event])
        atomic_write_yaml(self.task_dir(task_id) / "task.yaml", projection)
        if fault_hook:
            fault_hook("after_projection")
        return AppendResult(event, projection)

    def _authorize_governance_write(
        self, task_id: str, event_type: str, payload: dict[str, Any], actor: dict[str, Any], task: dict[str, Any], *,
        materializations: list[tuple[Path, dict[str, Any]]], authority_context: Any | None,
    ) -> None:
        """Bind privileged governance mutations to the frozen owner policy and entity actor."""
        actor_id = str(actor.get("id", ""))
        if not actor_id:
            raise MacError("ACTOR_ID_REQUIRED", "governance writes require an actor id", exit_code=ExitCode.SECURITY, task_id=task_id)
        privileged = {"scope_approved", "risk_accepted", "policy_rebased"}
        if event_type == "state_transitioned" and payload.get("to") in {"completed", "completed_with_risk"}:
            privileged.add(event_type)
        controlled = {"scope_proposed", "work_unit_created", "finding_opened", "finding_resolved", "evidence_invalidated"}
        actor_bound = {"run_started", "result_submitted"}
        if event_type not in privileged | controlled | actor_bound:
            return
        compiled = compile_policy(self.repo, task=task)
        scope_path = self.task_dir(task_id) / "scope-contract.yaml"
        scope = load_data(scope_path) if scope_path.is_file() else {}
        from .authority import VerifiedAuthorityContext, owner_approvers, require_external_authority

        approvers = owner_approvers(scope, compiled.ownership)
        events = self.list_events(task_id)
        creator = str(((events[0].get("actor") or {}).get("id", ""))) if events else ""
        if event_type in privileged:
            if not isinstance(authority_context, VerifiedAuthorityContext):
                require_external_authority(actor_id, None, operation=event_type)
            context = require_external_authority(actor_id, authority_context, operation=event_type)
            if actor_id not in approvers:
                raise MacError("ACTOR_UNAUTHORIZED", f"{event_type} requires frozen owner approval authority", exit_code=ExitCode.SECURITY, task_id=task_id)
            payload["verified_authority"] = context.audit_record()
        if event_type in controlled and actor_id not in approvers | {creator}:
            raise MacError("ACTOR_UNAUTHORIZED", f"{event_type} requires controller or frozen owner authority", exit_code=ExitCode.SECURITY, task_id=task_id)
        entity_actor = None
        run_entity = payload.get("run") if isinstance(payload.get("run"), dict) else None
        if run_entity is None and event_type == "run_started":
            run_entity = next((value for path, value in materializations if path.parent.name == "runs"), None)
        if event_type == "run_started":
            entity_actor = ((run_entity or {}).get("actor") or {}).get("id")
        elif event_type == "result_submitted":
            entity_actor = ((payload.get("run") or {}).get("actor") or {}).get("id")
        if entity_actor is not None and str(entity_actor) != actor_id:
            raise MacError("ACTOR_ENTITY_MISMATCH", f"{event_type} actor does not match the bound Run actor", exit_code=ExitCode.SECURITY, task_id=task_id)
        if event_type == "run_started" and run_entity is not None:
            level = str(run_entity.get("independence_level", "L0"))
            runtime = run_entity.get("runtime") or {}
            attestation = run_entity.get("independence_attestation")
            carries_provenance = any(runtime.get(name) for name in ("provider", "model")) or attestation is not None
            if level in {"L2", "L3"} or carries_provenance:
                if not isinstance(authority_context, VerifiedAuthorityContext) or authority_context.runtime is None:
                    raise MacError(
                        "PROVENANCE_UNVERIFIED", "attested Run metadata requires an external runtime verifier",
                        exit_code=ExitCode.EXTERNAL, task_id=task_id,
                    )
                context = require_external_authority(actor_id, authority_context, operation="attested Run registration")
                verified = context.runtime
                expected_runtime = {
                    "profile": verified.profile,
                    "execution_context_id": verified.execution_context_id,
                    "provider": verified.provider,
                    "model": verified.model,
                }
                expected_attestation = {
                    "read_only": verified.read_only,
                    "commit_participation": list(verified.commit_participation),
                }
                if runtime != expected_runtime or attestation != expected_attestation:
                    raise MacError(
                        "RUNTIME_CONTEXT_MISMATCH", "Run entity does not match externally verified provenance",
                        exit_code=ExitCode.SECURITY, task_id=task_id,
                    )
                payload["verified_authority"] = context.audit_record()

    def transition(
        self, task_id: str, target: str, context: TransitionContext, *, actor: dict[str, Any],
        expected_revision: int, idempotency_key: str, authority_context: Any | None = None,
    ) -> AppendResult:
        with self.lease(task_id, str(actor.get("id", "unknown"))):
            if existing := self._existing_idempotency(task_id, idempotency_key):
                if existing.get("event_type") != "state_transitioned" or (existing.get("payload") or {}).get("to") != target:
                    raise MacError("EVENT_IDEMPOTENCY_CONFLICT", "idempotency key belongs to another transition", exit_code=ExitCode.CONFLICT, task_id=task_id)
                through_revision = int(existing.get("new_revision", 0))
                original_events = [event for event in self.list_events(task_id) if int(event.get("new_revision", 0)) <= through_revision]
                return AppendResult(existing, replay_events(original_events), True)
            task = replay_events(self.list_events(task_id))
            if int(task["revision"]) != expected_revision:
                raise MacError("REVISION_CONFLICT", f"expected {expected_revision}, current {task['revision']}", exit_code=ExitCode.CONFLICT, task_id=task_id)
            compiled = compile_policy(self.repo, task=task)
            if target in {"completed", "completed_with_risk"}:
                from .authority import require_external_authority
                from .application.close import evaluate_repository_close

                require_external_authority(
                    str(actor.get("id", "")), authority_context, operation="task Close",
                )
                close = evaluate_repository_close(self.repo, task_id, str(actor.get("id", "")), compiled_policy=compiled)
                if not close.ok:
                    raise MacError("CLOSE_GATES_FAILED", "task cannot close", exit_code=ExitCode.EVIDENCE, task_id=task_id, details={"issues": [item.as_dict() for item in close.issues]})
            leased_context = replace(context, controller_lease_valid=True, lease_valid=True)
            decision = evaluate_transition(
                str(task["state"]), target, leased_context, transitions=compiled.transitions,
                states=compiled.states, terminal_states=compiled.terminal_states,
            )
            if not decision.ok:
                raise MacError(decision.codes[0], f"{task['state']} -> {target} rejected", exit_code=ExitCode.TRANSITION, details={"failed_guards": decision.failed_guards, "failed_conditions": decision.failed_conditions})
            payload: dict[str, Any] = {"from": task["state"], "to": target, "transition_id": decision.transition.id if decision.transition else None}
            if context.successor_task_id:
                payload["successor_task_id"] = context.successor_task_id
            return self._append_event_locked(
                task_id, "state_transitioned", payload, actor=actor,
                expected_revision=expected_revision, idempotency_key=idempotency_key,
                authority_context=authority_context,
            )


def discover_task_dirs(repo: Path) -> list[Path]:
    root = repo / "tasks"
    return sorted(path for path in root.glob("TASK-*") if path.is_dir()) if root.is_dir() else []


def _legacy_task_records(repo: Path) -> list[dict[str, Any]]:
    index = repo / "tasks/index.yaml"
    if not index.is_file():
        return []
    try:
        raw = load_data(index)
    except Exception:
        return []
    entries = raw.get("tasks", []) if isinstance(raw, dict) else []
    records = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        task_id = str(entry.get("id", ""))
        if not task_id.startswith("TASK-") or Path(task_id).name != task_id or "/" in task_id or "\\" in task_id:
            continue
        detail = repo / "tasks" / task_id / "task.md"
        records.append({
            "task_id": task_id,
            "detail_present": detail.is_file(),
            "legacy_integrity": "partial" if detail.is_file() else "metadata_only",
            "verification_status": "unverifiable",
        })
    return records


def _has_v6_task_entries(task_dir: Path) -> bool:
    return any((task_dir / name).exists() for name in V6_TASK_ENTRY_NAMES)


def _legacy_task_warning(record: dict[str, Any]) -> MacIssue:
    task_id = str(record["task_id"])
    path = f"tasks/{task_id}/task.md" if record["detail_present"] else "tasks/index.yaml"
    return MacIssue(
        "LEGACY_TASK_UNVERIFIABLE",
        "legacy v5 task is read-only and its historical verification is unverifiable",
        path,
        severity="warning",
        task_id=task_id,
        details={
            "source_format": "v5",
            "legacy_integrity": record["legacy_integrity"],
            "verification_status": record["verification_status"],
        },
    )


def validate_task_invariants(repo: Path, task_dir: Path) -> list[MacIssue]:
    issues: list[MacIssue] = []
    relative = task_dir.resolve().relative_to(repo.resolve()).as_posix()
    try:
        task = load_data(task_dir / "task.yaml")
        scope = load_data(task_dir / "scope-contract.yaml")
    except Exception:
        return issues
    if scope.get("task_id") != task.get("id"):
        issues.append(MacIssue("TASK_SCOPE_ID_MISMATCH", "scope task_id does not match task id", f"{relative}/scope-contract.yaml"))
    canonical = f"{relative}/scope-contract.yaml"
    if task.get("scope_contract_ref") != canonical:
        issues.append(MacIssue("TASK_SCOPE_REF_MISMATCH", "scope_contract_ref is not canonical", f"{relative}/task.yaml"))
    events = []
    for path in sorted((task_dir / "events").glob("*.json")):
        try:
            events.append(load_data(path))
        except Exception:
            continue
    try:
        projection = replay_events(events, initial_projection=task)
    except MacError as exc:
        issues.append(MacIssue(exc.code, str(exc), f"{relative}/events"))
        return issues
    if task != projection:
        issues.append(MacIssue("TASK_PROJECTION_STALE", "task projection differs from deterministic event replay", f"{relative}/task.yaml"))
    state = str(task.get("state"))
    if state in TERMINAL_STATES and not task.get("terminal"):
        issues.append(MacIssue("TASK_TERMINAL_METADATA_MISSING", "terminal task lacks close metadata", f"{relative}/task.yaml"))
    if state not in TERMINAL_STATES and task.get("terminal") is not None:
        issues.append(MacIssue("TASK_ACTIVE_HAS_TERMINAL", "active task contains terminal metadata", f"{relative}/task.yaml"))
    if state in TERMINAL_STATES:
        terminal_events = [event for event in events if event.get("event_type") in {"state_transitioned", "task_completed", "task_cancelled", "task_superseded", "legacy_imported"} and (event.get("payload") or {}).get("to", (event.get("payload") or {}).get("state", ((event.get("payload") or {}).get("task") or {}).get("state", state))) == state]
        if not terminal_events:
            issues.append(MacIssue("TASK_CLOSE_EVENT_MISSING", "terminal task has no matching close event", f"{relative}/events"))
    runs = {str(value.get("id")): value for path in sorted((task_dir / "runs").glob("*.json")) if (value := load_data(path))}
    work_units = {str(value.get("id")): value for path in sorted((task_dir / "work-units").glob("*.yaml")) if (value := load_data(path))}
    results = [load_data(path) for path in sorted((task_dir / "results").glob("*.json"))]
    evidence = [load_data(path) for path in sorted((task_dir / "evidence").glob("*.json"))]
    findings = [load_data(path) for path in sorted((task_dir / "findings").glob("*.json"))]
    for directory_name, values in (
        ("runs", list(runs.values())), ("work-units", list(work_units.values())),
        ("results", results),
        ("evidence", evidence), ("findings", findings),
        ("approvals", [load_data(path) for path in sorted((task_dir / "approvals").glob("*.json"))]),
        ("risk-acceptances", [load_data(path) for path in sorted((task_dir / "risk-acceptances").glob("*.json"))]),
    ):
        for value in values:
            if value.get("task_id") != task.get("id"):
                issues.append(MacIssue("TASK_ENTITY_ID_MISMATCH", f"{directory_name} entity belongs to a different task", f"{relative}/{directory_name}"))
    event_run_ids = {
        str(reference)
        for event in events
        for reference in (event.get("run_id"), (event.get("payload") or {}).get("run_id"))
        if reference
    }
    event_result_ids = {str((event.get("payload") or {}).get("result_id")) for event in events if (event.get("payload") or {}).get("result_id")}
    event_evidence_ids = {str((event.get("payload") or {}).get("evidence_id")) for event in events if (event.get("payload") or {}).get("evidence_id")}
    for run_id in sorted(set(runs) - event_run_ids):
        issues.append(MacIssue("RUN_EVENT_MISSING", "run entity has no referencing event", f"{relative}/runs/{run_id}.json", severity="warning"))
    for result in results:
        if str(result.get("id")) not in event_result_ids:
            issues.append(MacIssue("RESULT_EVENT_MISSING", "result entity has no referencing event", f"{relative}/results/{result.get('id')}.json", severity="warning"))
    for item in evidence:
        if str(item.get("id")) not in event_evidence_ids:
            issues.append(MacIssue("EVIDENCE_EVENT_MISSING", "evidence entity has no referencing event", f"{relative}/evidence/{item.get('id')}.json", severity="warning"))
    for result in results:
        if result.get("run_id") not in runs:
            issues.append(MacIssue("RESULT_RUN_REF_MISSING", str(result.get("run_id")), f"{relative}/results/{result.get('id')}.json"))
        if result.get("work_unit_id") not in work_units:
            issues.append(MacIssue("RESULT_WORK_UNIT_REF_MISSING", str(result.get("work_unit_id")), f"{relative}/results/{result.get('id')}.json"))
    try:
        projected_work_units = replay_work_units(events, initial_projection=task)
    except MacError as exc:
        issues.append(MacIssue(exc.code, str(exc), f"{relative}/events"))
        projected_work_units = {}
    for work_unit_id, projected_work_unit in projected_work_units.items():
        materialized = work_units.get(work_unit_id)
        if materialized is None:
            issues.append(MacIssue("WORK_UNIT_PROJECTION_MISSING", "event lifecycle work unit is not materialized", f"{relative}/work-units/{work_unit_id}.yaml"))
        elif materialized != projected_work_unit:
            issues.append(MacIssue("WORK_UNIT_PROJECTION_STALE", "work unit differs from event lifecycle replay", f"{relative}/work-units/{work_unit_id}.yaml"))
    policy_digest = (task.get("policy_ref") or {}).get("combined_digest")
    valid_claims: set[str] = set()
    for item in evidence:
        if item.get("run_id") and item.get("run_id") not in runs:
            issues.append(MacIssue("EVIDENCE_RUN_REF_MISSING", str(item.get("run_id")), f"{relative}/evidence"))
        if item.get("policy_digest") != policy_digest:
            issues.append(MacIssue("EVIDENCE_POLICY_MISMATCH", "evidence policy digest differs from frozen task policy", f"{relative}/evidence"))
            continue
        validity = item.get("validity") or {}
        if validity.get("status") == "valid" and not validity.get("invalidated_by"):
            valid_claims.update(str(claim_value) for claim in item.get("claims", []) for claim_value in claim.values())
    if state in {"completed", "completed_with_risk"}:
        if task.get("legacy_integrity") in {"partial", "metadata_only"}:
            issues.append(MacIssue("LEGACY_TASK_UNVERIFIABLE", "legacy completion is metadata-only and cannot be treated as current v6 Evidence", f"{relative}/task.yaml", severity="warning"))
            return issues
        incomplete_work_units = sorted(
            work_unit_id
            for work_unit_id, work_unit in work_units.items()
            if work_unit.get("status") != "completed"
        )
        if incomplete_work_units:
            issues.append(MacIssue(
                "TASK_REQUIRED_WORK_UNITS_INCOMPLETE",
                "terminal task has incomplete required work units",
                f"{relative}/work-units",
                details={"work_unit_ids": incomplete_work_units},
            ))
        required = set(str(value) for value in task.get("required_gates", []))
        required.update(str(item["id"]) for item in task.get("acceptance_criteria", []) if item.get("required", True))
        if missing := sorted(required - valid_claims):
            issues.append(MacIssue("TASK_GATE_COVERAGE_INCOMPLETE", "terminal task lacks valid evidence claims", f"{relative}/evidence", details={"missing": missing}))
        blocking = [item.get("id") for item in findings if item.get("status") in {"open", "fixing"} and item.get("blocking_effect") == "block_close"]
        if blocking:
            issues.append(MacIssue("TASK_BLOCKING_FINDINGS_OPEN", "terminal task has unresolved blocking findings", f"{relative}/findings", details={"finding_ids": blocking}))
        try:
            from .application.close import evaluate_repository_close

            closed_by = str((task.get("terminal") or {}).get("closed_by", ""))
            close = evaluate_repository_close(repo, str(task["id"]), closed_by)
            for item in close.issues:
                issues.append(MacIssue(item.code, item.message, item.path or relative, item.field, item.severity, item.suggestion, item.task_id or str(task["id"]), item.details))
        except (MacError, FileNotFoundError, ValueError, KeyError) as exc:
            issues.append(MacIssue("TASK_CLOSE_RECOMPUTE_FAILED", str(exc), relative))
    return issues


def _validate_glob(schema_set: SchemaSet, root: Path, pattern: str, schema: str, repo: Path) -> list[MacIssue]:
    issues: list[MacIssue] = []
    for path in sorted(root.glob(pattern)):
        if path.is_file():
            issues.extend(schema_set.validate_file(path, schema, root=repo))
    return issues


def validate_repository(repo: Path, schema_set: SchemaSet | None = None) -> list[MacIssue]:
    repo = repo.resolve()
    schemas = schema_set or SchemaSet()
    issues: list[MacIssue] = []
    from .schema_validation import schema_lock_issues

    if (repo / "schemas").is_dir() or (repo / ".agents/schemas.lock.json").is_file():
        issues.extend(schema_lock_issues(repo, repo / "schemas"))
    config_path, ownership_path = repo / ".agents/config.yaml", repo / ".agents/ownership.yaml"
    if not config_path.is_file():
        issues.append(MacIssue("CONFIG_MISSING", ".agents/config.yaml is required", ".agents/config.yaml"))
        return issues
    issues.extend(schemas.validate_file(config_path, "config.schema.json", root=repo))
    if ownership_path.is_file():
        issues.extend(schemas.validate_file(ownership_path, "ownership.schema.json", root=repo))
    else:
        issues.append(MacIssue("OWNERSHIP_MISSING", ".agents/ownership.yaml is required", ".agents/ownership.yaml"))
    workflow_root = repo / ".agents/workflows"
    for path in sorted(workflow_root.glob("*.yaml")):
        issues.extend(schemas.validate_file(path, "workflow.schema.json", root=repo))
        try:
            issues.extend(validate_workflow_invariants(load_data(path), path.relative_to(repo).as_posix()))
        except Exception:
            pass
    issues.extend(_validate_glob(schemas, repo, ".agents/runtime-profiles/*.yaml", "runtime-profile.schema.json", repo))
    config = load_data(config_path)
    workflow_name = config.get("default_workflow")
    if workflow_name and not (workflow_root / f"{workflow_name}.yaml").is_file():
        issues.append(MacIssue("DEFAULT_WORKFLOW_MISSING", str(workflow_name), config_path.relative_to(repo).as_posix()))
    profile = config.get("default_runtime_profile")
    if profile and not (repo / ".agents/runtime-profiles" / f"{profile}.yaml").is_file():
        issues.append(MacIssue("DEFAULT_PROFILE_MISSING", str(profile), config_path.relative_to(repo).as_posix()))
    legacy_records = {str(item["task_id"]): item for item in _legacy_task_records(repo)}
    v6_task_ids: set[str] = set()
    for task_dir in discover_task_dirs(repo):
        if task_dir.name in legacy_records and not _has_v6_task_entries(task_dir):
            continue
        v6_task_ids.add(task_dir.name)
        for filename, schema in SCHEMA_MAP.items():
            path = task_dir / filename
            if path.is_file():
                issues.extend(schemas.validate_file(path, schema, root=repo))
            else:
                issues.append(MacIssue("TASK_FILE_MISSING", f"{filename} is required", path.relative_to(repo).as_posix()))
        for pattern, schema in PATTERN_SCHEMAS.items():
            issues.extend(_validate_glob(schemas, task_dir, pattern, schema, repo))
        issues.extend(validate_task_invariants(repo, task_dir))
    for task_id, record in legacy_records.items():
        if task_id not in v6_task_ids:
            issues.append(_legacy_task_warning(record))
    return issues
