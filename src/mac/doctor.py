from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .io import atomic_write_json, load_data
from .policy import compile_policy
from .report import build_index
from .schema_validation import SchemaSet, schema_lock_issues


_ATOMIC_FILE = re.compile(r"^\..+\.[A-Za-z0-9_-]{6,}\.tmp$")
_TASK_STAGING = re.compile(r"^\.TASK-[^.]+\.TXN-[A-Z0-9]+\.tmp$")
_LEASE_QUARANTINE = re.compile(r"^\.controller\.lease\.LEASE-[A-Z0-9]+\.expired$")
_MINIMUM_TEMP_AGE_SECONDS = 60.0


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
    temporary_files: tuple[str, ...]
    expired_leases: tuple[str, ...]
    projections: tuple[str, ...]
    index_path: str

    def as_dict(self) -> dict[str, object]:
        action = "removed" if self.applied else "candidate"
        return {
            "ok": True,
            "applied": self.applied,
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


def _known_temporary_files(tasks: Path, *, now: float | None = None) -> list[Path]:
    if not tasks.is_dir():
        return []
    cutoff = (now if now is not None else time.time()) - _MINIMUM_TEMP_AGE_SECONDS
    candidates: list[Path] = []
    for path in tasks.rglob("*.tmp"):
        known = (path.is_file() and _ATOMIC_FILE.fullmatch(path.name)) or (path.is_dir() and path.parent == tasks and _TASK_STAGING.fullmatch(path.name))
        try:
            old_enough = path.stat().st_mtime <= cutoff
        except OSError:
            old_enough = False
        if known and old_enough:
            candidates.append(path)
    return sorted(candidates)


def _expired_leases(tasks: Path, *, now: float | None = None) -> list[Path]:
    current = now if now is not None else time.time()
    result: list[Path] = []
    if not tasks.is_dir():
        return result
    for path in sorted(tasks.rglob("controller.lease")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if float(data["expires_unix"]) <= current:
                result.append(path)
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            continue
    cutoff = current - _MINIMUM_TEMP_AGE_SECONDS
    for path in sorted(tasks.rglob(".controller.lease.*.expired")):
        try:
            if path.is_file() and _LEASE_QUARANTINE.fullmatch(path.name) and path.stat().st_mtime <= cutoff:
                result.append(path)
        except OSError:
            continue
    return result


def run_doctor(repo: Path) -> DoctorReport:
    """Inspect the repository without creating, deleting, or rewriting files."""
    root = repo.resolve()
    tasks = root / "tasks"
    config = root / ".agents/config.yaml"
    ownership = root / ".agents/ownership.yaml"
    workflows = root / ".agents/workflows"
    profiles = root / ".agents/runtime-profiles"
    temporary = _known_temporary_files(tasks)
    leases = _expired_leases(tasks)
    tracked_private = _tracked_private_files(root)
    untracked_logs = _untracked_sensitive_log_count(root)
    path_risks = _path_risk_count(root)
    policy_drift = _policy_drift_count(root)
    migration_incomplete = _migration_incomplete_count(root)
    cli_version = _cli_version(root)
    projection_drift = 0
    try:
        from .repository import FilesystemTaskRepository

        repository = FilesystemTaskRepository(root)
        projection_drift = sum(len(repository.projection_drift(path.parent.name)) for path in (root / "tasks").glob("TASK-*/task.yaml"))
    except Exception:
        projection_drift = 1
    local_schema_bundle = (root / "schemas").is_dir() or (root / ".agents/schemas.lock.json").is_file()
    lock_issues = schema_lock_issues(root, root / "schemas") if local_schema_bundle else []
    schema_message = ("schema lock matches" if local_schema_bundle else "using the executable's locked schema bundle") if not lock_issues else "; ".join(item.message for item in lock_issues)
    try:
        schemas = SchemaSet()
        policy = compile_policy(root, schemas=schemas)
        policy_ok, policy_message = True, f"compiled {policy.workflow.get('name')} with {policy.runtime_profile.get('id')}"
    except Exception as exc:
        policy_ok, policy_message = False, str(exc)
    checks = (
        DoctorCheck("python_runtime", sys.version_info >= (3, 11), True, f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"),
        DoctorCheck("cli_version", bool(cli_version), True, f"multi-agent-collab {cli_version or 'unknown'}"),
        DoctorCheck("git_repository", _git_available(root), False, "Git repository available"),
        DoctorCheck("config", config.is_file(), True, ".agents/config.yaml exists"),
        DoctorCheck("ownership", ownership.is_file(), True, ".agents/ownership.yaml exists"),
        DoctorCheck("workflow", workflows.is_dir() and any(workflows.glob("*.yaml")), True, "at least one workflow exists"),
        DoctorCheck("runtime_profiles", profiles.is_dir() and any(profiles.glob("*.yaml")), True, "at least one runtime profile exists"),
        DoctorCheck("schema_lock", not lock_issues, True, schema_message),
        DoctorCheck("compiled_policy", policy_ok, True, policy_message),
        DoctorCheck("tracked_private_artifacts", not tracked_private, True, f"{len(tracked_private)} private artifact files are tracked"),
        DoctorCheck("path_case_and_symlink_risk", path_risks == 0, True, f"{path_risks} path collision or symlink escape risks"),
        DoctorCheck("untracked_sensitive_logs", untracked_logs == 0, False, f"{untracked_logs} untracked private/log artifacts"),
        DoctorCheck("policy_drift", policy_drift == 0, False, f"{policy_drift} frozen policy references differ from the current policy"),
        DoctorCheck("projection_drift", projection_drift == 0, False, f"{projection_drift} derived projections require rebuild"),
        DoctorCheck("migration_completion", migration_incomplete == 0, False, f"{migration_incomplete} legacy tasks are not represented in tasks-v6"),
        DoctorCheck("recoverable_temporary_files", not temporary, False, f"{len(temporary)} known, old interrupted writes"),
        DoctorCheck("expired_controller_leases", not leases, False, f"{len(leases)} expired controller leases"),
    )
    return DoctorReport(all(item.ok for item in checks if item.required), checks)


def repair_safe(repo: Path, *, apply: bool = False) -> RepairReport:
    """List or repair only known derived-state failures; never alter business state."""
    from .repository import FilesystemTaskRepository

    root = repo.resolve()
    tasks = root / "tasks"
    temporary = _known_temporary_files(tasks)
    leases = _expired_leases(tasks)
    projections: list[str] = []
    repository = FilesystemTaskRepository(root)
    if tasks.is_dir():
        for task_dir in sorted(path for path in tasks.glob("TASK-*") if path.is_dir()):
            if not (task_dir / "events").is_dir():
                continue
            try:
                rebuilt = repository.projection_drift(task_dir.name)
            except Exception:
                continue
            if rebuilt:
                projections.extend(str(path) for path in rebuilt)
    if apply:
        import shutil

        for path in temporary:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
        for path in leases:
            path.unlink()
        projections = []
        if tasks.is_dir():
            for task_dir in sorted(path for path in tasks.glob("TASK-*") if path.is_dir() and (path / "events").is_dir()):
                drift = repository.projection_drift(task_dir.name)
                repository.rebuild_task(task_dir.name)
                projections.extend(drift)
        index_path = tasks / "INDEX.generated.json"
        atomic_write_json(index_path, {"schema_version": 1, "tasks": build_index(root)})
    index_path = tasks / "INDEX.generated.json"
    return RepairReport(
        apply,
        tuple(path.relative_to(root).as_posix() for path in temporary),
        tuple(path.relative_to(root).as_posix() for path in leases),
        tuple(projections),
        index_path.relative_to(root).as_posix(),
    )
