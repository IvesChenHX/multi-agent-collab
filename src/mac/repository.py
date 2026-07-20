from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import time
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, TypeAlias

from .authority import (
    AuthorityRequest,
    VerifiedAuthority,
    actor_authorized_for_scope,
    authority_audit_record,
    canonical_digest,
    current_authority_verifier,
    governance_sensitive,
    level_at_least,
    require_authority,
    scope_binding_matches,
    valid_scope_approvals,
    verify_authority_audit_record,
)
from .errors import ExitCode, MacError, MacIssue
from .events import replay_entity_snapshots, replay_events, replay_scope_snapshots, replay_work_units
from .git import GitRepository
from .ids import is_identifier, prefixed
from .io import atomic_write_json, atomic_write_yaml, load_data
from .policy import compile_frozen_policy, compile_policy, ownership_source_path, policy_source_paths
from .schema_validation import SchemaSet
from .scope import amend_scope, check_changes
from .state_machine import TERMINAL_STATES, TransitionContext, evaluate_transition, find_transition, validate_workflow_invariants

SCHEMA_MAP = {"task.yaml": "task.schema.json", "scope-contract.yaml": "scope-contract.schema.json"}
PATTERN_SCHEMAS = {
    "work-units/*.yaml": "work-unit.schema.json", "runs/*.json": "run.schema.json",
    "results/*.json": "result.schema.json", "findings/*.json": "finding.schema.json",
    "evidence/*.json": "evidence.schema.json", "approvals/*.json": "approval.schema.json",
    "risk-acceptances/*.json": "risk-acceptance.schema.json", "events/*.json": "event.schema.json",
}
V6_TASK_ENTRY_NAMES = frozenset(SCHEMA_MAP) | frozenset(pattern.partition("/")[0] for pattern in PATTERN_SCHEMAS)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_event_time(value: object) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Event timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def git_head(repo: Path) -> str | None:
    try:
        result = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    value = result.stdout.strip().lower()
    return value if len(value) == 40 else None


def _policy_path(relative: str) -> str:
    value = Path(relative)
    if value.is_absolute() or not value.parts or ".." in value.parts or "\x00" in relative:
        raise MacError(
            "POLICY_PATH_UNSAFE",
            "policy snapshot path must be repository-relative",
            exit_code=ExitCode.SECURITY,
            path=relative,
        )
    return value.as_posix()


def _git_bytes(repo: Path, *argv: str) -> bytes | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *argv],
            check=True,
            capture_output=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    return completed.stdout


def _canonical_policy_bytes(repo: Path, relative: str, head: str | None) -> tuple[bytes | None, bool]:
    """Return Git-canonical bytes and whether HEAD supplied the content."""

    path = repo / relative
    if head is not None:
        exists = _git_bytes(repo, "cat-file", "-e", f"{head}:{relative}") is not None
        clean = _git_bytes(repo, "diff", "--quiet", head, "--", relative) is not None
        if exists and clean:
            content = _git_bytes(repo, "show", f"{head}:{relative}")
            if content is not None:
                return content, True
    if not path.is_file():
        return None, False
    content = path.read_bytes()
    if b"\x00" not in content:
        content = content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return content, False


def build_policy_ref(repo: Path, relative_paths: list[str]) -> dict[str, Any]:
    root = repo.resolve()
    head = git_head(root)
    rows = []
    entirely_commit_bound = head is not None
    for raw_relative in relative_paths:
        relative = _policy_path(raw_relative)
        content, commit_bound = _canonical_policy_bytes(root, relative, head)
        if content is None:
            entirely_commit_bound = False
            continue
        rows.append({"path": relative, "digest": sha256_bytes(content)})
        entirely_commit_bound = entirely_commit_bound and commit_bound
    rows.sort(key=lambda row: row["path"])
    result: dict[str, Any] = {"combined_digest": sha256_bytes(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()), "files": rows}
    if head and entirely_commit_bound:
        result["source_commit"] = head
    return result


def policy_ref_matches_executable(
    repo: Path,
    reference: Mapping[str, Any],
    *,
    required_paths: Iterable[str] = (),
) -> bool:
    """Verify a frozen reference, including exact legacy CRLF checkout digests.

    Legacy v6-alpha snapshots hashed worktree bytes.  Equivalence is accepted
    only when every stored file digest is either the immutable source-commit
    blob digest or the exact CRLF checkout of a UTF-8 LF blob, the aggregate
    digest is internally consistent, and the current executable content still
    equals that source blob.
    """

    try:
        rows = [
            {"path": _policy_path(str(item["path"])), "digest": str(item["digest"])}
            for item in reference.get("files", [])
        ]
    except (KeyError, TypeError, ValueError, MacError):
        return False
    rows.sort(key=lambda row: row["path"])
    paths = [row["path"] for row in rows]
    if not rows or len(paths) != len(set(paths)):
        return False
    required = {_policy_path(value) for value in required_paths}
    missing_required = required - set(paths)
    aggregate = sha256_bytes(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode())
    if aggregate != reference.get("combined_digest"):
        return False
    source_commit = str(reference.get("source_commit", ""))
    if source_commit and re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        return False
    source_commit_valid = bool(re.fullmatch(r"[0-9a-f]{40}", source_commit))
    if source_commit_valid:
        source_commit_valid = _git_bytes(repo.resolve(), "rev-parse", f"{source_commit}^{{commit}}") is not None
    head = git_head(repo.resolve())

    def unchanged_from_source(path: str) -> bool:
        source = _git_bytes(repo.resolve(), "show", f"{source_commit}:{path}")
        current_content, _ = _canonical_policy_bytes(repo.resolve(), path, head)
        return source is not None and current_content == source

    if missing_required and (not source_commit_valid or not all(unchanged_from_source(path) for path in missing_required)):
        return False
    current = build_policy_ref(repo, paths)
    if current.get("combined_digest") == aggregate:
        return True
    if not source_commit_valid:
        return False
    for row in rows:
        source = _git_bytes(repo.resolve(), "show", f"{source_commit}:{row['path']}")
        current_content, _ = _canonical_policy_bytes(repo.resolve(), row["path"], head)
        if source is None or current_content != source:
            return False
        allowed = {sha256_bytes(source)}
        if b"\x00" not in source and b"\r" not in source:
            try:
                source.decode("utf-8")
            except UnicodeDecodeError:
                pass
            else:
                allowed.add(sha256_bytes(source.replace(b"\n", b"\r\n")))
        if row["digest"] not in allowed:
            return False
    return True


@dataclass(frozen=True, slots=True)
class AppendResult:
    event: dict[str, Any]
    projection: dict[str, Any]
    idempotent_replay: bool = False


@dataclass(frozen=True, slots=True)
class VerifiedTaskAggregate:
    """Event-replayed Task state plus exact projection consistency facts."""

    task: dict[str, Any]
    scope: dict[str, Any] | None
    scope_history: dict[int, dict[str, Any]]
    entities: dict[str, dict[str, dict[str, Any]]]
    entity_revisions: dict[str, dict[str, int]]
    scope_revision: int
    projection_drift: tuple[str, ...]


MUTATION_AUDIENCE = "mac-mutation-gateway/v1"


@dataclass(frozen=True, slots=True)
class CreateTask:
    task: Mapping[str, Any]
    initial_entities: tuple[tuple[str, Mapping[str, Any]], ...]
    actor_claim: Mapping[str, Any]
    idempotency_key: str
    operation: str = "task.create"
    minimum_independence: str | None = None
    replay_intent: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class AppendEvent:
    task_id: str
    event_type: str
    payload: Mapping[str, Any]
    actor_claim: Mapping[str, Any]
    expected_revision: int
    idempotency_key: str
    operation: str
    run_id: str | None = None
    event_id: str | None = None
    materializations: tuple[tuple[Path, Mapping[str, Any]], ...] = ()
    replace_existing: frozenset[Path] = frozenset()
    minimum_independence: str | None = None
    replay_intent: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class Transition:
    task_id: str
    target: str
    context: TransitionContext
    actor_claim: Mapping[str, Any]
    expected_revision: int
    idempotency_key: str
    operation: str
    transition_metadata: Mapping[str, Any] | None = None
    minimum_independence: str | None = None
    replay_intent: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class Rebuild:
    task_id: str
    actor_claim: Mapping[str, Any]
    expected_revision: int
    idempotency_key: str
    operation: str = "task.rebuild"
    minimum_independence: str | None = None
    replay_intent: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class RecordCommandEvidence:
    """Authorize command execution before running it, then append Evidence."""

    task_id: str
    claim: str
    argv: tuple[str, ...]
    actor_claim: Mapping[str, Any]
    expected_revision: int
    idempotency_key: str
    commit: bool = False
    operation: str = "evidence.record"
    minimum_independence: str | None = None
    replay_intent: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class SubmitResult:
    """Submit raw Result inputs; the Store derives every authoritative snapshot."""

    task_id: str
    result: Mapping[str, Any]
    intake_proof: Mapping[str, Any] | None
    actor_claim: Mapping[str, Any]
    expected_revision: int
    idempotency_key: str
    operation: str = "result.submit"
    minimum_independence: str | None = None


MutationCommand: TypeAlias = (
    CreateTask | AppendEvent | Transition | Rebuild | RecordCommandEvidence | SubmitResult
)


@dataclass(frozen=True, slots=True)
class MutationResult:
    event: Mapping[str, Any] | None
    projection: Mapping[str, Any]
    idempotent_replay: bool
    authority: Mapping[str, Any]
    value: Mapping[str, Any] | None = None


def _plain_mapping(value: Mapping[str, Any] | None, *, field: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise MacError(
            "MUTATION_COMMAND_INVALID",
            f"{field} must be a mapping",
            exit_code=ExitCode.VALIDATION,
        )
    def plain_json_tree(candidate: Any) -> Any:
        if isinstance(candidate, Mapping):
            items = list(candidate.items())
            if any(type(key) is not str for key, _ in items):
                raise TypeError("mapping keys must be strings")
            return {key: plain_json_tree(item) for key, item in items}
        if isinstance(candidate, (list, tuple)):
            return [plain_json_tree(item) for item in candidate]
        if candidate is None or type(candidate) in {str, int, float, bool}:
            return candidate
        raise TypeError(f"unsupported JSON value {type(candidate).__name__}")

    try:
        tree = plain_json_tree(value)
        encoded = json.dumps(
            tree,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        result = json.loads(encoded)
        if type(result) is not dict:
            raise TypeError("mapping snapshot did not produce an object")
        return result
    except Exception as exc:
        raise MacError(
            "MUTATION_COMMAND_UNSTABLE",
            f"{field} could not be captured as an immutable mutation snapshot",
            exit_code=ExitCode.SECURITY,
        ) from exc


def _snapshot_command(command: MutationCommand) -> MutationCommand:
    """Capture every mutable command input once before authorization or use."""

    actor = _plain_mapping(command.actor_claim, field="actor_claim") or {}
    replay_intent = _plain_mapping(getattr(command, "replay_intent", None), field="replay_intent")
    if isinstance(command, CreateTask):
        return CreateTask(
            task=_plain_mapping(command.task, field="task") or {},
            initial_entities=tuple(
                (str(path), _plain_mapping(value, field=f"initial_entities[{path}]") or {})
                for path, value in tuple(command.initial_entities)
            ),
            actor_claim=actor,
            idempotency_key=command.idempotency_key,
            operation=command.operation,
            minimum_independence=command.minimum_independence,
            replay_intent=replay_intent,
        )
    if isinstance(command, AppendEvent):
        return AppendEvent(
            task_id=command.task_id,
            event_type=command.event_type,
            payload=_plain_mapping(command.payload, field="payload") or {},
            actor_claim=actor,
            expected_revision=command.expected_revision,
            idempotency_key=command.idempotency_key,
            operation=command.operation,
            run_id=command.run_id,
            event_id=command.event_id,
            materializations=tuple(
                (Path(path), _plain_mapping(value, field=f"materialization[{path}]") or {})
                for path, value in tuple(command.materializations)
            ),
            replace_existing=frozenset(Path(path) for path in command.replace_existing),
            minimum_independence=command.minimum_independence,
            replay_intent=replay_intent,
        )
    if isinstance(command, Transition):
        return Transition(
            task_id=command.task_id,
            target=command.target,
            context=TransitionContext(**asdict(command.context)),
            actor_claim=actor,
            expected_revision=command.expected_revision,
            idempotency_key=command.idempotency_key,
            operation=command.operation,
            transition_metadata=_plain_mapping(command.transition_metadata, field="transition_metadata"),
            minimum_independence=command.minimum_independence,
            replay_intent=replay_intent,
        )
    if isinstance(command, RecordCommandEvidence):
        return RecordCommandEvidence(
            task_id=command.task_id,
            claim=command.claim,
            argv=tuple(command.argv),
            actor_claim=actor,
            expected_revision=command.expected_revision,
            idempotency_key=command.idempotency_key,
            commit=command.commit,
            operation=command.operation,
            minimum_independence=command.minimum_independence,
            replay_intent=replay_intent,
        )
    if isinstance(command, SubmitResult):
        return SubmitResult(
            task_id=command.task_id,
            result=_plain_mapping(command.result, field="result") or {},
            intake_proof=_plain_mapping(command.intake_proof, field="intake_proof"),
            actor_claim=actor,
            expected_revision=command.expected_revision,
            idempotency_key=command.idempotency_key,
            operation=command.operation,
            minimum_independence=command.minimum_independence,
        )
    return Rebuild(
        task_id=command.task_id,
        actor_claim=actor,
        expected_revision=command.expected_revision,
        idempotency_key=command.idempotency_key,
        operation=command.operation,
        minimum_independence=command.minimum_independence,
        replay_intent=replay_intent,
    )


_APPEND_OPERATION_EVENTS: dict[str, frozenset[str]] = {
    "scope.propose": frozenset({"scope_proposed"}),
    "scope.approve": frozenset({"scope_approved"}),
    "scope.amend": frozenset({"scope_proposed"}),
    "work_unit.create": frozenset({"work_unit_created"}),
    "work_unit.ready": frozenset({"work_unit_created"}),
    "run.register": frozenset({"run_started"}),
    "run.finish": frozenset({"run_finished"}),
    "evidence.record": frozenset({"evidence_recorded"}),
    "evidence.promote": frozenset({"evidence_recorded"}),
    "evidence.invalidate": frozenset({"evidence_invalidated"}),
    "finding.open": frozenset({"finding_opened"}),
    "finding.resolve": frozenset({"finding_resolved"}),
    "risk.accept": frozenset({"risk_accepted"}),
}

_ENTITY_SCHEMAS = {
    "work-units": ("yaml", "work-unit.schema.json", "work_unit"),
    "runs": ("json", "run.schema.json", "run"),
    "results": ("json", "result.schema.json", "result"),
    "evidence": ("json", "evidence.schema.json", "evidence"),
    "findings": ("json", "finding.schema.json", "finding"),
    "approvals": ("json", "approval.schema.json", "approval"),
    "risk-acceptances": ("json", "risk-acceptance.schema.json", "risk_acceptance"),
}

_ENTITY_ID_PREFIXES = {
    "work-units": "WU",
    "runs": "RUN",
    "results": "RESULT",
    "evidence": "EVD",
    "findings": "FND",
    "approvals": "APR",
    "risk-acceptances": "RISK",
}

_MATERIALIZATION_DIRECTORIES: dict[str, frozenset[str]] = {
    "scope.propose": frozenset({"scope-contract"}),
    "scope.approve": frozenset({"scope-contract", "approvals"}),
    "scope.amend": frozenset({"scope-contract", "scope-history"}),
    "work_unit.create": frozenset({"work-units"}),
    "work_unit.ready": frozenset({"work-units"}),
    "run.register": frozenset({"runs", "work-units"}),
    "run.finish": frozenset({"runs", "work-units"}),
    "result.submit": frozenset({"results", "runs", "work-units"}),
    "evidence.record": frozenset({"evidence", "runs"}),
    "evidence.promote": frozenset({"evidence"}),
    "evidence.invalidate": frozenset({"evidence"}),
    "finding.open": frozenset({"findings"}),
    "finding.resolve": frozenset({"findings"}),
    "risk.accept": frozenset({"risk-acceptances", "findings"}),
    "policy.rebase": frozenset(),
}

_REPLACE_DIRECTORIES: dict[str, frozenset[str]] = {
    "scope.propose": frozenset({"scope-contract"}),
    "scope.approve": frozenset({"scope-contract"}),
    "scope.amend": frozenset({"scope-contract"}),
    "work_unit.ready": frozenset({"work-units"}),
    "run.register": frozenset({"work-units"}),
    "run.finish": frozenset({"runs", "work-units"}),
    "result.submit": frozenset({"runs", "work-units"}),
    "evidence.invalidate": frozenset({"evidence"}),
    "finding.resolve": frozenset({"findings"}),
    "risk.accept": frozenset({"findings"}),
}

_SNAPSHOT_DIRECTORIES = {
    "scope": "scope-contract",
    "work_unit": "work-units",
    "run": "runs",
    "result": "results",
    "evidence": "evidence",
    "finding": "findings",
    "approval": "approvals",
    "risk_acceptance": "risk-acceptances",
}

_OPERATION_SNAPSHOTS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "scope.propose": (frozenset({"scope"}), frozenset({"scope"})),
    "scope.approve": (frozenset({"scope", "approval"}), frozenset({"scope", "approval"})),
    "scope.amend": (frozenset({"scope"}), frozenset({"scope"})),
    "approval.record": (frozenset({"approval"}), frozenset({"approval"})),
    "work_unit.create": (frozenset({"work_unit"}), frozenset({"work_unit"})),
    "work_unit.ready": (frozenset({"work_unit"}), frozenset({"work_unit"})),
    "run.register": (frozenset({"run", "work_unit"}), frozenset({"run", "work_unit"})),
    "run.finish": (frozenset({"run", "work_unit"}), frozenset({"run"})),
    "result.submit": (frozenset({"result", "run", "work_unit"}), frozenset({"result", "run", "work_unit"})),
    "evidence.record": (frozenset({"evidence", "run"}), frozenset({"evidence", "run"})),
    "evidence.promote": (frozenset({"evidence"}), frozenset({"evidence"})),
    "evidence.invalidate": (frozenset({"evidence"}), frozenset({"evidence"})),
    "finding.open": (frozenset({"finding"}), frozenset({"finding"})),
    "finding.resolve": (frozenset({"finding"}), frozenset({"finding"})),
    "risk.accept": (frozenset({"risk_acceptance", "finding"}), frozenset({"risk_acceptance", "finding"})),
    "policy.rebase": (frozenset(), frozenset()),
}

_OPERATION_PAYLOAD_KEYS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "scope.propose": (frozenset({"scope_id", "version", "scope", "authority"}), frozenset()),
    "scope.approve": (
        frozenset({"scope_id", "version", "approval_id", "approval", "scope", "authority"}),
        frozenset(),
    ),
    "scope.amend": (
        frozenset({"scope_id", "version", "amendment", "scope", "authority"}),
        frozenset(),
    ),
    "approval.record": (
        frozenset({"approval_kind", "approval_id", "approval", "authority"}),
        frozenset(),
    ),
    "work_unit.create": (
        frozenset({"work_unit_id", "work_unit", "authority"}),
        frozenset(),
    ),
    "work_unit.ready": (
        frozenset({"work_unit_id", "work_unit", "authority"}),
        frozenset(),
    ),
    "run.register": (
        frozenset({
            "run_id", "work_unit_id", "run", "work_unit", "baseline_subject",
            "worktree_identity", "repository_binding", "authority",
        }),
        frozenset(),
    ),
    "run.finish": (
        frozenset({"run_id", "status", "run", "authority"}),
        frozenset({"work_unit_id", "work_unit", "compensates_event_id"}),
    ),
    "result.submit": (
        frozenset({
            "result_id", "digest", "outcome", "work_unit_id", "work_unit", "run",
            "result", "intake_proof", "authority",
        }),
        frozenset(),
    ),
    "evidence.record": (
        frozenset({"evidence_id", "evidence", "run", "authority"}),
        frozenset(),
    ),
    "evidence.promote": (
        frozenset({"evidence_id", "evidence", "promotion", "authority"}),
        frozenset(),
    ),
    "evidence.invalidate": (
        frozenset({"evidence_id", "evidence", "reason", "authority"}),
        frozenset(),
    ),
    "finding.open": (
        frozenset({"finding_id", "finding", "authority"}),
        frozenset(),
    ),
    "finding.resolve": (
        frozenset({"finding_id", "finding", "authority"}),
        frozenset(),
    ),
    "risk.accept": (
        frozenset({"risk_acceptance_id", "risk_acceptance", "finding", "authority"}),
        frozenset(),
    ),
}


def _validate_payload_key_contract(
    operation: str,
    payload: Mapping[str, Any],
    *,
    persisted: bool,
    task_id: str,
) -> None:
    """Keep every governed Event payload closed and operation-specific."""

    if operation.startswith("task.transition.") or operation in {"task.cancel", "task.supersede"}:
        if not persisted:
            return
        required = {"from", "to", "transition_id", "terminal_state", "transition_metadata"}
        optional = {"successor_task_id"} if operation == "task.supersede" else set()
        metadata = payload.get("transition_metadata")
        metadata_keys = set(metadata) if isinstance(metadata, Mapping) else set()
        valid_metadata = (
            isinstance(metadata, Mapping)
            and "authority" in metadata_keys
            and metadata_keys.issubset({"authority", "transition_fact"})
        )
    elif operation == "task.create":
        required = {"task", "scope", "authority"} if persisted else {"task", "scope"}
        optional = set()
        valid_metadata = True
    else:
        operation_key = _materialization_operation(operation)
        contract = _OPERATION_PAYLOAD_KEYS.get(operation_key)
        if contract is None:
            raise MacError(
                "EVENT_PAYLOAD_CONTRACT_TAMPERED" if persisted else "MUTATION_PAYLOAD_CONTRACT_INVALID",
                "governed operation has no closed payload contract",
                exit_code=ExitCode.CORRUPTION if persisted else ExitCode.SECURITY,
                task_id=task_id,
            )
        required, optional = (set(contract[0]), set(contract[1]))
        if not persisted:
            required.discard("authority")
            optional.discard("authority")
            if operation_key == "run.register":
                store_derived = {"baseline_subject", "worktree_identity", "repository_binding"}
                required.difference_update(store_derived)
                optional.update(store_derived)
        valid_metadata = True
    actual = set(payload)
    if not required.issubset(actual) or not actual.issubset(required | optional) or not valid_metadata:
        raise MacError(
            "EVENT_PAYLOAD_CONTRACT_TAMPERED" if persisted else "MUTATION_PAYLOAD_CONTRACT_INVALID",
            "Event payload keys do not match the governed operation contract",
            exit_code=ExitCode.CORRUPTION if persisted else ExitCode.SECURITY,
            task_id=task_id,
            details={
                "missing": sorted(required - actual),
                "unexpected": sorted(actual - required - optional),
            },
        )
    if operation == "run.finish":
        unit_keys = {"work_unit_id", "work_unit"}
        status = payload.get("status")
        if (status in {"failed", "cancelled"}) != unit_keys.issubset(actual) or bool(actual & unit_keys) != unit_keys.issubset(actual):
            raise MacError(
                "EVENT_PAYLOAD_CONTRACT_TAMPERED" if persisted else "MUTATION_PAYLOAD_CONTRACT_INVALID",
                "failed or cancelled Run finish must bind exactly one Work Unit snapshot",
                exit_code=ExitCode.CORRUPTION if persisted else ExitCode.SECURITY,
                task_id=task_id,
            )


def _make_store_guard() -> tuple[
    Callable[["FilesystemTaskRepository", MutationCommand], MutationResult],
    Callable[[object | None, str | None], None],
]:
    """Keep the writer capability lexical; importing a module token is not authority."""

    permit = object()

    def dispatch(repository: "FilesystemTaskRepository", command: MutationCommand) -> MutationResult:
        return repository._execute_governed(command, _permit=permit)

    def require(candidate: object | None, task_id: str | None = None) -> None:
        if candidate is not permit:
            raise MacError(
                "MUTATION_GATEWAY_REQUIRED",
                "persistent repository writes must use MutationGateway.execute",
                exit_code=ExitCode.SECURITY,
                task_id=task_id,
            )

    return dispatch, require


_GOVERNED_STORE_EXECUTE, _require_store_permit = _make_store_guard()
del _make_store_guard


def _repository_identity(repo: Path) -> str:
    try:
        identity: Mapping[str, Any] = GitRepository(repo).storage_identity()
    except (MacError, OSError, ValueError):
        # Bootstrap/non-Git repositories still need an exact host binding.  The
        # fallback is intentionally path-specific and is replaced by the shared
        # Git storage identity once the repository exists.
        identity = {"resolved_root": str(repo.resolve())}
    return "repo:" + canonical_digest(identity)


def _without_authority(value: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(value))
    result.pop("authority", None)
    metadata = result.get("transition_metadata")
    if isinstance(metadata, dict):
        metadata.pop("authority", None)
    return result


def _repo_path(repo: Path, path: Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(repo.resolve()).as_posix()
    except ValueError as exc:
        raise MacError(
            "ENTITY_PATH_UNSAFE",
            "mutation path is outside the repository",
            exit_code=ExitCode.SECURITY,
            path=str(path),
        ) from exc


def _policy_digests(task: Mapping[str, Any]) -> tuple[str, str]:
    return (
        str((task.get("policy_ref") or {}).get("combined_digest", "")),
        str((task.get("ownership_ref") or {}).get("combined_digest", "")),
    )


def _validate_executable_policy_snapshot(repo: Path, task: Mapping[str, Any], *, task_id: str) -> None:
    compiled = compile_policy(repo, runtime_profile_id=str(task.get("runtime_profile") or "") or None)
    required_policy_paths = set(policy_source_paths(compiled.config, str(task.get("runtime_profile") or "") or None))
    required_ownership_path = ownership_source_path(compiled.config)
    if not policy_ref_matches_executable(repo, task.get("policy_ref") or {}, required_paths=required_policy_paths):
        raise MacError(
            "POLICY_DRIFT",
            "task policy snapshot does not match the executable machine policy",
            exit_code=ExitCode.SECURITY,
            task_id=task_id,
        )
    if not policy_ref_matches_executable(repo, task.get("ownership_ref") or {}, required_paths={required_ownership_path}):
        raise MacError(
            "OWNERSHIP_DRIFT",
            "task ownership snapshot does not match the executable ownership policy",
            exit_code=ExitCode.SECURITY,
            task_id=task_id,
        )


_INDEPENDENT_MUTATIONS = frozenset({
    "scope.approve",
    "risk.accept",
    "task.transition.completed",
    "task.transition.completed_with_risk",
})


def _enforce_operation_independence(
    audit: dict[str, Any],
    task: Mapping[str, Any],
    scope: Mapping[str, Any],
    config: Mapping[str, Any],
    *,
    operation: str,
    task_id: str,
) -> None:
    privileged = operation in _INDEPENDENT_MUTATIONS or operation.startswith("approval.record.")
    if not privileged:
        return
    mode = str(task.get("mode", "standard"))
    required = str(((config.get("modes") or {}).get(mode) or {}).get("minimum_review_independence", "L1"))
    if governance_sensitive(dict(scope), dict(config)) and not level_at_least(required, "L2"):
        required = "L2"
    if not level_at_least(str(audit.get("independence_level", "")), required):
        raise MacError(
            "MUTATION_INDEPENDENCE_INSUFFICIENT",
            "verified authority does not satisfy the policy-derived mutation independence",
            exit_code=ExitCode.SECURITY,
            task_id=task_id,
            details={"required": required},
        )
    stored_policy_minimum = audit.get("policy_minimum_independence")
    if stored_policy_minimum is not None and stored_policy_minimum != required:
        raise MacError(
            "MUTATION_POLICY_INDEPENDENCE_MISMATCH",
            "stored policy independence floor does not match frozen policy",
            exit_code=ExitCode.SECURITY,
            task_id=task_id,
        )
    # ``minimum_independence`` is part of the signed mutation intent. Keep it
    # byte-for-byte stable and record the Store-derived floor separately.
    audit["policy_minimum_independence"] = required


def _bind_entity_authority(
    repo: Path,
    command: AppendEvent,
    verified: VerifiedAuthority,
) -> tuple[dict[str, Any], list[tuple[Path, dict[str, Any]]]]:
    payload = _without_authority(command.payload)
    actor = {"id": verified.actor_id, "kind": verified.actor_kind}
    bound: list[tuple[Path, dict[str, Any]]] = []
    for path, raw in command.materializations:
        value = deepcopy(dict(raw))
        relative = _materialization_relative(repo, command.task_id, path)
        directory = _materialization_directory(relative)
        actor_field: str | None = None
        bind_independence = False
        if directory == "approvals":
            actor_field = "actor"
            bind_independence = True
        elif directory == "runs" and command.operation in {"run.register", "evidence.record"}:
            actor_field = "actor"
            # A Run's independence describes its execution context, while the
            # broker decision describes the authority used to persist it.  The
            # signed mutation intent already binds the requested minimum and
            # ``_verify_policy_authority`` proves the broker decision meets it;
            # replacing the Run value here would incorrectly turn an L0 Run
            # into L2/L3 whenever a more independent controller records it.
        elif directory == "risk-acceptances":
            actor_field = "accepted_by"
        if actor_field is not None:
            claimed = value.get(actor_field)
            if claimed != actor:
                raise MacError(
                    "MUTATION_ENTITY_ACTOR_MISMATCH",
                    "entity actor must equal the verified mutation actor",
                    exit_code=ExitCode.SECURITY,
                    path=relative.as_posix(),
                    task_id=command.task_id,
                )
            value[actor_field] = actor
        if bind_independence:
            value["independence_level"] = verified.independence_level
        if directory == "scope-contract":
            if command.operation in {"scope.propose", "scope.amend"} and value.get("proposed_by") != verified.actor_id:
                raise MacError(
                    "MUTATION_ENTITY_ACTOR_MISMATCH",
                    "Scope proposer must equal the verified mutation actor",
                    exit_code=ExitCode.SECURITY,
                    path=relative.as_posix(),
                    task_id=command.task_id,
                )
            if command.operation == "scope.approve" and value.get("approved_by") != [verified.actor_id]:
                raise MacError(
                    "MUTATION_ENTITY_ACTOR_MISMATCH",
                    "Scope approval must name only the verified mutation actor",
                    exit_code=ExitCode.SECURITY,
                    path=relative.as_posix(),
                    task_id=command.task_id,
                )
        snapshot_key = {directory: key for key, directory in _SNAPSHOT_DIRECTORIES.items()}.get(directory)
        if snapshot_key is not None and snapshot_key in payload:
            payload[snapshot_key] = deepcopy(value)
        bound.append((path, value))
    return payload, bound


def _bind_run_registration_facts(
    repo: Path,
    command: AppendEvent,
    task: Mapping[str, Any],
    scope: Mapping[str, Any],
    payload: dict[str, Any],
    materializations: list[tuple[Path, dict[str, Any]]],
    occurred_at: str,
) -> tuple[dict[str, Any], list[tuple[Path, dict[str, Any]]], str | None]:
    """Replace caller-reported Run Git facts with Store-derived values."""

    if command.operation != "run.register":
        return payload, materializations, None
    run = deepcopy(dict(payload["run"]))
    runtime = deepcopy(dict(run.get("runtime") or {}))
    if runtime.get("profile") != task.get("runtime_profile"):
        raise MacError(
            "MUTATION_RUN_PROFILE_INVALID",
            "Run profile must equal the Task frozen runtime profile",
            exit_code=ExitCode.SECURITY,
            task_id=command.task_id,
        )
    run_root = Path(str(runtime.get("worktree") or repo)).resolve()
    task_git = GitRepository(repo)
    run_git = GitRepository(run_root)
    baseline_subject = run_git.commit_subject("HEAD")
    binding_checks = task_git.run_worktree_binding_checks(
        run_git,
        approved_base=str(scope.get("base_commit", "")),
        baseline_subject=baseline_subject,
    )
    branch_result = subprocess.run(
        ["git", "-C", str(run_root), "rev-parse", "--abbrev-ref", "HEAD"],
        shell=False,
        text=True,
        capture_output=True,
    )
    actual_branch = branch_result.stdout.strip() if branch_result.returncode == 0 else ""
    if not all(binding_checks.values()) or not actual_branch:
        raise MacError(
            "MUTATION_RUN_REPOSITORY_INVALID",
            "Run worktree and baseline are not bound to the Task repository",
            exit_code=ExitCode.SECURITY,
            task_id=command.task_id,
            details={"checks": binding_checks},
        )
    runtime["worktree"] = str(run_root)
    runtime["branch"] = actual_branch
    run["runtime"] = runtime
    run["started_at"] = occurred_at
    run["finished_at"] = None
    run["exit_code"] = None
    payload["run"] = run
    payload["baseline_subject"] = baseline_subject
    payload["worktree_identity"] = {"path": str(run_root), "branch": actual_branch}
    payload["repository_binding"] = binding_checks
    rebound = [
        (path, deepcopy(run) if _materialization_directory(_materialization_relative(repo, command.task_id, path)) == "runs" else value)
        for path, value in materializations
    ]
    return payload, rebound, occurred_at


def _bind_run_finish_facts(
    repo: Path,
    command: AppendEvent,
    payload: dict[str, Any],
    materializations: list[tuple[Path, dict[str, Any]]],
    occurred_at: str,
) -> tuple[dict[str, Any], list[tuple[Path, dict[str, Any]]], str | None]:
    """Replace a caller-reported Run finish time with the Store commit time."""

    if command.operation != "run.finish":
        return payload, materializations, None
    run = deepcopy(dict(payload["run"]))
    run["finished_at"] = occurred_at
    payload["run"] = run
    rebound = [
        (
            path,
            deepcopy(run)
            if _materialization_directory(
                _materialization_relative(repo, command.task_id, path)
            ) == "runs"
            else value,
        )
        for path, value in materializations
    ]
    return payload, rebound, occurred_at


def _bind_entity_timestamps(
    repo: Path,
    command: AppendEvent,
    payload: dict[str, Any],
    materializations: list[tuple[Path, dict[str, Any]]],
    occurred_at: str,
) -> tuple[dict[str, Any], list[tuple[Path, dict[str, Any]]]]:
    """Replace caller-selected lifecycle timestamps with the Store commit time."""

    binding = {
        "scope.approve": ("approvals", "approval", "recorded_at"),
        "finding.open": ("findings", "finding", "opened_at"),
        "finding.resolve": ("findings", "finding", "resolved_at"),
        "risk.accept": ("risk-acceptances", "risk_acceptance", "accepted_at"),
        "evidence.promote": ("evidence", "evidence", "recorded_at"),
    }.get(_materialization_operation(command.operation))
    if command.operation.startswith("approval.record."):
        binding = ("approvals", "approval", "recorded_at")
    if binding is None:
        return payload, materializations
    directory, snapshot_key, field = binding
    rebound: list[tuple[Path, dict[str, Any]]] = []
    for path, raw in materializations:
        value = deepcopy(dict(raw))
        candidate_directory = _materialization_directory(
            _materialization_relative(repo, command.task_id, path)
        )
        if candidate_directory == directory:
            value[field] = occurred_at
            payload[snapshot_key] = deepcopy(value)
        rebound.append((path, value))
    return payload, rebound


def _without_fields(value: Mapping[str, Any], fields: set[str]) -> dict[str, Any]:
    return {key: deepcopy(item) for key, item in value.items() if key not in fields}


def _event_entity_revisions(
    events: Iterable[Mapping[str, Any]],
) -> tuple[dict[str, dict[str, int]], int]:
    """Return effective entity revisions; promotions inherit their source revision."""

    revisions: dict[str, dict[str, int]] = {
        directory: {} for directory in _ENTITY_SCHEMAS
    }
    scope_revision = -1
    for event in events:
        payload = event.get("payload") or {}
        revision = int(event.get("new_revision", -1))
        if isinstance(payload.get("scope"), Mapping):
            scope_revision = revision
        for snapshot_key, directory in _SNAPSHOT_DIRECTORIES.items():
            if directory == "scope-contract":
                continue
            snapshot = payload.get(snapshot_key)
            if not isinstance(snapshot, Mapping):
                continue
            entity_id = str(snapshot.get("id", ""))
            if directory == "evidence" and event.get("event_type") == "evidence_recorded":
                promotion = payload.get("promotion") or {}
                source_id = str(promotion.get("source_evidence_id", ""))
                revisions[directory][entity_id] = revisions[directory].get(
                    source_id,
                    revision,
                )
            elif directory == "evidence":
                revisions[directory].setdefault(entity_id, revision)
            else:
                revisions[directory][entity_id] = revision
    return revisions, scope_revision


def _finding_reverification_complete(
    events: Iterable[Mapping[str, Any]],
    evidence: Mapping[str, Mapping[str, Any]],
    runs: Mapping[str, Mapping[str, Any]],
    finding: Mapping[str, Any],
    *,
    task: Mapping[str, Any],
    current_subject: Mapping[str, Any] | None = None,
) -> bool:
    event_list = list(events)
    invalidated_claims = {str(value) for value in finding.get("invalidates", [])}
    if not invalidated_claims:
        return True
    finding_id = str(finding.get("id", ""))
    opened_revision = max(
        (
            int(event.get("new_revision", -1))
            for event in event_list
            if event.get("event_type") == "finding_opened"
            and ((event.get("payload") or {}).get("finding") or {}).get("id") == finding_id
        ),
        default=-1,
    )
    if opened_revision < 0:
        return False
    entity_revisions, scope_revision = _event_entity_revisions(event_list)
    evidence_revisions = entity_revisions["evidence"]
    minimum_revision = max(opened_revision, scope_revision)
    from .application.governance import evaluate_evidence

    covered: set[str] = set()
    for evidence_id, item in evidence.items():
        record_revision = evidence_revisions.get(str(evidence_id), -1)
        if record_revision <= minimum_revision:
            continue
        subject = current_subject if current_subject is not None else item.get("subject") or {}
        decision = evaluate_evidence(
            item,
            current_subject=subject,
            policy_digest=str((task.get("policy_ref") or {}).get("combined_digest", "")),
            runs=runs,
            applicable_claims=invalidated_claims,
            record_revision=record_revision,
            minimum_revision=minimum_revision + 1,
        )
        if not decision.ok:
            continue
        for claim in item.get("claims", []):
            if claim.get("gate"):
                covered.add(str(claim["gate"]))
            if claim.get("acceptance_criterion"):
                covered.add(str(claim["acceptance_criterion"]))
    return invalidated_claims.issubset(covered)


def _reject_terminal_task(task: Mapping[str, Any], *, task_id: str) -> None:
    if str(task.get("state", "")) in TERMINAL_STATES:
        raise MacError(
            "MUTATION_TERMINAL_TASK",
            "terminal Tasks do not accept further domain mutations",
            exit_code=ExitCode.SECURITY,
            task_id=task_id,
        )


def _validate_append_semantics(
    repo: Path,
    command: AppendEvent,
    task: Mapping[str, Any],
    scope: Mapping[str, Any],
    compiled: Any,
    verified: VerifiedAuthority,
    *,
    events: list[dict[str, Any]] | None = None,
) -> None:
    payload = _without_authority(command.payload)
    events = events if events is not None else FilesystemTaskRepository(repo).list_events(command.task_id)
    snapshots = replay_entity_snapshots(events)
    operation = command.operation
    _reject_terminal_task(task, task_id=command.task_id)
    if operation == "scope.propose":
        proposed = payload["scope"]
        allowed_changes = {"status", "proposed_by", "approved_by", "allowed_paths", "denied_paths", "owners", "allowed_operations"}
        if (
            scope.get("status") != "proposed"
            or proposed.get("status") != "proposed"
            or proposed.get("proposed_by") != verified.actor_id
            or proposed.get("approved_by", []) != []
            or _without_fields(scope, allowed_changes) != _without_fields(proposed, allowed_changes)
        ):
            raise MacError(
                "MUTATION_SCOPE_PROPOSAL_INVALID",
                "Scope proposal may only revise the still-unapproved v1 proposal fields",
                exit_code=ExitCode.SECURITY,
                task_id=command.task_id,
            )
    elif operation == "scope.amend":
        proposed = payload["scope"]
        history = [
            dict(value)
            for path, value in command.materializations
            if _materialization_directory(_materialization_relative(repo, command.task_id, path)) == "scope-history"
        ]
        add_paths = [str(path) for path in proposed.get("allowed_paths", []) if path not in scope.get("allowed_paths", [])]
        add_operations = [
            str(value)
            for value in proposed.get("allowed_operations", [])
            if value not in scope.get("allowed_operations", [])
        ]
        added_risk_tags = [str(tag) for tag in proposed.get("risk_tags", []) if tag not in scope.get("risk_tags", [])]
        try:
            expected = amend_scope(
                dict(scope),
                add_paths=add_paths,
                actor=verified.actor_id,
                approvers=[],
                added_risk_tags=added_risk_tags,
                independent_approval=False,
                add_operations=add_operations,
            )
        except ValueError as exc:
            raise MacError(
                "MUTATION_SCOPE_AMENDMENT_INVALID",
                str(exc),
                exit_code=ExitCode.SECURITY,
                task_id=command.task_id,
            ) from exc
        if scope.get("status") != "approved" or proposed != expected or history != [dict(scope)]:
            raise MacError(
                "MUTATION_SCOPE_AMENDMENT_INVALID",
                "Scope amendment must derive a new proposed version from the event-replayed approved Scope",
                exit_code=ExitCode.SECURITY,
                task_id=command.task_id,
            )
    elif operation == "work_unit.create":
        unit = payload["work_unit"]
        expected_result = str(unit.get("expected_result", ""))
        expected_prefix = f"tasks/{command.task_id}/results/"
        expected_name = expected_result.removeprefix(expected_prefix).removesuffix(".json")
        if (
            scope.get("status") != "approved"
            or unit.get("status") != "pending"
            or str(unit.get("id")) in snapshots["work-units"]
            or str(unit.get("owner")) not in {str(owner) for owner in scope.get("owners", [])}
            or any(path not in scope.get("allowed_paths", []) for path in unit.get("allowed_paths", []))
            or any(str(item) not in snapshots["work-units"] for item in unit.get("depends_on", []))
            or not expected_result.startswith(expected_prefix)
            or not expected_result.endswith(".json")
            or not is_identifier(expected_name, "RESULT")
        ):
            raise MacError("MUTATION_WORK_UNIT_STATE_INVALID", "new Work Unit must begin pending", exit_code=ExitCode.SECURITY, task_id=command.task_id)
    elif operation == "work_unit.ready":
        unit = payload["work_unit"]
        prior = snapshots["work-units"].get(str(unit.get("id")))
        if (
            scope.get("status") != "approved"
            or not isinstance(prior, Mapping)
            or prior.get("status") != "pending"
            or unit.get("status") != "ready"
            or _without_fields(prior, {"status"}) != _without_fields(unit, {"status"})
        ):
            raise MacError("MUTATION_WORK_UNIT_STATE_INVALID", "Work Unit ready must be pending -> ready only", exit_code=ExitCode.SECURITY, task_id=command.task_id)
    elif operation == "run.register":
        run = payload["run"]
        unit = payload["work_unit"]
        prior = snapshots["work-units"].get(str(unit.get("id")))
        dependencies = list((prior or {}).get("depends_on", [])) if isinstance(prior, Mapping) else []
        prior_invalid = not isinstance(prior, Mapping) or (
            prior.get("status") != "ready"
            or unit.get("status") != "running"
            or _without_fields(prior, {"status"}) != _without_fields(unit, {"status"})
            or any(snapshots["work-units"].get(str(item), {}).get("status") != "completed" for item in dependencies)
        )
        runtime = run.get("runtime") or {}
        run_root = Path(str(runtime.get("worktree") or repo)).resolve()
        binding_valid = False
        try:
            task_git = GitRepository(repo)
            run_git = GitRepository(run_root)
            baseline_subject = run_git.commit_subject("HEAD")
            binding_checks = task_git.run_worktree_binding_checks(
                run_git,
                approved_base=str(scope.get("base_commit", "")),
                baseline_subject=baseline_subject,
            )
            branch_result = subprocess.run(
                ["git", "-C", str(run_root), "rev-parse", "--abbrev-ref", "HEAD"],
                shell=False,
                text=True,
                capture_output=True,
            )
            actual_branch = branch_result.stdout.strip() if branch_result.returncode == 0 else ""
            binding_valid = (
                all(binding_checks.values())
                and payload.get("baseline_subject") == baseline_subject
                and payload.get("worktree_identity") == {"path": str(run_root), "branch": actual_branch}
                and payload.get("repository_binding") == binding_checks
                and runtime.get("worktree") == str(run_root)
                and runtime.get("branch") == actual_branch
                and runtime.get("profile") == task.get("runtime_profile")
            )
        except (MacError, OSError, TypeError, ValueError):
            binding_valid = False
        if (
            scope.get("status") != "approved"
            or str(task.get("state", "")) not in {"ready", "executing", "repairing"}
            or
            run.get("status") not in {"registered", "running"}
            or str(run.get("id")) in snapshots["runs"]
            or command.run_id not in {None, run.get("id")}
            or run.get("work_unit_id") != unit.get("id")
            or prior_invalid
            or not binding_valid
        ):
            raise MacError("MUTATION_RUN_REGISTER_INVALID", "Run registration does not match a ready Work Unit", exit_code=ExitCode.SECURITY, task_id=command.task_id)
    elif operation == "run.finish":
        run = payload["run"]
        prior = snapshots["runs"].get(str(run.get("id")))
        if run.get("status") == "succeeded":
            raise MacError(
                "RUN_SUCCESS_REQUIRES_RESULT",
                "successful Runs must be completed atomically by result submit",
                exit_code=ExitCode.TRANSITION,
                task_id=command.task_id,
            )
        if (
            not isinstance(prior, Mapping)
            or prior.get("status") not in {"registered", "running"}
            or run.get("status") not in {"succeeded", "failed", "cancelled"}
            or command.run_id != run.get("id")
            or (
                run.get("status") != "cancelled"
                and dict(prior.get("actor") or {})
                != {"id": verified.actor_id, "kind": verified.actor_kind}
            )
            or _without_fields(prior, {"status", "finished_at", "exit_code"})
            != _without_fields(run, {"status", "finished_at", "exit_code"})
        ):
            raise MacError("MUTATION_RUN_FINISH_INVALID", "Run finish may only terminalize an active Run", exit_code=ExitCode.SECURITY, task_id=command.task_id)
        try:
            started_at = datetime.fromisoformat(str(prior.get("started_at", "")).replace("Z", "+00:00"))
            finished_at = datetime.fromisoformat(str(run.get("finished_at", "")).replace("Z", "+00:00"))
        except ValueError as exc:
            raise MacError("MUTATION_RUN_FINISH_INVALID", "Run finish time is invalid", exit_code=ExitCode.SECURITY, task_id=command.task_id) from exc
        if (
            finished_at < started_at
            or (run.get("status") == "succeeded" and run.get("exit_code") != 0)
            or (run.get("status") == "failed" and run.get("exit_code") in {None, 0})
        ):
            raise MacError("MUTATION_RUN_FINISH_INVALID", "Run terminal status, time, and exit code are inconsistent", exit_code=ExitCode.SECURITY, task_id=command.task_id)
        unit = payload.get("work_unit")
        if isinstance(unit, Mapping):
            prior_unit = snapshots["work-units"].get(str(unit.get("id")))
            expected = "failed" if run.get("status") == "failed" else "cancelled"
            if (
                not isinstance(prior_unit, Mapping)
                or unit.get("status") != expected
                or _without_fields(prior_unit, {"status"}) != _without_fields(unit, {"status"})
            ):
                raise MacError("MUTATION_RUN_WORK_UNIT_INVALID", "Run failure Work Unit snapshot is invalid", exit_code=ExitCode.SECURITY, task_id=command.task_id)
    elif operation == "evidence.promote":
        from .evidence import promote_evidence

        evidence = payload["evidence"]
        promotion = payload.get("promotion") or {}
        source_id = str(promotion.get("source_evidence_id", ""))
        source = snapshots["evidence"].get(source_id)
        if not isinstance(source, Mapping) or str(evidence.get("id", "")) in snapshots["evidence"]:
            raise MacError("MUTATION_EVIDENCE_PROMOTION_INVALID", "Evidence promotion source is missing or target already exists", exit_code=ExitCode.SECURITY, task_id=command.task_id)
        try:
            proof = GitRepository(repo).workspace_equivalence_proof(
                dict(source.get("subject") or {}),
                "HEAD",
                task_id=command.task_id,
            )
            expected = promote_evidence(
                source,
                current_workspace_subject=proof.observed_workspace_subject,
                target_commit_subject=proof.target_commit_subject,
                equivalence_proof=proof,
            )
        except (MacError, OSError, TypeError, ValueError) as exc:
            raise MacError("MUTATION_EVIDENCE_PROMOTION_INVALID", "workspace Evidence is not commit-equivalent", exit_code=ExitCode.SECURITY, task_id=command.task_id) from exc
        stable_fields = {"id", "subject", "recorded_at"}
        expected_promotion = {
            **expected.event_payload,
            "promoted_evidence_id": evidence.get("id"),
        }
        if (
            not is_identifier(str(evidence.get("id", "")), "EVD")
            or _without_fields(source, stable_fields) != _without_fields(evidence, stable_fields)
            or evidence.get("subject") != proof.target_commit_subject
            or promotion != expected_promotion
        ):
            raise MacError("MUTATION_EVIDENCE_PROMOTION_INVALID", "Evidence promotion does not match Store-derived Git equivalence", exit_code=ExitCode.SECURITY, task_id=command.task_id)
    elif operation == "evidence.invalidate":
        from .evidence import invalidate_evidence

        evidence = payload["evidence"]
        evidence_id = str(payload.get("evidence_id", ""))
        prior = snapshots["evidence"].get(evidence_id)
        reason = str(payload.get("reason", ""))
        if (
            not isinstance(prior, Mapping)
            or not reason
            or command.event_id is None
            or not is_identifier(command.event_id, "EVT")
            or evidence != invalidate_evidence(prior, event_id=command.event_id, reason=reason)
        ):
            raise MacError("MUTATION_EVIDENCE_INVALIDATION_INVALID", "Evidence invalidation must derive from the event-replayed Evidence snapshot", exit_code=ExitCode.SECURITY, task_id=command.task_id)
    elif operation == "scope.approve":
        approval = payload["approval"]
        new_scope = payload["scope"]
        valid = valid_scope_approvals(task, scope, [approval], compiled.ownership, compiled.config)
        if (
            scope.get("status") != "proposed"
            or new_scope.get("status") != "approved"
            or not valid
            or _without_fields(scope, {"status", "approved_by"})
            != _without_fields(new_scope, {"status", "approved_by"})
        ):
            raise MacError("MUTATION_SCOPE_APPROVAL_INVALID", "Scope approval is not authorized by current policy and ownership", exit_code=ExitCode.SECURITY, task_id=command.task_id)
    elif operation.startswith("approval.record."):
        approval = payload["approval"]
        kind = operation.removeprefix("approval.record.")
        expected_subject = None
        if kind == "scope":
            from .authority import scope_approval_subject

            expected_subject = scope_approval_subject(task, scope)
        if (
            not actor_authorized_for_scope(verified.actor_id, scope, compiled.ownership)
            or approval.get("kind") != kind
            or approval.get("decision") not in {"approved", "rejected"}
            or (expected_subject is not None and approval.get("subject_ref") != expected_subject)
        ):
            raise MacError("MUTATION_APPROVAL_ACTOR_UNAUTHORIZED", "Approval actor is not authorized by Scope ownership", exit_code=ExitCode.SECURITY, task_id=command.task_id)
    elif operation == "risk.accept":
        from .application.governance import validate_risk_acceptance

        if not actor_authorized_for_scope(verified.actor_id, scope, compiled.ownership):
            raise MacError("MUTATION_RISK_ACTOR_UNAUTHORIZED", "Risk acceptor is not authorized by Scope ownership", exit_code=ExitCode.SECURITY, task_id=command.task_id)
        acceptance = payload["risk_acceptance"]
        finding = payload["finding"]
        finding_ids = [str(value) for value in acceptance.get("finding_ids", [])]
        prior = snapshots["findings"].get(finding_ids[0]) if len(finding_ids) == 1 else None
        decision = validate_risk_acceptance(
            acceptance,
            [prior] if isinstance(prior, Mapping) else [],
            authorized_actor_ids={verified.actor_id},
            non_waivable_gates=set((compiled.config.get("close_policy") or {}).get("non_waivable_gates", [])),
        )
        if (
            scope.get("status") != "approved"
            or not is_identifier(str(acceptance.get("id", "")), "RISK")
            or str(acceptance.get("id", "")) in snapshots["risk-acceptances"]
            or not isinstance(prior, Mapping)
            or prior.get("status") not in {"open", "acknowledged", "waived"}
            or not scope_binding_matches(acceptance.get("scope"), scope)
            or finding.get("status") != "waived"
            or _without_fields(prior, {"status"}) != _without_fields(finding, {"status"})
            or not decision.ok
        ):
            raise MacError(
                "MUTATION_RISK_ACCEPTANCE_INVALID",
                "Risk Acceptance must cover one event-replayed, policy-waivable Finding",
                exit_code=ExitCode.SECURITY,
                task_id=command.task_id,
                details={"issues": [issue.as_dict() for issue in decision.issues]},
            )
    elif operation == "finding.open":
        finding = payload["finding"]
        if (
            finding.get("status") != "open"
            or not is_identifier(str(finding.get("id", "")), "FND")
            or str(finding.get("id", "")) in snapshots["findings"]
            or finding.get("resolved_at") is not None
            or (
                finding.get("blocking_effect") != "advisory"
                and not finding.get("invalidates")
            )
            or (
                finding.get("root_cause_key") is not None
                and not _ROOT_CAUSE_KEY.fullmatch(str(finding.get("root_cause_key", "")))
            )
        ):
            raise MacError("MUTATION_FINDING_STATE_INVALID", "new Finding must begin open with a fresh FND id", exit_code=ExitCode.SECURITY, task_id=command.task_id)
    elif operation == "finding.resolve":
        finding = payload["finding"]
        prior = snapshots["findings"].get(str(finding.get("id")))
        fresh_categories = {
            str(value)
            for value in (compiled.config.get("repair_policy") or {}).get(
                "fresh_context_categories", []
            )
        }
        if (
            isinstance(prior, Mapping)
            and str(prior.get("category", "")) in fresh_categories
            and not level_at_least(verified.independence_level, "L1")
        ):
            raise MacError(
                "MUTATION_REPAIR_FRESH_CONTEXT_REQUIRED",
                "this Finding category requires a fresh repair context",
                exit_code=ExitCode.SECURITY,
                task_id=command.task_id,
            )
        if isinstance(prior, Mapping) and not _finding_reverification_complete(
            events,
            snapshots["evidence"],
            snapshots["runs"],
            prior,
            task=task,
            current_subject=(
                GitRepository(repo).workspace_subject(task_id=command.task_id)
                if GitRepository(repo).workspace_changes(task_id=command.task_id)
                else GitRepository(repo).current_code_subject(command.task_id)
            ),
        ):
            raise MacError(
                "MUTATION_FINDING_REVERIFICATION_REQUIRED",
                "Finding resolution requires fresh valid Evidence for every invalidated claim",
                exit_code=ExitCode.EVIDENCE,
                task_id=command.task_id,
            )
        if (
            not isinstance(prior, Mapping)
            or prior.get("status") not in {"open", "acknowledged", "waived"}
            or finding.get("status") != "resolved"
            or not finding.get("resolved_at")
            or _without_fields(prior, {"status", "resolved_at"})
            != _without_fields(finding, {"status", "resolved_at"})
        ):
            raise MacError("MUTATION_FINDING_STATE_INVALID", "Finding resolution requires an existing Finding", exit_code=ExitCode.SECURITY, task_id=command.task_id)
    elif operation == "result.submit":
        result = payload["result"]
        run = payload["run"]
        unit = payload["work_unit"]
        prior_run = snapshots["runs"].get(str(result.get("run_id")))
        prior_unit = snapshots["work-units"].get(str(result.get("work_unit_id")))
        succeeded = result.get("outcome") == "succeeded"
        if (
            not isinstance(prior_run, Mapping)
            or prior_run.get("status") not in {"registered", "running"}
            or not isinstance(prior_unit, Mapping)
            or prior_unit.get("status") != "running"
            or run.get("id") != prior_run.get("id")
            or unit.get("id") != prior_unit.get("id")
            or run.get("status") != ("succeeded" if succeeded else "failed")
            or unit.get("status") != ("completed" if succeeded else "failed")
            or result.get("task_id") != command.task_id
        ):
            raise MacError("MUTATION_RESULT_STATE_INVALID", "Result submission does not match an active Run and Work Unit", exit_code=ExitCode.SECURITY, task_id=command.task_id)


_EXPLICIT_TRANSITION_FACTS = frozenset({
    "blocking_findings_exist",
    "external_dependency_pending",
    "external_dependency_recovered",
    "external_evidence_received",
    "human_input_required",
    "input_received",
    "risk_surface_changed",
    "risk_surface_unchanged",
    "unrecoverable_failure",
})


def _verified_transition_fact(
    task: Mapping[str, Any],
    target: str,
    transition_fact: Mapping[str, Any] | None,
    *,
    compiled: Any,
) -> dict[str, bool]:
    transition = find_transition(str(task.get("state", "")), target, compiled.transitions)
    required = set(transition.conditions) & _EXPLICIT_TRANSITION_FACTS if transition is not None else set()
    if not required:
        if transition_fact is not None:
            raise MacError(
                "AUTHORITY_TRANSITION_FACT_UNEXPECTED",
                "this transition does not accept an external fact",
                exit_code=ExitCode.SECURITY,
                task_id=str(task.get("id", "")) or None,
            )
        return {}
    if not isinstance(transition_fact, Mapping):
        raise MacError(
            "AUTHORITY_TRANSITION_FACT_REQUIRED",
            "transition requires a validated external fact",
            exit_code=ExitCode.SECURITY,
            task_id=str(task.get("id", "")) or None,
        )
    fact = dict(transition_fact)
    conditions = fact.get("conditions")
    if (
        set(fact) != {"id", "source", "target", "conditions", "reason"}
        or not is_identifier(str(fact.get("id", "")), "FACT")
        or fact.get("source") != task.get("state")
        or fact.get("target") != target
        or not isinstance(conditions, list)
        or set(conditions) != required
        or len(conditions) != len(required)
        or not str(fact.get("reason", "")).strip()
    ):
        raise MacError(
            "AUTHORITY_TRANSITION_FACT_INVALID",
            "external transition fact does not exactly bind the workflow condition",
            exit_code=ExitCode.SECURITY,
            task_id=str(task.get("id", "")) or None,
        )
    replacements = {condition: True for condition in required if condition in TransitionContext.__dataclass_fields__}
    if "risk_surface_unchanged" in required:
        replacements["risk_surface_changed"] = False
    return replacements


def _close_transition_facts(
    close: Any,
    target: str,
    *,
    actor_authorized: bool,
) -> dict[str, bool]:
    """Map one Close decision to workflow guards without weakening review entry."""

    codes = set(close.codes)
    missing_non_review_gates = any(
        issue.code == "CLOSE_GATE_MISSING"
        and bool(set((issue.details or {}).get("gates", [])) - {"independent_review"})
        for issue in close.issues
    )
    evidence_coverage_ok = not missing_non_review_gates and "CLOSE_ACCEPTANCE_MISSING" not in codes
    review_complete = (
        evidence_coverage_ok
        and "independent_review" in set(close.covered_gates)
        and not any(code.startswith("REVIEW_") or code == "CLOSE_REVIEW_MISSING" for code in codes)
    )
    findings_clean = not any(
        code == "CLOSE_FINDING_BLOCKING"
        or code.startswith("RISK_")
        for code in codes
    )
    has_accepted_risk = bool(close.accepted_risk_acceptances)
    terminal_route_ok = close.ok and (
        (target == "completed" and not has_accepted_risk)
        or (target == "completed_with_risk" and has_accepted_risk)
    )
    if target in {"completed", "completed_with_risk"}:
        return {
            "evidence_complete": terminal_route_ok,
            "review_complete": terminal_route_ok,
            "close_findings_clean": terminal_route_ok,
            "close_actor_authorized": terminal_route_ok,
            "risk_acceptance_valid": (
                terminal_route_ok if target == "completed_with_risk" else True
            ),
        }
    return {
        "evidence_complete": evidence_coverage_ok,
        "review_complete": review_complete,
        "close_findings_clean": findings_clean,
        "close_actor_authorized": actor_authorized,
        "risk_acceptance_valid": True,
    }


_ROOT_CAUSE_KEY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


def _active_repair_roots(findings: Iterable[Mapping[str, Any]]) -> tuple[set[str], list[str]]:
    roots: set[str] = set()
    missing: list[str] = []
    for finding in findings:
        if (
            finding.get("blocking_effect") == "advisory"
            or finding.get("status") not in {"open", "fixing"}
        ):
            continue
        root = str(finding.get("root_cause_key", ""))
        if not _ROOT_CAUSE_KEY.fullmatch(root):
            missing.append(str(finding.get("id", "")))
        else:
            roots.add(root)
    return roots, sorted(value for value in missing if value)


def _assess_repair_round(
    prior_events: Iterable[Mapping[str, Any]],
    config: Mapping[str, Any],
    *,
    actor_kind: str,
    task_id: str,
) -> dict[str, Any]:
    """Enforce the frozen per-root automatic repair budget from Event history."""

    event_list = sorted(
        (dict(event) for event in prior_events),
        key=lambda event: (int(event.get("new_revision", -1)), str(event.get("event_id", ""))),
    )
    current_findings: dict[str, dict[str, Any]] = {}
    automatic_counts: dict[str, int] = {}
    for event in event_list:
        payload = event.get("payload") or {}
        finding = payload.get("finding")
        if isinstance(finding, Mapping) and finding.get("id"):
            current_findings[str(finding["id"])] = dict(finding)
        if (
            event.get("event_type") == "state_transitioned"
            and payload.get("to") == "repairing"
            and (event.get("actor") or {}).get("kind") in {"agent", "automation"}
        ):
            roots, _ = _active_repair_roots(current_findings.values())
            for root in roots:
                automatic_counts[root] = automatic_counts.get(root, 0) + 1
    active_roots, missing = _active_repair_roots(current_findings.values())
    if not active_roots and not missing:
        raise MacError(
            "REPAIR_FINDING_REQUIRED",
            "repairing requires an unresolved non-advisory Finding",
            exit_code=ExitCode.TRANSITION,
            task_id=task_id,
        )
    raw_limit = (config.get("repair_policy") or {}).get(
        "max_automatic_rounds_per_root_cause",
        2,
    )
    limit = raw_limit if type(raw_limit) is int and raw_limit >= 0 else 0
    automatic = actor_kind in {"agent", "automation"}
    if automatic and missing:
        raise MacError(
            "REPAIR_ROOT_CAUSE_REQUIRED",
            "automatic repair requires a stable root_cause_key on every active Finding",
            exit_code=ExitCode.TRANSITION,
            task_id=task_id,
            details={"finding_ids": missing, "next_targets": ["waiting_input", "failed"]},
        )
    exhausted = sorted(
        root for root in active_roots
        if automatic_counts.get(root, 0) >= limit
    ) if automatic else []
    if exhausted:
        raise MacError(
            "REPAIR_ROUND_LIMIT_EXHAUSTED",
            "automatic repair round budget is exhausted for an active root cause",
            exit_code=ExitCode.TRANSITION,
            task_id=task_id,
            details={
                "root_cause_keys": exhausted,
                "limit": limit,
                "counts": {root: automatic_counts.get(root, 0) for root in exhausted},
                "next_targets": ["waiting_input", "failed"],
            },
        )
    return {
        "automatic": automatic,
        "limit": limit,
        "active_roots": sorted(active_roots),
        "counts": {root: automatic_counts.get(root, 0) for root in sorted(active_roots)},
    }


def _results_complete_after_latest_repair(
    events: Iterable[Mapping[str, Any]],
    *,
    results_present: bool,
    work_units_complete: bool,
) -> bool:
    if not results_present or not work_units_complete:
        return False
    latest_repair = max(
        (
            int(event.get("new_revision", -1))
            for event in events
            if event.get("event_type") == "state_transitioned"
            and ((event.get("payload") or {}).get("to") == "repairing")
        ),
        default=-1,
    )
    latest_result = max(
        (
            int(event.get("new_revision", -1))
            for event in events
            if event.get("event_type") == "result_submitted"
        ),
        default=-1,
    )
    return latest_result > latest_repair


def resolve_transition_context(
    repo: Path,
    task_id: str,
    target: str,
    verified_actor: Mapping[str, Any] | str,
    transition_fact: Mapping[str, Any] | None = None,
    *,
    successor_task_id: str | None = None,
    verified_events: list[dict[str, Any]] | None = None,
) -> TransitionContext:
    """Recompute transition guards from repository facts, never caller booleans."""

    root = repo.resolve()
    repository = FilesystemTaskRepository(root)
    events = verified_events if verified_events is not None else repository.list_events(task_id)
    task = replay_events(events)
    directory = repository.task_dir(task_id)
    actor_id = (
        str(verified_actor.get("id", ""))
        if isinstance(verified_actor, Mapping)
        else str(verified_actor)
    )
    ordered_events = sorted(
        events,
        key=lambda event: (int(event.get("new_revision", -1)), str(event.get("event_id", ""))),
    )
    scope = next(
        (
            deepcopy(dict(snapshot))
            for event in reversed(ordered_events)
            if isinstance((snapshot := (event.get("payload") or {}).get("scope")), Mapping)
        ),
        None,
    )
    if scope is None:
        scope = load_data(directory / "scope-contract.yaml")
    snapshots = replay_entity_snapshots(events)
    work_units = list(snapshots["work-units"].values())
    runs = list(snapshots["runs"].values())
    results = list(snapshots["results"].values())
    approvals = list(snapshots["approvals"].values())
    compiled = compile_policy(root, runtime_profile_id=str(task.get("runtime_profile") or "") or None)
    transition = find_transition(str(task.get("state", "")), target, compiled.transitions)
    config = compiled.config
    ownership = compiled.ownership
    scope_approvals = valid_scope_approvals(task, scope, approvals, ownership, config)
    active_runs = [run for run in runs if run.get("status") in {"registered", "running"}]
    units_by_id = {str(unit.get("id")): unit for unit in work_units}
    dependencies_complete = bool(active_runs) and all(
        (unit := units_by_id.get(str(run.get("work_unit_id")))) is not None
        and unit.get("status") in {"ready", "running"}
        and all(
            units_by_id.get(str(dependency), {}).get("status") == "completed"
            for dependency in unit.get("depends_on", [])
        )
        for run in active_runs
    )
    try:
        git = GitRepository(root)
        scope_clean = check_changes(
            git.changes_since(scope.get("base_commit"), task_id=task_id),
            scope,
            ownership=ownership,
            repo_root=root,
            task_id=task_id,
            governance_approval_level=max(
                (str(item.get("independence_level", "L0")) for item in scope_approvals),
                default=None,
            ),
            submodule_approved=any("submodule_change" in item.get("comment", "") for item in scope_approvals),
        ).ok
        workspace_changes = git.workspace_changes(task_id=task_id)
        current_subject = (
            git.workspace_subject(task_id=task_id)
            if workspace_changes
            else git.current_code_subject(task_id)
        )
        current_subject_digest = bool(current_subject)
    except Exception:
        scope_clean = False
        current_subject = None
        current_subject_digest = False
    close = None
    if transition is not None and target in {"reviewing", "completed", "completed_with_risk"}:
        from .application.close import evaluate_repository_close

        close = evaluate_repository_close(root, task_id, actor_id)
    triage_complete = bool(
        task.get("mode")
        and task.get("acceptance_criteria")
        and scope.get("owners")
        and task.get("runtime_profile")
        and task.get("policy_ref")
        and task.get("ownership_ref")
    )
    work_units_complete = bool(work_units) and all(unit.get("status") == "completed" for unit in work_units)
    result_submitted = _results_complete_after_latest_repair(
        events,
        results_present=bool(results),
        work_units_complete=work_units_complete,
    )
    actor_authorized = actor_authorized_for_scope(actor_id, scope, ownership)
    verified_successor: str | None = None
    if target == "superseded" and actor_authorized and successor_task_id is not None:
        if (
            is_identifier(successor_task_id, "TASK")
            and successor_task_id != task_id
            and (repository.task_dir(successor_task_id) / "task.yaml").is_file()
        ):
            verified_successor = successor_task_id
    close_facts = (
        _close_transition_facts(close, target, actor_authorized=actor_authorized)
        if close is not None
        else {
            "evidence_complete": False,
            "review_complete": False,
            "close_findings_clean": True,
            "close_actor_authorized": actor_authorized,
            "risk_acceptance_valid": target != "completed_with_risk",
        }
    )
    mode_gates = set(
        str(value)
        for value in ((config.get("modes") or {}).get(str(task.get("mode", "")), {}) or {}).get("required_gates", [])
    )
    review_required = (
        str(task.get("mode", "")) in {"high_risk", "audit"}
        or "independent_review" in {
            *[str(value) for value in task.get("required_gates", [])],
            *[str(value) for value in scope.get("required_gates", [])],
            *mode_gates,
        }
    )
    context = TransitionContext(
        triage_complete=triage_complete,
        scope_approved=scope.get("status") == "approved" and bool(scope_approvals),
        gates_selected=bool(task.get("required_gates")),
        runtime_satisfied=bool(
            (compiled.runtime_profile.get("capabilities") or {}).get("command_execution")
        ),
        result_submitted=result_submitted,
        work_units_complete=work_units_complete,
        scope_clean=scope_clean,
        current_subject_digest=current_subject_digest,
        current_subject=deepcopy(current_subject),
        evidence_complete=close_facts["evidence_complete"],
        review_complete=close_facts["review_complete"],
        close_findings_clean=close_facts["close_findings_clean"],
        close_actor_authorized=close_facts["close_actor_authorized"],
        risk_acceptance_valid=close_facts["risk_acceptance_valid"],
        review_required=review_required,
        controller_lease_valid=False,
        lease_valid=False,
        executor_run_created=bool(active_runs) or target != "executing",
        work_unit_dependencies_complete=dependencies_complete,
        dependencies_complete=dependencies_complete,
        baseline_recorded=bool(scope.get("base_commit") or task.get("policy_ref", {}).get("source_commit")),
        authorized_cancellation=actor_authorized,
        successor_task_id=verified_successor,
    )
    replacements = _verified_transition_fact(task, target, transition_fact, compiled=compiled)
    return replace(context, **replacements) if replacements else context


def _transition_context_snapshot(value: object, *, task_id: str) -> TransitionContext:
    """Decode the complete signed context without bool/int coercion."""

    if not isinstance(value, Mapping):
        raise MacError(
            "EVENT_TRANSITION_CONTEXT_INVALID",
            "signed transition context is missing",
            exit_code=ExitCode.CORRUPTION,
            task_id=task_id,
        )
    expected = set(asdict(TransitionContext()))
    if set(value) != expected:
        raise MacError(
            "EVENT_TRANSITION_CONTEXT_INVALID",
            "signed transition context fields are not exact",
            exit_code=ExitCode.CORRUPTION,
            task_id=task_id,
        )
    boolean_fields = expected - {"successor_task_id", "current_subject"}
    if any(type(value.get(field)) is not bool for field in boolean_fields):
        raise MacError(
            "EVENT_TRANSITION_CONTEXT_INVALID",
            "signed transition guard facts must be booleans",
            exit_code=ExitCode.CORRUPTION,
            task_id=task_id,
        )
    successor = value.get("successor_task_id")
    subject = value.get("current_subject")
    if successor is not None and type(successor) is not str:
        raise MacError(
            "EVENT_TRANSITION_CONTEXT_INVALID",
            "signed successor identity is invalid",
            exit_code=ExitCode.CORRUPTION,
            task_id=task_id,
        )
    if subject is not None and (
        not isinstance(subject, Mapping)
        or any(type(key) is not str or type(item) is not str for key, item in subject.items())
    ):
        raise MacError(
            "EVENT_TRANSITION_CONTEXT_INVALID",
            "signed code subject is invalid",
            exit_code=ExitCode.CORRUPTION,
            task_id=task_id,
        )
    return TransitionContext(
        **{
            **dict(value),
            "current_subject": deepcopy(dict(subject)) if isinstance(subject, Mapping) else None,
        }
    )


def _historical_subject_scope_facts(
    repo: Path,
    task_id: str,
    subject: Mapping[str, Any] | None,
    scope: Mapping[str, Any],
    scope_approvals: list[Mapping[str, Any]],
    ownership: Mapping[str, Any],
    prior_events: list[dict[str, Any]],
) -> tuple[bool, bool]:
    """Verify a signed subject and its Scope diff without reading current workspace state."""

    if not isinstance(subject, Mapping):
        return False, False
    approval_level = max(
        (str(item.get("independence_level", "L0")) for item in scope_approvals),
        default=None,
    )
    submodule_approved = any(
        "submodule_change" in str(item.get("comment", ""))
        for item in scope_approvals
    )
    changes = None
    if subject.get("type") == "commit":
        try:
            git = GitRepository(repo)
            commit_sha = str(subject.get("commit_sha", ""))
            if git.commit_subject(commit_sha) != dict(subject):
                return False, False
            changes = git.changes_since(
                str(scope.get("base_commit", "")) or None,
                head=commit_sha,
                task_id=task_id,
                include_workspace=False,
            )
        except (MacError, OSError, TypeError, ValueError):
            return False, False
    elif subject.get("type") == "workspace":
        try:
            from .result import ResultIntakeProof

            for candidate in reversed(prior_events):
                candidate_payload = candidate.get("payload") or {}
                result = candidate_payload.get("result")
                proof_value = candidate_payload.get("intake_proof")
                if not isinstance(result, Mapping) or not isinstance(proof_value, Mapping):
                    continue
                proof = ResultIntakeProof.from_mapping(proof_value)
                if (
                    proof.valid()
                    and proof.binds(dict(result))
                    and proof.result_subject == dict(subject)
                ):
                    changes = proof.scope_changes()
                    break
        except (KeyError, TypeError, ValueError):
            return False, False
    if changes is None:
        return False, False
    result = check_changes(
        changes,
        dict(scope),
        ownership=dict(ownership),
        repo_root=None,
        task_id=task_id,
        governance_approval_level=approval_level,
        submodule_approved=submodule_approved,
    )
    return True, bool(scope_approvals) and result.ok


def _resolve_historical_transition_context(
    repo: Path,
    task_id: str,
    target: str,
    prior_events: list[dict[str, Any]],
    actor_id: str,
    actor_kind: str,
    transition_fact: Mapping[str, Any] | None,
    signed_context: object,
    *,
    compiled: Any,
    occurred_at: object,
    successor_task_id: str | None = None,
) -> TransitionContext:
    """Recompute replayable guards from prior Events and immutable Git objects."""

    context = _transition_context_snapshot(signed_context, task_id=task_id)
    task = replay_events(prior_events)
    scope, _ = replay_scope_snapshots(prior_events)
    if not isinstance(scope, Mapping):
        raise MacError(
            "EVENT_TRANSITION_SCOPE_MISSING",
            "historical transition has no replayable Scope Contract",
            exit_code=ExitCode.CORRUPTION,
            task_id=task_id,
        )
    transition = find_transition(str(task.get("state", "")), target, compiled.transitions)
    if transition is None:
        raise MacError(
            "EVENT_TRANSITION_NOT_ALLOWED",
            "historical transition is absent from the frozen workflow",
            exit_code=ExitCode.CORRUPTION,
            task_id=task_id,
        )
    if target == "repairing":
        _assess_repair_round(
            prior_events,
            compiled.config,
            actor_kind=actor_kind,
            task_id=task_id,
        )
    snapshots = replay_entity_snapshots(prior_events)
    work_units = list(snapshots["work-units"].values())
    runs = list(snapshots["runs"].values())
    results = list(snapshots["results"].values())
    approvals = list(snapshots["approvals"].values())
    scope_approvals = valid_scope_approvals(
        task,
        scope,
        approvals,
        compiled.ownership,
        compiled.config,
    )
    units_by_id = {str(unit.get("id")): unit for unit in work_units}
    active_runs = [run for run in runs if run.get("status") in {"registered", "running"}]
    dependencies_complete = bool(active_runs) and all(
        (unit := units_by_id.get(str(run.get("work_unit_id")))) is not None
        and unit.get("status") in {"ready", "running"}
        and all(
            units_by_id.get(str(dependency), {}).get("status") == "completed"
            for dependency in unit.get("depends_on", [])
        )
        for run in active_runs
    )
    work_units_complete = bool(work_units) and all(
        unit.get("status") == "completed" for unit in work_units
    )
    result_submitted = _results_complete_after_latest_repair(
        prior_events,
        results_present=bool(results),
        work_units_complete=work_units_complete,
    )
    actor_authorized = actor_authorized_for_scope(actor_id, scope, compiled.ownership)
    mode_gates = set(
        str(value)
        for value in (
            ((compiled.config.get("modes") or {}).get(str(task.get("mode", "")), {}) or {})
            .get("required_gates", [])
        )
    )
    review_required = (
        str(task.get("mode", "")) in {"high_risk", "audit"}
        or "independent_review" in {
            *[str(value) for value in task.get("required_gates", [])],
            *[str(value) for value in scope.get("required_gates", [])],
            *mode_gates,
        }
    )
    triage_complete = bool(
        task.get("mode")
        and task.get("acceptance_criteria")
        and scope.get("owners")
        and task.get("runtime_profile")
        and task.get("policy_ref")
        and task.get("ownership_ref")
    )
    verified_successor: str | None = None
    if target == "superseded" and actor_authorized and successor_task_id is not None:
        if (
            is_identifier(successor_task_id, "TASK")
            and successor_task_id != task_id
            and (FilesystemTaskRepository(repo).task_dir(successor_task_id) / "task.yaml").is_file()
        ):
            verified_successor = successor_task_id
    replacements: dict[str, Any] = {
        "triage_complete": triage_complete,
        "scope_approved": scope.get("status") == "approved" and bool(scope_approvals),
        "gates_selected": bool(task.get("required_gates")),
        "runtime_satisfied": bool(
            ((compiled.runtime_profile.get("capabilities") or {}).get("command_execution"))
        ),
        "result_submitted": result_submitted,
        "work_units_complete": work_units_complete,
        "review_required": review_required,
        "controller_lease_valid": False,
        "lease_valid": False,
        "executor_run_created": bool(active_runs) or target != "executing",
        "work_unit_dependencies_complete": dependencies_complete,
        "dependencies_complete": dependencies_complete,
        "baseline_recorded": bool(
            scope.get("base_commit") or (task.get("policy_ref") or {}).get("source_commit")
        ),
        "authorized_cancellation": actor_authorized,
        "successor_task_id": verified_successor,
    }
    needs_subject = (
        "current_subject_digest" in transition.requires
        or "scope_clean" in transition.requires
        or target in {"reviewing", "completed", "completed_with_risk"}
    )
    subject_valid = context.current_subject is not None
    scope_clean = context.scope_clean
    if needs_subject:
        subject_valid, scope_clean = _historical_subject_scope_facts(
            repo,
            task_id,
            context.current_subject,
            scope,
            scope_approvals,
            compiled.ownership,
            prior_events,
        )
        replacements.update({
            "current_subject_digest": subject_valid,
            "scope_clean": scope_clean,
            "current_subject": deepcopy(context.current_subject) if subject_valid else None,
        })
    if target in {"reviewing", "completed", "completed_with_risk"}:
        from .application.governance import CloseDecision, evaluate_close
        from .authority import owner_approvers

        task_for_close = deepcopy(task)
        task_for_close["work_units_complete"] = work_units_complete
        entity_revisions, scope_revision = _event_entity_revisions(prior_events)
        close = evaluate_close(
            task_for_close,
            scope,
            snapshots["evidence"].values(),
            snapshots["findings"].values(),
            snapshots["runs"],
            snapshots["risk-acceptances"].values(),
            current_subject=context.current_subject or {},
            policy_digest=str((task.get("policy_ref") or {}).get("combined_digest", "")),
            close_actor=actor_id,
            authorized_closers={actor_id} if actor_authorized else set(),
            non_waivable_gates=set(
                (compiled.config.get("close_policy") or {}).get("non_waivable_gates", [])
            ),
            authorized_risk_acceptors=owner_approvers(scope, compiled.ownership),
            current_diff_digest=(
                GitRepository(repo).review_diff_digest(
                    str(scope.get("base_commit", "")) or None,
                    head=str((context.current_subject or {}).get("commit_sha", "")),
                    task_id=task_id,
                    include_workspace=False,
                )
                if subject_valid and (context.current_subject or {}).get("type") == "commit"
                else ""
            ),
            runtime_profiles={str(compiled.runtime_profile.get("id", "")): compiled.runtime_profile},
            mode_required_gates=mode_gates,
            evidence_revisions=entity_revisions["evidence"],
            minimum_evidence_revision=scope_revision,
            require_commit_bound_evidence=bool(
                (compiled.config.get("close_policy") or {}).get("require_commit_bound_evidence", False)
            ),
            evaluated_at=_parse_event_time(occurred_at),
        )
        close_issues = list(close.issues)
        if not subject_valid:
            close_issues.append(MacIssue("CLOSE_SUBJECT_UNVERIFIABLE", "close subject is not an immutable Git object"))
        if not scope_approvals:
            close_issues.append(MacIssue("CLOSE_SCOPE_APPROVAL_INVALID", "approved scope has no authorized independent Approval"))
        if not scope_clean:
            close_issues.append(MacIssue("CLOSE_SCOPE_DIRTY", "immutable close diff violates the approved Scope"))
        historical_close = CloseDecision(
            not close_issues,
            tuple(close_issues),
            close.covered_gates,
            close.covered_acceptance,
            close.accepted_risk_acceptances,
        )
        replacements.update(
            _close_transition_facts(
                historical_close,
                target,
                actor_authorized=actor_authorized,
            )
        )
    context = replace(context, **replacements)
    external = _verified_transition_fact(
        task,
        target,
        transition_fact,
        compiled=compiled,
    )
    return replace(context, **external) if external else context


def _intent_common(
    *, operation: str, task_id: str, expected_revision: int,
    idempotency_key: str, minimum_independence: str | None,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "operation": operation,
        "task_id": task_id,
        "expected_revision": expected_revision,
        "idempotency_key": idempotency_key,
        "minimum_independence": minimum_independence,
    }


def _replay_shape(command: MutationCommand) -> dict[str, Any]:
    if isinstance(command, AppendEvent):
        return {"event_type": command.event_type}
    if isinstance(command, Transition):
        return {"target": command.target}
    if isinstance(command, RecordCommandEvidence):
        return {"claim": command.claim, "argv": list(command.argv), "commit": command.commit}
    if isinstance(command, SubmitResult):
        return {
            "result_id": str(command.result.get("id", "")),
            "run_id": str(command.result.get("run_id", "")),
            "work_unit_id": str(command.result.get("work_unit_id", "")),
        }
    return {}


def _replay_digest(command: MutationCommand, full_intent_body: Mapping[str, Any]) -> str:
    replay_intent = getattr(command, "replay_intent", None)
    if replay_intent is None:
        document: Mapping[str, Any] = full_intent_body
    else:
        if not isinstance(replay_intent, Mapping):
            raise MacError(
                "MUTATION_REPLAY_INTENT_INVALID",
                "replay intent must be a mapping",
                exit_code=ExitCode.VALIDATION,
            )
        document = {
            "schema_version": 1,
            "command_type": type(command).__name__,
            "operation": command.operation,
            "idempotency_key": command.idempotency_key,
            "shape": _replay_shape(command),
            "caller_intent": deepcopy(dict(replay_intent)),
        }
    try:
        return canonical_digest(document)
    except (TypeError, ValueError) as exc:
        raise MacError(
            "MUTATION_REPLAY_INTENT_INVALID",
            "replay intent is not canonically serializable",
            exit_code=ExitCode.VALIDATION,
        ) from exc


def _finalize_intent(command: MutationCommand, body: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(body))
    result["replay_digest"] = _replay_digest(command, body)
    return result


def _create_intent(command: CreateTask) -> dict[str, Any]:
    task_id = str(command.task["id"])
    body = {
        **_intent_common(
            operation=command.operation,
            task_id=task_id,
            expected_revision=-1,
            idempotency_key=command.idempotency_key,
            minimum_independence=command.minimum_independence,
        ),
        "task": deepcopy(dict(command.task)),
        "initial_entities": [[path, deepcopy(dict(value))] for path, value in command.initial_entities],
    }
    return _finalize_intent(command, body)


def _append_intent(repo: Path, command: AppendEvent) -> dict[str, Any]:
    body = {
        **_intent_common(
            operation=command.operation,
            task_id=command.task_id,
            expected_revision=command.expected_revision,
            idempotency_key=command.idempotency_key,
            minimum_independence=command.minimum_independence,
        ),
        "event_type": command.event_type,
        "payload": _without_authority(command.payload),
        "run_id": command.run_id,
        "event_id": command.event_id,
        "materializations": [
            [_repo_path(repo, path), deepcopy(dict(value))]
            for path, value in command.materializations
        ],
        "replace_existing": sorted(_repo_path(repo, path) for path in command.replace_existing),
    }
    return _finalize_intent(command, body)


def _transition_intent(command: Transition) -> dict[str, Any]:
    body = {
        **_intent_common(
            operation=command.operation,
            task_id=command.task_id,
            expected_revision=command.expected_revision,
            idempotency_key=command.idempotency_key,
            minimum_independence=command.minimum_independence,
        ),
        "target": command.target,
        "context": asdict(command.context),
        "transition_metadata": _without_authority(command.transition_metadata or {}),
    }
    return _finalize_intent(command, body)


def _rebuild_intent(command: Rebuild) -> dict[str, Any]:
    body = _intent_common(
        operation=command.operation,
        task_id=command.task_id,
        expected_revision=command.expected_revision,
        idempotency_key=command.idempotency_key,
        minimum_independence=command.minimum_independence,
    )
    return _finalize_intent(command, body)


def _record_evidence_intent(command: RecordCommandEvidence) -> dict[str, Any]:
    if not command.argv or any(not isinstance(value, str) or not value or "\x00" in value for value in command.argv):
        raise MacError(
            "EVIDENCE_COMMAND_INVALID",
            "evidence argv must contain non-empty NUL-free strings",
            exit_code=ExitCode.VALIDATION,
            task_id=command.task_id,
        )
    inspected_argv = list(command.argv)
    executable = Path(inspected_argv[0]).name.lower()
    if executable in {"env", "env.exe"}:
        wrapped_index = 1
        while wrapped_index < len(inspected_argv):
            value = inspected_argv[wrapped_index]
            if value in {"-i", "--ignore-environment"} or "=" in value:
                wrapped_index += 1
                continue
            if value in {"-u", "--unset"} and wrapped_index + 1 < len(inspected_argv):
                wrapped_index += 2
                continue
            break
        if wrapped_index < len(inspected_argv):
            inspected_argv = inspected_argv[wrapped_index:]
            executable = Path(inspected_argv[0]).name.lower()
    if executable in {"busybox", "busybox.exe"} and len(inspected_argv) > 1:
        inspected_argv = inspected_argv[1:]
        executable = Path(inspected_argv[0]).name.lower()
    shell_flags = {"-c", "/c", "-command", "-encodedcommand", "-enc"}
    dynamic_shells = {
        "sh", "sh.exe", "bash", "bash.exe", "zsh", "zsh.exe",
        "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    }
    if executable in dynamic_shells and any(value.lower() in shell_flags for value in inspected_argv[1:]):
        raise MacError(
            "EVIDENCE_DYNAMIC_SHELL_FORBIDDEN",
            "Evidence commands cannot invoke a dynamic shell",
            exit_code=ExitCode.SECURITY,
            task_id=command.task_id,
        )
    body = {
        **_intent_common(
            operation=command.operation,
            task_id=command.task_id,
            expected_revision=command.expected_revision,
            idempotency_key=command.idempotency_key,
            minimum_independence=command.minimum_independence,
        ),
        "claim": command.claim,
        "argv": list(command.argv),
        "commit": command.commit,
    }
    return _finalize_intent(command, body)


def _record_evidence_final_intent(
    command: RecordCommandEvidence,
    evidence: Mapping[str, Any],
    run: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind the post-execution snapshots in the authority persisted with Evidence."""

    intent = _record_evidence_intent(command)
    intent["final_evidence"] = deepcopy(dict(evidence))
    intent["final_run"] = deepcopy(dict(run))
    return intent


def _submit_result_intent(command: SubmitResult) -> dict[str, Any]:
    if command.operation != "result.submit":
        raise MacError(
            "MUTATION_OPERATION_INVALID",
            "SubmitResult requires result.submit authority",
            exit_code=ExitCode.SECURITY,
            task_id=command.task_id,
        )
    body = {
        **_intent_common(
            operation=command.operation,
            task_id=command.task_id,
            expected_revision=command.expected_revision,
            idempotency_key=command.idempotency_key,
            minimum_independence=command.minimum_independence,
        ),
        "result": deepcopy(dict(command.result)),
        "intake_proof": deepcopy(dict(command.intake_proof)) if command.intake_proof is not None else None,
    }
    # SubmitResult deliberately has no caller-selected replay intent: retries
    # must submit byte-equivalent semantic inputs.
    return _finalize_intent(command, body)


def _validate_append_operation(operation: str, event_type: str) -> None:
    allowed = _APPEND_OPERATION_EVENTS.get(operation)
    if operation.startswith("approval.record."):
        allowed = frozenset({"scope_approved"})
    if allowed is None or event_type not in allowed:
        raise MacError(
            "MUTATION_OPERATION_EVENT_MISMATCH",
            "mutation operation is not allowed to emit this event type",
            exit_code=ExitCode.SECURITY,
        )


def _materialization_operation(operation: str) -> str:
    return "approval.record" if operation.startswith("approval.record.") else operation


def _materialization_directory(relative: Path) -> str:
    parts = relative.parts
    if parts == ("scope-contract.yaml",):
        return "scope-contract"
    if (
        len(parts) == 2
        and parts[0] == "scope-history"
        and re.fullmatch(r"scope-contract\.v[1-9][0-9]*\.yaml", parts[1]) is not None
    ):
        return "scope-history"
    if len(parts) == 2 and parts[0] in _ENTITY_SCHEMAS:
        extension = _ENTITY_SCHEMAS[parts[0]][0]
        if parts[1].endswith(f".{extension}"):
            return parts[0]
    raise MacError(
        "MUTATION_MATERIALIZATION_FORBIDDEN",
        "mutation materialization target is not a governed entity path",
        exit_code=ExitCode.SECURITY,
        path=relative.as_posix(),
    )


def _materialization_relative(repo: Path, task_id: str, target: Path) -> Path:
    task_root = (repo / "tasks" / task_id).resolve()
    resolved = target.resolve(strict=False)
    try:
        relative = resolved.relative_to(task_root)
    except ValueError as exc:
        raise MacError(
            "MUTATION_MATERIALIZATION_FORBIDDEN",
            "mutation materialization target is outside its Task",
            exit_code=ExitCode.SECURITY,
            path=str(target),
            task_id=task_id,
        ) from exc
    if not relative.parts or relative.parts[0] in {"events", "private"} or relative.as_posix() == "task.yaml":
        raise MacError(
            "MUTATION_MATERIALIZATION_FORBIDDEN",
            "task projection, Event log, and private paths cannot be materialized by AppendEvent",
            exit_code=ExitCode.SECURITY,
            path=relative.as_posix(),
            task_id=task_id,
        )
    return relative


def _validate_entity_snapshot(
    command: AppendEvent,
    relative: Path,
    directory: str,
    value: Mapping[str, Any],
) -> None:
    if str(value.get("task_id", "")) != command.task_id:
        raise MacError(
            "MUTATION_ENTITY_TASK_MISMATCH",
            "materialized entity does not belong to the authorized Task",
            exit_code=ExitCode.SECURITY,
            path=relative.as_posix(),
            task_id=command.task_id,
        )
    if directory == "scope-contract":
        schema_name, snapshot_key = "scope-contract.schema.json", "scope"
    elif directory == "scope-history":
        schema_name, snapshot_key = "scope-contract.schema.json", None
    else:
        _, schema_name, snapshot_key = _ENTITY_SCHEMAS[directory]
        entity_id = str(value.get("id", ""))
        if not is_identifier(entity_id, _ENTITY_ID_PREFIXES[directory]):
            raise MacError(
                "MUTATION_ENTITY_ID_INVALID",
                "materialized entity id has the wrong governed prefix",
                exit_code=ExitCode.SECURITY,
                path=relative.as_posix(),
                task_id=command.task_id,
            )
        if relative.stem != entity_id:
            raise MacError(
                "MUTATION_ENTITY_ID_MISMATCH",
                "materialized entity id does not match its filename",
                exit_code=ExitCode.SECURITY,
                path=relative.as_posix(),
                task_id=command.task_id,
            )
    if (
        command.operation == "run.register"
        and directory == "runs"
        and value.get("status") not in {"registered", "running"}
    ):
        raise MacError(
            "MUTATION_RUN_REGISTER_INVALID",
            "Run registration must begin in registered or running state",
            exit_code=ExitCode.SECURITY,
            path=relative.as_posix(),
            task_id=command.task_id,
        )
    issues = SchemaSet().validate(dict(value), schema_name, path=relative.as_posix())
    if issues:
        raise MacError(
            "SCHEMA_INVALID",
            issues[0].message,
            exit_code=ExitCode.VALIDATION,
            path=relative.as_posix(),
            task_id=command.task_id,
            details={"issues": [issue.as_dict() for issue in issues]},
        )
    payload = _without_authority(command.payload)
    if snapshot_key is not None and payload.get(snapshot_key) != dict(value):
        raise MacError(
            "MUTATION_ENTITY_PAYLOAD_MISMATCH",
            "materialized entity is not the snapshot bound in the Event payload",
            exit_code=ExitCode.SECURITY,
            path=relative.as_posix(),
            task_id=command.task_id,
        )


def _validate_append_materializations(repo: Path, command: AppendEvent) -> None:
    operation = _materialization_operation(command.operation)
    allowed = (
        frozenset({"approvals"})
        if operation == "approval.record"
        else _MATERIALIZATION_DIRECTORIES.get(operation)
    )
    replace_allowed = frozenset() if operation == "approval.record" else _REPLACE_DIRECTORIES.get(operation, frozenset())
    if allowed is None:
        raise MacError(
            "MUTATION_OPERATION_INVALID",
            "mutation operation has no materialization contract",
            exit_code=ExitCode.SECURITY,
            task_id=command.task_id,
        )
    payload = _without_authority(command.payload)
    _validate_payload_key_contract(
        command.operation,
        payload,
        persisted=False,
        task_id=command.task_id,
    )
    paths: dict[Path, tuple[Path, str, Mapping[str, Any]]] = {}
    for target, value in command.materializations:
        if not isinstance(value, Mapping):
            raise MacError(
                "MUTATION_ENTITY_INVALID",
                "materialized entity must be a mapping",
                exit_code=ExitCode.VALIDATION,
                task_id=command.task_id,
            )
        relative = _materialization_relative(repo, command.task_id, target)
        directory = _materialization_directory(relative)
        if directory not in allowed:
            raise MacError(
                "MUTATION_MATERIALIZATION_FORBIDDEN",
                "mutation operation cannot materialize this entity directory",
                exit_code=ExitCode.SECURITY,
                path=relative.as_posix(),
                task_id=command.task_id,
            )
        resolved = target.resolve(strict=False)
        if resolved in paths:
            raise MacError(
                "MUTATION_MATERIALIZATION_DUPLICATE",
                "mutation contains duplicate materialization targets",
                exit_code=ExitCode.VALIDATION,
                path=relative.as_posix(),
                task_id=command.task_id,
            )
        paths[resolved] = (relative, directory, value)
        _validate_entity_snapshot(command, relative, directory, value)
    allowed_snapshots, required_snapshots = _OPERATION_SNAPSHOTS[operation]
    present_snapshots = {key for key in _SNAPSHOT_DIRECTORIES if key in payload}
    unexpected = present_snapshots - allowed_snapshots
    if unexpected:
        raise MacError(
            "MUTATION_PAYLOAD_SNAPSHOT_FORBIDDEN",
            "mutation payload contains entity snapshots outside its operation contract",
            exit_code=ExitCode.SECURITY,
            task_id=command.task_id,
            details={"snapshot_keys": sorted(unexpected)},
        )
    missing = required_snapshots - present_snapshots
    if missing:
        raise MacError(
            "MUTATION_PAYLOAD_SNAPSHOT_MISSING",
            "mutation payload is missing its required authoritative entity snapshot",
            exit_code=ExitCode.SECURITY,
            task_id=command.task_id,
            details={"snapshot_keys": sorted(missing)},
        )
    for key in present_snapshots:
        snapshot = payload.get(key)
        directory = _SNAPSHOT_DIRECTORIES[key]
        matches = [
            value
            for _, candidate_directory, value in paths.values()
            if candidate_directory == directory and dict(value) == snapshot
        ]
        if not isinstance(snapshot, Mapping) or len(matches) != 1:
            raise MacError(
                "MUTATION_PAYLOAD_MATERIALIZATION_MISMATCH",
                "every payload entity snapshot must have exactly one identical materialization",
                exit_code=ExitCode.SECURITY,
                task_id=command.task_id,
                details={"snapshot_key": key},
            )
    directory_snapshot_keys = {directory: key for key, directory in _SNAPSHOT_DIRECTORIES.items()}
    for relative, directory, value in paths.values():
        if directory == "scope-history":
            continue
        key = directory_snapshot_keys[directory]
        if key not in present_snapshots or payload.get(key) != dict(value):
            raise MacError(
                "MUTATION_MATERIALIZATION_PAYLOAD_MISMATCH",
                "every materialization must have exactly one identical payload snapshot",
                exit_code=ExitCode.SECURITY,
                path=relative.as_posix(),
                task_id=command.task_id,
            )
    history_entries = [
        (relative, value)
        for relative, directory, value in paths.values()
        if directory == "scope-history"
    ]
    if operation == "scope.amend":
        current_scope = payload.get("scope")
        if len(history_entries) != 1 or not isinstance(current_scope, Mapping):
            raise MacError(
                "MUTATION_SCOPE_HISTORY_MISMATCH",
                "scope amendment requires exactly one prior-version history snapshot",
                exit_code=ExitCode.SECURITY,
                task_id=command.task_id,
            )
        history_path, prior_scope = history_entries[0]
        prior_version = prior_scope.get("version")
        if (
            isinstance(prior_version, bool)
            or not isinstance(prior_version, int)
            or history_path.name != f"scope-contract.v{prior_version}.yaml"
            or prior_scope.get("id") != current_scope.get("id")
            or current_scope.get("version") != prior_version + 1
        ):
            raise MacError(
                "MUTATION_SCOPE_HISTORY_MISMATCH",
                "scope history does not bind the immediately preceding Scope version",
                exit_code=ExitCode.SECURITY,
                path=history_path.as_posix(),
                task_id=command.task_id,
            )
    elif history_entries:
        raise MacError(
            "MUTATION_SCOPE_HISTORY_FORBIDDEN",
            "only scope.amend may materialize Scope history",
            exit_code=ExitCode.SECURITY,
            task_id=command.task_id,
        )
    replace_targets = {path.resolve(strict=False) for path in command.replace_existing}
    if not replace_targets.issubset(paths):
        raise MacError(
            "MUTATION_REPLACE_TARGET_INVALID",
            "replace_existing must be a subset of materialized targets",
            exit_code=ExitCode.SECURITY,
            task_id=command.task_id,
        )
    for target in replace_targets:
        relative, directory, _ = paths[target]
        if directory not in replace_allowed:
            raise MacError(
                "MUTATION_REPLACE_TARGET_FORBIDDEN",
                "mutation operation cannot replace this entity",
                exit_code=ExitCode.SECURITY,
                path=relative.as_posix(),
                task_id=command.task_id,
            )


def _validate_create_materializations(command: CreateTask) -> None:
    task = dict(command.task)
    task_id = str(task.get("id", ""))
    if len(command.initial_entities) != 1 or command.initial_entities[0][0] != "scope-contract.yaml":
        raise MacError(
            "MUTATION_CREATE_ENTITIES_FORBIDDEN",
            "CreateTask must initialize exactly scope-contract.yaml",
            exit_code=ExitCode.SECURITY,
            task_id=task_id or None,
        )
    scope = dict(command.initial_entities[0][1])
    if (
        task.get("state") != "triage"
        or task.get("revision") != 0
        or task.get("terminal") is not None
        or task.get("active_controller") is not None
        or scope.get("status") != "proposed"
        or scope.get("approved_by") not in (None, [])
    ):
        raise MacError(
            "MUTATION_CREATE_STATE_INVALID",
            "CreateTask must begin at triage revision zero with a proposed unapproved Scope",
            exit_code=ExitCode.SECURITY,
            task_id=task_id or None,
        )
    if scope.get("task_id") != task_id or task.get("scope_contract_ref") != f"tasks/{task_id}/scope-contract.yaml":
        raise MacError(
            "MUTATION_CREATE_ENTITY_MISMATCH",
            "CreateTask scope identity does not match the Task",
            exit_code=ExitCode.SECURITY,
            task_id=task_id or None,
        )
    schema_set = SchemaSet()
    issues = [
        *schema_set.validate(task, "task.schema.json", path="task.yaml"),
        *schema_set.validate(scope, "scope-contract.schema.json", path="scope-contract.yaml"),
    ]
    if issues:
        raise MacError(
            "SCHEMA_INVALID",
            issues[0].message,
            exit_code=ExitCode.VALIDATION,
            task_id=task_id or None,
            details={"issues": [issue.as_dict() for issue in issues]},
        )


def _validate_transition_operation(operation: str, target: str) -> None:
    allowed = {f"task.transition.{target}"}
    if target == "cancelled":
        allowed.add("task.cancel")
    if target == "superseded":
        allowed.add("task.supersede")
    if operation not in allowed:
        raise MacError(
            "MUTATION_OPERATION_TRANSITION_MISMATCH",
            "mutation operation is not allowed to perform this transition",
            exit_code=ExitCode.SECURITY,
        )


def _validate_store_authority(
    repo: Path,
    verified: VerifiedAuthority,
    *,
    operation: str,
    task_id: str,
    expected_revision: int,
    idempotency_key: str,
    intent: Mapping[str, Any],
    policy_digest: str,
    ownership_digest: str,
    actor_claim: Mapping[str, Any],
) -> dict[str, Any]:
    audit = authority_audit_record(verified)
    expected = {
        "repository_identity": _repository_identity(repo),
        "operation": operation,
        "task_id": task_id,
        "expected_revision": expected_revision,
        "idempotency_key": idempotency_key,
        "intent_digest": canonical_digest(intent),
        "policy_digest": policy_digest,
        "ownership_digest": ownership_digest,
        "audience": MUTATION_AUDIENCE,
        "actor_id": str(actor_claim.get("id", "")),
        "actor_kind": str(actor_claim.get("kind", "")),
    }
    if any(audit.get(key) != value for key, value in expected.items()):
        raise MacError(
            "MUTATION_AUTHORITY_BINDING_MISMATCH",
            "verified authority does not bind the exact repository mutation",
            exit_code=ExitCode.SECURITY,
            task_id=task_id,
        )
    replay_digest = intent.get("replay_digest")
    if not isinstance(replay_digest, str):
        raise MacError(
            "MUTATION_REPLAY_INTENT_INVALID",
            "authorized mutation intent is missing its replay digest",
            exit_code=ExitCode.SECURITY,
            task_id=task_id,
        )
    audit["replay_digest"] = replay_digest
    audit["minimum_independence"] = intent.get("minimum_independence")
    audit["authorized_intent"] = deepcopy(dict(intent))
    return audit


def _command_intent(repo: Path, command: MutationCommand) -> dict[str, Any]:
    if isinstance(command, CreateTask):
        return _create_intent(command)
    if isinstance(command, AppendEvent):
        return _append_intent(repo, command)
    if isinstance(command, Transition):
        return _transition_intent(command)
    if isinstance(command, RecordCommandEvidence):
        return _record_evidence_intent(command)
    if isinstance(command, SubmitResult):
        return _submit_result_intent(command)
    return _rebuild_intent(command)


def _event_authority(event: Mapping[str, Any]) -> Mapping[str, Any]:
    payload = event.get("payload") or {}
    authority = payload.get("authority") if isinstance(payload, Mapping) else None
    if not isinstance(authority, Mapping) and isinstance(payload, Mapping):
        metadata = payload.get("transition_metadata") or {}
        authority = metadata.get("authority") if isinstance(metadata, Mapping) else None
    if not isinstance(authority, Mapping):
        raise MacError(
            "MUTATION_IDEMPOTENCY_CONFLICT",
            "idempotency event has no verified mutation authority binding",
            exit_code=ExitCode.CONFLICT,
            task_id=str(event.get("task_id", "")) or None,
        )
    return authority


def _valid_legacy_import_event(event: Mapping[str, Any]) -> bool:
    """Recognize only explicitly unverifiable v5 migration records."""

    if event.get("event_type") != "legacy_imported":
        return False
    payload = event.get("payload")
    if not isinstance(payload, Mapping) or set(payload) != {
        "task",
        "legacy_id",
        "legacy_status",
        "integrity",
        "verification_status",
        "source_path",
        "source_digest",
    }:
        return False
    task = payload.get("task")
    source_path = str(payload.get("source_path", ""))
    source_value = Path(source_path)
    return bool(
        isinstance(task, Mapping)
        and int(event.get("expected_revision", -2)) == -1
        and int(event.get("new_revision", -2)) == 0
        and event.get("run_id") is None
        and event.get("actor") == {"id": "migration-automation", "kind": "automation"}
        and task.get("id") == event.get("task_id")
        and task.get("legacy_id") == payload.get("legacy_id")
        and task.get("legacy_integrity") in {"partial", "metadata_only"}
        and payload.get("integrity") == task.get("legacy_integrity")
        and payload.get("verification_status") == "unverifiable"
        and source_path
        and not source_value.is_absolute()
        and ".." not in source_value.parts
        and "\x00" not in source_path
        and re.fullmatch(r"sha256:[0-9a-f]{64}", str(payload.get("source_digest", "")))
    )


def _derived_event_id(authority: Mapping[str, Any]) -> str:
    """Derive a stable Event identity from the broker-signed attestation."""

    seed = canonical_digest({
        "attestation_id": authority.get("attestation_id"),
        "request_digest": authority.get("request_digest"),
        "task_id": authority.get("task_id"),
        "expected_revision": authority.get("expected_revision"),
        "idempotency_key": authority.get("idempotency_key"),
    }).removeprefix("sha256:")
    value = int(seed, 16) >> (256 - 130)
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    chars = ["0"] * 26
    for index in range(25, -1, -1):
        value, remainder = divmod(value, 32)
        chars[index] = alphabet[remainder]
    return "EVT-" + "".join(chars)


def _validate_governed_event_contract(
    event: Mapping[str, Any],
    prior_events: list[dict[str, Any]],
    *,
    repo: Path | None = None,
    require_authority: bool = False,
    frozen_policy_cache: dict[str, Any] | None = None,
    repository_identity: str | None = None,
) -> None:
    """Reject governed Event tampering before any projection consumes it."""

    payload = event.get("payload")
    if not isinstance(payload, Mapping):
        raise MacError(
            "EVENT_PAYLOAD_INVALID",
            "Event payload must be an object",
            exit_code=ExitCode.CORRUPTION,
            task_id=str(event.get("task_id", "")) or None,
        )
    metadata = payload.get("transition_metadata")
    authority_candidate = payload.get("authority")
    if authority_candidate is None and isinstance(metadata, Mapping):
        authority_candidate = metadata.get("authority")
    if authority_candidate is None:
        if require_authority:
            raise MacError(
                "EVENT_AUTHORITY_MISSING",
                "full-integrity governed Event is missing its authority fact",
                exit_code=ExitCode.CORRUPTION,
                task_id=str(event.get("task_id", "")) or None,
            )
        return
    if not isinstance(authority_candidate, Mapping):
        raise MacError(
            "EVENT_AUTHORITY_TAMPERED",
            "governed Event authority is malformed",
            exit_code=ExitCode.CORRUPTION,
            task_id=str(event.get("task_id", "")) or None,
        )
    authority = dict(authority_candidate)
    store_contract_version = authority.get("store_contract_version", 1)
    operation = str(authority.get("operation", ""))
    event_type = str(event.get("event_type", ""))
    task_id = str(event.get("task_id", ""))
    actor = event.get("actor") or {}
    if (
        authority.get("allowed") is not True
        or authority.get("authenticated") is not True
        or authority.get("task_id") != task_id
        or authority.get("expected_revision") != event.get("expected_revision")
        or authority.get("idempotency_key") != event.get("idempotency_key")
        or {"id": authority.get("actor_id"), "kind": authority.get("actor_kind")} != actor
        or int(event.get("new_revision", -2)) != int(event.get("expected_revision", -2)) + 1
        or not is_identifier(str(event.get("event_id", "")), "EVT")
        or type(store_contract_version) is not int
    ):
        raise MacError(
            "EVENT_AUTHORITY_TAMPERED",
            "Event metadata no longer matches its governed authority fact",
            exit_code=ExitCode.CORRUPTION,
            task_id=task_id or None,
        )
    if store_contract_version != 2:
        raise MacError(
            "EVENT_AUTHORITY_VERSION_UNSUPPORTED",
            "governed Event does not use the current signed Store contract",
            exit_code=ExitCode.CORRUPTION,
            task_id=task_id or None,
        )

    try:
        authority_request = AuthorityRequest(
            repository_identity=str(authority.get("repository_identity", "")),
            operation=operation,
            task_id=task_id,
            actor_claim={
                "id": str(authority.get("actor_id", "")),
                "kind": str(authority.get("actor_kind", "")),
            },
            expected_revision=int(authority.get("expected_revision", -2)),
            idempotency_key=str(authority.get("idempotency_key", "")),
            intent_digest=str(authority.get("intent_digest", "")),
            policy_digest=str(authority.get("policy_digest", "")),
            ownership_digest=str(authority.get("ownership_digest", "")),
            audience=str(authority.get("audience", "")),
        )
    except (MacError, TypeError, ValueError) as exc:
        raise MacError(
            "EVENT_AUTHORITY_TAMPERED",
            "Event authority request is not canonical",
            exit_code=ExitCode.CORRUPTION,
            task_id=task_id or None,
        ) from exc
    if (
        authority.get("request_digest") != authority_request.request_digest
        or authority.get("binding_digest") != authority_request.binding_digest
        or (
            repo is not None
            and authority.get("repository_identity")
            != (repository_identity or _repository_identity(repo))
        )
    ):
        raise MacError(
            "EVENT_AUTHORITY_TAMPERED",
            "Event authority digest chain does not match its request",
            exit_code=ExitCode.CORRUPTION,
            task_id=task_id or None,
        )

    envelope = authority.get("signed_envelope")
    signature_verified = False
    if envelope is not None:
        try:
            verify_authority_audit_record(authority, authority_request)
            signature_verified = True
        except MacError as exc:
            raise MacError(
                "EVENT_AUTHORITY_SIGNATURE_INVALID",
                "Event authority signature cannot be verified",
                exit_code=ExitCode.CORRUPTION,
                task_id=task_id or None,
            ) from exc
    if not signature_verified:
        raise MacError(
            "EVENT_AUTHORITY_SIGNATURE_MISSING",
            "Event authority is neither broker-signed nor frozen in Git",
            exit_code=ExitCode.CORRUPTION,
            task_id=task_id or None,
        )
    authorized_intent = authority.get("authorized_intent")
    if store_contract_version >= 2 and (
        not isinstance(authorized_intent, Mapping)
        or canonical_digest(dict(authorized_intent)) != authority.get("intent_digest")
    ):
        raise MacError(
            "EVENT_AUTHORITY_INTENT_TAMPERED",
            "Event authority does not retain its signed canonical mutation intent",
            exit_code=ExitCode.CORRUPTION,
            task_id=task_id or None,
        )
    intent_document = dict(authorized_intent)
    caller_event_id = intent_document.get("event_id")
    expected_event_id = (
        str(caller_event_id)
        if isinstance(caller_event_id, str) and caller_event_id
        else _derived_event_id(authority)
    )
    if (
        event.get("event_id") != expected_event_id
        or event.get("occurred_at") != authority.get("issued_at")
        or authority.get("replay_digest") != intent_document.get("replay_digest")
        or authority.get("minimum_independence") != intent_document.get("minimum_independence")
    ):
        raise MacError(
            "EVENT_STORE_FACT_TAMPERED",
            "Event identity, time, or replay facts do not match signed authority",
            exit_code=ExitCode.CORRUPTION,
            task_id=task_id or None,
        )

    _validate_payload_key_contract(
        operation,
        payload,
        persisted=True,
        task_id=task_id,
    )
    raw_intent_payload = intent_document.get("payload")
    intent_payload = dict(raw_intent_payload) if isinstance(raw_intent_payload, Mapping) else {}

    if operation == "task.create":
        allowed_types = {"task_created"}
        required_snapshots = allowed_snapshots = frozenset({"scope"})
    elif operation.startswith("task.transition.") or operation in {"task.cancel", "task.supersede"}:
        allowed_types = {"state_transitioned"}
        required_snapshots = allowed_snapshots = frozenset()
    elif operation == "result.submit":
        allowed_types = {"result_submitted"}
        allowed_snapshots, required_snapshots = _OPERATION_SNAPSHOTS[operation]
    else:
        try:
            _validate_append_operation(operation, event_type)
        except MacError as exc:
            raise MacError(
                "EVENT_OPERATION_TAMPERED",
                "Event type does not match its governed operation",
                exit_code=ExitCode.CORRUPTION,
                task_id=task_id or None,
            ) from exc
        operation_key = _materialization_operation(operation)
        contract = _OPERATION_SNAPSHOTS.get(operation_key)
        if contract is None:
            raise MacError(
                "EVENT_OPERATION_TAMPERED",
                "governed Event operation has no replay contract",
                exit_code=ExitCode.CORRUPTION,
                task_id=task_id or None,
            )
        allowed_snapshots, required_snapshots = contract
        allowed_types = {event_type}
    if event_type not in allowed_types:
        raise MacError(
            "EVENT_OPERATION_TAMPERED",
            "Event type does not match its governed operation",
            exit_code=ExitCode.CORRUPTION,
            task_id=task_id or None,
        )
    present_snapshots = frozenset(key for key in _SNAPSHOT_DIRECTORIES if key in payload)
    if not required_snapshots.issubset(present_snapshots) or not present_snapshots.issubset(allowed_snapshots):
        raise MacError(
            "EVENT_SNAPSHOT_CONTRACT_TAMPERED",
            "Event snapshots do not match the governed operation contract",
            exit_code=ExitCode.CORRUPTION,
            task_id=task_id or None,
        )

    schema_set = SchemaSet()
    for key in present_snapshots:
        value = payload[key]
        if not isinstance(value, Mapping):
            raise MacError(
                "EVENT_SNAPSHOT_TAMPERED",
                "Event entity snapshot is not an object",
                exit_code=ExitCode.CORRUPTION,
                task_id=task_id or None,
            )
        directory = _SNAPSHOT_DIRECTORIES[key]
        if directory == "scope-contract":
            schema_name = "scope-contract.schema.json"
        else:
            _, schema_name, _ = _ENTITY_SCHEMAS[directory]
            entity_id = str(value.get("id", ""))
            if not is_identifier(entity_id, _ENTITY_ID_PREFIXES[directory]):
                raise MacError(
                    "EVENT_ENTITY_ID_INVALID",
                    "Event entity id has the wrong governed prefix",
                    exit_code=ExitCode.CORRUPTION,
                    task_id=task_id or None,
                )
        issues = schema_set.validate(dict(value), schema_name, path=f"event.payload.{key}")
        if issues or str(value.get("task_id", "")) != task_id:
            raise MacError(
                "EVENT_SNAPSHOT_TAMPERED",
                "Event entity snapshot is invalid or belongs to another Task",
                exit_code=ExitCode.CORRUPTION,
                task_id=task_id or None,
                details={"issues": [issue.as_dict() for issue in issues]},
            )

    if operation == "task.create":
        created_task = payload.get("task")
        created_scope = payload.get("scope")
        task_issues = (
            SchemaSet().validate(dict(created_task), "task.schema.json", path="event.payload.task")
            if isinstance(created_task, Mapping)
            else [MacIssue("EVENT_TASK_INVALID", "created Task snapshot is not an object")]
        )
        valid = (
            not prior_events
            and not task_issues
            and isinstance(created_scope, Mapping)
            and created_task.get("id") == task_id
            and created_task.get("state") == "triage"
            and int(created_task.get("revision", -1)) == 0
            and created_scope.get("task_id") == task_id
            and created_scope.get("status") == "proposed"
            and int(created_scope.get("version", 0)) == 1
            and (
                store_contract_version < 2
                or (
                    intent_document.get("task") == created_task
                    and intent_document.get("initial_entities")
                    == [["scope-contract.yaml", created_scope]]
                )
            )
            and (authority.get("policy_digest"), authority.get("ownership_digest"))
            == _policy_digests(created_task)
        )
        if not valid:
            raise MacError(
                "EVENT_TASK_CREATE_TAMPERED",
                "Task creation Event is not a canonical initial aggregate",
                exit_code=ExitCode.CORRUPTION,
                task_id=task_id or None,
                details={"issues": [issue.as_dict() for issue in task_issues]},
            )
        return

    snapshots = replay_entity_snapshots(prior_events)
    prior_task = replay_events(prior_events)
    if (authority.get("policy_digest"), authority.get("ownership_digest")) != _policy_digests(prior_task):
        raise MacError(
            "EVENT_AUTHORITY_POLICY_TAMPERED",
            "Event authority does not bind the prior Task policy snapshot",
            exit_code=ExitCode.CORRUPTION,
            task_id=task_id or None,
        )
    prior_scope: Mapping[str, Any] | None = None
    for prior_event in prior_events:
        candidate = (prior_event.get("payload") or {}).get("scope")
        if isinstance(candidate, Mapping):
            prior_scope = candidate
    frozen_policy = None
    if repo is not None and isinstance(prior_scope, Mapping):
        try:
            cache_key = canonical_digest({
                "repo": str(repo.resolve()),
                "policy_ref": prior_task.get("policy_ref") or {},
                "ownership_ref": prior_task.get("ownership_ref") or {},
                "runtime_profile": str(prior_task.get("runtime_profile") or ""),
            })
            frozen_policy = (
                frozen_policy_cache.get(cache_key)
                if frozen_policy_cache is not None
                else None
            )
            if frozen_policy is None:
                frozen_policy = compile_frozen_policy(
                    repo,
                    prior_task.get("policy_ref") or {},
                    prior_task.get("ownership_ref") or {},
                    runtime_profile_id=str(prior_task.get("runtime_profile") or "") or None,
                )
                if frozen_policy_cache is not None:
                    frozen_policy_cache[cache_key] = frozen_policy
            _enforce_operation_independence(
                authority,
                prior_task,
                prior_scope,
                frozen_policy.config,
                operation=operation,
                task_id=task_id,
            )
        except (MacError, OSError, TypeError, ValueError) as exc:
            raise MacError(
                "EVENT_POLICY_GUARD_INVALID",
                "Event authority does not satisfy the frozen policy guards",
                exit_code=ExitCode.CORRUPTION,
                task_id=task_id or None,
            ) from exc
    reference_fields = {
        "work_unit": "work_unit_id",
        "run": "run_id",
        "result": "result_id",
        "evidence": "evidence_id",
        "finding": "finding_id",
        "approval": "approval_id",
        "risk_acceptance": "risk_acceptance_id",
    }
    reference_valid = all(
        field not in payload or payload[field] == payload[key].get("id")
        for key, field in reference_fields.items()
        if key in present_snapshots
    )
    authority_actor = {"id": authority.get("actor_id"), "kind": authority.get("actor_kind")}
    authority_bound = True
    if "approval" in present_snapshots:
        approval_snapshot = payload["approval"]
        authority_bound = (
            approval_snapshot.get("actor") == authority_actor
            and approval_snapshot.get("independence_level") == authority.get("independence_level")
        )
    if operation in {"run.register", "evidence.record"} and "run" in present_snapshots:
        run_snapshot = payload["run"]
        authority_bound = authority_bound and (
            run_snapshot.get("actor") == authority_actor
            and level_at_least(
                str(authority.get("independence_level", "")),
                str(run_snapshot.get("independence_level", "")),
            )
        )
    if "risk_acceptance" in present_snapshots:
        authority_bound = authority_bound and payload["risk_acceptance"].get("accepted_by") == authority_actor
    if operation == "finding.open":
        finding = payload["finding"]
        valid = (
            finding.get("status") == "open"
            and finding.get("resolved_at") is None
            and (
                store_contract_version < 2
                or finding.get("opened_at") == event.get("occurred_at")
            )
            and (
                store_contract_version < 2
                or (
                    isinstance(intent_payload.get("finding"), Mapping)
                    and _without_fields(intent_payload["finding"], {"opened_at"})
                    == _without_fields(finding, {"opened_at"})
                )
            )
            and str(finding.get("id", "")) not in snapshots["findings"]
            and (
                finding.get("blocking_effect") == "advisory"
                or bool(finding.get("invalidates"))
            )
            and (
                finding.get("root_cause_key") is None
                or bool(_ROOT_CAUSE_KEY.fullmatch(str(finding.get("root_cause_key", ""))))
            )
        )
    elif operation == "finding.resolve":
        finding = payload["finding"]
        prior = snapshots["findings"].get(str(finding.get("id", "")))
        resolution_requirements_valid = store_contract_version < 2
        if store_contract_version >= 2 and isinstance(prior, Mapping) and repo is not None:
            try:
                frozen = frozen_policy or compile_frozen_policy(
                    repo,
                    prior_task.get("policy_ref") or {},
                    prior_task.get("ownership_ref") or {},
                    runtime_profile_id=str(prior_task.get("runtime_profile") or "") or None,
                )
                fresh_categories = {
                    str(value)
                    for value in (frozen.config.get("repair_policy") or {}).get(
                        "fresh_context_categories", []
                    )
                }
                resolution_requirements_valid = (
                    (
                        str(prior.get("category", "")) not in fresh_categories
                        or level_at_least(str(authority.get("independence_level", "")), "L1")
                    )
                    and _finding_reverification_complete(
                        prior_events,
                        snapshots["evidence"],
                        snapshots["runs"],
                        prior,
                        task=prior_task,
                    )
                )
            except (MacError, OSError, TypeError, ValueError):
                resolution_requirements_valid = False
        valid = (
            isinstance(prior, Mapping)
            and prior.get("status") in {"open", "acknowledged", "waived"}
            and finding.get("status") == "resolved"
            and (
                store_contract_version < 2
                or finding.get("resolved_at") == event.get("occurred_at")
            )
            and _without_fields(prior, {"status", "resolved_at"})
            == _without_fields(finding, {"status", "resolved_at"})
            and (
                store_contract_version < 2
                or (
                    isinstance(intent_payload.get("finding"), Mapping)
                    and _without_fields(intent_payload["finding"], {"resolved_at"})
                    == _without_fields(finding, {"resolved_at"})
                )
            )
            and resolution_requirements_valid
        )
    elif operation == "risk.accept":
        from .application.governance import validate_risk_acceptance

        finding = payload["finding"]
        acceptance = payload["risk_acceptance"]
        prior = snapshots["findings"].get(str(finding.get("id", "")))
        risk_policy_valid = False
        if (
            isinstance(prior, Mapping)
            and isinstance(prior_scope, Mapping)
            and frozen_policy is not None
        ):
            risk_policy_valid = validate_risk_acceptance(
                acceptance,
                [prior],
                authorized_actor_ids={str(authority.get("actor_id", ""))},
                non_waivable_gates=set(
                    (frozen_policy.config.get("close_policy") or {}).get(
                        "non_waivable_gates", []
                    )
                ),
                now=_parse_event_time(event.get("occurred_at")),
            ).ok and actor_authorized_for_scope(
                str(authority.get("actor_id", "")),
                prior_scope,
                frozen_policy.ownership,
            )
        valid = (
            isinstance(prior, Mapping)
            and prior.get("status") in {"open", "acknowledged"}
            and finding.get("status") == "waived"
            and _without_fields(prior, {"status"}) == _without_fields(finding, {"status"})
            and acceptance.get("finding_ids") == [finding.get("id")]
            and (
                store_contract_version < 2
                or acceptance.get("accepted_at") == event.get("occurred_at")
            )
            and isinstance(prior_scope, Mapping)
            and prior_scope.get("status") == "approved"
            and scope_binding_matches(acceptance.get("scope"), prior_scope)
            and (
                store_contract_version < 2
                or (
                    isinstance(intent_payload.get("risk_acceptance"), Mapping)
                    and _without_fields(intent_payload["risk_acceptance"], {"accepted_at"})
                    == _without_fields(acceptance, {"accepted_at"})
                    and intent_payload.get("finding") == finding
                )
            )
            and str(acceptance.get("id", "")) not in snapshots["risk-acceptances"]
            and risk_policy_valid
        )
    elif operation == "work_unit.create":
        unit = payload["work_unit"]
        expected_result = str(unit.get("expected_result", ""))
        expected_prefix = f"tasks/{task_id}/results/"
        result_name = expected_result.removeprefix(expected_prefix).removesuffix(".json")
        valid = (
            isinstance(prior_scope, Mapping)
            and prior_scope.get("status") == "approved"
            and unit.get("status") == "pending"
            and str(unit.get("id", "")) not in snapshots["work-units"]
            and str(unit.get("owner", "")) in {str(value) for value in prior_scope.get("owners", [])}
            and all(path in prior_scope.get("allowed_paths", []) for path in unit.get("allowed_paths", []))
            and all(str(item) in snapshots["work-units"] for item in unit.get("depends_on", []))
            and expected_result.startswith(expected_prefix)
            and expected_result.endswith(".json")
            and is_identifier(result_name, "RESULT")
            and (store_contract_version < 2 or intent_payload.get("work_unit") == unit)
        )
    elif operation == "work_unit.ready":
        unit = payload["work_unit"]
        prior = snapshots["work-units"].get(str(unit.get("id", "")))
        valid = (
            isinstance(prior, Mapping)
            and prior.get("status") == "pending"
            and unit.get("status") == "ready"
            and _without_fields(prior, {"status"}) == _without_fields(unit, {"status"})
            and (store_contract_version < 2 or intent_payload.get("work_unit") == unit)
        )
    elif operation == "run.register":
        run = payload["run"]
        unit = payload["work_unit"]
        prior_unit = snapshots["work-units"].get(str(unit.get("id", "")))
        dependencies = list(prior_unit.get("depends_on", [])) if isinstance(prior_unit, Mapping) else []
        runtime = run.get("runtime") or {}
        binding_valid = False
        try:
            if repo is not None and isinstance(prior_scope, Mapping):
                run_root = Path(str(runtime.get("worktree", ""))).resolve()
                baseline_subject = dict(payload.get("baseline_subject") or {})
                binding_checks = GitRepository(repo).run_worktree_binding_checks(
                    GitRepository(run_root),
                    approved_base=str(prior_scope.get("base_commit", "")),
                    baseline_subject=baseline_subject,
                )
                binding_valid = (
                    all(binding_checks.values())
                    and payload.get("repository_binding") == binding_checks
                    and payload.get("worktree_identity")
                    == {"path": str(run_root), "branch": runtime.get("branch")}
                    and runtime.get("worktree") == str(run_root)
                    and runtime.get("profile") == prior_task.get("runtime_profile")
                )
        except (MacError, OSError, TypeError, ValueError):
            binding_valid = False
        valid = (
            isinstance(prior_unit, Mapping)
            and prior_unit.get("status") == "ready"
            and unit.get("status") == "running"
            and _without_fields(prior_unit, {"status"}) == _without_fields(unit, {"status"})
            and isinstance(prior_scope, Mapping)
            and prior_scope.get("status") == "approved"
            and prior_task.get("state") in {"ready", "executing", "repairing"}
            and run.get("status") in {"registered", "running"}
            and run.get("work_unit_id") == unit.get("id")
            and run.get("finished_at") is None
            and run.get("exit_code") is None
            and payload.get("run_id") == run.get("id")
            and (store_contract_version < 2 or event.get("run_id") == run.get("id"))
            and str(run.get("id", "")) not in snapshots["runs"]
            and run.get("started_at") == event.get("occurred_at")
            and all(
                snapshots["work-units"].get(str(item), {}).get("status") == "completed"
                for item in dependencies
            )
            and binding_valid
            and (
                store_contract_version < 2
                or (
                    isinstance(intent_payload.get("run"), Mapping)
                    and _without_fields(intent_payload["run"], {"independence_level", "started_at", "runtime"})
                    == _without_fields(run, {"independence_level", "started_at", "runtime"})
                    and _without_fields(intent_payload["run"].get("runtime") or {}, {"worktree", "branch"})
                    == _without_fields(runtime, {"worktree", "branch"})
                    and intent_payload.get("work_unit") == unit
                )
            )
        )
    elif operation == "run.finish":
        run = payload["run"]
        prior = snapshots["runs"].get(str(run.get("id", "")))
        expected_run = deepcopy(dict(prior)) if isinstance(prior, Mapping) else None
        if expected_run is not None:
            expected_run.update({
                "status": run.get("status"),
                "finished_at": event.get("occurred_at"),
                "exit_code": run.get("exit_code"),
            })
        terminal_status = str(run.get("status", ""))
        exit_code = run.get("exit_code")
        unit = payload.get("work_unit")
        prior_unit = (
            snapshots["work-units"].get(str(unit.get("id", "")))
            if isinstance(unit, Mapping)
            else None
        )
        expected_unit_status = "failed" if terminal_status == "failed" else "cancelled"
        unit_valid = (
            isinstance(unit, Mapping)
            and isinstance(prior_unit, Mapping)
            and prior_unit.get("status") == "running"
            and unit.get("status") == expected_unit_status
            and _without_fields(prior_unit, {"status"}) == _without_fields(unit, {"status"})
        ) if terminal_status in {"failed", "cancelled"} else unit is None
        valid = (
            isinstance(prior, Mapping)
            and prior.get("status") in {"registered", "running"}
            and run.get("status") in {"succeeded", "failed", "cancelled"}
            and run.get("finished_at") == event.get("occurred_at")
            and run == expected_run
            and payload.get("run_id") == run.get("id")
            and payload.get("status") == run.get("status")
            and (store_contract_version < 2 or event.get("run_id") == run.get("id"))
            and (
                terminal_status == "cancelled"
                or run.get("actor") == authority_actor
            )
            and (
                (terminal_status == "succeeded" and exit_code == 0)
                or (terminal_status == "failed" and exit_code not in {None, 0})
                or (terminal_status == "cancelled" and exit_code is None)
            )
            and unit_valid
            and (
                store_contract_version < 2
                or (
                    isinstance(intent_payload.get("run"), Mapping)
                    and _without_fields(intent_payload["run"], {"finished_at"})
                    == _without_fields(run, {"finished_at"})
                    and intent_payload.get("status") == run.get("status")
                    and (
                        unit is None
                        or intent_payload.get("work_unit") == unit
                    )
                )
            )
        )
    elif operation == "result.submit":
        result = payload["result"]
        run = payload["run"]
        unit = payload["work_unit"]
        prior_run = snapshots["runs"].get(str(result.get("run_id", "")))
        prior_unit = snapshots["work-units"].get(str(result.get("work_unit_id", "")))
        succeeded = result.get("outcome") == "succeeded"
        expected_run = deepcopy(dict(prior_run)) if isinstance(prior_run, Mapping) else None
        expected_unit = deepcopy(dict(prior_unit)) if isinstance(prior_unit, Mapping) else None
        command_codes = [int(item.get("exit_code", 1)) for item in result.get("commands", [])]
        if expected_run is not None:
            expected_run.update({
                "status": "succeeded" if succeeded else "failed",
                "finished_at": event.get("occurred_at"),
                "exit_code": next(
                    (code for code in command_codes if code != 0),
                    0 if succeeded else 1,
                ),
            })
        if expected_unit is not None:
            expected_unit["status"] = "completed" if succeeded else "failed"
        canonical = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        valid = (
            isinstance(prior_run, Mapping)
            and prior_run.get("status") in {"registered", "running"}
            and isinstance(prior_unit, Mapping)
            and prior_unit.get("status") == "running"
            and result.get("task_id") == task_id
            and result.get("run_id") == run.get("id")
            and (store_contract_version < 2 or event.get("run_id") == run.get("id"))
            and result.get("work_unit_id") == unit.get("id")
            and result.get("submitted_at") == event.get("occurred_at")
            and run.get("finished_at") == event.get("occurred_at")
            and run == expected_run
            and unit == expected_unit
            and payload.get("result_id") == result.get("id")
            and payload.get("work_unit_id") == unit.get("id")
            and payload.get("outcome") == result.get("outcome")
            and payload.get("digest") == sha256_bytes(canonical)
            and str(result.get("id", "")) not in snapshots["results"]
            and (
                store_contract_version < 2
                or (
                    isinstance(intent_document.get("result"), Mapping)
                    and _without_fields(intent_document["result"], {"submitted_at"})
                    == _without_fields(result, {"submitted_at"})
                    and payload.get("intake_proof") == intent_document.get("intake_proof")
                )
            )
        )
    elif operation == "scope.propose":
        proposed = payload["scope"]
        allowed_changes = {"status", "proposed_by", "approved_by", "allowed_paths", "denied_paths", "owners", "allowed_operations"}
        valid = (
            isinstance(prior_scope, Mapping)
            and prior_scope.get("status") == "proposed"
            and proposed.get("status") == "proposed"
            and proposed.get("version") == prior_scope.get("version") == 1
            and payload.get("scope_id") == proposed.get("id")
            and payload.get("version") == proposed.get("version")
            and proposed.get("proposed_by") == authority.get("actor_id")
            and proposed.get("approved_by", []) == []
            and _without_fields(prior_scope, allowed_changes)
            == _without_fields(proposed, allowed_changes)
            and (store_contract_version < 2 or intent_payload.get("scope") == proposed)
        )
    elif operation == "scope.amend":
        proposed = payload["scope"]
        valid = False
        if isinstance(prior_scope, Mapping) and prior_scope.get("status") == "approved":
            try:
                expected_scope = amend_scope(
                    dict(prior_scope),
                    add_paths=[
                        str(path)
                        for path in proposed.get("allowed_paths", [])
                        if path not in prior_scope.get("allowed_paths", [])
                    ],
                    actor=str(authority.get("actor_id", "")),
                    approvers=[],
                    added_risk_tags=[
                        str(tag)
                        for tag in proposed.get("risk_tags", [])
                        if tag not in prior_scope.get("risk_tags", [])
                    ],
                    independent_approval=False,
                    add_operations=[
                        str(value)
                        for value in proposed.get("allowed_operations", [])
                        if value not in prior_scope.get("allowed_operations", [])
                    ],
                )
                valid = dict(proposed) == expected_scope
                valid = valid and (
                    payload.get("scope_id") == proposed.get("id")
                    and payload.get("version") == proposed.get("version")
                    and payload.get("amendment") is True
                    and (store_contract_version < 2 or intent_payload.get("scope") == proposed)
                )
            except ValueError:
                valid = False
    elif operation == "scope.approve":
        from .authority import scope_approval_subject

        approved = payload["scope"]
        approval = payload["approval"]
        allowed_subjects = {scope_approval_subject(prior_task, prior_scope)} if isinstance(prior_scope, Mapping) else set()
        if isinstance(prior_scope, Mapping) and int(prior_scope.get("version", 0)) == 1:
            allowed_subjects.update({str(prior_task.get("scope_contract_ref", "")), "scope-contract.yaml"})
        valid = (
            isinstance(prior_scope, Mapping)
            and prior_scope.get("status") == "proposed"
            and approved.get("status") == "approved"
            and approved.get("approved_by") == [authority.get("actor_id")]
            and payload.get("scope_id") == approved.get("id")
            and payload.get("version") == approved.get("version")
            and _without_fields(prior_scope, {"status", "approved_by"})
            == _without_fields(approved, {"status", "approved_by"})
            and approval.get("kind") == "scope"
            and approval.get("decision") == "approved"
            and (
                store_contract_version < 2
                or approval.get("recorded_at") == event.get("occurred_at")
            )
            and approval.get("subject_ref") in allowed_subjects
            and frozen_policy is not None
            and bool(valid_scope_approvals(
                prior_task,
                prior_scope,
                [approval],
                frozen_policy.ownership,
                frozen_policy.config,
            ))
            and (
                store_contract_version < 2
                or (
                    intent_payload.get("scope") == approved
                    and isinstance(intent_payload.get("approval"), Mapping)
                    and _without_fields(
                        intent_payload["approval"],
                        {"actor", "independence_level", "recorded_at"},
                    )
                    == _without_fields(
                        approval,
                        {"actor", "independence_level", "recorded_at"},
                    )
                )
            )
            and str(approval.get("id", "")) not in snapshots["approvals"]
        )
    elif operation.startswith("approval.record."):
        approval = payload["approval"]
        approval_kind = operation.removeprefix("approval.record.")
        expected_subject = None
        if approval_kind == "scope" and isinstance(prior_scope, Mapping):
            from .authority import scope_approval_subject

            expected_subject = scope_approval_subject(prior_task, prior_scope)
        valid = (
            frozen_policy is not None
            and isinstance(prior_scope, Mapping)
            and actor_authorized_for_scope(
                str(authority.get("actor_id", "")),
                prior_scope,
                frozen_policy.ownership,
            )
            and approval.get("kind") == approval_kind
            and payload.get("approval_kind") == approval.get("kind")
            and approval.get("decision") in {"approved", "rejected"}
            and (expected_subject is None or approval.get("subject_ref") == expected_subject)
            and (
                store_contract_version < 2
                or approval.get("recorded_at") == event.get("occurred_at")
            )
            and (
                store_contract_version < 2
                or (
                    isinstance(intent_payload.get("approval"), Mapping)
                    and _without_fields(
                        intent_payload["approval"],
                        {"actor", "independence_level", "recorded_at"},
                    )
                    == _without_fields(
                        approval,
                        {"actor", "independence_level", "recorded_at"},
                    )
                )
            )
            and str(approval.get("id", "")) not in snapshots["approvals"]
        )
    elif operation == "evidence.record":
        evidence = payload["evidence"]
        run = payload["run"]
        execution = evidence.get("execution") or {}
        exit_code = execution.get("exit_code")
        valid = (
            str(evidence.get("id", "")) not in snapshots["evidence"]
            and str(run.get("id", "")) not in snapshots["runs"]
            and evidence.get("kind") == "command"
            and evidence.get("run_id") == run.get("id") == event.get("run_id")
            and evidence.get("policy_digest") == (prior_task.get("policy_ref") or {}).get("combined_digest")
            and run.get("work_unit_id") == "verification"
            and run.get("started_at") == execution.get("started_at")
            and run.get("finished_at") == execution.get("finished_at") == evidence.get("recorded_at")
            and run.get("exit_code") == exit_code
            and run.get("status") == ("succeeded" if exit_code == 0 else "failed")
            and (evidence.get("validity") or {}).get("status") == ("valid" if exit_code == 0 else "invalid")
            and not (evidence.get("validity") or {}).get("invalidated_by")
            and (
                store_contract_version < 2
                or (
                    evidence.get("claims") == [{"gate": intent_document.get("claim")}]
                    and (evidence.get("execution") or {}).get("argv") == intent_document.get("argv")
                    and intent_document.get("final_evidence") == evidence
                    and intent_document.get("final_run") == run
                    and (
                        (evidence.get("subject") or {}).get("type") == "commit"
                    ) is bool(intent_document.get("commit"))
                )
            )
        )
    elif operation == "evidence.promote":
        evidence = payload["evidence"]
        promotion = payload.get("promotion") or {}
        source = snapshots["evidence"].get(str(promotion.get("source_evidence_id", "")))
        valid = (
            isinstance(source, Mapping)
            and (source.get("subject") or {}).get("type") == "workspace"
            and str(evidence.get("id", "")) not in snapshots["evidence"]
            and promotion.get("promoted_evidence_id") == evidence.get("id")
            and promotion.get("workspace_subject") == source.get("subject")
            and promotion.get("commit_subject") == evidence.get("subject")
            and (
                store_contract_version < 2
                or evidence.get("recorded_at") == event.get("occurred_at")
            )
            and _without_fields(source, {"id", "subject", "recorded_at"})
            == _without_fields(evidence, {"id", "subject", "recorded_at"})
            and (
                store_contract_version < 2
                or (
                    intent_payload.get("promotion") == promotion
                    and isinstance(intent_payload.get("evidence"), Mapping)
                    and _without_fields(intent_payload["evidence"], {"recorded_at"})
                    == _without_fields(evidence, {"recorded_at"})
                )
            )
        )
    elif operation == "evidence.invalidate":
        from .evidence import invalidate_evidence

        evidence = payload["evidence"]
        prior = snapshots["evidence"].get(str(evidence.get("id", "")))
        try:
            expected_evidence = invalidate_evidence(
                prior,
                event_id=str(event.get("event_id", "")),
                reason=str(payload.get("reason", "")),
            ) if isinstance(prior, Mapping) else None
        except (TypeError, ValueError):
            expected_evidence = None
        valid = expected_evidence == evidence and (
            store_contract_version < 2
            or (
                intent_payload.get("evidence") == evidence
                and intent_payload.get("reason") == payload.get("reason")
            )
        )
    elif operation.startswith("task.transition.") or operation in {"task.cancel", "task.supersede"}:
        expected_target = {
            "task.cancel": "cancelled",
            "task.supersede": "superseded",
        }.get(operation, operation.removeprefix("task.transition."))
        successor = payload.get("successor_task_id")
        workflow_transition = None
        workflow_terminal_states = TERMINAL_STATES
        transition_fact_valid = False
        try:
            if repo is not None:
                compiled = frozen_policy or compile_frozen_policy(
                    repo,
                    prior_task.get("policy_ref") or {},
                    prior_task.get("ownership_ref") or {},
                    runtime_profile_id=str(prior_task.get("runtime_profile") or "") or None,
                )
                workflow_transition = find_transition(
                    str(prior_task.get("state", "")),
                    expected_target,
                    compiled.transitions,
                )
                workflow_terminal_states = compiled.terminal_states
                metadata_snapshot = payload.get("transition_metadata") or {}
                transition_fact = (
                    metadata_snapshot.get("transition_fact")
                    if isinstance(metadata_snapshot, Mapping)
                    else None
                )
                historical_context = _resolve_historical_transition_context(
                    repo,
                    task_id,
                    expected_target,
                    prior_events,
                    str(authority.get("actor_id", "")),
                    str(authority.get("actor_kind", "")),
                    transition_fact if isinstance(transition_fact, Mapping) else None,
                    intent_document.get("context"),
                    compiled=compiled,
                    occurred_at=event.get("occurred_at"),
                    successor_task_id=str(successor) if isinstance(successor, str) else None,
                )
                context_exact = asdict(historical_context) == intent_document.get("context")
                decision = evaluate_transition(
                    str(prior_task.get("state", "")),
                    expected_target,
                    replace(
                        historical_context,
                        controller_lease_valid=True,
                        lease_valid=True,
                    ),
                    transitions=compiled.transitions,
                    states=compiled.states,
                    terminal_states=compiled.terminal_states,
                )
                workflow_transition = decision.transition
                transition_fact_valid = context_exact and decision.ok
        except (MacError, OSError, TypeError, ValueError):
            transition_fact_valid = False
        valid = (
            payload.get("from") == prior_task.get("state")
            and payload.get("to") == expected_target
            and workflow_transition is not None
            and payload.get("transition_id") == workflow_transition.id
            and transition_fact_valid
            and type(payload.get("terminal_state")) is bool
            and payload.get("terminal_state") is (expected_target in workflow_terminal_states)
            and (
                store_contract_version < 2
                or (
                    intent_document.get("target") == expected_target
                    and intent_document.get("transition_metadata")
                    == _without_authority(payload.get("transition_metadata") or {})
                )
            )
            and (
                is_identifier(str(successor), "TASK") and successor != task_id
                if expected_target == "superseded"
                else successor is None
            )
        )
    else:
        valid = True
    if not valid or not reference_valid or not authority_bound:
        raise MacError(
            "EVENT_SEMANTIC_TAMPERED",
            "Event snapshot violates its governed operation semantics",
            exit_code=ExitCode.CORRUPTION,
            task_id=task_id or None,
        )


def _validate_loaded_event_stream(
    repo: Path,
    task_id: str,
    loaded: Iterable[Mapping[str, Any]],
    *,
    schema_set: SchemaSet | None = None,
    frozen_policy_cache: dict[str, Any] | None = None,
    repository_identity: str | None = None,
) -> list[dict[str, Any]]:
    """Validate an already frozen Event byte stream before any replay consumer."""

    schemas = schema_set or SchemaSet()
    verified_repository_identity = repository_identity or _repository_identity(repo)
    events = sorted(
        (deepcopy(dict(event)) for event in loaded),
        key=lambda item: int(item.get("new_revision", -2)),
    )
    for index, event in enumerate(events):
        event_id = str(event.get("event_id", ""))
        path = f"tasks/{task_id}/events/{event_id or '<unknown>'}.json"
        issues = schemas.validate(event, "event.schema.json", path=path)
        if issues:
            raise MacError(
                "EVENT_SCHEMA_INVALID",
                "stored Event does not satisfy the Event schema",
                exit_code=ExitCode.CORRUPTION,
                path=path,
                task_id=task_id,
                details={"issues": [issue.as_dict() for issue in issues]},
            )
        if str(event.get("task_id", "")) != task_id:
            raise MacError(
                "EVENT_PATH_TAMPERED",
                "Event Task id does not match its storage stream",
                exit_code=ExitCode.CORRUPTION,
                path=path,
                task_id=task_id,
            )
        if event.get("event_type") == "legacy_imported":
            if not _valid_legacy_import_event(event):
                raise MacError(
                    "EVENT_LEGACY_IMPORT_INVALID",
                    "legacy import Event does not prove an explicitly unverifiable migration",
                    exit_code=ExitCode.CORRUPTION,
                    task_id=task_id,
                )
            continue
        _validate_governed_event_contract(
            event,
            events[:index],
            repo=repo,
            require_authority=True,
            frozen_policy_cache=frozen_policy_cache,
            repository_identity=verified_repository_identity,
        )
    if events:
        replay_events(events)
    return events


def _validate_replay_shape(command: MutationCommand, event: Mapping[str, Any]) -> None:
    payload = event.get("payload") or {}
    if isinstance(command, CreateTask):
        matches = event.get("event_type") == "task_created"
    elif isinstance(command, AppendEvent):
        matches = event.get("event_type") == command.event_type
    elif isinstance(command, Transition):
        matches = event.get("event_type") == "state_transitioned" and payload.get("to") == command.target
    elif isinstance(command, RecordCommandEvidence):
        matches = event.get("event_type") == "evidence_recorded"
    elif isinstance(command, SubmitResult):
        stored_result = payload.get("result") if isinstance(payload, Mapping) else None
        matches = (
            event.get("event_type") == "result_submitted"
            and isinstance(stored_result, Mapping)
            and _without_fields(stored_result, {"submitted_at"})
            == _without_fields(command.result, {"submitted_at"})
            and stored_result.get("submitted_at") == event.get("occurred_at")
            and payload.get("intake_proof")
            == (dict(command.intake_proof) if command.intake_proof is not None else None)
        )
    else:
        matches = False
    if not matches:
        raise MacError(
            "MUTATION_IDEMPOTENCY_CONFLICT",
            "idempotency key belongs to a different mutation shape",
            exit_code=ExitCode.CONFLICT,
            task_id=str(event.get("task_id", "")) or None,
        )


def _validate_result_replay_payload(
    command: SubmitResult,
    event: Mapping[str, Any],
    prior_events: list[dict[str, Any]],
    authority: Mapping[str, Any],
) -> None:
    """Bind a Result retry to the exact Store-derived event snapshots."""

    payload = event.get("payload")
    result = dict(command.result)
    stored_result = deepcopy(result)
    stored_result["submitted_at"] = event.get("occurred_at")
    result_id = str(result.get("id", ""))
    work_unit_id = str(result.get("work_unit_id", ""))
    run_id = str(result.get("run_id", ""))
    if (
        not isinstance(payload, Mapping)
        or not is_identifier(result_id, "RESULT")
        or not is_identifier(work_unit_id, "WU")
        or not is_identifier(run_id, "RUN")
    ):
        raise MacError(
            "MUTATION_IDEMPOTENCY_CONFLICT",
            "stored Result replay identifiers are invalid",
            exit_code=ExitCode.CONFLICT,
            task_id=command.task_id,
        )
    snapshots = replay_entity_snapshots(prior_events)
    prior_work_unit = snapshots["work-units"].get(work_unit_id)
    prior_run = snapshots["runs"].get(run_id)
    if not isinstance(prior_work_unit, Mapping) or not isinstance(prior_run, Mapping):
        raise MacError(
            "MUTATION_IDEMPOTENCY_CONFLICT",
            "stored Result replay cannot reconstruct its prior Run and Work Unit",
            exit_code=ExitCode.CONFLICT,
            task_id=command.task_id,
        )
    for entity, schema_name, path in (
        (prior_work_unit, "work-unit.schema.json", "prior_work_unit"),
        (prior_run, "run.schema.json", "prior_run"),
        (stored_result, "result.schema.json", "result"),
    ):
        issues = SchemaSet().validate(dict(entity), schema_name, path=path)
        if issues:
            raise MacError(
                "MUTATION_IDEMPOTENCY_CONFLICT",
                "stored Result replay contains an invalid authoritative snapshot",
                exit_code=ExitCode.CONFLICT,
                task_id=command.task_id,
                details={"issues": [issue.as_dict() for issue in issues]},
            )
    completed_work_unit = deepcopy(dict(prior_work_unit))
    completed_work_unit["status"] = "completed" if result.get("outcome") == "succeeded" else "failed"
    command_codes = [int(item.get("exit_code", 1)) for item in result.get("commands", [])]
    completed_run = deepcopy(dict(prior_run))
    completed_run["status"] = "succeeded" if result.get("outcome") == "succeeded" else "failed"
    completed_run["finished_at"] = event.get("occurred_at")
    completed_run["exit_code"] = next(
        (code for code in command_codes if code != 0),
        0 if result.get("outcome") == "succeeded" else 1,
    )
    canonical = json.dumps(stored_result, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    expected_payload = {
        "result_id": result_id,
        "digest": sha256_bytes(canonical),
        "outcome": result.get("outcome"),
        "work_unit_id": work_unit_id,
        "work_unit": completed_work_unit,
        "run": completed_run,
        "result": stored_result,
        "intake_proof": dict(command.intake_proof) if command.intake_proof is not None else None,
        "authority": dict(authority),
    }
    expected_revision = int(event.get("expected_revision", -2))
    if (
        dict(payload) != expected_payload
        or str(event.get("task_id", "")) != command.task_id
        or str(event.get("run_id", "")) != run_id
        or int(event.get("new_revision", -2)) != expected_revision + 1
    ):
        raise MacError(
            "MUTATION_IDEMPOTENCY_CONFLICT",
            "stored Result event does not match the authorized Store-derived replay payload",
            exit_code=ExitCode.CONFLICT,
            task_id=command.task_id,
        )


def _replay_authority_request(
    repo: Path,
    command: MutationCommand,
    event: Mapping[str, Any],
    *,
    events: list[dict[str, Any]] | None = None,
) -> AuthorityRequest:
    _validate_replay_shape(command, event)
    original = _event_authority(event)
    intent = _command_intent(repo, command)
    replay_digest = intent.get("replay_digest")
    if original.get("replay_digest") != replay_digest:
        raise MacError(
            "MUTATION_IDEMPOTENCY_CONFLICT",
            "idempotency key was previously used with a different stable intent",
            exit_code=ExitCode.CONFLICT,
            task_id=str(event.get("task_id", "")) or None,
        )
    original_minimum = original.get("minimum_independence")
    if original_minimum is not None and not level_at_least(command.minimum_independence, str(original_minimum)):
        raise MacError(
            "MUTATION_REPLAY_INDEPENDENCE_DOWNGRADE",
            "idempotent retry cannot lower the original minimum independence requirement",
            exit_code=ExitCode.SECURITY,
            task_id=str(event.get("task_id", "")) or None,
        )
    actor = {str(key): str(value) for key, value in dict(command.actor_claim).items()}
    if actor != {"id": original.get("actor_id"), "kind": original.get("actor_kind")}:
        raise MacError(
            "MUTATION_IDEMPOTENCY_CONFLICT",
            "idempotent retry actor does not match the original authority",
            exit_code=ExitCode.CONFLICT,
            task_id=str(event.get("task_id", "")) or None,
        )
    task_id = str(event.get("task_id", ""))
    event_expected_revision = int(event.get("expected_revision", -2))
    if event_expected_revision == -1 and event.get("event_type") == "task_created":
        created_task = (event.get("payload") or {}).get("task") or {}
        policy_digest, ownership_digest = _policy_digests(created_task)
    else:
        source_events = (
            events
            if events is not None
            else FilesystemTaskRepository(repo).list_events(task_id)
        )
        prior_events = [
            candidate
            for candidate in source_events
            if int(candidate.get("new_revision", -1)) <= event_expected_revision
        ]
        try:
            prior_task = replay_events(prior_events)
        except (KeyError, TypeError, ValueError, MacError) as exc:
            raise MacError(
                "MUTATION_IDEMPOTENCY_CONFLICT",
                "original mutation policy snapshot cannot be reconstructed",
                exit_code=ExitCode.CONFLICT,
                task_id=task_id or None,
            ) from exc
        policy_digest, ownership_digest = _policy_digests(prior_task)
        if isinstance(command, SubmitResult):
            _validate_result_replay_payload(command, event, prior_events, original)
    stable = {
        "repository_identity": _repository_identity(repo),
        "operation": command.operation,
        "task_id": task_id,
        "expected_revision": original.get("expected_revision"),
        "idempotency_key": command.idempotency_key,
        "intent_digest": original.get("intent_digest"),
        "policy_digest": policy_digest,
        "ownership_digest": ownership_digest,
        "audience": MUTATION_AUDIENCE,
    }
    if (
        original.get("repository_identity") != stable["repository_identity"]
        or original.get("operation") != stable["operation"]
        or original.get("task_id") != task_id
        or original.get("expected_revision") != event_expected_revision
        or original.get("idempotency_key") != stable["idempotency_key"]
        or event.get("idempotency_key") != stable["idempotency_key"]
        or original.get("policy_digest") != policy_digest
        or original.get("ownership_digest") != ownership_digest
        or original.get("audience") != MUTATION_AUDIENCE
    ):
        raise MacError(
            "MUTATION_IDEMPOTENCY_CONFLICT",
            "original mutation authority binding is inconsistent with its event",
            exit_code=ExitCode.CONFLICT,
            task_id=task_id or None,
        )
    try:
        request = AuthorityRequest(actor_claim=actor, **stable)
    except (TypeError, ValueError, MacError) as exc:
        raise MacError(
            "MUTATION_IDEMPOTENCY_CONFLICT",
            "original mutation authority request is invalid",
            exit_code=ExitCode.CONFLICT,
            task_id=task_id or None,
        ) from exc
    if original.get("request_digest") != request.request_digest or original.get("binding_digest") != request.binding_digest:
        raise MacError(
            "MUTATION_IDEMPOTENCY_CONFLICT",
            "original mutation authority digests are inconsistent",
            exit_code=ExitCode.CONFLICT,
            task_id=task_id or None,
        )
    return request


def _validate_replay_authority(
    repo: Path,
    command: MutationCommand,
    event: Mapping[str, Any],
    verified: VerifiedAuthority,
    *,
    events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    request = _replay_authority_request(repo, command, event, events=events)
    audit = authority_audit_record(verified)
    expected = {
        **request.as_dict(),
        "actor_id": request.actor_claim["id"],
        "actor_kind": request.actor_claim["kind"],
        "request_digest": request.request_digest,
        "binding_digest": request.binding_digest,
    }
    expected.pop("schema_version", None)
    expected.pop("actor_claim", None)
    if any(audit.get(key) != value for key, value in expected.items()):
        raise MacError(
            "MUTATION_AUTHORITY_BINDING_MISMATCH",
            "verified authority does not bind the original idempotent mutation",
            exit_code=ExitCode.SECURITY,
            task_id=request.task_id,
        )
    original = _event_authority(event)
    if not level_at_least(str(audit.get("independence_level", "")), str(original.get("independence_level", ""))):
        raise MacError(
            "MUTATION_REPLAY_INDEPENDENCE_DOWNGRADE",
            "idempotent retry authority is less independent than the original authority",
            exit_code=ExitCode.SECURITY,
            task_id=request.task_id,
        )
    audit["replay_digest"] = str(_event_authority(event)["replay_digest"])
    audit["minimum_independence"] = original.get("minimum_independence")
    return audit


def _authority_request_for_command(
    repo: Path,
    command: MutationCommand,
    task: Mapping[str, Any],
) -> AuthorityRequest:
    task_id = str(command.task["id"]) if isinstance(command, CreateTask) else command.task_id
    policy_digest, ownership_digest = _policy_digests(task)
    return AuthorityRequest(
        repository_identity=_repository_identity(repo),
        operation=command.operation,
        task_id=task_id,
        actor_claim={str(key): str(value) for key, value in dict(command.actor_claim).items()},
        expected_revision=-1 if isinstance(command, CreateTask) else command.expected_revision,
        idempotency_key=command.idempotency_key,
        intent_digest=canonical_digest(_command_intent(repo, command)),
        policy_digest=policy_digest,
        ownership_digest=ownership_digest,
        audience=MUTATION_AUDIENCE,
    )


def _verify_command_authority(
    repo: Path,
    command: MutationCommand,
    task: Mapping[str, Any],
    *,
    existing: Mapping[str, Any] | None = None,
) -> VerifiedAuthority:
    request = (
        _replay_authority_request(repo, command, existing)
        if existing is not None
        else _authority_request_for_command(repo, command, task)
    )
    return require_authority(
        current_authority_verifier(),
        request=request,
        minimum_independence=command.minimum_independence,
    )


def _verify_exact_intent_authority(
    repo: Path,
    command: MutationCommand,
    task: Mapping[str, Any],
    intent: Mapping[str, Any],
) -> VerifiedAuthority:
    task_id = str(command.task["id"]) if isinstance(command, CreateTask) else command.task_id
    policy_digest, ownership_digest = _policy_digests(task)
    request = AuthorityRequest(
        repository_identity=_repository_identity(repo),
        operation=command.operation,
        task_id=task_id,
        actor_claim={str(key): str(value) for key, value in dict(command.actor_claim).items()},
        expected_revision=-1 if isinstance(command, CreateTask) else command.expected_revision,
        idempotency_key=command.idempotency_key,
        intent_digest=canonical_digest(intent),
        policy_digest=policy_digest,
        ownership_digest=ownership_digest,
        audience=MUTATION_AUDIENCE,
    )
    return require_authority(
        current_authority_verifier(),
        request=request,
        minimum_independence=command.minimum_independence,
    )


def _stored_mutation_result(
    stored: AppendResult,
    authority: Mapping[str, Any],
    *,
    value: Mapping[str, Any] | None = None,
) -> MutationResult:
    return MutationResult(
        stored.event,
        stored.projection,
        stored.idempotent_replay,
        deepcopy(dict(authority)),
        deepcopy(dict(value)) if value is not None else None,
    )


class FilesystemTaskRepository:
    def __init__(self, repo: Path) -> None:
        self.repo = repo.resolve()
        self.tasks_root = self.repo / "tasks"
        self._frozen_policy_cache: dict[str, Any] = {}

    def task_dir(self, task_id: str) -> Path:
        if "/" in task_id or "\\" in task_id or task_id in {"", ".", ".."}:
            raise MacError("TASK_ID_UNSAFE", "unsafe task id", exit_code=ExitCode.SECURITY)
        tasks_root = self.tasks_root.absolute()
        resolved_tasks_root = tasks_root.resolve(strict=False)
        candidate = tasks_root / task_id
        resolved_candidate = candidate.resolve(strict=False)
        try:
            resolved_tasks_root.relative_to(self.repo)
            resolved_candidate.relative_to(resolved_tasks_root)
        except ValueError as exc:
            raise MacError(
                "TASK_PATH_UNSAFE",
                "Task path resolves outside the repository Task root",
                exit_code=ExitCode.SECURITY,
                task_id=task_id,
            ) from exc
        if resolved_tasks_root != tasks_root or (candidate.exists() and resolved_candidate != candidate.absolute()):
            raise MacError(
                "TASK_PATH_UNSAFE",
                "Task root or Task directory is a symlink or junction",
                exit_code=ExitCode.SECURITY,
                task_id=task_id,
            )
        return candidate

    def list_events(self, task_id: str) -> list[dict[str, Any]]:
        loaded: list[dict[str, Any]] = []
        for path in sorted((self.task_dir(task_id) / "events").glob("EVT-*.json")):
            event = load_data(path)
            if not isinstance(event, dict):
                raise MacError(
                    "EVENT_SCHEMA_INVALID",
                    "stored Event does not satisfy the Event schema",
                    exit_code=ExitCode.CORRUPTION,
                    path=path.relative_to(self.repo).as_posix(),
                    task_id=task_id,
                )
            if (
                path.stem != str(event.get("event_id", ""))
                or str(event.get("task_id", "")) != task_id
            ):
                raise MacError(
                    "EVENT_PATH_TAMPERED",
                    "Event filename or Task id does not match its storage path",
                    exit_code=ExitCode.CORRUPTION,
                    path=path.relative_to(self.repo).as_posix(),
                    task_id=task_id,
                )
            loaded.append(event)
        return _validate_loaded_event_stream(
            self.repo,
            task_id,
            loaded,
            frozen_policy_cache=self._frozen_policy_cache,
        )

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

    def _replayed_state(
        self,
        task_id: str,
        *,
        events: list[dict[str, Any]] | None = None,
    ) -> tuple[dict[str, Any], dict[str, dict[str, dict[str, Any]]]]:
        events = self.list_events(task_id) if events is None else events
        has_creation_event = any(event.get("event_type") == "task_created" for event in events)
        if has_creation_event:
            seed = None
        else:
            try:
                seed = self.load_task(task_id)
            except MacError:
                seed = None
        projection = replay_events(events, initial_projection=seed)
        snapshots = replay_entity_snapshots(events, initial_projection=seed)
        return projection, snapshots

    def _replayed_scope(
        self,
        task_id: str,
        *,
        events: list[dict[str, Any]] | None = None,
    ) -> tuple[dict[str, Any] | None, dict[int, dict[str, Any]]]:
        events = self.list_events(task_id) if events is None else events
        current, history = replay_scope_snapshots(events)
        created_scope = next(
            (
                deepcopy(dict(scope))
                for event in events
                if event.get("event_type") == "task_created"
                and isinstance((scope := (event.get("payload") or {}).get("scope")), Mapping)
            ),
            None,
        )
        versions = dict(history)
        if created_scope is not None:
            versions.setdefault(int(created_scope["version"]), created_scope)
        if current is not None:
            versions[int(current["version"])] = current
        elif created_scope is not None:
            current = created_scope
        if current is None:
            return None, {}
        current_version = int(current["version"])
        return current, {
            version: snapshot
            for version, snapshot in sorted(versions.items())
            if version != current_version
        }

    def projection_drift(self, task_id: str) -> list[str]:
        events = self.list_events(task_id)
        projection, snapshots = self._replayed_state(task_id, events=events)
        scope, scope_history = self._replayed_scope(task_id, events=events)
        return self._projection_drift_for(task_id, projection, snapshots, scope, scope_history)

    def _projection_drift_for(
        self,
        task_id: str,
        projection: Mapping[str, Any],
        snapshots: Mapping[str, Mapping[str, Mapping[str, Any]]],
        scope: Mapping[str, Any] | None,
        scope_history: Mapping[int, Mapping[str, Any]],
    ) -> list[str]:
        drift: list[str] = []
        task_root = self.task_dir(task_id)
        task_path = task_root / "task.yaml"
        try:
            current_task = load_data(task_path)
        except (FileNotFoundError, ValueError):
            current_task = None
        if current_task != projection:
            drift.append(task_path.relative_to(self.repo).as_posix())
        scope_path = task_root / "scope-contract.yaml"
        try:
            current_scope = load_data(scope_path)
        except (FileNotFoundError, ValueError):
            current_scope = None
        if current_scope != scope:
            drift.append(scope_path.relative_to(self.repo).as_posix())
        history_root = task_root / "scope-history"
        expected_history = {
            history_root / f"scope-contract.v{version}.yaml": value
            for version, value in scope_history.items()
        }
        actual_history = set(history_root.iterdir()) if history_root.is_dir() else set()
        for path in sorted(set(expected_history) | actual_history):
            try:
                if not path.is_file() or path.is_symlink():
                    raise ValueError("non-canonical Scope history entry")
                current = load_data(path)
            except (OSError, ValueError):
                current = None
            if current != expected_history.get(path):
                drift.append(path.relative_to(self.repo).as_posix())
        for directory, (extension, _, _) in _ENTITY_SCHEMAS.items():
            entities = snapshots.get(directory, {})
            expected_paths = {
                self._replay_entity_target(task_id, directory, entity_id, entity): entity
                for entity_id, entity in entities.items()
            }
            directory_path = task_root / directory
            actual_paths = set(directory_path.iterdir()) if directory_path.is_dir() else set()
            for path in sorted(set(expected_paths) | actual_paths):
                try:
                    if not path.is_file() or path.is_symlink():
                        raise ValueError("non-canonical governed entity entry")
                    current = load_data(path)
                except (OSError, ValueError):
                    current = None
                if current != expected_paths.get(path):
                    drift.append(path.relative_to(self.repo).as_posix())
        return sorted(drift)

    def load_verified_aggregate(self, task_id: str) -> VerifiedTaskAggregate:
        """Load the single authoritative aggregate consumed by governance decisions."""

        events = self.list_events(task_id)
        task, entities = self._replayed_state(task_id, events=events)
        scope, history = self._replayed_scope(task_id, events=events)
        entity_revisions, scope_revision = _event_entity_revisions(events)
        drift = self._projection_drift_for(task_id, task, entities, scope, history)
        if self.list_events(task_id) != events:
            raise MacError(
                "AGGREGATE_EVENT_STREAM_CHANGED",
                "Task Event stream changed while loading its verified aggregate",
                exit_code=ExitCode.CONFLICT,
                task_id=task_id,
            )
        return VerifiedTaskAggregate(
            deepcopy(task),
            deepcopy(scope) if scope is not None else None,
            deepcopy(history),
            deepcopy(entities),
            deepcopy(entity_revisions),
            scope_revision,
            tuple(drift),
        )

    def _require_projection_clean(
        self,
        task_id: str,
        *,
        events: list[dict[str, Any]] | None = None,
    ) -> None:
        if events is None:
            drift = self.projection_drift(task_id)
        else:
            projection, snapshots = self._replayed_state(task_id, events=events)
            scope, scope_history = self._replayed_scope(task_id, events=events)
            drift = self._projection_drift_for(
                task_id,
                projection,
                snapshots,
                scope,
                scope_history,
            )
        if drift:
            raise MacError(
                "MUTATION_PROJECTION_DRIFT",
                "Task projections differ from the verified Event aggregate",
                exit_code=ExitCode.CORRUPTION,
                task_id=task_id,
                details={"paths": drift},
            )

    def _replay_entity_target(
        self,
        task_id: str,
        directory: str,
        entity_id: str,
        entity: Mapping[str, Any],
    ) -> Path:
        """Validate an Event-derived entity before it can influence a path."""

        prefix = _ENTITY_ID_PREFIXES.get(directory)
        schema = _ENTITY_SCHEMAS.get(directory)
        if prefix is None or schema is None or not is_identifier(entity_id, prefix):
            raise MacError(
                "EVENT_ENTITY_ID_INVALID",
                "Event entity id is not valid for its projection directory",
                exit_code=ExitCode.CORRUPTION,
                task_id=task_id,
                details={"directory": directory, "entity_id": entity_id},
            )
        if str(entity.get("id", "")) != entity_id or str(entity.get("task_id", "")) != task_id:
            raise MacError(
                "EVENT_ENTITY_BINDING_INVALID",
                "Event entity snapshot does not bind its Task and projection id",
                exit_code=ExitCode.CORRUPTION,
                task_id=task_id,
                details={"directory": directory, "entity_id": entity_id},
            )
        issues = SchemaSet().validate(dict(entity), schema[1], path=f"events/*/{directory}/{entity_id}")
        if issues:
            raise MacError(
                "EVENT_ENTITY_SCHEMA_INVALID",
                issues[0].message,
                exit_code=ExitCode.CORRUPTION,
                task_id=task_id,
                details={"issues": [issue.as_dict() for issue in issues]},
            )
        extension = schema[0]
        task_root = self.task_dir(task_id).resolve(strict=False)
        directory_root = (task_root / directory).resolve(strict=False)
        target = directory_root / f"{entity_id}.{extension}"
        try:
            directory_root.relative_to(task_root)
            target.resolve(strict=False).relative_to(directory_root)
        except ValueError as exc:
            raise MacError(
                "EVENT_ENTITY_PATH_INVALID",
                "Event entity projection target escapes its Task directory",
                exit_code=ExitCode.CORRUPTION,
                task_id=task_id,
            ) from exc
        return target

    def rebuild_task(self, task_id: str) -> dict[str, Any]:
        _require_store_permit(None, task_id=task_id)
        raise AssertionError("unreachable")

    def _materialize_replayed_task(
        self,
        task_id: str,
        *,
        events: list[dict[str, Any]] | None = None,
        _permit: object,
    ) -> dict[str, Any]:
        _require_store_permit(_permit, task_id=task_id)
        source_events = events if events is not None else self.list_events(task_id)
        projection, snapshots = self._replayed_state(task_id, events=source_events)
        validated_entities: list[tuple[Path, Mapping[str, Any]]] = []
        for directory, entities in snapshots.items():
            for entity_id, entity in entities.items():
                target = self._replay_entity_target(task_id, directory, entity_id, entity)
                validated_entities.append((target, entity))
        current_scope, scope_history = self._replayed_scope(task_id, events=source_events)
        scope_values = ([current_scope] if current_scope is not None else []) + list(scope_history.values())
        for scope in scope_values:
            if str(scope.get("task_id", "")) != task_id:
                raise MacError(
                    "EVENT_SCOPE_TASK_MISMATCH",
                    "Event Scope snapshot belongs to another Task",
                    exit_code=ExitCode.CORRUPTION,
                    task_id=task_id,
                )
            issues = SchemaSet().validate(dict(scope), "scope-contract.schema.json", path="events/*/scope")
            if issues:
                raise MacError(
                    "EVENT_SCOPE_SCHEMA_INVALID",
                    issues[0].message,
                    exit_code=ExitCode.CORRUPTION,
                    task_id=task_id,
                    details={"issues": [issue.as_dict() for issue in issues]},
                )
        if self.list_events(task_id) != source_events:
            raise MacError(
                "MUTATION_EVENT_STREAM_CHANGED",
                "Task Event stream changed before replay materialization",
                exit_code=ExitCode.CONFLICT,
                task_id=task_id,
            )
        atomic_write_yaml(self.task_dir(task_id) / "task.yaml", projection)
        for target, entity in validated_entities:
            writer = atomic_write_yaml if target.suffix.lower() in {".yaml", ".yml"} else atomic_write_json
            writer(target, dict(entity))
        if current_scope is not None:
            atomic_write_yaml(self.task_dir(task_id) / "scope-contract.yaml", current_scope)
        for version, scope in scope_history.items():
            atomic_write_yaml(
                self.task_dir(task_id) / "scope-history" / f"scope-contract.v{version}.yaml",
                scope,
            )
        return projection

    def _rebuild_task(
        self,
        command: Rebuild,
        *,
        _permit: object,
    ) -> MutationResult:
        _require_store_permit(_permit, task_id=command.task_id)
        command = _snapshot_command(command)
        assert isinstance(command, Rebuild)
        if command.operation != "task.rebuild":
            raise MacError("MUTATION_OPERATION_INVALID", "Rebuild requires task.rebuild authority", exit_code=ExitCode.SECURITY, task_id=command.task_id)
        lease_owner = str(command.actor_claim.get("id", "unverified"))
        with self.lease(command.task_id, lease_owner):
            events = self.list_events(command.task_id)
            task = replay_events(events)
            current = int(task["revision"])
            if current != command.expected_revision:
                raise MacError(
                    "REVISION_CONFLICT",
                    f"expected {command.expected_revision}, current {current}",
                    exit_code=ExitCode.CONFLICT,
                    task_id=command.task_id,
                )
            _validate_executable_policy_snapshot(self.repo, task, task_id=command.task_id)
            verified_authority = _verify_command_authority(self.repo, command, task)
            policy_digest, ownership_digest = _policy_digests(task)
            authority = _validate_store_authority(
                self.repo,
                verified_authority,
                operation=command.operation,
                task_id=command.task_id,
                expected_revision=command.expected_revision,
                idempotency_key=command.idempotency_key,
                intent=_rebuild_intent(command),
                policy_digest=policy_digest,
                ownership_digest=ownership_digest,
                actor_claim=command.actor_claim,
            )
            _validate_executable_policy_snapshot(self.repo, task, task_id=command.task_id)
            projection = self._materialize_replayed_task(
                command.task_id,
                events=events,
                _permit=_permit,
            )
            return MutationResult(None, projection, False, authority)

    def _existing_idempotency(
        self,
        task_id: str,
        key: str,
        *,
        events: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        source = events if events is not None else self.list_events(task_id)
        return next((event for event in source if event.get("idempotency_key") == key), None)

    @contextmanager
    def lease(self, task_id: str, owner: str, *, ttl_seconds: float = 30.0) -> Iterator[str]:
        path = self.task_dir(task_id) / "private" / "controller.lease"
        path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = path.with_suffix(".lock")
        token = prefixed("LEASE")
        payload = {"token": token, "owner": owner, "acquired_at": utc_now(), "expires_unix": time.time() + ttl_seconds}
        if ttl_seconds <= 0:
            raise ValueError("lease ttl must be positive")
        lock_handle = lock_path.open("a+b")
        acquired_lock = False
        wrote_lease = False
        try:
            lock_handle.seek(0, os.SEEK_END)
            if lock_handle.tell() == 0:
                lock_handle.write(b"\0")
                lock_handle.flush()
                os.fsync(lock_handle.fileno())
            lock_handle.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(lock_handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired_lock = True
            except (OSError, BlockingIOError) as exc:
                raise MacError(
                    "LEASE_CONFLICT",
                    "task controller lease is held by another process",
                    exit_code=ExitCode.CONFLICT,
                    task_id=task_id,
                ) from exc
            if path.is_file():
                try:
                    current = json.loads(path.read_text(encoding="utf-8"))
                    expired = float(current.get("expires_unix", 0)) <= time.time()
                except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise MacError(
                        "LEASE_CORRUPT",
                        "controller lease cannot be parsed safely",
                        exit_code=ExitCode.CORRUPTION,
                        task_id=task_id,
                    ) from exc
                if not expired:
                    raise MacError(
                        "LEASE_CONFLICT",
                        "task controller lease is active",
                        exit_code=ExitCode.CONFLICT,
                        task_id=task_id,
                    )
            atomic_write_json(path, payload)
            wrote_lease = True
            yield token
        finally:
            if acquired_lock and wrote_lease:
                try:
                    current = json.loads(path.read_text(encoding="utf-8"))
                    if current.get("token") == token:
                        path.unlink()
                except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
                    pass
            if acquired_lock:
                lock_handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(lock_handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            lock_handle.close()

    @contextmanager
    def _creation_lease(self) -> Iterator[None]:
        """Serialize repository-wide Task idempotency and directory creation."""

        self.tasks_root.mkdir(parents=True, exist_ok=True)
        lock_path = self.tasks_root / ".task-create.lock"
        lock_handle = lock_path.open("a+b")
        acquired = False
        try:
            lock_handle.seek(0, os.SEEK_END)
            if lock_handle.tell() == 0:
                lock_handle.write(b"\0")
                lock_handle.flush()
                os.fsync(lock_handle.fileno())
            lock_handle.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(lock_handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except (OSError, BlockingIOError) as exc:
                raise MacError(
                    "LEASE_CONFLICT",
                    "repository Task creation lease is held by another process",
                    exit_code=ExitCode.CONFLICT,
                ) from exc
            yield
        finally:
            if acquired:
                lock_handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(lock_handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            lock_handle.close()
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass

    def create_task(
        self, task: dict[str, Any], *, actor: dict[str, Any], idempotency_key: str,
        initial_entities: list[tuple[str, dict[str, Any]]] | None = None,
        authority: Mapping[str, Any] | None = None,
    ) -> AppendResult:
        _require_store_permit(None, task_id=str(task.get("id", "")) or None)
        raise AssertionError("unreachable")

    def _create_task(
        self,
        command: CreateTask,
        *,
        _permit: object,
    ) -> MutationResult:
        _require_store_permit(_permit)
        command = _snapshot_command(command)
        assert isinstance(command, CreateTask)
        task = deepcopy(dict(command.task))
        task_id = str(task["id"])
        _validate_create_materializations(command)
        if command.operation != "task.create":
            raise MacError("MUTATION_OPERATION_INVALID", "CreateTask requires task.create authority", exit_code=ExitCode.SECURITY, task_id=task_id)
        with self._creation_lease():
            found = self.find_idempotency(command.idempotency_key)
            if found is not None:
                existing_task_id, existing = found
                created_task = dict((existing.get("payload") or {}).get("task") or {})
                _validate_executable_policy_snapshot(self.repo, created_task, task_id=existing_task_id)
                verified = _verify_command_authority(self.repo, command, created_task, existing=existing)
                audit = _validate_replay_authority(self.repo, command, existing, verified)
                stored = AppendResult(dict(existing), replay_events(self.list_events(existing_task_id)), True)
                return _stored_mutation_result(stored, audit)

            directory = self.task_dir(task_id)
            if directory.exists():
                raise MacError("TASK_EXISTS", f"task {task_id} already exists", exit_code=ExitCode.CONFLICT)
            _validate_executable_policy_snapshot(self.repo, task, task_id=task_id)
            verified = _verify_command_authority(self.repo, command, task)
            policy_digest, ownership_digest = _policy_digests(task)
            authority = _validate_store_authority(
                self.repo,
                verified,
                operation=command.operation,
                task_id=task_id,
                expected_revision=-1,
                idempotency_key=command.idempotency_key,
                intent=_create_intent(command),
                policy_digest=policy_digest,
                ownership_digest=ownership_digest,
                actor_claim=command.actor_claim,
            )
            initial_scope = dict(command.initial_entities[0][1])
            if initial_scope.get("proposed_by") != verified.actor_id:
                raise MacError(
                    "MUTATION_ENTITY_ACTOR_MISMATCH",
                    "initial Scope proposer must equal the verified mutation actor",
                    exit_code=ExitCode.SECURITY,
                    task_id=task_id,
                )
            actor = {"id": verified.actor_id, "kind": verified.actor_kind}
            event = {
                "schema_version": 1, "event_id": _derived_event_id(authority), "task_id": task_id,
                "event_type": "task_created", "occurred_at": verified.issued_at, "actor": actor, "run_id": None,
                "expected_revision": -1, "new_revision": 0, "idempotency_key": command.idempotency_key,
                "payload": {
                    "task": deepcopy(task),
                    "scope": deepcopy(initial_scope),
                    "authority": deepcopy(dict(authority)),
                },
            }
            _validate_executable_policy_snapshot(self.repo, task, task_id=task_id)
            projection = replay_events([event])
            staging = self.tasks_root / f".{task_id}.{prefixed('TXN')}.tmp"
            staging.mkdir(parents=False, exist_ok=False)
            try:
                atomic_write_json(staging / "events" / f"{event['event_id']}.json", event)
                for relative, value in command.initial_entities:
                    target = staging / relative
                    resolved = target.resolve(strict=False)
                    try:
                        resolved.relative_to(staging.resolve())
                    except ValueError as exc:
                        raise MacError("ENTITY_PATH_UNSAFE", "initial entity is outside the task transaction", exit_code=ExitCode.SECURITY, path=relative) from exc
                    writer = atomic_write_yaml if target.suffix.lower() in {".yaml", ".yml"} else atomic_write_json
                    writer(target, deepcopy(dict(value)))
                atomic_write_yaml(staging / "task.yaml", projection)
                os.replace(staging, directory)
            except BaseException:
                if staging.is_dir():
                    shutil.rmtree(staging)
                raise
            return _stored_mutation_result(AppendResult(event, projection), authority)

    def _append_event_locked(
        self, task_id: str, event_type: str, payload: dict[str, Any], *, actor: dict[str, Any],
        expected_revision: int, idempotency_key: str, run_id: str | None = None,
        event_id: str | None = None,
        occurred_at: str | None = None,
        precommit_check: Callable[[], None] | None = None,
        fault_hook: Callable[[str], None] | None = None,
        materializations: list[tuple[Path, dict[str, Any]]] | None = None,
        replace_existing: set[Path] | None = None,
        verified_events: list[dict[str, Any]] | None = None,
        _permit: object,
    ) -> AppendResult:
        _require_store_permit(_permit, task_id=task_id)
        events = verified_events if verified_events is not None else self.list_events(task_id)
        if existing := self._existing_idempotency(task_id, idempotency_key, events=events):
            if existing.get("event_type") != event_type:
                raise MacError("EVENT_IDEMPOTENCY_CONFLICT", "idempotency key belongs to another operation", exit_code=ExitCode.CONFLICT, task_id=task_id)
            through_revision = int(existing.get("new_revision", 0))
            original_events = [event for event in events if int(event.get("new_revision", 0)) <= through_revision]
            self._materialize_replayed_task(task_id, events=events, _permit=_permit)
            return AppendResult(existing, replay_events(original_events), True)
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
        selected_event_id = event_id or prefixed("EVT")
        if not is_identifier(selected_event_id, "EVT"):
            raise MacError(
                "EVENT_ID_UNSAFE",
                "event id must be a valid EVT identifier",
                exit_code=ExitCode.SECURITY,
                task_id=task_id,
            )
        task_root = self.task_dir(task_id).resolve(strict=False)
        event_root = (task_root / "events").resolve(strict=False)
        event_path = event_root / f"{selected_event_id}.json"
        try:
            event_root.relative_to(task_root)
            event_path.resolve(strict=False).relative_to(event_root)
        except ValueError as exc:
            raise MacError(
                "EVENT_PATH_UNSAFE",
                "event path escapes the immutable Event directory",
                exit_code=ExitCode.SECURITY,
                task_id=task_id,
            ) from exc
        if event_path.exists():
            raise MacError(
                "EVENT_ID_CONFLICT",
                "event id already exists and immutable Events cannot be overwritten",
                exit_code=ExitCode.CONFLICT,
                task_id=task_id,
            )
        if precommit_check is None:
            raise MacError(
                "MUTATION_PRECOMMIT_CHECK_REQUIRED",
                "governed Event writes require a Store-owned precommit check",
                exit_code=ExitCode.SECURITY,
                task_id=task_id,
            )
        precommit_check()
        if self.list_events(task_id) != events:
            raise MacError(
                "MUTATION_EVENT_STREAM_CHANGED",
                "Task Event stream changed after mutation validation",
                exit_code=ExitCode.CONFLICT,
                task_id=task_id,
            )
        event = {
            "schema_version": 1, "event_id": selected_event_id, "task_id": task_id,
            "event_type": event_type, "occurred_at": occurred_at or utc_now(), "actor": actor, "run_id": run_id,
            "expected_revision": current, "new_revision": current + 1,
            "idempotency_key": idempotency_key, "payload": deepcopy(payload),
        }
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

    def append_event(
        self, task_id: str, event_type: str, payload: dict[str, Any], *, actor: dict[str, Any],
        expected_revision: int, idempotency_key: str, run_id: str | None = None,
        event_id: str | None = None,
        fault_hook: Callable[[str], None] | None = None,
        materializations: list[tuple[Path, dict[str, Any]]] | None = None,
        replace_existing: set[Path] | None = None,
    ) -> AppendResult:
        _require_store_permit(None, task_id=task_id)
        raise AssertionError("unreachable")

    def _append_event(
        self,
        command: AppendEvent,
        *,
        _permit: object,
    ) -> MutationResult:
        _require_store_permit(_permit, task_id=command.task_id)
        command = _snapshot_command(command)
        assert isinstance(command, AppendEvent)
        _validate_append_operation(command.operation, command.event_type)
        lease_owner = str(command.actor_claim.get("id", "unverified"))
        with self.lease(command.task_id, lease_owner):
            events = self.list_events(command.task_id)
            task = replay_events(events)
            _validate_executable_policy_snapshot(self.repo, task, task_id=command.task_id)
            existing = self._existing_idempotency(
                command.task_id,
                command.idempotency_key,
                events=events,
            )
            if existing is None:
                current = int(task.get("revision", -1))
                if current != command.expected_revision:
                    raise MacError(
                        "REVISION_CONFLICT",
                        f"expected {command.expected_revision}, current {current}",
                        exit_code=ExitCode.CONFLICT,
                        task_id=command.task_id,
                    )
            verified_authority = _verify_command_authority(
                self.repo,
                command,
                task,
                existing=existing,
            )
            if existing is not None:
                audit = _validate_replay_authority(
                    self.repo,
                    command,
                    existing,
                    verified_authority,
                    events=events,
                )
                through_revision = int(existing.get("new_revision", 0))
                original_events = [
                    event for event in events
                    if int(event.get("new_revision", 0)) <= through_revision
                ]
                self._materialize_replayed_task(
                    command.task_id,
                    events=events,
                    _permit=_permit,
                )
                return _stored_mutation_result(
                    AppendResult(dict(existing), replay_events(original_events), True),
                    audit,
                )
            self._require_projection_clean(command.task_id, events=events)
            policy_digest, ownership_digest = _policy_digests(task)
            authority = _validate_store_authority(
                self.repo,
                verified_authority,
                operation=command.operation,
                task_id=command.task_id,
                expected_revision=command.expected_revision,
                idempotency_key=command.idempotency_key,
                intent=_append_intent(self.repo, command),
                policy_digest=policy_digest,
                ownership_digest=ownership_digest,
                actor_claim=command.actor_claim,
            )
            current_scope, _ = self._replayed_scope(command.task_id, events=events)
            if current_scope is None:
                raise MacError(
                    "EVENT_SCOPE_MISSING",
                    "Task Event stream has no replayable Scope Contract",
                    exit_code=ExitCode.CORRUPTION,
                    task_id=command.task_id,
                )
            compiled = compile_policy(self.repo, runtime_profile_id=str(task.get("runtime_profile") or "") or None)
            _enforce_operation_independence(
                authority,
                task,
                current_scope,
                compiled.config,
                operation=command.operation,
                task_id=command.task_id,
            )
            payload, bound_materializations = _bind_entity_authority(self.repo, command, verified_authority)
            occurred_at = verified_authority.issued_at
            payload, bound_materializations, _ = _bind_run_registration_facts(
                self.repo,
                command,
                task,
                current_scope,
                payload,
                bound_materializations,
                occurred_at,
            )
            payload, bound_materializations, _ = _bind_run_finish_facts(
                self.repo,
                command,
                payload,
                bound_materializations,
                occurred_at,
            )
            payload, bound_materializations = _bind_entity_timestamps(
                self.repo,
                command,
                payload,
                bound_materializations,
                occurred_at,
            )
            bound_command = replace(command, payload=payload, materializations=tuple(bound_materializations))
            _validate_append_materializations(self.repo, bound_command)
            _validate_append_semantics(
                self.repo,
                bound_command,
                task,
                current_scope,
                compiled,
                verified_authority,
                events=events,
            )
            payload["authority"] = authority
            stored = self._append_event_locked(
                command.task_id,
                command.event_type,
                payload,
                actor={"id": verified_authority.actor_id, "kind": verified_authority.actor_kind},
                expected_revision=command.expected_revision,
                idempotency_key=command.idempotency_key,
                run_id=command.run_id,
                event_id=command.event_id or _derived_event_id(authority),
                occurred_at=occurred_at,
                precommit_check=lambda: _validate_executable_policy_snapshot(
                    self.repo,
                    task,
                    task_id=command.task_id,
                ),
                materializations=bound_materializations,
                replace_existing=set(command.replace_existing),
                verified_events=events,
                _permit=_permit,
            )
            return _stored_mutation_result(stored, authority)

    def _record_command_evidence(
        self,
        command: RecordCommandEvidence,
        *,
        _permit: object,
    ) -> MutationResult:
        _require_store_permit(_permit, task_id=command.task_id)
        command = _snapshot_command(command)
        assert isinstance(command, RecordCommandEvidence)
        if command.operation != "evidence.record":
            raise MacError(
                "MUTATION_OPERATION_INVALID",
                "RecordCommandEvidence requires evidence.record authority",
                exit_code=ExitCode.SECURITY,
                task_id=command.task_id,
            )
        lease_owner = str(command.actor_claim.get("id", "unverified"))
        with self.lease(command.task_id, lease_owner):
            events = self.list_events(command.task_id)
            task = replay_events(events)
            _validate_executable_policy_snapshot(self.repo, task, task_id=command.task_id)
            existing = self._existing_idempotency(
                command.task_id,
                command.idempotency_key,
                events=events,
            )
            if existing is None:
                current = int(task.get("revision", -1))
                if current != command.expected_revision:
                    raise MacError(
                        "REVISION_CONFLICT",
                        f"expected {command.expected_revision}, current {current}",
                        exit_code=ExitCode.CONFLICT,
                        task_id=command.task_id,
                    )
            verified = _verify_command_authority(self.repo, command, task, existing=existing)
            if existing is not None:
                audit = _validate_replay_authority(
                    self.repo,
                    command,
                    existing,
                    verified,
                    events=events,
                )
                through_revision = int(existing.get("new_revision", 0))
                original_events = [
                    event for event in events
                    if int(event.get("new_revision", 0)) <= through_revision
                ]
                self._materialize_replayed_task(
                    command.task_id,
                    events=events,
                    _permit=_permit,
                )
                evidence = (existing.get("payload") or {}).get("evidence")
                return _stored_mutation_result(
                    AppendResult(dict(existing), replay_events(original_events), True),
                    audit,
                    value=dict(evidence) if isinstance(evidence, Mapping) else None,
                )

            _reject_terminal_task(task, task_id=command.task_id)
            self._require_projection_clean(command.task_id, events=events)
            current_scope, _ = self._replayed_scope(command.task_id, events=events)
            if (
                current_scope is None
                or current_scope.get("status") != "approved"
                or str(task.get("state", "")) not in {"ready", "executing", "verifying", "repairing"}
                or "execute_tests" not in current_scope.get("allowed_operations", [])
            ):
                raise MacError(
                    "EVIDENCE_EXECUTION_NOT_AUTHORIZED",
                    "command Evidence requires an approved executable Task state and Scope",
                    exit_code=ExitCode.SECURITY,
                    task_id=command.task_id,
                )
            policy_digest, ownership_digest = _policy_digests(task)
            authority = _validate_store_authority(
                self.repo,
                verified,
                operation=command.operation,
                task_id=command.task_id,
                expected_revision=command.expected_revision,
                idempotency_key=command.idempotency_key,
                intent=_record_evidence_intent(command),
                policy_digest=policy_digest,
                ownership_digest=ownership_digest,
                actor_claim=command.actor_claim,
            )

            compiled = compile_policy(
                self.repo,
                runtime_profile_id=str(task.get("runtime_profile") or "") or None,
            )
            capabilities = compiled.runtime_profile.get("capabilities") or {}
            if capabilities.get("command_execution") is not True:
                raise MacError(
                    "EVIDENCE_COMMAND_EXECUTION_UNAVAILABLE",
                    "the frozen runtime profile cannot execute Evidence commands",
                    exit_code=ExitCode.EXTERNAL,
                    task_id=command.task_id,
                )
            if (
                str(task.get("mode", "")) in {"high_risk", "audit"}
                or capabilities.get("network_control") != "native"
                or capabilities.get("worktree") != "native"
            ):
                raise MacError(
                    "EVIDENCE_ISOLATED_EXECUTOR_REQUIRED",
                    "formal command Evidence requires an attested native isolated executor",
                    exit_code=ExitCode.EXTERNAL,
                    task_id=command.task_id,
                )
            if current_scope.get("secret_access"):
                raise MacError(
                    "EVIDENCE_SECRET_BROKER_REQUIRED",
                    "the local command runner cannot inject authorized secrets",
                    exit_code=ExitCode.SECURITY,
                    task_id=command.task_id,
                )
            if (
                current_scope.get("network_access") != "none"
                and "network" not in current_scope.get("allowed_operations", [])
            ):
                raise MacError(
                    "EVIDENCE_NETWORK_OPERATION_NOT_AUTHORIZED",
                    "networked Evidence execution requires the Scope network operation",
                    exit_code=ExitCode.SECURITY,
                    task_id=command.task_id,
                )
            network_control = str(capabilities.get("network_control", "unavailable"))
            if (
                current_scope.get("network_access") != "none"
                or str(task.get("mode", "")) in {"high_risk", "audit"}
            ) and network_control == "unavailable":
                raise MacError(
                    "EVIDENCE_NETWORK_CONTROL_UNAVAILABLE",
                    "the frozen runtime cannot enforce the Scope network policy",
                    exit_code=ExitCode.EXTERNAL,
                    task_id=command.task_id,
                )
            snapshots = replay_entity_snapshots(events)
            approvals = list(snapshots["approvals"].values())
            valid_approvals = valid_scope_approvals(
                task,
                current_scope,
                approvals,
                compiled.ownership,
                compiled.config,
            )
            git = GitRepository(self.repo)
            if command.commit and not git.workspace_equivalent_to_commit("HEAD", task_id=command.task_id):
                raise MacError(
                    "EVIDENCE_COMMIT_WORKSPACE_DIRTY",
                    "commit evidence requires a workspace exactly equivalent to HEAD",
                    exit_code=ExitCode.EVIDENCE,
                    task_id=command.task_id,
                )
            run_id, started = prefixed("RUN"), utc_now()
            safe_environment = {
                "APPDATA", "COMSPEC", "HOME", "LANG", "LOCALAPPDATA", "PATH", "PATHEXT",
                "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "PYTHONIOENCODING",
                "PYTHONPATH", "PYTHONUTF8", "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "TMP",
                "USERPROFILE", "VIRTUAL_ENV", "WINDIR",
            }
            command_env = {
                key: value
                for key, value in os.environ.items()
                if key.upper() in safe_environment or key.upper().startswith("LC_")
            }
            timeout_seconds = int((compiled.runtime_profile.get("limits") or {}).get("default_timeout_seconds", 3600))
            try:
                completed = subprocess.run(
                    list(command.argv),
                    cwd=self.repo,
                    shell=False,
                    env=command_env,
                    timeout=timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                raise MacError(
                    "EVIDENCE_COMMAND_TIMEOUT",
                    "Evidence command exceeded the frozen runtime timeout",
                    exit_code=ExitCode.EXTERNAL,
                    task_id=command.task_id,
                ) from exc
            finished = utc_now()
            if self.list_events(command.task_id) != events:
                raise MacError(
                    "REVISION_CONFLICT",
                    "Task Event stream changed while the Evidence command was running",
                    exit_code=ExitCode.CONFLICT,
                    task_id=command.task_id,
                )
            _validate_executable_policy_snapshot(self.repo, task, task_id=command.task_id)
            if command.commit and not git.workspace_equivalent_to_commit("HEAD", task_id=command.task_id):
                raise MacError(
                    "EVIDENCE_COMMAND_CHANGED_WORKSPACE",
                    "command changed the workspace; commit evidence cannot bind HEAD",
                    exit_code=ExitCode.EVIDENCE,
                    task_id=command.task_id,
                )
            scope_result = check_changes(
                git.changes_since(current_scope.get("base_commit"), task_id=command.task_id),
                current_scope,
                ownership=compiled.ownership,
                repo_root=self.repo,
                task_id=command.task_id,
                governance_approval_level=max(
                    (str(item.get("independence_level", "L0")) for item in valid_approvals),
                    default=None,
                ),
                submodule_approved=any(
                    "submodule_change" in str(item.get("comment", ""))
                    for item in valid_approvals
                ),
            )
            if scope_result.issues:
                raise MacError(
                    "EVIDENCE_COMMAND_SCOPE_VIOLATION",
                    "Evidence command left repository changes outside the approved Scope",
                    exit_code=ExitCode.SCOPE,
                    task_id=command.task_id,
                    details={"issues": [issue.as_dict() for issue in scope_result.issues]},
                )
            subject = git.current_code_subject(command.task_id) if command.commit else git.workspace_subject(task_id=command.task_id)

            def evidence_precommit() -> None:
                _validate_executable_policy_snapshot(self.repo, task, task_id=command.task_id)
                if self.list_events(command.task_id) != events:
                    raise MacError(
                        "REVISION_CONFLICT",
                        "Task Event stream changed before Evidence commit",
                        exit_code=ExitCode.CONFLICT,
                        task_id=command.task_id,
                    )
                self._require_projection_clean(command.task_id, events=events)
                current_subject = (
                    git.current_code_subject(command.task_id)
                    if command.commit
                    else git.workspace_subject(task_id=command.task_id)
                )
                if current_subject != subject:
                    raise MacError(
                        "EVIDENCE_SUBJECT_CHANGED",
                        "repository subject changed after Evidence verification",
                        exit_code=ExitCode.EVIDENCE,
                        task_id=command.task_id,
                    )
                final_scope_result = check_changes(
                    git.changes_since(current_scope.get("base_commit"), task_id=command.task_id),
                    current_scope,
                    ownership=compiled.ownership,
                    repo_root=self.repo,
                    task_id=command.task_id,
                    governance_approval_level=max(
                        (str(item.get("independence_level", "L0")) for item in valid_approvals),
                        default=None,
                    ),
                    submodule_approved=any(
                        "submodule_change" in str(item.get("comment", ""))
                        for item in valid_approvals
                    ),
                )
                if final_scope_result.issues:
                    raise MacError(
                        "EVIDENCE_COMMAND_SCOPE_VIOLATION",
                        "repository changes no longer satisfy the approved Scope",
                        exit_code=ExitCode.SCOPE,
                        task_id=command.task_id,
                        details={"issues": [issue.as_dict() for issue in final_scope_result.issues]},
                    )
            actor = {"id": verified.actor_id, "kind": verified.actor_kind}
            run = {
                "schema_version": 1,
                "id": run_id,
                "task_id": command.task_id,
                "work_unit_id": "verification",
                "status": "succeeded" if completed.returncode == 0 else "failed",
                "actor": actor,
                "runtime": {"profile": "local-command", "execution_context_id": run_id},
                "independence_level": verified.independence_level,
                "started_at": started,
                "finished_at": finished,
                "exit_code": completed.returncode,
            }
            evidence = {
                "schema_version": 1,
                "id": prefixed("EVD"),
                "task_id": command.task_id,
                "kind": "command",
                "subject": subject,
                "policy_digest": task["policy_ref"]["combined_digest"],
                "run_id": run_id,
                "claims": [{"gate": command.claim}],
                "execution": {"argv": list(command.argv), "exit_code": completed.returncode, "started_at": started, "finished_at": finished},
                "environment": {"os": platform.system().lower(), "architecture": platform.machine(), "tool_versions": {"python": platform.python_version()}},
                "artifacts": [],
                "recorded_at": finished,
                "validity": {"status": "valid" if completed.returncode == 0 else "invalid", "invalidated_by": []},
            }
            schema_set = SchemaSet()
            issues = [
                *schema_set.validate(run, "run.schema.json", path="run"),
                *schema_set.validate(evidence, "evidence.schema.json", path="evidence"),
            ]
            if issues:
                raise MacError(
                    issues[0].code,
                    issues[0].message,
                    exit_code=ExitCode.VALIDATION,
                    task_id=command.task_id,
                    details={"issues": [issue.as_dict() for issue in issues]},
                )
            final_intent = _record_evidence_final_intent(command, evidence, run)
            final_verified = _verify_exact_intent_authority(
                self.repo,
                command,
                task,
                final_intent,
            )
            if (
                final_verified.actor_id != verified.actor_id
                or final_verified.actor_kind != verified.actor_kind
                or final_verified.independence_level != verified.independence_level
            ):
                raise MacError(
                    "EVIDENCE_FINAL_AUTHORITY_DOWNGRADE",
                    "post-execution Evidence authority does not preserve the execution authority",
                    exit_code=ExitCode.SECURITY,
                    task_id=command.task_id,
                )
            authority = _validate_store_authority(
                self.repo,
                final_verified,
                operation=command.operation,
                task_id=command.task_id,
                expected_revision=command.expected_revision,
                idempotency_key=command.idempotency_key,
                intent=final_intent,
                policy_digest=policy_digest,
                ownership_digest=ownership_digest,
                actor_claim=command.actor_claim,
            )
            lowered = AppendEvent(
                task_id=command.task_id,
                event_type="evidence_recorded",
                payload={"evidence_id": evidence["id"], "evidence": evidence, "run": run},
                actor_claim=command.actor_claim,
                expected_revision=command.expected_revision,
                idempotency_key=command.idempotency_key,
                operation=command.operation,
                run_id=run_id,
                materializations=(
                    (self.task_dir(command.task_id) / "runs" / f"{run_id}.json", run),
                    (self.task_dir(command.task_id) / "evidence" / f"{evidence['id']}.json", evidence),
                ),
                minimum_independence=command.minimum_independence,
                replay_intent=command.replay_intent,
            )
            _validate_append_operation(command.operation, lowered.event_type)
            _validate_append_materializations(self.repo, lowered)
            payload, bound_materializations = _bind_entity_authority(self.repo, lowered, final_verified)
            bound_lowered = replace(lowered, payload=payload, materializations=tuple(bound_materializations))
            _validate_append_materializations(self.repo, bound_lowered)
            payload["authority"] = authority
            stored = self._append_event_locked(
                command.task_id,
                lowered.event_type,
                payload,
                actor=actor,
                expected_revision=command.expected_revision,
                idempotency_key=command.idempotency_key,
                run_id=lowered.run_id,
                event_id=_derived_event_id(authority),
                occurred_at=final_verified.issued_at,
                precommit_check=evidence_precommit,
                materializations=bound_materializations,
                replace_existing=set(lowered.replace_existing),
                verified_events=events,
                _permit=_permit,
            )
            return _stored_mutation_result(stored, authority, value=evidence)

    def _submit_result(
        self,
        command: SubmitResult,
        *,
        _permit: object,
    ) -> MutationResult:
        """Validate Result intake under the Task lease and derive all writes."""

        _require_store_permit(_permit, task_id=command.task_id)
        command = _snapshot_command(command)
        assert isinstance(command, SubmitResult)
        if command.operation != "result.submit":
            raise MacError(
                "MUTATION_OPERATION_INVALID",
                "SubmitResult requires result.submit authority",
                exit_code=ExitCode.SECURITY,
                task_id=command.task_id,
            )
        lease_owner = str(command.actor_claim.get("id", "unverified"))
        with self.lease(command.task_id, lease_owner):
            events = self.list_events(command.task_id)
            task = replay_events(events)
            _validate_executable_policy_snapshot(self.repo, task, task_id=command.task_id)
            existing = self._existing_idempotency(
                command.task_id,
                command.idempotency_key,
                events=events,
            )
            verified_authority = _verify_command_authority(
                self.repo,
                command,
                task,
                existing=existing,
            )
            if existing is not None:
                audit = _validate_replay_authority(
                    self.repo,
                    command,
                    existing,
                    verified_authority,
                    events=events,
                )
                through_revision = int(existing.get("new_revision", 0))
                original_events = [
                    event for event in events
                    if int(event.get("new_revision", 0)) <= through_revision
                ]
                self._materialize_replayed_task(
                    command.task_id,
                    events=events,
                    _permit=_permit,
                )
                stored_result = (existing.get("payload") or {}).get("result")
                return _stored_mutation_result(
                    AppendResult(dict(existing), replay_events(original_events), True),
                    audit,
                    value=dict(stored_result) if isinstance(stored_result, Mapping) else None,
                )
            _reject_terminal_task(task, task_id=command.task_id)
            self._require_projection_clean(command.task_id, events=events)
            if str(task.get("state", "")) not in {"ready", "executing", "repairing"}:
                raise MacError(
                    "RESULT_TASK_STATE_INVALID",
                    "Result submission requires a ready, executing, or repairing Task",
                    exit_code=ExitCode.SECURITY,
                    task_id=command.task_id,
                )
            current = int(task.get("revision", -1))
            if current != command.expected_revision:
                raise MacError(
                    "REVISION_CONFLICT",
                    f"expected {command.expected_revision}, current {current}",
                    exit_code=ExitCode.CONFLICT,
                    task_id=command.task_id,
                )
            policy_digest, ownership_digest = _policy_digests(task)
            authority = _validate_store_authority(
                self.repo,
                verified_authority,
                operation=command.operation,
                task_id=command.task_id,
                expected_revision=command.expected_revision,
                idempotency_key=command.idempotency_key,
                intent=_submit_result_intent(command),
                policy_digest=policy_digest,
                ownership_digest=ownership_digest,
                actor_claim=command.actor_claim,
            )

            from .result import prepare_result_submission_locked

            compiled = compile_policy(
                self.repo,
                runtime_profile_id=str(task.get("runtime_profile") or "") or None,
            )
            occurred_at = verified_authority.issued_at
            plan = prepare_result_submission_locked(
                repo=self.repo,
                repository=self,
                task=task,
                events=events,
                result=dict(command.result),
                intake_proof=dict(command.intake_proof) if command.intake_proof is not None else None,
                verified_actor={"id": verified_authority.actor_id, "kind": verified_authority.actor_kind},
                verified_independence=verified_authority.independence_level,
                committed_at=occurred_at,
                policy_config=compiled.config,
                policy_ownership=compiled.ownership,
            )
            def result_precommit() -> None:
                _validate_executable_policy_snapshot(self.repo, task, task_id=command.task_id)
                for git_root, expected_subject in (
                    (self.repo, plan.task_subject),
                    (plan.run_root, plan.run_subject),
                ):
                    git = GitRepository(git_root)
                    workspace_changes = git.workspace_changes(task_id=command.task_id)
                    current_subject = (
                        git.workspace_subject(task_id=command.task_id)
                        if workspace_changes
                        else git.current_code_subject(command.task_id)
                    )
                    if current_subject != expected_subject:
                        raise MacError(
                            "RESULT_WORKTREE_CHANGED_DURING_INTAKE",
                            "repository worktree changed before Result event commit",
                            exit_code=ExitCode.SECURITY,
                            task_id=command.task_id,
                        )

            result_precommit()
            task_dir = self.task_dir(command.task_id)
            work_unit_path = task_dir / "work-units" / f"{plan.work_unit['id']}.yaml"
            run_path = task_dir / "runs" / f"{plan.run['id']}.json"
            result_path = task_dir / "results" / f"{plan.result['id']}.json"
            payload = {**plan.payload, "authority": authority}
            stored = self._append_event_locked(
                command.task_id,
                "result_submitted",
                payload,
                actor={"id": verified_authority.actor_id, "kind": verified_authority.actor_kind},
                expected_revision=command.expected_revision,
                idempotency_key=command.idempotency_key,
                run_id=str(plan.run["id"]),
                event_id=_derived_event_id(authority),
                occurred_at=occurred_at,
                precommit_check=result_precommit,
                materializations=[
                    (work_unit_path, plan.work_unit),
                    (run_path, plan.run),
                    (result_path, plan.result),
                ],
                replace_existing={work_unit_path, run_path},
                verified_events=events,
                _permit=_permit,
            )
            return _stored_mutation_result(stored, authority, value=plan.result)

    def transition(
        self, task_id: str, target: str, context: TransitionContext, *, actor: dict[str, Any],
        expected_revision: int, idempotency_key: str,
        transition_metadata: Mapping[str, Any] | None = None,
    ) -> AppendResult:
        _require_store_permit(None, task_id=task_id)
        raise AssertionError("unreachable")

    def _transition(
        self,
        command: Transition,
        *,
        _permit: object,
    ) -> MutationResult:
        _require_store_permit(_permit, task_id=command.task_id)
        command = _snapshot_command(command)
        assert isinstance(command, Transition)
        _validate_transition_operation(command.operation, command.target)
        frozen_metadata = _without_authority(command.transition_metadata or {})
        lease_owner = str(command.actor_claim.get("id", "unverified"))
        with self.lease(command.task_id, lease_owner):
            events = self.list_events(command.task_id)
            task = replay_events(events)
            _validate_executable_policy_snapshot(self.repo, task, task_id=command.task_id)
            existing = self._existing_idempotency(
                command.task_id,
                command.idempotency_key,
                events=events,
            )
            if existing is None:
                current = int(task.get("revision", -1))
                if current != command.expected_revision:
                    raise MacError(
                        "REVISION_CONFLICT",
                        f"expected {command.expected_revision}, current {current}",
                        exit_code=ExitCode.CONFLICT,
                        task_id=command.task_id,
                    )
            verified_authority = _verify_command_authority(
                self.repo,
                command,
                task,
                existing=existing,
            )
            if existing is not None:
                audit = _validate_replay_authority(
                    self.repo,
                    command,
                    existing,
                    verified_authority,
                    events=events,
                )
                through_revision = int(existing.get("new_revision", 0))
                original_events = [
                    event for event in events
                    if int(event.get("new_revision", 0)) <= through_revision
                ]
                self._materialize_replayed_task(
                    command.task_id,
                    events=events,
                    _permit=_permit,
                )
                return _stored_mutation_result(
                    AppendResult(dict(existing), replay_events(original_events), True),
                    audit,
                )
            self._require_projection_clean(command.task_id, events=events)
            policy_digest, ownership_digest = _policy_digests(task)
            authority = _validate_store_authority(
                self.repo,
                verified_authority,
                operation=command.operation,
                task_id=command.task_id,
                expected_revision=command.expected_revision,
                idempotency_key=command.idempotency_key,
                intent=_transition_intent(command),
                policy_digest=policy_digest,
                ownership_digest=ownership_digest,
                actor_claim=command.actor_claim,
            )
            current_scope, _ = self._replayed_scope(command.task_id, events=events)
            if current_scope is None:
                raise MacError(
                    "EVENT_SCOPE_MISSING",
                    "Task Event stream has no replayable Scope Contract",
                    exit_code=ExitCode.CORRUPTION,
                    task_id=command.task_id,
                )
            compiled = compile_policy(self.repo, runtime_profile_id=str(task.get("runtime_profile") or "") or None)
            if command.target == "repairing":
                _assess_repair_round(
                    events,
                    compiled.config,
                    actor_kind=verified_authority.actor_kind,
                    task_id=command.task_id,
                )
            _enforce_operation_independence(
                authority,
                task,
                current_scope,
                compiled.config,
                operation=command.operation,
                task_id=command.task_id,
            )
            unexpected_metadata = set(frozen_metadata) - {"transition_fact"}
            if unexpected_metadata:
                raise MacError(
                    "AUTHORITY_TRANSITION_METADATA_INVALID",
                    "transition metadata contains fields outside the machine-validated contract",
                    exit_code=ExitCode.SECURITY,
                    task_id=command.task_id,
                )
            transition_fact = frozen_metadata.get("transition_fact")
            canonical_context = resolve_transition_context(
                self.repo,
                command.task_id,
                command.target,
                {"id": verified_authority.actor_id, "kind": verified_authority.actor_kind},
                transition_fact if isinstance(transition_fact, Mapping) else None,
                successor_task_id=command.context.successor_task_id,
                verified_events=events,
            )
            if asdict(command.context) != asdict(canonical_context):
                raise MacError(
                    "AUTHORITY_CONTEXT_INVALID",
                    "caller transition context does not match repository-derived facts",
                    exit_code=ExitCode.SECURITY,
                    task_id=command.task_id,
                )
            frozen_metadata["authority"] = authority
            leased_context = replace(canonical_context, controller_lease_valid=True, lease_valid=True)
            decision = evaluate_transition(
                str(task["state"]),
                command.target,
                leased_context,
                transitions=compiled.transitions,
                states=compiled.states,
                terminal_states=compiled.terminal_states,
            )
            if not decision.ok:
                raise MacError(decision.codes[0], f"{task['state']} -> {command.target} rejected", exit_code=ExitCode.TRANSITION, details={"failed_guards": decision.failed_guards, "failed_conditions": decision.failed_conditions})
            payload: dict[str, Any] = {"from": task["state"], "to": command.target, "transition_id": decision.transition.id if decision.transition else None}
            payload["terminal_state"] = command.target in compiled.terminal_states
            if frozen_metadata is not None:
                payload["transition_metadata"] = frozen_metadata
            if command.context.successor_task_id:
                payload["successor_task_id"] = command.context.successor_task_id
            stored = self._append_event_locked(
                command.task_id, "state_transitioned", payload,
                actor={"id": verified_authority.actor_id, "kind": verified_authority.actor_kind},
                expected_revision=command.expected_revision, idempotency_key=command.idempotency_key,
                event_id=_derived_event_id(authority),
                occurred_at=verified_authority.issued_at,
                precommit_check=lambda: _validate_executable_policy_snapshot(
                    self.repo,
                    task,
                    task_id=command.task_id,
                ),
                verified_events=events,
                _permit=_permit,
            )
            return _stored_mutation_result(stored, authority)

    def _execute_governed(self, command: MutationCommand, *, _permit: object) -> MutationResult:
        """Closed Store dispatcher; each branch verifies authority inside its lease."""

        _require_store_permit(_permit)
        if type(command) not in {CreateTask, AppendEvent, Transition, Rebuild, RecordCommandEvidence, SubmitResult}:
            raise MacError(
                "MUTATION_COMMAND_UNSUPPORTED",
                "MutationGateway accepts only closed typed commands",
                exit_code=ExitCode.SECURITY,
            )
        command = _snapshot_command(command)
        if isinstance(command, CreateTask):
            _validate_create_materializations(command)
            return self._create_task(command, _permit=_permit)
        if isinstance(command, AppendEvent):
            if command.operation == "evidence.record":
                raise MacError(
                    "MUTATION_DEDICATED_COMMAND_REQUIRED",
                    "evidence.record must use RecordCommandEvidence",
                    exit_code=ExitCode.SECURITY,
                    task_id=command.task_id,
                )
            _validate_append_operation(command.operation, command.event_type)
            return self._append_event(command, _permit=_permit)
        if isinstance(command, Transition):
            _validate_transition_operation(command.operation, command.target)
            return self._transition(command, _permit=_permit)
        if isinstance(command, RecordCommandEvidence):
            return self._record_command_evidence(command, _permit=_permit)
        if isinstance(command, SubmitResult):
            return self._submit_result(command, _permit=_permit)
        return self._rebuild_task(command, _permit=_permit)


class MutationGateway:
    """The sole public Interface for governed persistent repository mutation."""

    def __init__(
        self,
        repo: Path,
        *,
        repository: FilesystemTaskRepository | None = None,
    ) -> None:
        self.repo = repo.resolve()
        self.repository = repository or FilesystemTaskRepository(self.repo)

    def execute(self, command: MutationCommand) -> MutationResult:
        return _GOVERNED_STORE_EXECUTE(self.repository, command)


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
    try:
        events = FilesystemTaskRepository(repo).list_events(task_dir.name)
    except MacError as exc:
        issues.append(MacIssue(
            exc.code,
            str(exc),
            exc.issue.path or f"{relative}/events",
            exc.issue.field,
            exc.issue.severity,
            exc.issue.suggestion,
            exc.issue.task_id or str(task.get("id", "")) or None,
            exc.issue.details,
        ))
        return issues
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
