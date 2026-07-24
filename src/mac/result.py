from __future__ import annotations

import json
import hashlib
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from .errors import ExitCode, MacError, MacIssue
from .authority import level_at_least, valid_scope_approvals
from .events import replay_entity_snapshots, replay_scope_snapshots
from .git import GitRepository
from .ids import is_identifier
from .io import load_data
from .repository import FilesystemTaskRepository, MutationGateway, SubmitResult, sha256_bytes
from .schema_validation import SchemaSet
from .scope import Change, check_changes, normalize_repo_path
from .security import validate_result_security


RESULT_INTAKE_CHECKS = frozenset({"run_baseline_bound", "worktree_identity_bound", "diff_recomputed", "paths_exact"})


@dataclass(frozen=True, slots=True)
class ResultIntakeProof:
    task_id: str
    work_unit_id: str
    run_id: str
    baseline_subject: dict[str, Any]
    worktree_identity: dict[str, Any]
    result_subject: dict[str, Any]
    changes: list[dict[str, Any]]
    checks: dict[str, bool]
    verifier: str
    digest: str

    @staticmethod
    def _digest(payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    @classmethod
    def verified(cls, **values: Any) -> "ResultIntakeProof":
        payload = {
            "task_id": str(values["task_id"]),
            "work_unit_id": str(values["work_unit_id"]),
            "run_id": str(values["run_id"]),
            "baseline_subject": dict(values["baseline_subject"]),
            "worktree_identity": dict(values["worktree_identity"]),
            "result_subject": dict(values["result_subject"]),
            "changes": [dict(change) for change in values["changes"]],
            "checks": dict(values["checks"]),
            "verifier": str(values["verifier"]),
        }
        return cls(**payload, digest=cls._digest(payload))

    def _payload(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "work_unit_id": self.work_unit_id,
            "run_id": self.run_id,
            "baseline_subject": self.baseline_subject,
            "worktree_identity": self.worktree_identity,
            "result_subject": self.result_subject,
            "changes": self.changes,
            "checks": self.checks,
            "verifier": self.verifier,
        }

    def as_dict(self) -> dict[str, Any]:
        return {**deepcopy(self._payload()), "digest": self.digest}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ResultIntakeProof":
        expected = {
            "task_id", "work_unit_id", "run_id", "baseline_subject",
            "worktree_identity", "result_subject", "changes", "checks",
            "verifier", "digest",
        }
        if set(value) != expected:
            raise ValueError("Result intake proof fields are invalid")
        return cls(
            task_id=str(value["task_id"]),
            work_unit_id=str(value["work_unit_id"]),
            run_id=str(value["run_id"]),
            baseline_subject=dict(value["baseline_subject"]),
            worktree_identity=dict(value["worktree_identity"]),
            result_subject=dict(value["result_subject"]),
            changes=[dict(change) for change in value["changes"]],
            checks={str(key): bool(item) for key, item in dict(value["checks"]).items()},
            verifier=str(value["verifier"]),
            digest=str(value["digest"]),
        )

    def valid(self) -> bool:
        try:
            for change in self.changes:
                if change.get("operation") not in {"add", "modify", "delete", "rename", "copy"}:
                    return False
                normalize_repo_path(str(change["path"]))
                if change.get("old_path"):
                    normalize_repo_path(str(change["old_path"]))
        except (KeyError, TypeError, ValueError):
            return False
        return (
            bool(self.verifier)
            and RESULT_INTAKE_CHECKS.issubset(self.checks)
            and all(self.checks[name] is True for name in RESULT_INTAKE_CHECKS)
            and self.digest == self._digest(self._payload())
        )

    def changed_paths(self) -> set[str]:
        return {
            normalize_repo_path(str(path))
            for change in self.changes
            for path in (change.get("old_path"), change.get("path"))
            if path
        }

    def binds(self, result: dict[str, Any]) -> bool:
        return (
            self.task_id == result.get("task_id")
            and self.work_unit_id == result.get("work_unit_id")
            and self.run_id == result.get("run_id")
            and self.changed_paths() == {normalize_repo_path(str(path)) for path in result.get("changed_files", [])}
        )

    def scope_changes(self) -> list[Change]:
        return [
            Change(
                operation=str(value["operation"]),
                path=normalize_repo_path(str(value["path"])),
                old_path=normalize_repo_path(str(value["old_path"])) if value.get("old_path") else None,
                submodule=bool(value.get("submodule", False)),
            )
            for value in self.changes
        ]


@dataclass(frozen=True, slots=True)
class ResultSubmissionPlan:
    result: dict[str, Any]
    run: dict[str, Any]
    work_unit: dict[str, Any]
    payload: dict[str, Any]
    run_root: Path
    run_subject: dict[str, Any]
    task_subject: dict[str, Any]


def _current_scope_from_events(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    current, _ = replay_scope_snapshots(events)
    if current is not None:
        return current
    for event in sorted(events, key=lambda item: int(item.get("new_revision", -1)), reverse=True):
        candidate = (event.get("payload") or {}).get("scope")
        if isinstance(candidate, dict):
            return deepcopy(candidate)
    return None


def prepare_result_submission_locked(
    *,
    repo: Path,
    repository: FilesystemTaskRepository,
    task: Mapping[str, Any],
    events: list[dict[str, Any]],
    result: dict[str, Any],
    intake_proof: dict[str, Any] | None,
    verified_actor: Mapping[str, str],
    verified_independence: str,
    committed_at: str,
    policy_config: Mapping[str, Any] | None = None,
    policy_ownership: Mapping[str, Any] | None = None,
) -> ResultSubmissionPlan:
    """Revalidate Result intake from event/Git facts while the Task lease is held."""

    task_id = str(task.get("id", ""))
    issues = SchemaSet().validate(result, "result.schema.json", path="result")
    issues.extend(validate_result_security(result))
    scope_issues: list[MacIssue] = []
    if result.get("task_id") != task_id:
        issues.append(MacIssue("RESULT_TASK_MISMATCH", "result task_id does not match target task"))

    scope = _current_scope_from_events(events)
    if not isinstance(scope, dict):
        issues.append(MacIssue("RESULT_SCOPE_MISSING", "result requires a replayable Scope Contract"))
        scope = {}
    snapshots = replay_entity_snapshots(events)
    work_unit_id = str(result.get("work_unit_id", ""))
    run_id = str(result.get("run_id", ""))
    result_id = str(result.get("id", ""))
    work_unit = snapshots["work-units"].get(work_unit_id) if is_identifier(work_unit_id, "WU") else None
    run = snapshots["runs"].get(run_id) if is_identifier(run_id, "RUN") else None
    if not is_identifier(work_unit_id, "WU"):
        issues.append(MacIssue("RESULT_WORK_UNIT_ID_UNSAFE", "result work_unit_id is not a valid WU identifier"))
    elif work_unit is None:
        issues.append(MacIssue("RESULT_WORK_UNIT_REF_MISSING", "result work_unit_id does not exist in Task events"))
    if not is_identifier(run_id, "RUN"):
        issues.append(MacIssue("RESULT_RUN_ID_UNSAFE", "result run_id is not a valid RUN identifier"))
    elif run is None:
        issues.append(MacIssue("RESULT_RUN_REF_MISSING", "result run_id does not exist in Task events"))
    if not is_identifier(result_id, "RESULT"):
        issues.append(MacIssue("RESULT_ID_UNSAFE", "result id is not a valid RESULT identifier"))
    if isinstance(work_unit, dict):
        if work_unit.get("status") != "running":
            issues.append(MacIssue("RESULT_WORK_UNIT_NOT_RUNNING", "result work unit is not running"))
        if work_unit.get("task_id") != task_id:
            issues.append(MacIssue("RESULT_WORK_UNIT_TASK_MISMATCH", "result work unit belongs to another task"))
        if str(work_unit.get("owner")) not in {str(owner) for owner in scope.get("owners", [])}:
            issues.append(MacIssue("RESULT_WORK_UNIT_OWNER_OUTSIDE", "work unit owner is not authorized by task scope"))
        expected_result = f"tasks/{task_id}/results/{result_id}.json"
        try:
            recorded_expected = normalize_repo_path(str(work_unit.get("expected_result", "")))
        except (TypeError, ValueError):
            recorded_expected = ""
        if recorded_expected != expected_result:
            issues.append(MacIssue("RESULT_EXPECTED_PATH_MISMATCH", "result id does not match the Work Unit expected_result contract"))
    if isinstance(run, dict):
        if run.get("task_id") != task_id:
            issues.append(MacIssue("RESULT_RUN_TASK_MISMATCH", "result run belongs to another task"))
        if run.get("work_unit_id") != work_unit_id:
            issues.append(MacIssue("RESULT_RUN_WORK_UNIT_MISMATCH", "result run and work unit do not match"))
        if run.get("status") not in {"registered", "running"}:
            issues.append(MacIssue("RESULT_RUN_NOT_ACTIVE", "result run is not active"))
        if dict(run.get("actor") or {}) != dict(verified_actor):
            issues.append(MacIssue("RESULT_ACTOR_MISMATCH", "Result submitter must equal the verified Run actor"))
        if not level_at_least(verified_independence, str(run.get("independence_level", "L0"))):
            issues.append(MacIssue("RESULT_INDEPENDENCE_DOWNGRADE", "Result submitter is less independent than the Run"))
        try:
            started_at = datetime.fromisoformat(str(run.get("started_at", "")).replace("Z", "+00:00"))
            store_finished_at = datetime.fromisoformat(committed_at.replace("Z", "+00:00"))
            if store_finished_at < started_at:
                issues.append(MacIssue("RESULT_RUN_TIME_INVALID", "Store commit time precedes the Run start time"))
        except ValueError:
            issues.append(MacIssue("RESULT_RUN_TIME_INVALID", "Run timestamps are invalid"))

    proof: ResultIntakeProof | None = None
    if intake_proof is not None:
        try:
            proof = ResultIntakeProof.from_mapping(intake_proof)
        except (KeyError, TypeError, ValueError):
            issues.append(MacIssue("RESULT_RUN_PROOF_INVALID", "Result intake proof is malformed"))

    try:
        config = deepcopy(dict(policy_config)) if policy_config is not None else load_data(repo / ".agents/config.yaml")
        ownership = deepcopy(dict(policy_ownership)) if policy_ownership is not None else load_data(repo / str(config["paths"]["ownership"]))
        approvals = list(snapshots["approvals"].values())
        valid_approvals = valid_scope_approvals(task, scope, approvals, ownership, config)
        run_binding_ok = False
        recomputed_changes: list[Change] | None = None
        initial_subject: dict[str, Any] | None = None
        run_root = repo
        if isinstance(run, dict):
            started = next(
                (
                    event for event in events
                    if event.get("event_type") == "run_started"
                    and str((event.get("payload") or {}).get("run_id", event.get("run_id", ""))) == run_id
                ),
                None,
            )
            started_payload = (started or {}).get("payload") or {}
            frozen_baseline = started_payload.get("baseline_subject")
            frozen_identity = started_payload.get("worktree_identity")
            runtime = run.get("runtime") or {}
            run_root = Path(str(runtime.get("worktree") or repo)).resolve()
            try:
                task_git = GitRepository(repo)
                run_git = GitRepository(run_root)
                baseline_commit = str((frozen_baseline or {}).get("commit_sha", ""))
                binding_checks = task_git.run_worktree_binding_checks(
                    run_git,
                    approved_base=str(scope.get("base_commit", "")),
                    baseline_subject=dict(frozen_baseline) if isinstance(frozen_baseline, dict) else {},
                )
                same_repository = binding_checks["same_common_dir"] and binding_checks["same_object_dir"]
                baseline_valid = (
                    binding_checks["approved_base_resolved"]
                    and binding_checks["baseline_subject_bound"]
                    and binding_checks["baseline_descends_from_approved_base"]
                )
                if not same_repository:
                    issues.append(MacIssue("RESULT_RUN_REPOSITORY_MISMATCH", "run worktree does not share the Task repository Git storage"))
                elif not baseline_valid:
                    issues.append(MacIssue("RESULT_RUN_BASELINE_INVALID", "run baseline is not bound to the approved Scope base"))
                recomputed_changes = run_git.changes_since(baseline_commit, task_id=task_id) if (frozen_baseline or {}).get("type") == "commit" else []
                workspace_changes = run_git.workspace_changes(task_id=task_id)
                initial_subject = run_git.workspace_subject(task_id=task_id) if workspace_changes else run_git.current_code_subject(task_id)
                run_binding_ok = same_repository and baseline_valid and initial_subject is not None
                if proof is not None:
                    proof_root = Path(str(proof.worktree_identity.get("path", ""))).resolve()
                    proof_keys = {
                        (change.operation, change.path, change.old_path, change.submodule)
                        for change in proof.scope_changes()
                    }
                    recomputed_keys = {
                        (change.operation, change.path, change.old_path, change.submodule)
                        for change in recomputed_changes
                    }
                    proof_matches = (
                        proof.valid()
                        and proof.binds(result)
                        and isinstance(frozen_baseline, dict)
                        and proof.baseline_subject == frozen_baseline
                        and isinstance(frozen_identity, dict)
                        and proof.worktree_identity == frozen_identity
                        and proof_root == run_root
                        and run_binding_ok
                        and proof.result_subject == initial_subject
                        and proof_keys == recomputed_keys
                    )
                    if not proof_matches:
                        issues.append(MacIssue("RESULT_RUN_PROOF_INVALID", "Result intake proof does not match immutable Run and Git facts"))
            except (MacError, OSError, TypeError, ValueError):
                run_binding_ok = False
            if not run_binding_ok and not any(
                issue.code in {"RESULT_RUN_REPOSITORY_MISMATCH", "RESULT_RUN_BASELINE_INVALID"}
                for issue in issues
            ):
                issues.append(MacIssue("RESULT_RUN_BASELINE_INVALID", "run baseline and worktree could not be revalidated"))

        task_git = GitRepository(repo)
        actual_changes = task_git.changes_since(scope.get("base_commit"), task_id=task_id)
        task_workspace_changes = task_git.workspace_changes(task_id=task_id)
        task_subject = task_git.workspace_subject(task_id=task_id) if task_workspace_changes else task_git.current_code_subject(task_id)
        approval_level = max((str(item.get("independence_level", "L0")) for item in valid_approvals), default=None)
        submodule_approved = any("submodule_change" in item.get("comment", "") for item in valid_approvals)
        actual_result = check_changes(
            actual_changes,
            scope,
            ownership=ownership,
            repo_root=repo,
            task_id=task_id,
            governance_approval_level=approval_level,
            submodule_approved=submodule_approved,
        )
        scope_issues.extend(actual_result.issues)
        issues.extend(actual_result.issues)
        result_changes = recomputed_changes if run_binding_ok and recomputed_changes is not None else actual_changes
        if run_binding_ok:
            run_scope = check_changes(
                result_changes,
                scope,
                ownership=ownership,
                repo_root=repo,
                task_id=task_id,
                governance_approval_level=approval_level,
                submodule_approved=submodule_approved,
            )
            scope_issues.extend(run_scope.issues)
            issues.extend(run_scope.issues)
        if isinstance(work_unit, dict):
            unit_scope = check_changes(
                result_changes,
                {**scope, "allowed_paths": list(work_unit.get("allowed_paths", []))},
                ownership=ownership,
                repo_root=repo,
                task_id=task_id,
                governance_approval_level=approval_level,
                submodule_approved=submodule_approved,
            )
            scope_issues.extend(unit_scope.issues)
            issues.extend(unit_scope.issues)
        corresponding_paths = {
            normalize_repo_path(path)
            for change in result_changes
            for path in ([change.old_path, change.path] if change.old_path else [change.path])
            if path
        }
        reported_paths = {normalize_repo_path(str(path)) for path in result.get("changed_files", [])}
        if corresponding_paths != reported_paths:
            issues.append(MacIssue("RESULT_DIFF_MISMATCH", "reported changed_files must exactly match the repository-bound Result diff", details={"actual": sorted(corresponding_paths), "reported": sorted(reported_paths)}))
        if scope.get("status") != "approved" or not valid_approvals:
            issues.append(MacIssue("RESULT_SCOPE_APPROVAL_INVALID", "result requires an authorized approved Scope Contract"))
        if run_binding_ok and initial_subject is not None:
            run_git = GitRepository(run_root)
            final_changes = run_git.workspace_changes(task_id=task_id)
            final_subject = run_git.workspace_subject(task_id=task_id) if final_changes else run_git.current_code_subject(task_id)
            if final_subject != initial_subject:
                issues.append(MacIssue("RESULT_WORKTREE_CHANGED_DURING_INTAKE", "run worktree changed during Result intake"))
    except MacError as exc:
        issues.append(MacIssue(exc.code, str(exc)))
    except (KeyError, ValueError, FileNotFoundError) as exc:
        issues.append(MacIssue("RESULT_POLICY_INVALID", str(exc)))

    command_codes = [int(command.get("exit_code", 1)) for command in result.get("commands", [])]
    if result.get("outcome") == "succeeded" and any(code != 0 for code in command_codes):
        issues.append(MacIssue("RESULT_OUTCOME_COMMAND_MISMATCH", "succeeded result contains a failed command"))
    if str(result.get("id", "")) in snapshots["results"]:
        issues.append(MacIssue("RESULT_ID_CONFLICT", "result id already exists"))
    if issues:
        security = any(issue.code in {
            "RESULT_UNSAFE_SHELL", "SECRET_DETECTED", "RESULT_RUN_REPOSITORY_MISMATCH",
            "RESULT_RUN_BASELINE_INVALID", "RESULT_RUN_PROOF_INVALID", "RESULT_ACTOR_MISMATCH",
            "RESULT_INDEPENDENCE_DOWNGRADE", "RESULT_WORKTREE_CHANGED_DURING_INTAKE",
        } for issue in issues)
        non_scope_issues = [issue for issue in issues if issue not in scope_issues]
        exit_code = ExitCode.SECURITY if security else (ExitCode.VALIDATION if non_scope_issues else ExitCode.SCOPE)
        raise MacError(issues[0].code, issues[0].message, exit_code=exit_code, details={"issues": [issue.as_dict() for issue in issues]})

    assert isinstance(work_unit, dict) and isinstance(run, dict)
    assert run_binding_ok and initial_subject is not None
    assert isinstance(task_subject, dict)
    completed_work_unit = deepcopy(work_unit)
    completed_work_unit["status"] = "completed" if result["outcome"] == "succeeded" else "failed"
    stored_result = deepcopy(result)
    stored_result["submitted_at"] = committed_at
    completed_run = deepcopy(run)
    completed_run["status"] = "succeeded" if result["outcome"] == "succeeded" else "failed"
    completed_run["finished_at"] = committed_at
    completed_run["exit_code"] = next((code for code in command_codes if code != 0), 0 if result["outcome"] == "succeeded" else 1)
    canonical = json.dumps(stored_result, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    proof_payload = proof.as_dict() if proof is not None else None
    payload = {
        "result_id": stored_result["id"],
        "digest": sha256_bytes(canonical),
        "outcome": stored_result["outcome"],
        "work_unit_id": completed_work_unit["id"],
        "work_unit": completed_work_unit,
        "run": completed_run,
        "result": deepcopy(stored_result),
        "intake_proof": proof_payload,
    }
    return ResultSubmissionPlan(
        stored_result,
        completed_run,
        completed_work_unit,
        payload,
        run_root,
        deepcopy(initial_subject),
        deepcopy(task_subject),
    )


class ResultService:
    def __init__(
        self,
        repo: Path,
        repository: FilesystemTaskRepository | None = None,
        schemas: SchemaSet | None = None,
        gateway: MutationGateway | None = None,
    ) -> None:
        self.repo = repo.resolve()
        self.repository = repository or FilesystemTaskRepository(self.repo)
        self.schemas = schemas or SchemaSet()
        self.mutations = gateway or MutationGateway(self.repo, repository=self.repository)

    def submit(
        self, task_id: str, result_or_path: dict[str, Any] | Path, *, expected_revision: int,
        idempotency_key: str, actor: dict[str, Any], intake_proof: ResultIntakeProof | None = None,
    ) -> dict[str, Any]:
        result = load_data(result_or_path) if isinstance(result_or_path, Path) else dict(result_or_path)
        appended = self.mutations.execute(SubmitResult(
            task_id=task_id,
            result=result,
            intake_proof=intake_proof.as_dict() if intake_proof is not None else None,
            actor_claim=actor,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
        ))
        submitted = appended.value or ((appended.event or {}).get("payload") or {}).get("result")
        return dict(submitted) if isinstance(submitted, Mapping) else result
