from __future__ import annotations

import json
import hashlib
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ExitCode, MacError, MacIssue
from .authority import valid_scope_approvals
from .git import GitRepository
from .ids import is_identifier
from .io import load_data
from .repository import FilesystemTaskRepository, sha256_bytes
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


class ResultService:
    def __init__(self, repo: Path, repository: FilesystemTaskRepository | None = None, schemas: SchemaSet | None = None) -> None:
        self.repo = repo.resolve()
        self.repository = repository or FilesystemTaskRepository(self.repo)
        self.schemas = schemas or SchemaSet()

    def submit(
        self, task_id: str, result_or_path: dict[str, Any] | Path, *, expected_revision: int,
        idempotency_key: str, actor: dict[str, Any], intake_proof: ResultIntakeProof | None = None,
    ) -> dict[str, Any]:
        result = load_data(result_or_path) if isinstance(result_or_path, Path) else dict(result_or_path)
        issues = self.schemas.validate(result, "result.schema.json", path="result")
        issues.extend(validate_result_security(result))
        if result.get("task_id") != task_id:
            issues.append(MacIssue("RESULT_TASK_MISMATCH", "result task_id does not match target task"))
        task_dir = self.repository.task_dir(task_id)
        existing = next((event for event in self.repository.list_events(task_id) if event.get("idempotency_key") == idempotency_key), None)
        if existing is not None:
            result_id = str((existing.get("payload") or {}).get("result_id", ""))
            if existing.get("event_type") != "result_submitted" or not result_id:
                raise MacError("EVENT_IDEMPOTENCY_CONFLICT", "idempotency key belongs to another operation", exit_code=ExitCode.CONFLICT)
            return load_data(task_dir / "results" / f"{result_id}.json")
        scope = load_data(task_dir / "scope-contract.yaml")
        scope_issues: list[MacIssue] = []
        work_unit_id = str(result.get("work_unit_id", ""))
        run_id = str(result.get("run_id", ""))
        work_unit_path = task_dir / "work-units" / f"{work_unit_id}.yaml" if is_identifier(work_unit_id, "WU") else None
        run_path = task_dir / "runs" / f"{run_id}.json" if is_identifier(run_id, "RUN") else None
        if work_unit_path is None:
            issues.append(MacIssue("RESULT_WORK_UNIT_ID_UNSAFE", "result work_unit_id is not a valid WU identifier"))
        elif not work_unit_path.is_file():
            issues.append(MacIssue("RESULT_WORK_UNIT_REF_MISSING", "result work_unit_id does not exist"))
        if run_path is None:
            issues.append(MacIssue("RESULT_RUN_ID_UNSAFE", "result run_id is not a valid RUN identifier"))
        elif not run_path.is_file():
            issues.append(MacIssue("RESULT_RUN_REF_MISSING", "result run_id does not exist"))
        work_unit = load_data(work_unit_path) if work_unit_path is not None and work_unit_path.is_file() else None
        run = load_data(run_path) if run_path is not None and run_path.is_file() else None
        if work_unit is not None and work_unit.get("status") != "running":
            issues.append(MacIssue("RESULT_WORK_UNIT_NOT_RUNNING", "result work unit is not running"))
        if work_unit is not None and work_unit.get("task_id") != task_id:
            issues.append(MacIssue("RESULT_WORK_UNIT_TASK_MISMATCH", "result work unit belongs to another task"))
        if run is not None:
            if run.get("task_id") != task_id:
                issues.append(MacIssue("RESULT_RUN_TASK_MISMATCH", "result run belongs to another task"))
            if run.get("work_unit_id") != result.get("work_unit_id"):
                issues.append(MacIssue("RESULT_RUN_WORK_UNIT_MISMATCH", "result run and work unit do not match"))
            if run.get("status") not in {"registered", "running"}:
                issues.append(MacIssue("RESULT_RUN_NOT_ACTIVE", "result run is not active"))
        if work_unit is not None:
            if str(work_unit.get("owner")) not in {str(owner) for owner in scope.get("owners", [])}:
                issues.append(MacIssue("RESULT_WORK_UNIT_OWNER_OUTSIDE", "work unit owner is not authorized by task scope"))
        try:
            config = load_data(self.repo / ".agents/config.yaml")
            ownership = load_data(self.repo / str(config["paths"]["ownership"]))
            approvals = [load_data(path) for path in (task_dir / "approvals").glob("*.json")]
            task = self.repository.load_task(task_id)
            valid_approvals = valid_scope_approvals(task, scope, approvals, ownership, config)
            proof_ok = False
            if intake_proof is not None and run is not None:
                started = next(
                    (
                        event for event in self.repository.list_events(task_id)
                        if event.get("event_type") == "run_started"
                        and str((event.get("payload") or {}).get("run_id", event.get("run_id", ""))) == run_id
                    ),
                    None,
                )
                payload = (started or {}).get("payload") or {}
                frozen_baseline = payload.get("baseline_subject")
                frozen_identity = payload.get("worktree_identity")
                runtime = run.get("runtime") or {}
                run_root = Path(str(runtime.get("worktree") or self.repo)).resolve()
                try:
                    proof_root = Path(str(intake_proof.worktree_identity.get("path", ""))).resolve()
                    run_git = GitRepository(run_root)
                    baseline_commit = str((frozen_baseline or {}).get("commit_sha", ""))
                    recomputed_changes = run_git.changes_since(baseline_commit, task_id=task_id) if (frozen_baseline or {}).get("type") == "commit" else []
                    current_workspace_changes = run_git.workspace_changes(task_id=task_id)
                    recomputed_subject = run_git.workspace_subject(task_id=task_id) if current_workspace_changes else run_git.current_code_subject(task_id)
                    recomputed_keys = {
                        (change.operation, change.path, change.old_path, change.submodule)
                        for change in recomputed_changes
                    }
                    proof_keys = {
                        (change.operation, change.path, change.old_path, change.submodule)
                        for change in intake_proof.scope_changes()
                    }
                    proof_ok = (
                        intake_proof.valid()
                        and intake_proof.binds(result)
                        and isinstance(frozen_baseline, dict)
                        and intake_proof.baseline_subject == frozen_baseline
                        and isinstance(frozen_identity, dict)
                        and intake_proof.worktree_identity == frozen_identity
                        and proof_root == run_root
                        and intake_proof.result_subject == recomputed_subject
                        and proof_keys == recomputed_keys
                    )
                except (MacError, OSError, TypeError, ValueError):
                    proof_ok = False
                if not proof_ok:
                    issues.append(MacIssue("RESULT_RUN_PROOF_INVALID", "Result intake proof does not match the immutable run baseline, worktree identity, current Git subject, and recomputed diff"))
            actual_changes = GitRepository(self.repo).changes_since(scope.get("base_commit"), task_id=task_id)
            actual_result = check_changes(
                actual_changes, scope, ownership=ownership, repo_root=self.repo, task_id=task_id,
                governance_approval_level=max((str(item.get("independence_level", "L0")) for item in valid_approvals), default=None),
                submodule_approved=any("submodule_change" in item.get("comment", "") for item in valid_approvals),
            )
            scope_issues.extend(actual_result.issues)
            issues.extend(actual_result.issues)
            if work_unit is not None:
                work_unit_changes = intake_proof.scope_changes() if proof_ok and intake_proof is not None else actual_changes
                work_unit_actual = check_changes(work_unit_changes, {**scope, "allowed_paths": list(work_unit.get("allowed_paths", []))}, ownership=ownership, repo_root=self.repo, task_id=task_id, governance_approval_level=max((str(item.get("independence_level", "L0")) for item in valid_approvals), default=None), submodule_approved=any("submodule_change" in item.get("comment", "") for item in valid_approvals))
                scope_issues.extend(work_unit_actual.issues)
                issues.extend(work_unit_actual.issues)
            actual_paths = {
                normalize_repo_path(path)
                for change in actual_changes
                for path in ([change.old_path, change.path] if change.old_path else [change.path])
                if path
            }
            reported_paths = {normalize_repo_path(str(path)) for path in result.get("changed_files", [])}
            if not proof_ok and actual_paths != reported_paths:
                issues.append(MacIssue("RESULT_DIFF_MISMATCH", "without a run-bound proof, reported changed_files must exactly match the current Task diff", details={"actual": sorted(actual_paths), "reported": sorted(reported_paths)}))
            if scope.get("status") != "approved" or not valid_approvals:
                issues.append(MacIssue("RESULT_SCOPE_APPROVAL_INVALID", "result requires an authorized approved Scope Contract"))
        except MacError as exc:
            issues.append(MacIssue(exc.code, str(exc)))
        except (KeyError, ValueError, FileNotFoundError) as exc:
            issues.append(MacIssue("RESULT_POLICY_INVALID", str(exc)))
        command_codes = [int(command.get("exit_code", 1)) for command in result.get("commands", [])]
        if result.get("outcome") == "succeeded" and any(code != 0 for code in command_codes):
            issues.append(MacIssue("RESULT_OUTCOME_COMMAND_MISMATCH", "succeeded result contains a failed command"))
        if issues:
            security = any(issue.code in {"RESULT_UNSAFE_SHELL", "SECRET_DETECTED"} for issue in issues)
            non_scope_issues = [issue for issue in issues if issue not in scope_issues]
            exit_code = ExitCode.SECURITY if security else (ExitCode.VALIDATION if non_scope_issues else ExitCode.SCOPE)
            raise MacError(issues[0].code, issues[0].message, exit_code=exit_code, details={"issues": [issue.as_dict() for issue in issues]})
        assert work_unit is not None and run is not None and work_unit_path is not None and run_path is not None
        completed_work_unit = deepcopy(work_unit)
        completed_work_unit["status"] = "completed" if result["outcome"] == "succeeded" else "failed"
        completed_run = deepcopy(run)
        completed_run["status"] = "succeeded" if result["outcome"] == "succeeded" else "failed"
        completed_run["finished_at"] = result["submitted_at"]
        completed_run["exit_code"] = next((code for code in command_codes if code != 0), 0 if result["outcome"] == "succeeded" else 1)
        target = task_dir / "results" / f"{result['id']}.json"
        canonical = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        appended = self.repository.append_event(
            task_id,
            "result_submitted",
            {
                "result_id": result["id"],
                "digest": sha256_bytes(canonical),
                "outcome": result["outcome"],
                "work_unit_id": completed_work_unit["id"],
                "work_unit": completed_work_unit,
                "run": completed_run,
                "result": result,
                "intake_proof": {"verifier": intake_proof.verifier, "digest": intake_proof.digest, "checks": dict(intake_proof.checks)} if intake_proof is not None else None,
            },
            actor=actor,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            run_id=str(result["run_id"]),
            materializations=[(work_unit_path, completed_work_unit), (run_path, completed_run), (target, result)],
            replace_existing={work_unit_path, run_path},
        )
        result_id = str((appended.event.get("payload") or {}).get("result_id", result["id"]))
        return load_data(task_dir / "results" / f"{result_id}.json")
