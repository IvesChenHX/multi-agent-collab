from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from .errors import ExitCode, MacError, MacIssue
from .authority import valid_scope_approvals
from .git import GitRepository
from .ids import is_identifier
from .io import load_data
from .repository import FilesystemTaskRepository, sha256_bytes
from .schema_validation import SchemaSet
from .scope import check_changes, check_paths, normalize_repo_path
from .security import validate_result_security


class ResultService:
    def __init__(self, repo: Path, repository: FilesystemTaskRepository | None = None, schemas: SchemaSet | None = None) -> None:
        self.repo = repo.resolve()
        self.repository = repository or FilesystemTaskRepository(self.repo)
        self.schemas = schemas or SchemaSet()

    def submit(self, task_id: str, result_or_path: dict[str, Any] | Path, *, expected_revision: int, idempotency_key: str, actor: dict[str, Any]) -> dict[str, Any]:
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
        scope_result = check_paths(list(result.get("changed_files", [])), scope, repo_root=self.repo)
        issues.extend(scope_result.issues)
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
        if run is not None:
            if run.get("work_unit_id") != result.get("work_unit_id"):
                issues.append(MacIssue("RESULT_RUN_WORK_UNIT_MISMATCH", "result run and work unit do not match"))
            if run.get("status") not in {"registered", "running"}:
                issues.append(MacIssue("RESULT_RUN_NOT_ACTIVE", "result run is not active"))
        if work_unit is not None:
            if str(work_unit.get("owner")) not in {str(owner) for owner in scope.get("owners", [])}:
                issues.append(MacIssue("RESULT_WORK_UNIT_OWNER_OUTSIDE", "work unit owner is not authorized by task scope"))
            work_unit_contract = {
                **scope,
                "allowed_paths": list(work_unit.get("allowed_paths", [])),
                "owners": [str(work_unit.get("owner"))],
            }
            issues.extend(check_paths(list(result.get("changed_files", [])), work_unit_contract, repo_root=self.repo).issues)
        try:
            config = load_data(self.repo / ".agents/config.yaml")
            ownership = load_data(self.repo / str(config["paths"]["ownership"]))
            approvals = [load_data(path) for path in (task_dir / "approvals").glob("*.json")]
            task = self.repository.load_task(task_id)
            valid_approvals = valid_scope_approvals(task, scope, approvals, ownership, config)
            actual_changes = GitRepository(self.repo).changes_since(scope.get("base_commit"), task_id=task_id)
            actual_result = check_changes(
                actual_changes, scope, ownership=ownership, repo_root=self.repo, task_id=task_id,
                governance_approval_level=max((str(item.get("independence_level", "L0")) for item in valid_approvals), default=None),
                submodule_approved=any("submodule_change" in item.get("comment", "") for item in valid_approvals),
            )
            issues.extend(actual_result.issues)
            if work_unit is not None:
                work_unit_actual = check_changes(actual_changes, {**scope, "allowed_paths": list(work_unit.get("allowed_paths", [])), "owners": [str(work_unit.get("owner"))]}, ownership=ownership, repo_root=self.repo, task_id=task_id, governance_approval_level=max((str(item.get("independence_level", "L0")) for item in valid_approvals), default=None), submodule_approved=any("submodule_change" in item.get("comment", "") for item in valid_approvals))
                issues.extend(work_unit_actual.issues)
            actual_paths = {
                normalize_repo_path(path)
                for change in actual_changes
                for path in ([change.old_path, change.path] if change.old_path else [change.path])
                if path
            }
            reported_paths = {normalize_repo_path(str(path)) for path in result.get("changed_files", [])}
            if actual_paths != reported_paths:
                issues.append(MacIssue("RESULT_DIFF_MISMATCH", "reported changed_files do not exactly match the current Git diff", details={"actual": sorted(actual_paths), "reported": sorted(reported_paths)}))
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
            non_scope_issues = [issue for issue in issues if issue not in scope_result.issues]
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
