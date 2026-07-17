from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, Optional

import typer
from typer import _click as click

from .application.close import evaluate_repository_close
from .application.governance import validate_risk_acceptance
from .application.task_service import TaskService
from .authority import actor_authorized_for_scope, owner_approvers, valid_scope_approvals
from .doctor import repair_safe, run_doctor
from .errors import ExitCode, MacError, MacIssue
from .evidence import invalidate_evidence, promote_evidence
from .git import GitRepository
from .handoff import build_handoff_packet, write_handoff_packet
from .ids import is_identifier, prefixed
from .io import atomic_write_json, atomic_write_yaml, load_data
from .migration import convert_v5, scan_v5
from .policy import compile_policy
from .report import build_audit_bundle, build_index, render_task_report, verify_audit_bundle
from .repository import FilesystemTaskRepository, build_policy_ref, utc_now, validate_repository
from .result import ResultService
from .runtime import evaluate_capabilities, resolve_profile
from .schema_validation import SchemaSet, install_schema_bundle
from .scope import amend_scope, check_changes
from .security import validate_result_security
from .state_machine import TransitionContext, default_workflow_document

app = typer.Typer(no_args_is_help=True, help="multi-agent-collab v6 governance core")
policy_app = typer.Typer(no_args_is_help=True); task_app = typer.Typer(no_args_is_help=True)
scope_app = typer.Typer(no_args_is_help=True); work_unit_app = typer.Typer(no_args_is_help=True)
run_app = typer.Typer(no_args_is_help=True); result_app = typer.Typer(no_args_is_help=True)
evidence_app = typer.Typer(no_args_is_help=True); finding_app = typer.Typer(no_args_is_help=True)
approval_app = typer.Typer(no_args_is_help=True); handoff_app = typer.Typer(no_args_is_help=True)
report_app = typer.Typer(no_args_is_help=True); index_app = typer.Typer(no_args_is_help=True)
migrate_app = typer.Typer(no_args_is_help=True)
for name, group in (("policy", policy_app), ("task", task_app), ("scope", scope_app), ("work-unit", work_unit_app), ("run", run_app), ("result", result_app), ("evidence", evidence_app), ("finding", finding_app), ("approval", approval_app), ("handoff", handoff_app), ("report", report_app), ("index", index_app), ("migrate", migrate_app)):
    app.add_typer(group, name=name)


def _emit(value: Any, json_output: bool = False) -> None:
    if json_output or not isinstance(value, str):
        typer.echo(json.dumps(value, ensure_ascii=False, indent=None if json_output else 2, default=str))
    else:
        typer.echo(value)


def _repository(repo: Path) -> FilesystemTaskRepository:
    return FilesystemTaskRepository(repo)


def _actor(actor: str, kind: str = "human") -> dict[str, str]:
    return {"id": actor, "kind": kind}


def _entity_paths(repo: Path, task_id: str, directory: str, suffix: str) -> list[Path]:
    return sorted((_repository(repo).task_dir(task_id) / directory).glob(f"*.{suffix}"))


def _operation_replay(repository: FilesystemTaskRepository, task_id: str, idempotency_key: str, event_type: str) -> dict[str, Any] | None:
    event = next((item for item in repository.list_events(task_id) if item.get("idempotency_key") == idempotency_key), None)
    if event is None:
        return None
    if event.get("event_type") != event_type:
        raise MacError("EVENT_IDEMPOTENCY_CONFLICT", "idempotency key belongs to another operation", exit_code=ExitCode.CONFLICT, task_id=task_id)
    return event


def _write_entity(
    repo: Path, task_id: str, directory: str, entity: dict[str, Any], schema_name: str, event_type: str, *,
    expected_revision: int, idempotency_key: str, actor: str,
    related_entities: list[tuple[Path, dict[str, Any]]] | None = None,
    event_payload: dict[str, Any] | None = None,
    replace_existing: set[Path] | None = None,
) -> dict[str, Any]:
    issues = SchemaSet().validate(entity, schema_name, path=f"{directory}/{entity['id']}")
    if issues:
        raise MacError("SCHEMA_INVALID", issues[0].message, exit_code=ExitCode.VALIDATION, details={"issues": [item.as_dict() for item in issues]})
    extension = "yaml" if directory == "work-units" else "json"
    repository = _repository(repo)
    target = repository.task_dir(task_id) / directory / f"{entity['id']}.{extension}"
    reference_key = f"{directory.rstrip('s').replace('-', '_')}_id"
    snapshot_key = {
        "work-units": "work_unit", "runs": "run", "results": "result",
        "evidence": "evidence", "findings": "finding", "approvals": "approval",
        "risk-acceptances": "risk_acceptance",
    }.get(directory)
    payload = {**(event_payload or {}), reference_key: entity["id"]}
    if snapshot_key:
        payload[snapshot_key] = entity
    appended = repository.append_event(
        task_id,
        event_type,
        payload,
        actor=_actor(actor),
        expected_revision=expected_revision,
        idempotency_key=idempotency_key,
        run_id=str(entity.get("run_id")) if entity.get("run_id") else None,
        materializations=[*(related_entities or []), (target, entity)],
        replace_existing=replace_existing,
    )
    entity_id = str((appended.event.get("payload") or {}).get(reference_key, entity["id"]))
    return load_data(repository.task_dir(task_id) / directory / f"{entity_id}.{extension}")


@app.command("init")
def init_command(repo: Path = typer.Option(Path("."), "--repo"), project: str = typer.Option("multi-agent-project", "--project"), json_output: bool = typer.Option(False, "--json")) -> None:
    root = repo.resolve(); agents = root / ".agents"
    if (agents / "config.yaml").exists():
        raise MacError("INIT_ALREADY_EXISTS", ".agents/config.yaml already exists", exit_code=ExitCode.CONFLICT)
    config = {"schema_version": 6, "project": project, "governance_level": "advisory", "default_workflow": "evidence-driven-development", "default_runtime_profile": "local-single", "paths": {"tasks": "tasks", "ownership": ".agents/ownership.yaml", "workflows": ".agents/workflows", "runtime_profiles": ".agents/runtime-profiles", "private_artifacts": "tasks/private"}, "modes": {"ask": {"persistent": False, "allow_write": False}, "quick": {"persistent": False, "max_changed_files": 5, "max_changed_lines": 200, "require_single_owner": True, "require_targeted_verification": True, "forbidden_risk_tags": ["public_contract", "data_migration", "auth_security", "production_deploy", "cross_service_consistency", "policy_change"]}, "standard": {"persistent": True, "required_gates": ["targeted_tests"], "minimum_review_independence": "L1"}, "high_risk": {"persistent": True, "required_gates": ["targeted_tests", "independent_review", "rollback_plan"], "minimum_review_independence": "L2"}, "audit": {"persistent": True, "required_gates": ["targeted_tests", "independent_review", "rollback_plan", "audit_bundle"], "minimum_review_independence": "L3", "require_export_bundle": True}}, "close_policy": {"require_commit_bound_evidence": True, "non_waivable_gates": ["approved_scope", "evidence_matches_current_commit", "independent_review"], "risk_acceptance_default_ttl_days": 30}, "repair_policy": {"max_automatic_rounds_per_root_cause": 2, "fresh_context_categories": ["security", "data", "compatibility"]}, "security": {"governance_sensitive_paths": ["AGENTS.md", ".agents/**", ".github/workflows/*governance*", "schemas/**"], "forbid_shell_by_default": True, "raw_logs_committed": False}}
    workflow = default_workflow_document()
    ownership = {"schema_version": 6, "matching": {"semantics": "gitwildmatch", "ambiguous": "require_triage", "unassigned": "require_triage", "case_sensitive": "auto"}, "owners": {"governance": {"priority": 1000, "implementation_role": "governance-maintainer", "include": ["AGENTS.md", ".agents/**", "schemas/**"], "approvers": ["governance-owner"]}}, "sensitive_paths": []}
    atomic_write_yaml(agents / "config.yaml", config); atomic_write_yaml(agents / "ownership.yaml", ownership); atomic_write_yaml(agents / "workflows/evidence-driven-development.yaml", workflow); atomic_write_yaml(agents / "runtime-profiles/local-single.yaml", resolve_profile(agents / "runtime-profiles")); install_schema_bundle(root); (root / "tasks").mkdir(exist_ok=True)
    _emit({"ok": True, "repo": str(root), "governance_level": "advisory"}, json_output)


@app.command("doctor")
def doctor_command(repo: Path = typer.Option(Path("."), "--repo"), repair: bool = typer.Option(False, "--repair-safe"), apply_repairs: bool = typer.Option(False, "--apply", help="Apply the repair-safe candidate set."), json_output: bool = typer.Option(False, "--json")) -> None:
    if apply_repairs and not repair:
        raise MacError("DOCTOR_APPLY_REQUIRES_REPAIR_SAFE", "--apply requires --repair-safe", exit_code=ExitCode.CLI_USAGE)
    payload = repair_safe(repo, apply=apply_repairs).as_dict() if repair else run_doctor(repo).as_dict(); _emit(payload, json_output)
    if not payload["ok"]: raise typer.Exit(ExitCode.VALIDATION)


@app.command("validate")
def validate_command(repo: Path = typer.Option(Path("."), "--repo"), schema_dir: Optional[Path] = typer.Option(None, "--schema-dir"), json_output: bool = typer.Option(False, "--json")) -> None:
    issues = validate_repository(repo, SchemaSet(schema_dir)); payload = {"ok": not any(item.severity == "error" for item in issues), "issues": [item.as_dict() for item in issues]}; _emit(payload, json_output)
    if not payload["ok"]: raise typer.Exit(ExitCode.VALIDATION)


@policy_app.command("compile")
def policy_compile(repo: Path = typer.Option(Path("."), "--repo"), json_output: bool = typer.Option(False, "--json")) -> None:
    compiled = compile_policy(repo)
    config = compiled.config
    policy_paths = ["AGENTS.md", ".agents/config.yaml", f"{config['paths']['workflows']}/{config['default_workflow']}.yaml"]
    ownership_paths = [str(config["paths"]["ownership"])]
    _emit({
        "ok": True,
        "policy_ref": build_policy_ref(repo, policy_paths),
        "ownership_ref": build_policy_ref(repo, ownership_paths),
        "workflow": compiled.workflow["name"],
        "transition_ids": [item.id for item in compiled.transitions],
        "runtime_profile": compiled.runtime_profile["id"],
        "governance_level": config["governance_level"],
        "modes": config["modes"],
    }, json_output)


@app.command("classify")
def classify(changed_files: int = typer.Option(0, "--changed-files"), changed_lines: int = typer.Option(0, "--changed-lines"), owners: list[str] = typer.Option([], "--owner"), risk_tags: list[str] = typer.Option([], "--risk-tag"), write: bool = typer.Option(True, "--write/--read-only"), json_output: bool = typer.Option(False, "--json")) -> None:
    forbidden = {"public_contract", "data_migration", "auth_security", "production_deploy", "cross_service_consistency", "policy_change"}
    mode = "ask" if not write else ("high_risk" if forbidden & set(risk_tags) else ("quick" if changed_files <= 5 and changed_lines <= 200 and len(set(owners)) <= 1 else "standard"))
    _emit({"ok": True, "mode": mode, "persistent": mode not in {"ask", "quick"}, "upgrade_required": mode not in {"ask", "quick"}}, json_output)


@task_app.command("new")
def task_new(title: str = typer.Option(..., "--title"), objective: str = typer.Option(..., "--objective"), mode: str = typer.Option("standard", "--mode"), allow: list[str] = typer.Option(..., "--allow"), owner: list[str] = typer.Option(..., "--owner"), acceptance: list[str] = typer.Option(..., "--accept"), runtime_profile: str = typer.Option("local-single", "--runtime-profile"), gate: list[str] = typer.Option(["targeted_tests"], "--gate"), actor: str = typer.Option("cli-user", "--actor"), idempotency_key: str = typer.Option(..., "--idempotency-key"), repo: Path = typer.Option(Path("."), "--repo"), json_output: bool = typer.Option(False, "--json")) -> None:
    value = TaskService(repo).create(title=title, mode=mode, objective=objective, acceptance=acceptance, allowed_paths=allow, owners=owner, runtime_profile=runtime_profile, required_gates=gate, actor=_actor(actor), idempotency_key=idempotency_key); _emit({"ok": True, "task_id": value["task"]["id"], "task": value["task"], "scope": value["scope"]}, json_output)


@task_app.command("show")
def task_show(task_id: str, repo: Path = typer.Option(Path("."), "--repo"), json_output: bool = typer.Option(False, "--json")) -> None: _emit({"ok": True, "task": _repository(repo).load_task(task_id)}, json_output)


@task_app.command("list")
def task_list(repo: Path = typer.Option(Path("."), "--repo"), json_output: bool = typer.Option(False, "--json")) -> None: _emit({"ok": True, "tasks": build_index(repo)}, json_output)


def _close_decision(repo: Path, task_id: str, actor: str):
    return evaluate_repository_close(repo, task_id, actor)


def _transition_context(repo: Path, task_id: str, target: str, actor: str = "cli-user") -> TransitionContext:
    directory = _repository(repo).task_dir(task_id); task = _repository(repo).load_task(task_id); scope = load_data(directory / "scope-contract.yaml")
    results = list((directory / "results").glob("*.json")); runs = [load_data(path) for path in (directory / "runs").glob("*.json")]; work_units = [load_data(path) for path in (directory / "work-units").glob("*.yaml")]
    approvals = [load_data(path) for path in (directory / "approvals").glob("*.json")]
    config = load_data(repo / ".agents/config.yaml"); ownership = load_data(repo / str(config["paths"]["ownership"]))
    scope_approvals = valid_scope_approvals(task, scope, approvals, ownership, config)
    active_runs = [run for run in runs if run.get("status") in {"registered", "running"}]
    units_by_id = {str(unit.get("id")): unit for unit in work_units}
    dependencies_complete = bool(active_runs) and all(
        (unit := units_by_id.get(str(run.get("work_unit_id")))) is not None
        and unit.get("status") in {"ready", "running"}
        and all(units_by_id.get(str(dependency), {}).get("status") == "completed" for dependency in unit.get("depends_on", []))
        for run in active_runs
    )
    try:
        git = GitRepository(repo)
        scope_clean = check_changes(git.changes_since(scope.get("base_commit"), task_id=task_id), scope, ownership=ownership, repo_root=repo, task_id=task_id, governance_approval_level=max((str(item.get("independence_level", "L0")) for item in scope_approvals), default=None), submodule_approved=any("submodule_change" in item.get("comment", "") for item in scope_approvals)).ok
        current_subject_digest = bool(git.workspace_subject(task_id=task_id))
    except Exception:
        scope_clean = False
        current_subject_digest = False
    close = _close_decision(repo, task_id, actor) if target in {"completed", "completed_with_risk"} else None
    close_codes = set(close.codes) if close else set()
    triage_complete = bool(task.get("mode") and task.get("acceptance_criteria") and scope.get("owners") and task.get("runtime_profile") and task.get("policy_ref") and task.get("ownership_ref"))
    work_units_complete = bool(work_units) and all(unit.get("status") == "completed" for unit in work_units)
    return TransitionContext(
        triage_complete=triage_complete,
        scope_approved=scope.get("status") == "approved" and bool(scope_approvals),
        gates_selected=bool(task.get("required_gates")),
        runtime_satisfied=bool((resolve_profile(repo / str(config["paths"]["runtime_profiles"]), explicit=str(task.get("runtime_profile"))).get("capabilities") or {}).get("command_execution")),
        result_submitted=bool(results) and work_units_complete,
        work_units_complete=work_units_complete,
        scope_clean=scope_clean,
        current_subject_digest=current_subject_digest,
        evidence_complete=(not any(code.startswith(("EVIDENCE_", "CLOSE_GATE_", "CLOSE_ACCEPTANCE_")) for code in close_codes)) if close else True,
        review_complete=(not any(code.startswith("REVIEW_") or code == "CLOSE_REVIEW_MISSING" for code in close_codes)) if close else False,
        close_findings_clean=(not any(code.startswith("CLOSE_FINDING") for code in close_codes)) if close else True,
        close_actor_authorized=actor_authorized_for_scope(actor, scope, ownership),
        risk_acceptance_valid=(close.ok if close and target == "completed_with_risk" else target != "completed_with_risk"),
        review_required="independent_review" in task.get("required_gates", []),
        controller_lease_valid=False,
        lease_valid=False,
        executor_run_created=bool(active_runs) or target != "executing",
        work_unit_dependencies_complete=dependencies_complete,
        dependencies_complete=dependencies_complete,
        baseline_recorded=bool(scope.get("base_commit") or task.get("policy_ref", {}).get("source_commit")),
        authorized_cancellation=True,
    )


@task_app.command("transition")
def task_transition(task_id: str, target: str, expected_revision: int = typer.Option(..., "--expected-revision"), idempotency_key: str = typer.Option(..., "--idempotency-key"), actor: str = typer.Option("cli-user", "--actor"), repo: Path = typer.Option(Path("."), "--repo"), json_output: bool = typer.Option(False, "--json")) -> None:
    if target in {"completed", "completed_with_risk"}:
        close = _close_decision(repo, task_id, actor)
        if not close.ok:
            raise MacError("CLOSE_GATES_FAILED", "task cannot close", exit_code=ExitCode.EVIDENCE, details={"issues": [item.as_dict() for item in close.issues]})
    result = _repository(repo).transition(task_id, target, _transition_context(repo, task_id, target, actor), actor=_actor(actor), expected_revision=expected_revision, idempotency_key=idempotency_key); _emit({"ok": True, "task": result.projection, "event": result.event}, json_output)


@task_app.command("cancel")
def task_cancel(task_id: str, expected_revision: int = typer.Option(...), idempotency_key: str = typer.Option(...), actor: str = typer.Option("cli-user"), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    result = _repository(repo).transition(task_id, "cancelled", TransitionContext(authorized_cancellation=True), actor=_actor(actor), expected_revision=expected_revision, idempotency_key=idempotency_key); _emit({"ok": True, "task": result.projection}, json_output)


@task_app.command("supersede")
def task_supersede(task_id: str, successor: str = typer.Option(..., "--successor"), expected_revision: int = typer.Option(...), idempotency_key: str = typer.Option(...), actor: str = typer.Option("cli-user"), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    result = _repository(repo).transition(task_id, "superseded", TransitionContext(successor_task_id=successor), actor=_actor(actor), expected_revision=expected_revision, idempotency_key=idempotency_key); _emit({"ok": True, "task": result.projection}, json_output)


@task_app.command("rebuild")
def task_rebuild(task_id: str, repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None: _emit({"ok": True, "task": _repository(repo).rebuild_task(task_id)}, json_output)


@scope_app.command("propose")
def scope_propose(task_id: str, allow: list[str] = typer.Option(..., "--allow"), deny: list[str] = typer.Option([], "--deny"), owner: list[str] = typer.Option(..., "--owner"), expected_revision: int = typer.Option(..., "--expected-revision"), idempotency_key: str = typer.Option(..., "--idempotency-key"), actor: str = typer.Option("cli-user"), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    repository = _repository(repo); path = repository.task_dir(task_id) / "scope-contract.yaml"
    if replay := _operation_replay(repository, task_id, idempotency_key, "scope_proposed"):
        _emit({"ok": True, "scope": (replay.get("payload") or {}).get("scope"), "revision": replay.get("revision")}, json_output); return
    scope = load_data(path)
    if scope.get("status") == "approved": raise MacError("SCOPE_APPROVED_IMMUTABLE", "approved scope must be amended, not edited", exit_code=ExitCode.SCOPE)
    scope = deepcopy(scope); scope.update({"status": "proposed", "proposed_by": actor, "approved_by": [], "allowed_paths": allow, "denied_paths": deny, "owners": owner})
    issues = SchemaSet().validate(scope, "scope-contract.schema.json", path="scope-contract.yaml")
    if issues: raise MacError("SCHEMA_INVALID", issues[0].message, exit_code=ExitCode.VALIDATION, details={"issues": [item.as_dict() for item in issues]})
    appended = repository.append_event(task_id, "scope_proposed", {"scope_id": scope["id"], "version": scope["version"], "scope": scope}, actor=_actor(actor), expected_revision=expected_revision, idempotency_key=idempotency_key, materializations=[(path, scope)], replace_existing={path})
    _emit({"ok": True, "scope": load_data(path), "revision": appended.projection["revision"]}, json_output)


@scope_app.command("approve")
def scope_approve(task_id: str, expected_revision: int = typer.Option(...), idempotency_key: str = typer.Option(...), actor: str = typer.Option(...), independence_level: str = typer.Option("L1"), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    repository = _repository(repo); directory = repository.task_dir(task_id); path = directory / "scope-contract.yaml"
    if replay := _operation_replay(repository, task_id, idempotency_key, "scope_approved"):
        payload = replay.get("payload") or {}; _emit({"ok": True, "scope": payload.get("scope"), "approval": payload.get("approval"), "revision": replay.get("revision")}, json_output); return
    scope = load_data(path)
    if scope["status"] != "proposed": raise MacError("SCOPE_NOT_PROPOSED", "only proposed scope can be approved", exit_code=ExitCode.SCOPE)
    task = _repository(repo).load_task(task_id); config = load_data(repo / ".agents/config.yaml"); ownership = load_data(repo / str(config["paths"]["ownership"]))
    approval = {"schema_version": 1, "id": prefixed("APR"), "task_id": task_id, "kind": "scope", "actor": _actor(actor), "decision": "approved", "subject_ref": str(task["scope_contract_ref"]), "independence_level": independence_level, "recorded_at": utc_now()}
    if not valid_scope_approvals(task, scope, [approval], ownership, config):
        raise MacError("SCOPE_APPROVER_UNAUTHORIZED", "scope approval lacks owner authority or required independence", exit_code=ExitCode.SECURITY, task_id=task_id)
    scope = deepcopy(scope); scope["status"] = "approved"; scope["approved_by"] = [actor]
    approval_path = directory / "approvals" / f"{approval['id']}.json"; event = _repository(repo).append_event(task_id, "scope_approved", {"scope_id": scope["id"], "version": scope["version"], "approval_id": approval["id"], "approval": approval, "scope": scope}, actor=_actor(actor), expected_revision=expected_revision, idempotency_key=idempotency_key, materializations=[(approval_path, approval), (path, scope)], replace_existing={path}); _emit({"ok": True, "scope": scope, "approval": approval, "revision": event.projection["revision"]}, json_output)


@scope_app.command("amend")
def scope_amend(task_id: str, add: list[str] = typer.Option(..., "--add"), expected_revision: int = typer.Option(...), idempotency_key: str = typer.Option(...), actor: str = typer.Option(...), approver: list[str] = typer.Option(...), risk_tag: list[str] = typer.Option([], "--risk-tag"), independent: bool = typer.Option(False), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    repository = _repository(repo); directory = repository.task_dir(task_id); path = directory / "scope-contract.yaml"
    if replay := _operation_replay(repository, task_id, idempotency_key, "scope_proposed"):
        _emit({"ok": True, "scope": (replay.get("payload") or {}).get("scope"), "revision": replay.get("revision"), "approval_required": True}, json_output); return
    old = load_data(path); new = amend_scope(old, add_paths=add, actor=actor, approvers=approver, added_risk_tags=risk_tag, independent_approval=independent); history = directory / "scope-history" / f"scope-contract.v{old['version']}.yaml"; result = repository.append_event(task_id, "scope_proposed", {"scope_id": new["id"], "version": new["version"], "amendment": True, "scope": new}, actor=_actor(actor), expected_revision=expected_revision, idempotency_key=idempotency_key, materializations=[(history, old), (path, new)], replace_existing={path}); _emit({"ok": True, "scope": new, "revision": result.projection["revision"], "approval_required": True}, json_output)


@scope_app.command("check")
def scope_check(task_id: str, base: Optional[str] = typer.Option(None), head: str = typer.Option("HEAD"), workspace: bool = typer.Option(False), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    directory = _repository(repo).task_dir(task_id); task = load_data(directory / "task.yaml"); scope = load_data(directory / "scope-contract.yaml"); git = GitRepository(repo); changes = git.workspace_changes(task_id=task_id) if workspace or not base else git.diff_changes(base, head); config = load_data(repo / ".agents/config.yaml"); ownership = load_data(repo / str(config["paths"]["ownership"])); approvals = [load_data(path) for path in (directory / "approvals").glob("*.json")]; valid = valid_scope_approvals(task, scope, approvals, ownership, config); result = check_changes(changes, scope, ownership=ownership, repo_root=repo, task_id=task_id, governance_approval_level=max((str(item.get("independence_level", "L0")) for item in valid), default=None), submodule_approved=any("submodule_change" in item.get("comment", "") for item in valid)); _emit({"ok": result.ok, "allowed": result.allowed, "issues": [item.as_dict() for item in result.issues]}, json_output)
    if not result.ok: raise typer.Exit(ExitCode.SCOPE)


@work_unit_app.command("new")
def work_unit_new(task_id: str, title: str = typer.Option(...), owner: str = typer.Option(...), allow: list[str] = typer.Option(...), depends_on: list[str] = typer.Option([], "--depends-on"), expected_revision: int = typer.Option(...), idempotency_key: str = typer.Option(...), actor: str = typer.Option("cli-user"), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    entity = {"schema_version": 1, "id": prefixed("WU"), "task_id": task_id, "title": title, "status": "pending", "owner": owner, "allowed_paths": allow, "depends_on": depends_on, "acceptance_criteria": [], "expected_result": f"tasks/{task_id}/results/{prefixed('RESULT')}.json"}; entity = _write_entity(repo, task_id, "work-units", entity, "work-unit.schema.json", "work_unit_created", expected_revision=expected_revision, idempotency_key=idempotency_key, actor=actor); _emit({"ok": True, "work_unit": entity}, json_output)


def _event_update_entity(
    repo: Path, task_id: str, directory: str, entity_id: str, schema_name: str,
    event_type: str, changes: dict[str, Any], *, expected_revision: int,
    idempotency_key: str, actor: str,
) -> dict[str, Any]:
    repository = _repository(repo)
    if replay := _operation_replay(repository, task_id, idempotency_key, event_type):
        snapshot_key = {"work-units": "work_unit", "findings": "finding", "evidence": "evidence"}[directory]
        snapshot = (replay.get("payload") or {}).get(snapshot_key)
        if isinstance(snapshot, dict):
            return dict(snapshot)
    extensions = {"work-units": "yaml"}
    path = repository.task_dir(task_id) / directory / f"{entity_id}.{extensions.get(directory, 'json')}"
    if not path.is_file():
        raise MacError("ENTITY_NOT_FOUND", entity_id, exit_code=ExitCode.VALIDATION, task_id=task_id)
    entity = deepcopy(load_data(path)); entity.update(changes)
    issues = SchemaSet().validate(entity, schema_name, path=path.relative_to(repo.resolve()).as_posix())
    if issues:
        raise MacError("SCHEMA_INVALID", issues[0].message, exit_code=ExitCode.VALIDATION, details={"issues": [item.as_dict() for item in issues]})
    snapshot_key = {"work-units": "work_unit", "findings": "finding", "evidence": "evidence"}[directory]
    reference_key = f"{directory.rstrip('s').replace('-', '_')}_id"
    appended = repository.append_event(
        task_id, event_type, {reference_key: entity_id, snapshot_key: entity},
        actor=_actor(actor), expected_revision=expected_revision, idempotency_key=idempotency_key,
        materializations=[(path, entity)], replace_existing={path},
    )
    snapshot = (appended.event.get("payload") or {}).get(snapshot_key)
    return dict(snapshot) if isinstance(snapshot, dict) else load_data(path)


@work_unit_app.command("ready")
def work_unit_ready(task_id: str, work_unit_id: str, expected_revision: int = typer.Option(..., "--expected-revision"), idempotency_key: str = typer.Option(..., "--idempotency-key"), actor: str = typer.Option("cli-user"), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    repository = _repository(repo)
    if replay := _operation_replay(repository, task_id, idempotency_key, "work_unit_created"):
        _emit({"ok": True, "work_unit": (replay.get("payload") or {}).get("work_unit")}, json_output); return
    path = repository.task_dir(task_id) / "work-units" / f"{work_unit_id}.yaml"
    current = load_data(path)
    if current.get("status") != "pending": raise MacError("WORK_UNIT_NOT_PENDING", "only pending work units can become ready", exit_code=ExitCode.TRANSITION, task_id=task_id)
    _emit({"ok": True, "work_unit": _event_update_entity(repo, task_id, "work-units", work_unit_id, "work-unit.schema.json", "work_unit_created", {"status": "ready"}, expected_revision=expected_revision, idempotency_key=idempotency_key, actor=actor)}, json_output)


@work_unit_app.command("show")
def work_unit_show(task_id: str, work_unit_id: str, repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None: _emit({"ok": True, "work_unit": load_data(next((_repository(repo).task_dir(task_id)/"work-units").glob(f"{work_unit_id}.*")))}, json_output)


@run_app.command("register")
def run_register(task_id: str, work_unit_id: str = typer.Option(...), profile: str = typer.Option("local-single"), context_id: str = typer.Option(...), actor: str = typer.Option("cli-agent"), actor_kind: str = typer.Option("agent"), independence_level: str = typer.Option("L0"), expected_revision: int = typer.Option(...), idempotency_key: str = typer.Option(...), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    repository = _repository(repo)
    if not is_identifier(work_unit_id, "WU"):
        raise MacError("WORK_UNIT_ID_UNSAFE", "work unit id is invalid", exit_code=ExitCode.SECURITY, task_id=task_id)
    existing = next((event for event in repository.list_events(task_id) if event.get("idempotency_key") == idempotency_key), None)
    if existing is not None:
        existing_run_id = str((existing.get("payload") or {}).get("run_id", ""))
        if existing.get("event_type") != "run_started" or not existing_run_id:
            raise MacError("EVENT_IDEMPOTENCY_CONFLICT", "idempotency key belongs to another operation", exit_code=ExitCode.CONFLICT)
        _emit({"ok": True, "run": load_data(repository.task_dir(task_id) / "runs" / f"{existing_run_id}.json")}, json_output)
        return
    work_unit_path = repository.task_dir(task_id) / "work-units" / f"{work_unit_id}.yaml"
    if not work_unit_path.is_file():
        raise MacError("WORK_UNIT_NOT_FOUND", work_unit_id, exit_code=ExitCode.VALIDATION, task_id=task_id)
    work_unit = load_data(work_unit_path)
    work_units = {
        str(unit.get("id")): unit
        for path in (repository.task_dir(task_id) / "work-units").glob("*.yaml")
        if (unit := load_data(path))
    }
    dependencies = list(work_unit.get("depends_on", []))
    if work_unit.get("status") != "ready" or any(work_units.get(str(dependency), {}).get("status") != "completed" for dependency in dependencies):
        raise MacError("WORK_UNIT_NOT_READY", "work unit is not ready or has incomplete dependencies", exit_code=ExitCode.TRANSITION, task_id=task_id, details={"work_unit_id": work_unit_id})
    running_work_unit = deepcopy(work_unit)
    running_work_unit["status"] = "running"
    entity = {
        "schema_version": 1,
        "id": prefixed("RUN"),
        "task_id": task_id,
        "work_unit_id": work_unit_id,
        "status": "running",
        "actor": _actor(actor, actor_kind),
        "runtime": {"profile": profile, "execution_context_id": context_id},
        "independence_level": independence_level,
        "started_at": utc_now(),
        "finished_at": None,
        "exit_code": None,
    }
    entity = _write_entity(
        repo,
        task_id,
        "runs",
        entity,
        "run.schema.json",
        "run_started",
        expected_revision=expected_revision,
        idempotency_key=idempotency_key,
        actor=actor,
        related_entities=[(work_unit_path, running_work_unit)],
        event_payload={"work_unit_id": work_unit_id, "work_unit": running_work_unit},
        replace_existing={work_unit_path},
    )
    _emit({"ok": True, "run": entity}, json_output)


@run_app.command("finish")
def run_finish(task_id: str, run_id: str, status: str = typer.Option(...), exit_code: Optional[int] = typer.Option(None), expected_revision: Optional[int] = typer.Option(None), idempotency_key: Optional[str] = typer.Option(None), actor: str = typer.Option("cli-agent"), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    repository = _repository(repo)
    if not is_identifier(run_id, "RUN"):
        raise MacError("RUN_ID_UNSAFE", "run id is invalid", exit_code=ExitCode.SECURITY, task_id=task_id)
    run_path = repository.task_dir(task_id) / "runs" / f"{run_id}.json"
    run = load_data(run_path)
    if run.get("status") == status and run.get("exit_code") == exit_code and run.get("finished_at"):
        _emit({"ok": True, "run": run}, json_output)
        return
    if run.get("status") not in {"registered", "running", "unknown"}:
        raise MacError("RUN_ALREADY_FINISHED", "run is already terminal with different data", exit_code=ExitCode.TRANSITION, task_id=task_id)
    finished = deepcopy(run)
    finished["status"] = status
    finished["finished_at"] = utc_now()
    finished["exit_code"] = exit_code
    current_revision = int(repository.load_task(task_id)["revision"])
    revision = current_revision if expected_revision is None else expected_revision
    key = idempotency_key or f"run-finish:{run_id}:{status}:{exit_code}"
    materializations: list[tuple[Path, dict[str, Any]]] = [(run_path, finished)]
    replace_existing = {run_path}
    payload: dict[str, Any] = {"run_id": run_id, "status": status}
    if status in {"failed", "cancelled"}:
        work_unit_path = repository.task_dir(task_id) / "work-units" / f"{run['work_unit_id']}.yaml"
        work_unit = deepcopy(load_data(work_unit_path))
        work_unit["status"] = "failed" if status == "failed" else "cancelled"
        materializations.append((work_unit_path, work_unit))
        replace_existing.add(work_unit_path)
        payload.update({"work_unit_id": work_unit["id"], "work_unit": work_unit})
    repository.append_event(
        task_id,
        "run_finished",
        payload,
        actor=_actor(actor, "agent"),
        expected_revision=revision,
        idempotency_key=key,
        run_id=run_id,
        materializations=materializations,
        replace_existing=replace_existing,
    )
    _emit({"ok": True, "run": finished}, json_output)


@run_app.command("inspect")
def run_inspect(task_id: str, run_id: str, repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None: _emit({"ok": True, "run": load_data(_repository(repo).task_dir(task_id)/"runs"/f"{run_id}.json")}, json_output)


@result_app.command("validate")
def result_validate(path: Path, json_output: bool = typer.Option(False, "--json")) -> None:
    value = load_data(path); issues = [*SchemaSet().validate(value, "result.schema.json", path=str(path)), *validate_result_security(value)]; _emit({"ok": not issues, "issues": [item.as_dict() for item in issues]}, json_output)
    if issues: raise typer.Exit(ExitCode.VALIDATION)


@result_app.command("submit")
def result_submit(task_id: str, path: Path, expected_revision: int = typer.Option(...), idempotency_key: str = typer.Option(...), actor: str = typer.Option("cli-user"), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None: _emit({"ok": True, "result": ResultService(repo).submit(task_id, path, expected_revision=expected_revision, idempotency_key=idempotency_key, actor=_actor(actor))}, json_output)


@evidence_app.command("record", context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def evidence_record(ctx: typer.Context, task_id: str, claim: str = typer.Option(...), expected_revision: int = typer.Option(...), idempotency_key: str = typer.Option(...), actor: str = typer.Option("cli-automation"), repo: Path = typer.Option(Path(".")), commit: bool = typer.Option(False), json_output: bool = typer.Option(False, "--json")) -> None:
    argv = list(ctx.args)
    if not argv: raise MacError("COMMAND_MISSING", "command argv is required after --", exit_code=ExitCode.CLI_USAGE)
    repository = _repository(repo)
    existing = next((event for event in repository.list_events(task_id) if event.get("idempotency_key") == idempotency_key), None)
    if existing is not None:
        if existing.get("event_type") != "evidence_recorded": raise MacError("EVENT_IDEMPOTENCY_CONFLICT", "idempotency key belongs to another operation", exit_code=ExitCode.CONFLICT, task_id=task_id)
        existing_id = str((existing.get("payload") or {}).get("evidence_id", "")); entity = load_data(repository.task_dir(task_id) / "evidence" / f"{existing_id}.json"); ok = int((entity.get("execution") or {}).get("exit_code", 1)) == 0; _emit({"ok": ok, "evidence": entity, "idempotent_replay": True}, json_output)
        if not ok: raise typer.Exit(ExitCode.EVIDENCE)
        return
    git = GitRepository(repo)
    if commit and not git.workspace_equivalent_to_commit("HEAD", task_id=task_id):
        raise MacError("EVIDENCE_COMMIT_WORKSPACE_DIRTY", "commit evidence requires a workspace exactly equivalent to HEAD", exit_code=ExitCode.EVIDENCE, task_id=task_id)
    run_id, started = prefixed("RUN"), utc_now(); completed = subprocess.run(argv, cwd=repo, shell=False); finished = utc_now()
    if commit and not git.workspace_equivalent_to_commit("HEAD", task_id=task_id):
        raise MacError("EVIDENCE_COMMAND_CHANGED_WORKSPACE", "command changed the workspace; commit evidence cannot bind HEAD", exit_code=ExitCode.EVIDENCE, task_id=task_id)
    subject = git.current_code_subject(task_id) if commit else git.workspace_subject(task_id=task_id); task = _repository(repo).load_task(task_id)
    run = {"schema_version": 1, "id": run_id, "task_id": task_id, "work_unit_id": "verification", "status": "succeeded" if completed.returncode == 0 else "failed", "actor": _actor(actor, "automation"), "runtime": {"profile": "local-command", "execution_context_id": run_id}, "independence_level": "L0", "started_at": started, "finished_at": finished, "exit_code": completed.returncode}
    entity = {"schema_version": 1, "id": prefixed("EVD"), "task_id": task_id, "kind": "command", "subject": subject, "policy_digest": task["policy_ref"]["combined_digest"], "run_id": run_id, "claims": [{"gate": claim}], "execution": {"argv": argv, "exit_code": completed.returncode, "started_at": started, "finished_at": finished}, "environment": {"os": platform.system().lower(), "architecture": platform.machine(), "tool_versions": {"python": platform.python_version()}}, "artifacts": [], "recorded_at": finished, "validity": {"status": "valid" if completed.returncode == 0 else "invalid", "invalidated_by": []}}
    entity = _write_entity(repo, task_id, "evidence", entity, "evidence.schema.json", "evidence_recorded", expected_revision=expected_revision, idempotency_key=idempotency_key, actor=actor, related_entities=[(_repository(repo).task_dir(task_id)/"runs"/f"{run_id}.json", run)], event_payload={"run": run}); _emit({"ok": completed.returncode == 0, "evidence": entity}, json_output)
    if completed.returncode: raise typer.Exit(ExitCode.EVIDENCE)


@evidence_app.command("promote")
def evidence_promote(task_id: str, evidence_id: str, expected_revision: int = typer.Option(..., "--expected-revision"), idempotency_key: str = typer.Option(..., "--idempotency-key"), actor: str = typer.Option("cli-automation"), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    repository = _repository(repo)
    if replay := _operation_replay(repository, task_id, idempotency_key, "evidence_recorded"):
        payload = replay.get("payload") or {}; _emit({"ok": True, "evidence": payload.get("evidence"), "promotion": payload.get("promotion")}, json_output); return
    directory = repository.task_dir(task_id)/"evidence"; source = load_data(directory/f"{evidence_id}.json"); git = GitRepository(repo); workspace = git.workspace_subject(task_id=task_id); target = git.current_code_subject(task_id); promoted = promote_evidence(source, current_workspace_subject=workspace, target_commit_subject=target, workspace_equivalent=git.workspace_equivalent_to_commit("HEAD", task_id=task_id, source_workspace_subject=source.get("subject"))); entity = _write_entity(repo, task_id, "evidence", promoted.evidence, "evidence.schema.json", "evidence_recorded", expected_revision=expected_revision, idempotency_key=idempotency_key, actor=actor, event_payload={"promotion": promoted.event_payload}); _emit({"ok": True, "evidence": entity, "promotion": promoted.event_payload}, json_output)


@evidence_app.command("invalidate")
def evidence_invalidate(task_id: str, evidence_id: str, reason: str = typer.Option(...), expected_revision: int = typer.Option(..., "--expected-revision"), idempotency_key: str = typer.Option(..., "--idempotency-key"), actor: str = typer.Option("cli-automation"), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    repository = _repository(repo)
    if replay := _operation_replay(repository, task_id, idempotency_key, "evidence_invalidated"):
        _emit({"ok": True, "evidence": (replay.get("payload") or {}).get("evidence")}, json_output); return
    path = repository.task_dir(task_id)/"evidence"/f"{evidence_id}.json"; event_id = prefixed("EVT"); entity = invalidate_evidence(load_data(path), event_id=event_id, reason=reason); appended = repository.append_event(task_id, "evidence_invalidated", {"evidence_id": evidence_id, "evidence": entity, "reason": reason}, actor=_actor(actor), expected_revision=expected_revision, idempotency_key=idempotency_key, event_id=event_id, materializations=[(path, entity)], replace_existing={path}); snapshot = (appended.event.get("payload") or {}).get("evidence"); _emit({"ok": True, "evidence": snapshot if isinstance(snapshot, dict) else load_data(path)}, json_output)


@evidence_app.command("list")
def evidence_list(task_id: str, repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None: _emit({"ok": True, "evidence": [load_data(path) for path in _entity_paths(repo, task_id, "evidence", "json")]}, json_output)


@finding_app.command("open")
def finding_open(task_id: str, title: str = typer.Option(...), risk: str = typer.Option(...), severity: str = typer.Option(...), category: str = typer.Option(...), blocking_effect: str = typer.Option("block_close"), owner: str = typer.Option(...), expected_revision: int = typer.Option(...), idempotency_key: str = typer.Option(...), actor: str = typer.Option("cli-user"), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    entity = {"schema_version": 1, "id": prefixed("FND"), "task_id": task_id, "severity": severity, "category": category, "blocking_effect": blocking_effect, "confidence": "confirmed", "status": "open", "title": title, "risk": risk, "owner": owner, "evidence_refs": [], "invalidates": [], "opened_at": utc_now(), "resolved_at": None}; entity = _write_entity(repo, task_id, "findings", entity, "finding.schema.json", "finding_opened", expected_revision=expected_revision, idempotency_key=idempotency_key, actor=actor); _emit({"ok": True, "finding": entity}, json_output)


@finding_app.command("resolve")
def finding_resolve(task_id: str, finding_id: str, expected_revision: int = typer.Option(..., "--expected-revision"), idempotency_key: str = typer.Option(..., "--idempotency-key"), actor: str = typer.Option("cli-user"), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    _emit({"ok": True, "finding": _event_update_entity(repo, task_id, "findings", finding_id, "finding.schema.json", "finding_resolved", {"status": "resolved", "resolved_at": utc_now()}, expected_revision=expected_revision, idempotency_key=idempotency_key, actor=actor)}, json_output)


@finding_app.command("waive")
def finding_waive(task_id: str, finding_id: str, rationale: str = typer.Option(..., "--rationale"), control: list[str] = typer.Option(..., "--control"), expires_at: str = typer.Option(..., "--expires-at"), expected_revision: int = typer.Option(..., "--expected-revision"), idempotency_key: str = typer.Option(..., "--idempotency-key"), actor: str = typer.Option(..., "--actor"), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    repository = _repository(repo)
    if replay := _operation_replay(repository, task_id, idempotency_key, "risk_accepted"):
        payload = replay.get("payload") or {}; _emit({"ok": True, "finding": payload.get("finding"), "risk_acceptance": payload.get("risk_acceptance")}, json_output); return
    directory = repository.task_dir(task_id); finding_path = directory / "findings" / f"{finding_id}.json"; finding = load_data(finding_path); scope = load_data(directory / "scope-contract.yaml"); config = load_data(repo / ".agents/config.yaml"); ownership = load_data(repo / str(config["paths"]["ownership"])); authorized = owner_approvers(scope, ownership)
    acceptance = {"schema_version": 1, "id": prefixed("RISK"), "task_id": task_id, "finding_ids": [finding_id], "accepted_by": _actor(actor), "accepted_at": utc_now(), "rationale": rationale, "compensating_controls": control, "expires_at": expires_at, "scope": {"paths": list(scope.get("allowed_paths", []))}}
    decision = validate_risk_acceptance(acceptance, [finding], authorized_actor_ids=authorized, non_waivable_gates=set((config.get("close_policy") or {}).get("non_waivable_gates", [])))
    if not decision.ok: raise MacError("RISK_ACCEPTANCE_REJECTED", "finding cannot be waived", exit_code=ExitCode.SECURITY, details={"issues": [item.as_dict() for item in decision.issues]})
    waived = deepcopy(finding); waived["status"] = "waived"; risk_path = directory / "risk-acceptances" / f"{acceptance['id']}.json"
    entity = _write_entity(repo, task_id, "risk-acceptances", acceptance, "risk-acceptance.schema.json", "risk_accepted", expected_revision=expected_revision, idempotency_key=idempotency_key, actor=actor, related_entities=[(finding_path, waived)], event_payload={"finding": waived}, replace_existing={finding_path}); _emit({"ok": True, "finding": waived, "risk_acceptance": entity}, json_output)


@finding_app.command("list")
def finding_list(task_id: str, repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None: _emit({"ok": True, "findings": [load_data(path) for path in _entity_paths(repo, task_id, "findings", "json")]}, json_output)


@approval_app.command("record")
def approval_record(task_id: str, kind: str = typer.Option(...), decision: str = typer.Option(...), subject_ref: str = typer.Option(...), actor: str = typer.Option(...), independence_level: str = typer.Option("L1"), expected_revision: int = typer.Option(..., "--expected-revision"), idempotency_key: str = typer.Option(..., "--idempotency-key"), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    repository = _repository(repo)
    if replay := _operation_replay(repository, task_id, idempotency_key, "scope_approved"):
        _emit({"ok": True, "approval": (replay.get("payload") or {}).get("approval")}, json_output); return
    entity = {"schema_version": 1, "id": prefixed("APR"), "task_id": task_id, "kind": kind, "actor": _actor(actor), "decision": decision, "subject_ref": subject_ref, "independence_level": independence_level, "recorded_at": utc_now()}; issues = SchemaSet().validate(entity, "approval.schema.json", path="approval");
    if issues: raise MacError("SCHEMA_INVALID", issues[0].message, exit_code=ExitCode.VALIDATION)
    scope = load_data(repository.task_dir(task_id) / "scope-contract.yaml"); config = load_data(repo / ".agents/config.yaml"); ownership = load_data(repo / str(config["paths"]["ownership"]));
    if not actor_authorized_for_scope(actor, scope, ownership): raise MacError("APPROVAL_ACTOR_UNAUTHORIZED", "actor is not an authorized owner approver", exit_code=ExitCode.SECURITY, task_id=task_id)
    entity = _write_entity(repo, task_id, "approvals", entity, "approval.schema.json", "scope_approved", expected_revision=expected_revision, idempotency_key=idempotency_key, actor=actor, event_payload={"approval_kind": kind}); _emit({"ok": True, "approval": entity}, json_output)


@approval_app.command("verify")
def approval_verify(task_id: str, repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    values = [load_data(path) for path in _entity_paths(repo, task_id, "approvals", "json")]; issues = [issue for value in values for issue in SchemaSet().validate(value, "approval.schema.json", path=str(value.get("id")))]; _emit({"ok": not issues, "approvals": values, "issues": [item.as_dict() for item in issues]}, json_output)


@handoff_app.command("build")
def handoff_build(task_id: str, work_unit_id: str = typer.Option(...), out: Path = typer.Option(...), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    directory = _repository(repo).task_dir(task_id); packet = build_handoff_packet(load_data(directory/"task.yaml"), load_data(directory/"work-units"/f"{work_unit_id}.yaml"), load_data(directory/"scope-contract.yaml"), open_findings=[load_data(path) for path in (directory/"findings").glob("*.json")], invalidated_evidence=[load_data(path) for path in (directory/"evidence").glob("*.json") if (load_data(path).get("validity") or {}).get("status") != "valid"], result_path=f"tasks/{task_id}/results/{prefixed('RESULT')}.json"); write_handoff_packet(out, packet); _emit({"ok": True, "path": str(out), "packet": packet}, json_output)


@handoff_app.command("collect")
def handoff_collect(task_id: str, path: Path, expected_revision: int = typer.Option(...), idempotency_key: str = typer.Option(...), actor: str = typer.Option("cli-user"), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None: result_submit(task_id, path, expected_revision, idempotency_key, actor, repo, json_output)


@report_app.command("render")
def report_render(task_id: str, out: Optional[Path] = typer.Option(None), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None:
    directory = _repository(repo).task_dir(task_id); content = render_task_report(directory); target = out or directory/"report.md"; target.write_text(content, encoding="utf-8"); _emit({"ok": True, "path": str(target)}, json_output)


@report_app.command("bundle")
def report_bundle(task_id: str, out: Path = typer.Option(...), redact: bool = typer.Option(True), repo: Path = typer.Option(Path(".")), json_output: bool = typer.Option(False, "--json")) -> None: _emit({"ok": True, "manifest": build_audit_bundle(_repository(repo).task_dir(task_id), out, redact=redact)}, json_output)


@report_app.command("verify-bundle")
def report_verify_bundle(bundle: Path = typer.Argument(..., exists=True, dir_okay=False), json_output: bool = typer.Option(False, "--json")) -> None:
    _emit(verify_audit_bundle(bundle), json_output)


@index_app.command("build")
def index_build(repo: Path = typer.Option(Path(".")), out: Optional[Path] = typer.Option(None), json_output: bool = typer.Option(False, "--json")) -> None:
    payload = {"schema_version": 1, "generated_at": utc_now(), "tasks": build_index(repo)}; target = out or repo/"tasks"/"INDEX.generated.json"; atomic_write_json(target, payload); _emit({"ok": True, "path": str(target), **payload}, json_output)


@migrate_app.command("v5-to-v6")
def migrate_v5(repo: Path = typer.Option(Path(".")), scan: bool = typer.Option(False), apply: bool = typer.Option(False), output: Optional[Path] = typer.Option(None), report: Optional[Path] = typer.Option(None), json_output: bool = typer.Option(False, "--json")) -> None:
    payload = scan_v5(repo) if scan and not apply else convert_v5(repo, output=output, dry_run=not apply)
    if report: atomic_write_json(report, payload)
    _emit({"ok": True, **payload}, json_output)


def _emit_error(error: MacError) -> None:
    typer.echo(json.dumps(error.as_dict(), ensure_ascii=False), err=True)


def main(args: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if args is None else args)
    try:
        result = app(args=argv, standalone_mode=False)
        if isinstance(result, int) and result != 0:
            raise SystemExit(result)
    except MacError as exc:
        _emit_error(exc)
        raise SystemExit(exc.exit_code)
    except click.exceptions.Exit as exc:
        raise SystemExit(exc.exit_code)
    except click.ClickException as exc:
        error = MacError(
            "CLI_USAGE_ERROR",
            exc.format_message(),
            exit_code=ExitCode.CLI_USAGE,
            field=str(getattr(exc, "param_hint", "")) or None,
            suggestion="run the leaf command with --help to inspect required arguments",
        )
        _emit_error(error)
        raise SystemExit(error.exit_code)
    except FileNotFoundError as exc:
        error = MacError(
            "FILE_NOT_FOUND",
            "required input file does not exist",
            exit_code=ExitCode.VALIDATION,
            path=str(exc.filename) if exc.filename else None,
        )
        _emit_error(error)
        raise SystemExit(error.exit_code)
    except ValueError as exc:
        error = MacError("INPUT_INVALID", str(exc), exit_code=ExitCode.VALIDATION)
        _emit_error(error)
        raise SystemExit(error.exit_code)
    except Exception as exc:
        error = MacError(
            "INTERNAL_ERROR",
            "internal command failure",
            exit_code=ExitCode.INTERNAL,
            details={"exception_type": type(exc).__name__},
        )
        _emit_error(error)
        raise SystemExit(error.exit_code)


if __name__ == "__main__":
    main()
