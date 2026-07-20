from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from mac.errors import MacIssue


@dataclass(frozen=True, slots=True)
class Decision:
    ok: bool
    issues: tuple[MacIssue, ...] = ()

    @property
    def codes(self) -> tuple[str, ...]:
        return tuple(issue.code for issue in self.issues)


@dataclass(frozen=True, slots=True)
class CloseDecision(Decision):
    covered_gates: tuple[str, ...] = ()
    covered_acceptance: tuple[str, ...] = ()


_LEVEL = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}


def _issue(code: str, message: str, *, details: dict[str, Any] | None = None) -> MacIssue:
    return MacIssue(code, message, details=details)


def _claim_values(evidence: Mapping[str, Any]) -> set[str]:
    result: set[str] = set()
    for claim in evidence.get("claims", []):
        if claim.get("gate"):
            result.add(str(claim["gate"]))
        if claim.get("acceptance_criterion"):
            result.add(str(claim["acceptance_criterion"]))
    return result


def evaluate_evidence(
    evidence: Mapping[str, Any], *, current_subject: Mapping[str, Any], policy_digest: str,
    runs: Mapping[str, Mapping[str, Any]] | None = None, required_independence: str = "L0",
    applicable_claims: set[str] | None = None,
) -> Decision:
    issues: list[MacIssue] = []
    validity = evidence.get("validity", {})
    if validity.get("status") != "valid" or validity.get("invalidated_by"):
        issues.append(_issue("EVIDENCE_STATUS_INVALID", "evidence is invalid, expired, unverifiable, or explicitly invalidated"))
    if dict(evidence.get("subject", {})) != dict(current_subject):
        issues.append(_issue("EVIDENCE_SUBJECT_MISMATCH", "evidence does not bind the current code subject"))
    if evidence.get("policy_digest") != policy_digest:
        issues.append(_issue("EVIDENCE_POLICY_MISMATCH", "evidence does not bind the frozen policy digest"))
    claims = _claim_values(evidence)
    if not claims:
        issues.append(_issue("EVIDENCE_CLAIMS_MISSING", "evidence has no gate or acceptance claim"))
    if applicable_claims is not None and not claims.intersection(applicable_claims):
        issues.append(_issue("EVIDENCE_CLAIM_NOT_APPLICABLE", "evidence claims are no longer applicable"))
    run_id = evidence.get("run_id")
    run = (runs or {}).get(str(run_id)) if run_id else None
    if evidence.get("kind") != "manual":
        if run is None and runs is not None:
            issues.append(_issue("EVIDENCE_RUN_INVALID", "evidence run is missing"))
        elif run is not None and run.get("status") != "succeeded":
            issues.append(_issue("EVIDENCE_RUN_INVALID", "evidence run did not complete successfully"))
    execution = evidence.get("execution") or {}
    if evidence.get("kind") in {"command", "ci", "static_analysis", "deployment"} and execution.get("exit_code") != 0:
        issues.append(_issue("EVIDENCE_RUN_INVALID", "evidence execution has a non-zero or missing exit code"))
    level = (evidence.get("review") or {}).get("independence_level") or (run or {}).get("independence_level", "L0")
    if _LEVEL.get(str(level), -1) < _LEVEL.get(required_independence, 0):
        issues.append(_issue("EVIDENCE_INDEPENDENCE_INSUFFICIENT", f"evidence independence {level} is below {required_independence}"))
    return Decision(not issues, tuple(issues))


def evaluate_review_independence(
    review_evidence: Mapping[str, Any], reviewer_run: Mapping[str, Any], implementer_runs: Iterable[Mapping[str, Any]], *,
    current_diff_digest: str, minimum_level: str,
    runtime_profiles: Mapping[str, Mapping[str, Any]] | None = None,
    verified_run_ids: set[str] | None = None,
) -> Decision:
    issues: list[MacIssue] = []
    implementers = list(implementer_runs)
    reviewer_id = str(reviewer_run.get("id", review_evidence.get("run_id", "")))
    if any(str(run.get("id")) == reviewer_id for run in implementers):
        issues.append(_issue("REVIEW_SAME_RUN", "review and implementation use the same run"))
    reviewer_context = (reviewer_run.get("runtime") or {}).get("execution_context_id")
    if reviewer_context and any((run.get("runtime") or {}).get("execution_context_id") == reviewer_context for run in implementers):
        issues.append(_issue("REVIEW_SAME_CONTEXT", "review and implementation use the same execution context"))
    reviewer_actor = str((reviewer_run.get("actor") or {}).get("id", ""))
    implementer_actors = {str((run.get("actor") or {}).get("id", "")) for run in implementers}
    if not reviewer_actor or reviewer_actor in implementer_actors:
        issues.append(_issue("REVIEW_COMMIT_PARTICIPATION", "reviewer actor is missing or participated in implementation"))
    review = review_evidence.get("review") or {}
    if review.get("reviewed_diff_digest") != current_diff_digest:
        issues.append(_issue("REVIEW_DIFF_STALE", "reviewed diff changed after review"))
    review_level = str(review.get("independence_level") or "L0")
    run_level = str(reviewer_run.get("independence_level", "L0"))
    if _LEVEL.get(review_level, -1) > _LEVEL.get(run_level, -1):
        issues.append(_issue("REVIEW_LEVEL_UNATTESTED", "review evidence claims a higher level than its Run"))
    level = min((review_level, run_level), key=lambda value: _LEVEL.get(value, -1))
    if _LEVEL.get(level, -1) < _LEVEL.get(minimum_level, 0):
        issues.append(_issue("REVIEW_LEVEL_INSUFFICIENT", f"review level {level} is below {minimum_level}"))
    if reviewer_run.get("status") != "succeeded":
        issues.append(_issue("REVIEW_RUN_INVALID", "review run is not successful"))
    if _LEVEL.get(minimum_level, 0) >= _LEVEL["L2"]:
        if verified_run_ids is not None:
            unverified = {
                str(run.get("id", "")) for run in [reviewer_run, *implementers]
                if str(run.get("id", "")) not in verified_run_ids
            }
            if unverified:
                issues.append(_issue(
                    "REVIEW_PROVENANCE_UNVERIFIED",
                    "L2 review depends on Run provenance without a verified authority event",
                    details={"run_ids": sorted(unverified)},
                ))
        runtime = reviewer_run.get("runtime") or {}
        provider, model, profile_id = runtime.get("provider"), runtime.get("model"), runtime.get("profile")
        if not provider or not model or not profile_id:
            issues.append(_issue("REVIEW_PROVENANCE_MISSING", "L2 review requires provider, model, profile, and context provenance"))
        distinct = False
        for implementer in implementers:
            implementation_runtime = implementer.get("runtime") or {}
            if not implementation_runtime.get("provider") or not implementation_runtime.get("model"):
                issues.append(_issue("REVIEW_IMPLEMENTER_PROVENANCE_MISSING", "implementer provenance is incomplete"))
                continue
            if (
                implementation_runtime.get("profile") != profile_id
                or implementation_runtime.get("provider") != provider
                or implementation_runtime.get("model") != model
            ):
                distinct = True
        if implementers and not distinct:
            issues.append(_issue("REVIEW_RUNTIME_NOT_INDEPENDENT", "L2 review must use a different model or runtime"))
        profile = (runtime_profiles or {}).get(str(profile_id))
        read_only = ((profile or {}).get("capabilities") or {}).get("read_only_run")
        attestation = reviewer_run.get("independence_attestation") or {}
        if attestation and attestation.get("read_only") is not True:
            issues.append(_issue("REVIEW_WRITE_CAPABILITY", "L2 reviewer attestation does not prove a read-only run"))
        reviewed_commit = str((review_evidence.get("subject") or {}).get("commit_sha", ""))
        participation = attestation.get("commit_participation") if attestation else None
        if participation is not None and reviewed_commit and reviewed_commit in {str(value) for value in participation}:
            issues.append(_issue("REVIEW_COMMIT_PARTICIPATION", "reviewer participated in the reviewed commit"))
        human_l3 = _LEVEL.get(level, -1) >= _LEVEL["L3"] and (reviewer_run.get("actor") or {}).get("kind") == "human"
        if read_only != "native" and not human_l3:
            issues.append(_issue("REVIEW_WRITE_CAPABILITY", "L2 reviewer runtime is not proven read-only"))
    if _LEVEL.get(minimum_level, 0) >= _LEVEL["L3"] and (reviewer_run.get("actor") or {}).get("kind") != "human":
        issues.append(_issue("REVIEW_HUMAN_REQUIRED", "L3 review requires a human actor"))
    return Decision(not issues, tuple(issues))


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate_risk_acceptance(
    acceptance: Mapping[str, Any], findings: Iterable[Mapping[str, Any]], *, authorized_actor_ids: set[str],
    non_waivable_gates: set[str], now: datetime | None = None,
) -> Decision:
    issues: list[MacIssue] = []
    actor_id = str((acceptance.get("accepted_by") or {}).get("id", ""))
    if actor_id not in authorized_actor_ids:
        issues.append(_issue("RISK_ACTOR_UNAUTHORIZED", "risk acceptor is not authorized"))
    current = now or datetime.now(timezone.utc)
    try:
        if _parse_time(str(acceptance.get("expires_at"))) <= current:
            issues.append(_issue("RISK_EXPIRED", "risk acceptance is expired"))
    except (TypeError, ValueError):
        issues.append(_issue("RISK_EXPIRED", "risk acceptance expiry is invalid"))
    by_id = {str(finding.get("id")): finding for finding in findings}
    for finding_id in acceptance.get("finding_ids", []):
        finding = by_id.get(str(finding_id))
        if finding is None:
            issues.append(_issue("RISK_FINDING_UNKNOWN", f"finding {finding_id} does not exist"))
            continue
        if finding.get("blocking_effect") != "waiver_allowed":
            issues.append(_issue("RISK_FINDING_NOT_WAIVABLE", f"finding {finding_id} cannot be waived"))
        category = str(finding.get("category", ""))
        severity = str(finding.get("severity", ""))
        confidence = str(finding.get("confidence", ""))
        if confidence == "confirmed" and category in {"security", "data", "compliance", "independence", "data_integrity"}:
            issues.append(_issue("RISK_CATEGORY_NON_WAIVABLE", f"confirmed {category} finding {finding_id} cannot be waived"))
        gates = set(str(value) for value in finding.get("invalidates", []))
        if gates & non_waivable_gates:
            issues.append(_issue("RISK_NON_WAIVABLE", f"finding {finding_id} invalidates a non-waivable gate", details={"gates": sorted(gates & non_waivable_gates)}))
        if gates & {"compliance", "regulatory", "contract", "independent_review", "data_integrity"}:
            issues.append(_issue("RISK_NON_WAIVABLE", f"finding {finding_id} invalidates a mandatory legal, data, or review gate"))
    if not acceptance.get("rationale") or not acceptance.get("compensating_controls"):
        issues.append(_issue("RISK_CONTROL_INCOMPLETE", "rationale and compensating controls are required"))
    return Decision(not issues, tuple(issues))


def record_verified_scope_approval(
    repo: Path,
    task_id: str,
    *,
    declared_actor: str,
    independence_level: str,
    expected_revision: int,
    idempotency_key: str,
    authority_context: Any,
) -> dict[str, Any]:
    """Event-first scope approval entrypoint for an external verifier adapter."""

    from mac.authority import require_external_authority, valid_scope_approvals
    from mac.ids import prefixed
    from mac.io import load_data
    from mac.policy import compile_policy
    from mac.repository import FilesystemTaskRepository, utc_now
    from mac.schema_validation import SchemaSet

    context = require_external_authority(declared_actor, authority_context, operation="scope approval")
    repository = FilesystemTaskRepository(repo)
    directory = repository.task_dir(task_id)
    existing = next(
        (event for event in repository.list_events(task_id) if event.get("idempotency_key") == idempotency_key),
        None,
    )
    if existing is not None:
        if existing.get("event_type") != "scope_approved":
            from mac.errors import ExitCode, MacError

            raise MacError("EVENT_IDEMPOTENCY_CONFLICT", "idempotency key belongs to another operation", exit_code=ExitCode.CONFLICT)
        payload = existing.get("payload") or {}
        if (payload.get("verified_authority") or {}).get("assertion_digest") != context.assertion_digest:
            from mac.errors import ExitCode, MacError

            raise MacError("ACTOR_CONTEXT_MISMATCH", "idempotent approval belongs to another verified context", exit_code=ExitCode.SECURITY)
        return {"scope": payload.get("scope"), "approval": payload.get("approval"), "event": existing}
    scope_path = directory / "scope-contract.yaml"
    task = repository.load_task(task_id)
    scope = load_data(scope_path)
    if scope.get("status") != "proposed":
        from mac.errors import ExitCode, MacError

        raise MacError("SCOPE_NOT_PROPOSED", "only proposed scope can be approved", exit_code=ExitCode.SCOPE)
    compiled = compile_policy(repo, task=task)
    approval = {
        "schema_version": 1,
        "id": prefixed("APR"),
        "task_id": task_id,
        "kind": "scope",
        "actor": context.actor(),
        "decision": "approved",
        "subject_ref": str(task["scope_contract_ref"]),
        "independence_level": independence_level,
        "recorded_at": utc_now(),
    }
    issues = SchemaSet(repo.resolve() / "schemas").validate(
        approval, "approval.schema.json", path=f"approvals/{approval['id']}.json",
    )
    if issues or not valid_scope_approvals(task, scope, [approval], compiled.ownership, compiled.config):
        from mac.errors import ExitCode, MacError

        raise MacError(
            "SCOPE_APPROVER_UNAUTHORIZED",
            "verified actor lacks frozen owner authority or required independence",
            exit_code=ExitCode.SECURITY,
            details={"issues": [item.as_dict() for item in issues]},
        )
    approved_scope = deepcopy(scope)
    approved_scope["status"] = "approved"
    approved_scope["approved_by"] = [context.actor_id]
    approval_path = directory / "approvals" / f"{approval['id']}.json"
    result = repository.append_event(
        task_id,
        "scope_approved",
        {
            "scope_id": approved_scope["id"],
            "version": approved_scope["version"],
            "approval_id": approval["id"],
            "approval": approval,
            "scope": approved_scope,
        },
        actor=context.actor(),
        expected_revision=expected_revision,
        idempotency_key=idempotency_key,
        materializations=[(approval_path, approval), (scope_path, approved_scope)],
        replace_existing={scope_path},
        authority_context=context,
    )
    return {"scope": approved_scope, "approval": approval, "event": result.event}


def evaluate_close(
    task: Mapping[str, Any], scope: Mapping[str, Any], evidence: Iterable[Mapping[str, Any]],
    findings: Iterable[Mapping[str, Any]], runs: Mapping[str, Mapping[str, Any]],
    risk_acceptances: Iterable[Mapping[str, Any]], *, current_subject: Mapping[str, Any], policy_digest: str,
    close_actor: str, authorized_closers: set[str], non_waivable_gates: set[str],
    authorized_risk_acceptors: set[str] | None = None, current_diff_digest: str | None = None,
    runtime_profiles: Mapping[str, Mapping[str, Any]] | None = None,
    minimum_review_level: str | None = None, review_required: bool | None = None,
    verified_run_ids: set[str] | None = None,
    trusted_risk_acceptance_ids: set[str] | None = None,
) -> CloseDecision:
    issues: list[MacIssue] = []
    if scope.get("status") != "approved":
        issues.append(_issue("CLOSE_SCOPE_UNAPPROVED", "scope contract is not approved"))
    if close_actor not in authorized_closers:
        issues.append(_issue("CLOSE_ACTOR_UNAUTHORIZED", "close actor is not authorized"))
    if task.get("work_units_complete") is False:
        issues.append(_issue("CLOSE_WORK_UNITS_INCOMPLETE", "required work units are incomplete"))
    required_gates = set(str(value) for value in task.get("required_gates", []))
    required_acceptance = {str(item["id"]) for item in task.get("acceptance_criteria", []) if item.get("required", True)}
    applicable = required_gates | required_acceptance
    valid_evidence: list[Mapping[str, Any]] = []
    for item in evidence:
        decision = evaluate_evidence(item, current_subject=current_subject, policy_digest=policy_digest, runs=runs, applicable_claims=applicable)
        if decision.ok:
            valid_evidence.append(item)
        else:
            issues.extend(decision.issues)
    covered = set().union(*(_claim_values(item) for item in valid_evidence)) if valid_evidence else set()
    missing_gates = required_gates - covered
    missing_acceptance = required_acceptance - covered
    if missing_gates:
        issues.append(_issue("CLOSE_GATE_MISSING", "required gates lack valid evidence", details={"gates": sorted(missing_gates)}))
    if missing_acceptance:
        issues.append(_issue("CLOSE_ACCEPTANCE_MISSING", "required acceptance criteria lack valid evidence", details={"acceptance": sorted(missing_acceptance)}))
    finding_list = list(findings)
    acceptance_list = list(risk_acceptances)
    accepted_ids: set[str] = set()
    for acceptance in acceptance_list:
        acceptance_id = str(acceptance.get("id", ""))
        if trusted_risk_acceptance_ids is not None and acceptance_id not in trusted_risk_acceptance_ids:
            issues.append(_issue(
                "RISK_AUTHORITY_UNVERIFIED",
                f"risk acceptance {acceptance_id} lacks a verified authority event",
            ))
            continue
        decision = validate_risk_acceptance(
            acceptance, finding_list, authorized_actor_ids=authorized_risk_acceptors or authorized_closers,
            non_waivable_gates=non_waivable_gates,
        )
        if decision.ok:
            accepted_ids.update(str(value) for value in acceptance.get("finding_ids", []))
        else:
            issues.extend(decision.issues)
    for finding in finding_list:
        if finding.get("status") in {"resolved", "obsolete"} or finding.get("blocking_effect") == "advisory":
            continue
        finding_id = str(finding.get("id"))
        if finding.get("blocking_effect") == "waiver_allowed" and finding_id in accepted_ids:
            continue
        issues.append(_issue("CLOSE_FINDING_BLOCKING", f"finding {finding_id} blocks close"))
    mode = str(task.get("mode", "standard"))
    minimum = minimum_review_level or {"standard": "L1", "high_risk": "L2", "audit": "L3"}.get(mode, "L1")
    needs_review = review_required if review_required is not None else ("independent_review" in required_gates or mode in {"high_risk", "audit"})
    if needs_review:
        review_ok = False
        implementation_run_ids = {
            str(item.get("run_id")) for item in valid_evidence
            if item.get("kind") != "review" and item.get("run_id")
        }
        for item in valid_evidence:
            if item.get("kind") != "review":
                continue
            reviewer = runs.get(str(item.get("run_id")), {})
            implementers = [run for run in runs.values() if str(run.get("id")) in implementation_run_ids]
            if not implementers:
                implementers = [run for run in runs.values() if str(run.get("id")) != str(reviewer.get("id"))]
            digest = current_diff_digest or str((item.get("review") or {}).get("reviewed_diff_digest", ""))
            review_decision = evaluate_review_independence(
                item, reviewer, implementers, current_diff_digest=digest,
                minimum_level=minimum, runtime_profiles=runtime_profiles,
                verified_run_ids=verified_run_ids,
            )
            if review_decision.ok:
                review_ok = True
                break
            issues.extend(review_decision.issues)
        if not review_ok:
            issues.append(_issue("CLOSE_REVIEW_MISSING", f"{mode} close requires an independent {minimum} review"))
    return CloseDecision(not issues, tuple(issues), tuple(sorted(required_gates & covered)), tuple(sorted(required_acceptance & covered)))
