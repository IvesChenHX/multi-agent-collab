from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from mac.authority import scope_binding_matches
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
    accepted_risk_acceptances: tuple[str, ...] = ()


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
    applicable_claims: set[str] | None = None, record_revision: int | None = None,
    minimum_revision: int | None = None,
) -> Decision:
    issues: list[MacIssue] = []
    validity = evidence.get("validity", {})
    if validity.get("status") != "valid" or validity.get("invalidated_by"):
        issues.append(_issue("EVIDENCE_STATUS_INVALID", "evidence is invalid, expired, unverifiable, or explicitly invalidated"))
    if dict(evidence.get("subject", {})) != dict(current_subject):
        issues.append(_issue("EVIDENCE_SUBJECT_MISMATCH", "evidence does not bind the current code subject"))
    if evidence.get("policy_digest") != policy_digest:
        issues.append(_issue("EVIDENCE_POLICY_MISMATCH", "evidence does not bind the frozen policy digest"))
    if (
        minimum_revision is not None
        and record_revision is not None
        and record_revision < minimum_revision
    ):
        issues.append(_issue("EVIDENCE_SCOPE_STALE", "evidence does not bind the current approved Scope version"))
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
) -> Decision:
    issues: list[MacIssue] = []
    implementers = list(implementer_runs)
    reviewer_id = str(reviewer_run.get("id", review_evidence.get("run_id", "")))
    if any(str(run.get("id")) == reviewer_id for run in implementers):
        issues.append(_issue("REVIEW_SAME_RUN", "review and implementation use the same run"))
    reviewer_context = (reviewer_run.get("runtime") or {}).get("execution_context_id")
    if _LEVEL.get(minimum_level, 0) >= _LEVEL["L1"] and not implementers:
        issues.append(_issue("REVIEW_IMPLEMENTATION_RUNS_MISSING", "independent review requires the complete implementation run set"))
    if _LEVEL.get(minimum_level, 0) >= _LEVEL["L1"] and not reviewer_context:
        issues.append(_issue("REVIEW_PROVENANCE_MISSING", "independent review requires an execution context"))
    if _LEVEL.get(minimum_level, 0) >= _LEVEL["L1"] and any(not (run.get("runtime") or {}).get("execution_context_id") for run in implementers):
        issues.append(_issue("REVIEW_IMPLEMENTER_PROVENANCE_MISSING", "implementer execution context is incomplete"))
    if reviewer_context and any((run.get("runtime") or {}).get("execution_context_id") == reviewer_context for run in implementers):
        issues.append(_issue("REVIEW_SAME_CONTEXT", "review and implementation use the same execution context"))
    reviewer_actor = str((reviewer_run.get("actor") or {}).get("id", ""))
    implementer_actors = {str((run.get("actor") or {}).get("id", "")) for run in implementers}
    if not reviewer_actor or reviewer_actor in implementer_actors:
        issues.append(_issue("REVIEW_COMMIT_PARTICIPATION", "reviewer actor is missing or participated in implementation"))
    review = review_evidence.get("review") or {}
    if review.get("reviewed_diff_digest") != current_diff_digest:
        issues.append(_issue("REVIEW_DIFF_STALE", "reviewed diff changed after review"))
    claimed_level = str(review.get("independence_level", ""))
    run_level = str(reviewer_run.get("independence_level", ""))
    if not claimed_level or not run_level or claimed_level != run_level:
        issues.append(_issue("REVIEW_LEVEL_ATTESTATION_MISMATCH", "review Evidence and reviewer Run independence levels must match"))
    level = run_level or "L0"
    if _LEVEL.get(level, -1) < _LEVEL.get(minimum_level, 0):
        issues.append(_issue("REVIEW_LEVEL_INSUFFICIENT", f"review level {level} is below {minimum_level}"))
    if reviewer_run.get("status") != "succeeded":
        issues.append(_issue("REVIEW_RUN_INVALID", "review run is not successful"))
    if _LEVEL.get(minimum_level, 0) >= _LEVEL["L2"]:
        runtime = reviewer_run.get("runtime") or {}
        provider, model, profile_id = runtime.get("provider"), runtime.get("model"), runtime.get("profile")
        if not provider or not model or not profile_id:
            issues.append(_issue("REVIEW_PROVENANCE_MISSING", "L2 review requires provider, model, profile, and context provenance"))
        distinct = bool(implementers)
        for implementer in implementers:
            implementation_runtime = implementer.get("runtime") or {}
            if not implementation_runtime.get("provider") or not implementation_runtime.get("model"):
                issues.append(_issue("REVIEW_IMPLEMENTER_PROVENANCE_MISSING", "implementer provenance is incomplete"))
                distinct = False
                continue
            if not (
                implementation_runtime.get("profile") != profile_id
                or implementation_runtime.get("provider") != provider
                or implementation_runtime.get("model") != model
            ):
                distinct = False
        if not distinct:
            issues.append(_issue("REVIEW_RUNTIME_NOT_INDEPENDENT", "L2 review must use a different model or runtime"))
        profile = (runtime_profiles or {}).get(str(profile_id))
        read_only = ((profile or {}).get("capabilities") or {}).get("read_only_run")
        human_l3 = _LEVEL.get(level, -1) >= _LEVEL["L3"] and (reviewer_run.get("actor") or {}).get("kind") == "human"
        if read_only != "native" and not human_l3:
            issues.append(_issue("REVIEW_WRITE_CAPABILITY", "L2 reviewer runtime is not proven read-only"))
        if reviewer_run.get("can_write_business_code") is True and not human_l3:
            issues.append(_issue("REVIEW_WRITE_CAPABILITY", "L2 reviewer Run reports business-code write capability"))
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
        accepted_at = _parse_time(str(acceptance.get("accepted_at")))
        expires_at = _parse_time(str(acceptance.get("expires_at")))
        if accepted_at > current or expires_at <= current or expires_at <= accepted_at:
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
        if confidence == "confirmed" and category in {
            "security", "data", "data_integrity", "compliance", "independence",
        }:
            issues.append(_issue("RISK_CATEGORY_NON_WAIVABLE", f"confirmed {category} finding {finding_id} cannot be waived"))
        gates = set(str(value) for value in finding.get("invalidates", []))
        if gates & non_waivable_gates:
            issues.append(_issue("RISK_NON_WAIVABLE", f"finding {finding_id} invalidates a non-waivable gate", details={"gates": sorted(gates & non_waivable_gates)}))
        if gates & {"compliance", "regulatory", "contract", "independent_review", "data_integrity"}:
            issues.append(_issue("RISK_NON_WAIVABLE", f"finding {finding_id} invalidates a mandatory legal, data, or review gate"))
    if not acceptance.get("rationale") or not acceptance.get("compensating_controls"):
        issues.append(_issue("RISK_CONTROL_INCOMPLETE", "rationale and compensating controls are required"))
    return Decision(not issues, tuple(issues))


def evaluate_close(
    task: Mapping[str, Any], scope: Mapping[str, Any], evidence: Iterable[Mapping[str, Any]],
    findings: Iterable[Mapping[str, Any]], runs: Mapping[str, Mapping[str, Any]],
    risk_acceptances: Iterable[Mapping[str, Any]], *, current_subject: Mapping[str, Any], policy_digest: str,
    close_actor: str, authorized_closers: set[str], non_waivable_gates: set[str],
    authorized_risk_acceptors: set[str] | None = None, current_diff_digest: str | None = None,
    runtime_profiles: Mapping[str, Mapping[str, Any]] | None = None,
    mode_required_gates: Iterable[str] = (), evidence_revisions: Mapping[str, int] | None = None,
    minimum_evidence_revision: int | None = None,
    require_commit_bound_evidence: bool = False,
    evaluated_at: datetime | None = None,
) -> CloseDecision:
    issues: list[MacIssue] = []
    if scope.get("status") != "approved":
        issues.append(_issue("CLOSE_SCOPE_UNAPPROVED", "scope contract is not approved"))
    if close_actor not in authorized_closers:
        issues.append(_issue("CLOSE_ACTOR_UNAUTHORIZED", "close actor is not authorized"))
    if task.get("work_units_complete") is False:
        issues.append(_issue("CLOSE_WORK_UNITS_INCOMPLETE", "required work units are incomplete"))
    required_gates = {
        str(value)
        for values in (task.get("required_gates", []), scope.get("required_gates", []), mode_required_gates)
        for value in values
    }
    required_acceptance = {str(item["id"]) for item in task.get("acceptance_criteria", []) if item.get("required", True)}
    applicable = required_gates | required_acceptance
    valid_evidence: list[Mapping[str, Any]] = []
    invalid_evidence_by_claim: dict[str, list[MacIssue]] = {}
    for item in evidence:
        decision = evaluate_evidence(
            item,
            current_subject=current_subject,
            policy_digest=policy_digest,
            runs=runs,
            applicable_claims=applicable,
            record_revision=(evidence_revisions or {}).get(str(item.get("id", ""))),
            minimum_revision=minimum_evidence_revision,
        )
        if decision.ok and require_commit_bound_evidence and (item.get("subject") or {}).get("type") != "commit":
            decision = Decision(False, (_issue(
                "EVIDENCE_COMMIT_REQUIRED",
                "close requires Evidence bound to an immutable commit subject",
            ),))
        if decision.ok:
            valid_evidence.append(item)
        else:
            for claim in _claim_values(item) & applicable:
                invalid_evidence_by_claim.setdefault(claim, []).extend(decision.issues)
    covered = set().union(*(_claim_values(item) for item in valid_evidence)) if valid_evidence else set()
    missing_gates = required_gates - covered
    missing_acceptance = required_acceptance - covered
    for claim in sorted(missing_gates | missing_acceptance):
        for invalid_issue in invalid_evidence_by_claim.get(claim, []):
            if invalid_issue not in issues:
                issues.append(invalid_issue)
    if missing_gates:
        issues.append(_issue("CLOSE_GATE_MISSING", "required gates lack valid evidence", details={"gates": sorted(missing_gates)}))
    if missing_acceptance:
        issues.append(_issue("CLOSE_ACCEPTANCE_MISSING", "required acceptance criteria lack valid evidence", details={"acceptance": sorted(missing_acceptance)}))
    finding_list = list(findings)
    acceptance_list = list(risk_acceptances)
    accepted_risk_acceptances: set[str] = set()
    for finding in finding_list:
        if finding.get("status") in {"resolved", "obsolete"} or finding.get("blocking_effect") == "advisory":
            continue
        finding_id = str(finding.get("id"))
        if finding.get("blocking_effect") == "waiver_allowed":
            candidate_issues: list[MacIssue] = []
            accepted = False
            for acceptance in acceptance_list:
                if finding_id not in {str(value) for value in acceptance.get("finding_ids", [])}:
                    continue
                if not scope_binding_matches(acceptance.get("scope"), scope):
                    candidate_issues.append(_issue(
                        "RISK_SCOPE_STALE",
                        "risk acceptance does not bind the current approved Scope version",
                        details={"risk_acceptance_id": acceptance.get("id")},
                    ))
                    continue
                decision = validate_risk_acceptance(
                    acceptance,
                    finding_list,
                    authorized_actor_ids=authorized_risk_acceptors or authorized_closers,
                    non_waivable_gates=non_waivable_gates,
                    now=evaluated_at,
                )
                if decision.ok:
                    accepted = True
                    accepted_risk_acceptances.add(str(acceptance.get("id", "")))
                    break
                candidate_issues.extend(decision.issues)
            if accepted:
                continue
            for candidate_issue in candidate_issues:
                if candidate_issue not in issues:
                    issues.append(candidate_issue)
        issues.append(_issue("CLOSE_FINDING_BLOCKING", f"finding {finding_id} blocks close"))
    mode = str(task.get("mode", "standard"))
    minimum = {"standard": "L1", "high_risk": "L2", "audit": "L3"}.get(mode, "L1")
    review_required = "independent_review" in required_gates or mode in {"high_risk", "audit"}
    if review_required:
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
            digest = current_diff_digest or str((item.get("review") or {}).get("reviewed_diff_digest", ""))
            review_decision = evaluate_review_independence(item, reviewer, implementers, current_diff_digest=digest, minimum_level=minimum, runtime_profiles=runtime_profiles)
            if review_decision.ok:
                review_ok = True
                break
            issues.extend(review_decision.issues)
        if not review_ok:
            issues.append(_issue("CLOSE_REVIEW_MISSING", f"{mode} close requires an independent {minimum} review"))
    return CloseDecision(
        not issues,
        tuple(issues),
        tuple(sorted(required_gates & covered)),
        tuple(sorted(required_acceptance & covered)),
        tuple(sorted(value for value in accepted_risk_acceptances if value)),
    )
