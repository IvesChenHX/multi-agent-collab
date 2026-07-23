import hashlib
import json
import shutil
import subprocess
from copy import deepcopy
from dataclasses import replace
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
import yaml

from scripts.ci import governance_pr
from scripts.ci.governance_pr import (
    check_current_evidence,
    discover_task_ids,
    evaluate,
    github_attested_scope_prepare_main,
    github_attested_task_apply_main,
    github_attested_task_prepare_main,
    github_attestation_probe_prepare_main,
    github_attestation_probe_verify_main,
    github_oidc_broker_exchange,
    github_oidc_broker_main,
    github_oidc_probe_main,
)
from mac.authority import AuthorityRequest, canonical_digest
from mac.git import GitRepository
from mac.repository import AppendEvent, CreateTask, Transition
from mac.state_machine import TransitionContext


TASK_ID = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
SUCCESSOR_TASK_ID = "TASK-01KY4P812NAHXDYZDFJ2X3QK9H-github-authority-bootstrap-successor"
REGRESSION_SCOPE_PATHS = [
    "src/mac/authority.py",
    "src/mac/cli.py",
    "src/mac/git.py",
    "src/mac/migration.py",
    "src/mac/repository.py",
    "src/mac/schema_validation.py",
    "src/mac/scope.py",
    "tests/test_event_store.py",
    "tests/test_examples_v6.py",
    "tests/test_migration_and_services.py",
    "tests/test_repair_round4.py",
    "tests/test_repair_round5_platform.py",
    "tests/test_schema_validation.py",
    "tests/test_scope_amendment_and_workflow.py",
    "tests/operations/test_release_artifacts.py",
    "examples/v6/**",
]
BOOTSTRAP_SCOPE_PATHS = [
    "src/mac/authority.py",
    "src/mac/repository.py",
    "src/mac/application/task_service.py",
    "src/mac/cli.py",
    "scripts/ci/governance_pr.py",
    ".github/workflows/governance-pr.yml",
    "tests/operations/test_governance_pr.py",
    "tests/security/test_authority_commands.py",
    "docs/pilot/alpha-close-report.md",
]
SUCCESSOR_REQUIRED_GATES = [
    "targeted_tests",
    "negative_security_tests",
    "secret_scan",
    "scope_guard",
    "compatibility_review",
    "independent_review",
    "rollback_plan",
    "rollback_verification",
    "evidence_matches_current_commit",
]
SUCCESSOR_ALLOWED_OPERATIONS = [
    "read",
    "write",
    "execute_tests",
    "generate_artifacts",
]


def _authority_request() -> AuthorityRequest:
    return AuthorityRequest(
        repository_identity="github:repository-id:1290429577",
        operation="evidence.record",
        task_id=TASK_ID,
        actor_claim={"id": "166317138", "kind": "human"},
        expected_revision=35,
        idempotency_key="github-oidc-authority-test",
        intent_digest=canonical_digest({"evidence": "current"}),
        policy_digest=canonical_digest({"policy": "frozen"}),
        ownership_digest=canonical_digest({"ownership": "frozen"}),
        audience="mac-mutation-gateway/v1",
    )


def _oidc_environment() -> dict[str, str]:
    return {
        "ACTIONS_ID_TOKEN_REQUEST_URL": (
            "https://pipelines.actions.githubusercontent.com/oidc?job=trusted"
        ),
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "github-request-token",
        "MAC_AUTHORITY_BROKER_CONTEXT_ENDPOINT": (
            "https://authority.example.test/v1/decisions"
        ),
        "MAC_AUTHORITY_BROKER_CONTEXT_OIDC_AUDIENCE": "mac-governance-authority",
        "MAC_AUTHORITY_BROKER_MANIFEST_SHA256": "sha256:" + "a" * 64,
    }


def _probe_environment(ref: str = "refs/heads/master") -> dict[str, str]:
    return {
        "GITHUB_REPOSITORY": "IvesChenHX/multi-agent-collab",
        "GITHUB_REPOSITORY_ID": "1290429577",
        "GITHUB_ACTOR_ID": "166317138",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": ref,
        "GITHUB_WORKFLOW_REF": (
            "IvesChenHX/multi-agent-collab/"
            f".github/workflows/governance-pr.yml@{ref}"
        ),
        "GITHUB_RUN_ID": "987654",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_SHA": "a" * 40,
        "MAC_AUTHORITY_PROBE_TASK_ID": TASK_ID,
    }


def _write_probe_task(repo: Path) -> None:
    task_dir = repo / "tasks" / TASK_ID
    task_dir.mkdir(parents=True)
    (task_dir / "task.yaml").write_text(
        yaml.safe_dump(
            {
                "id": TASK_ID,
                "revision": 35,
                "policy_ref": {"combined_digest": "sha256:" + "1" * 64},
                "ownership_ref": {"combined_digest": "sha256:" + "2" * 64},
            }
        ),
        encoding="utf-8",
    )


def _successor_documents(
    task_id: str,
    *,
    profile: str,
    version: int,
) -> tuple[dict[str, object], dict[str, object]]:
    if profile == "bootstrap":
        title = "GitHub authority bootstrap successor"
        objective = (
            "Create the first GitHub-Sigstore-authorized governance successor and "
            "complete the two-phase Mutation Gateway trust loop."
        )
        acceptance = [
            "Every persisted mutation carries a verified non-secret Sigstore authority bundle.",
            "Scope approval and replay succeed against the exact signed mutation intent.",
            "No OIDC bearer token or GitHub token enters Task, Event, Evidence, logs, or Git.",
            "Governance-sensitive changes receive L2 review before merge.",
        ]
        allowed_paths = list(BOOTSTRAP_SCOPE_PATHS)
        allowed_paths.extend([
            f"tasks/{task_id}/**",
            f"tasks/private/{task_id}/**",
        ])
        owners = ["governance", "platform", "security", "devex", "tests", "docs"]
        risk_tags: list[str] = []
        if version >= 2:
            allowed_paths.extend([
                "src/mac/migration.py",
                "tests/test_authorityless_v6_migration.py",
                "migration/v6-authorityless/**",
                "tasks-v6/**",
            ])
            risk_tags = ["data_migration"]
        if version >= 3:
            allowed_paths.append(".github/workflows/ci.yml")
            risk_tags = ["auth_security", "data_migration"]
    else:
        title = "Full regression closure successor"
        objective = (
            "Close the full cross-platform regression suite while preserving the "
            "GitHub-Sigstore authority and commit-bound evidence loop."
        )
        acceptance = [
            "The full locked test suite passes on Linux, macOS, and Windows for every supported Python version.",
            "Trusted repository validation remains green on every CI matrix entry.",
            "Legacy Scope, migration, Git workspace, LFS, and YAML compatibility regressions are covered test-first.",
            "All persisted mutations and completion evidence remain bound to approved Scope and the current commit.",
        ]
        allowed_paths = list(REGRESSION_SCOPE_PATHS)
        allowed_paths.extend([
            f"tasks/{task_id}/**",
            f"tasks/private/{task_id}/**",
        ])
        owners = ["governance", "platform", "devex", "tests", "examples", "docs"]
        risk_tags = ["auth_security", "compatibility", "data_migration"]
    predecessor = TASK_ID
    base_commit = "a" * 40
    task: dict[str, object] = {
        "id": task_id,
        "schema_version": 6,
        "title": title,
        "mode": "high_risk",
        "objective": objective,
        "acceptance_criteria": [
            {"id": f"AC-{index:03d}", "required": True, "text": text}
            for index, text in enumerate(acceptance, start=1)
        ],
        "runtime_profile": "local-multi",
        "required_gates": ["approved_scope", *SUCCESSOR_REQUIRED_GATES],
        "state": "triage",
        "revision": version * 2 - 1,
        "legacy_integrity": "full",
        "active_controller": None,
        "terminal": None,
        "scope_contract_ref": f"tasks/{task_id}/scope-contract.yaml",
        "relationships": {
            "parent_task": predecessor,
            "superseded_by": None,
            "supersedes": [predecessor],
        },
        "policy_ref": {"source_commit": base_commit},
        "ownership_ref": {"source_commit": base_commit},
    }
    scope: dict[str, object] = {
        "id": "SCOPE-01KY58ZZZZZZZZZZZZZZZZZZZZ",
        "schema_version": 1,
        "task_id": task_id,
        "version": version,
        "status": "approved",
        "proposed_by": "governance-owner" if version == 1 else "repo-owner",
        "approved_by": ["repo-owner" if version == 1 else "governance-owner"],
        "base_commit": base_commit,
        "allowed_paths": allowed_paths,
        "allowed_operations": list(SUCCESSOR_ALLOWED_OPERATIONS),
        "denied_paths": [],
        "owners": owners,
        "network_access": "none",
        "secret_access": [],
        "required_gates": list(SUCCESSOR_REQUIRED_GATES),
        "amendment_policy": {
            "max_amendments": 2,
            "max_paths_per_amendment": 4,
            "require_independent_approval_for": [
                "auth_security",
                "production_deploy",
            ],
        },
        "risk_tags": risk_tags,
    }
    return task, scope


def test_github_oidc_bridge_binds_token_audience_and_forwards_no_request_secret():
    request = _authority_request()
    calls: list[dict[str, object]] = []
    signed_response = {"payload": {"decision": "signed"}, "signature": "detached"}

    def request_json(**kwargs: object) -> object:
        calls.append(dict(kwargs))
        if kwargs["method"] == "GET":
            return {"value": "header.payload.signature"}
        return signed_response

    response = github_oidc_broker_exchange(
        request.as_dict(),
        environment=_oidc_environment(),
        request_json=request_json,
    )

    assert response == signed_response
    assert len(calls) == 2
    oidc_call, broker_call = calls
    oidc_query = parse_qs(urlsplit(str(oidc_call["url"])).query)
    assert oidc_query["audience"] == [
        (
            f"mac-governance-authority:{request.binding_digest}:"
            f"sha256:{'a' * 64}"
        )
    ]
    assert oidc_call["headers"] == {
        "Accept": "application/json",
        "Authorization": "bearer github-request-token",
    }
    assert broker_call["url"] == "https://authority.example.test/v1/decisions"
    assert broker_call["headers"] == {
        "Accept": "application/json",
        "Authorization": "Bearer header.payload.signature",
        "Content-Type": "application/json",
        "X-MAC-Authority-Binding": request.binding_digest,
        "X-MAC-Broker-Manifest": "sha256:" + "a" * 64,
        "X-MAC-Authority-Request": request.request_digest,
    }
    broker_body = json.loads(bytes(broker_call["body"]).decode("utf-8"))
    assert broker_body == {
        "schema_version": 1,
        "broker_manifest_digest": "sha256:" + "a" * 64,
        "request": request.as_dict(),
    }
    assert "header.payload.signature" not in json.dumps(broker_body)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ACTIONS_ID_TOKEN_REQUEST_URL", "https://attacker.example/oidc"),
        (
            "MAC_AUTHORITY_BROKER_CONTEXT_ENDPOINT",
            "http://authority.example.test/v1/decisions",
        ),
    ],
)
def test_github_oidc_bridge_rejects_token_exfiltration_routes(name: str, value: str):
    environment = _oidc_environment()
    environment[name] = value

    with pytest.raises(ValueError, match="configuration is invalid"):
        github_oidc_broker_exchange(
            _authority_request().as_dict(),
            environment=environment,
            request_json=lambda **_: pytest.fail("network must not be reached"),
        )


def test_github_oidc_bridge_failure_is_generic_and_does_not_echo_credentials():
    request = _authority_request()
    raw = json.dumps(
        request.as_dict(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    stdout = StringIO()
    stderr = StringIO()

    exit_code = github_oidc_broker_main(
        stdin=StringIO(raw + "\n"),
        stdout=stdout,
        stderr=stderr,
        environment=_oidc_environment(),
        request_json=lambda **_: (_ for _ in ()).throw(
            RuntimeError("github-request-token header.payload.signature")
        ),
    )

    assert exit_code == 2
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "trusted authority OIDC bridge failed\n"


def test_github_oidc_probe_binds_the_pinned_repository_actor_and_task(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    task_dir = tmp_path / "tasks" / TASK_ID
    task_dir.mkdir(parents=True)
    task = {
        "id": TASK_ID,
        "revision": 35,
        "policy_ref": {"combined_digest": "sha256:" + "1" * 64},
        "ownership_ref": {"combined_digest": "sha256:" + "2" * 64},
    }
    (task_dir / "task.yaml").write_text(yaml.safe_dump(task), encoding="utf-8")
    environment = {
        **_oidc_environment(),
        "GITHUB_REPOSITORY": "IvesChenHX/multi-agent-collab",
        "GITHUB_REPOSITORY_ID": "1290429577",
        "GITHUB_ACTOR_ID": "166317138",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/master",
        "GITHUB_WORKFLOW_REF": (
            "IvesChenHX/multi-agent-collab/"
            ".github/workflows/governance-pr.yml@refs/heads/master"
        ),
        "GITHUB_RUN_ID": "987654",
        "GITHUB_RUN_ATTEMPT": "2",
        "MAC_AUTHORITY_PROBE_TASK_ID": TASK_ID,
        "MAC_AUTHORITY_EXPECTED_ISSUER": "github-authority",
        "MAC_AUTHORITY_PUBLIC_KEYRING_B64": "public-keyring",
    }
    captured: dict[str, object] = {}
    verifier = object()
    monkeypatch.setattr(governance_pr, "command_manifest_digest", lambda _: "sha256:" + "a" * 64)
    monkeypatch.setattr(governance_pr, "current_authority_verifier", lambda: verifier)

    def require(verifier_value: object, *, request: AuthorityRequest, minimum_independence: str):
        captured.update(
            verifier=verifier_value,
            request=request,
            minimum_independence=minimum_independence,
        )
        return SimpleNamespace(
            actor_id=request.actor_claim["id"],
            attestation_id="ATT-github-probe",
            binding_digest=request.binding_digest,
            broker_digest="sha256:" + "a" * 64,
            independence_level="L2",
            issuer="github-authority",
            key_id="authority-key-2026",
            request_digest=request.request_digest,
            task_id=request.task_id,
            trust_digest="sha256:" + "b" * 64,
        )

    monkeypatch.setattr(governance_pr, "require_authority", require)
    stdout = StringIO()
    stderr = StringIO()

    exit_code = github_oidc_probe_main(
        repo=tmp_path,
        stdout=stdout,
        stderr=stderr,
        environment=environment,
    )

    assert exit_code == 0
    assert stderr.getvalue() == ""
    request = captured["request"]
    assert isinstance(request, AuthorityRequest)
    assert request.repository_identity == "github:repository-id:1290429577"
    assert request.actor_claim == {"id": "166317138", "kind": "human"}
    assert request.operation == "authority.probe"
    assert request.expected_revision == 35
    assert captured["minimum_independence"] == "L2"
    assert json.loads(stdout.getvalue())["ok"] is True


def test_github_attestation_probe_prepares_canonical_non_secret_documents(tmp_path: Path):
    _write_probe_task(tmp_path)
    subject_path = tmp_path / "out" / "subject.json"
    predicate_path = tmp_path / "out" / "predicate.json"
    stdout = StringIO()
    stderr = StringIO()

    exit_code = github_attestation_probe_prepare_main(
        subject_path=subject_path,
        predicate_path=predicate_path,
        repo=tmp_path,
        stdout=stdout,
        stderr=stderr,
        environment=_probe_environment(),
    )

    assert exit_code == 0
    assert stderr.getvalue() == ""
    subject_raw = subject_path.read_bytes()
    predicate_raw = predicate_path.read_bytes()
    subject = json.loads(subject_raw)
    predicate = json.loads(predicate_raw)
    assert subject_raw == json.dumps(
        subject, sort_keys=True, separators=(",", ":")
    ).encode()
    assert predicate_raw == json.dumps(
        predicate, sort_keys=True, separators=(",", ":")
    ).encode()
    assert subject["request"]["actor_claim"] == {"id": "166317138", "kind": "human"}
    assert subject["request"]["operation"] == "authority.probe"
    assert predicate["environment"] == "governance-authority"
    assert predicate["independence_level"] == "L2"
    assert predicate["source"]["workflow_digest"] == "a" * 40
    rendered = subject_raw + predicate_raw + stdout.getvalue().encode()
    assert b"ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in rendered
    assert b"github-request-token" not in rendered


def test_github_attestation_probe_accepts_only_the_exact_bootstrap_branch(tmp_path: Path):
    _write_probe_task(tmp_path)
    bootstrap = "refs/heads/codex/governance-authority-sigstore"

    assert github_attestation_probe_prepare_main(
        subject_path=tmp_path / "bootstrap-subject.json",
        predicate_path=tmp_path / "bootstrap-predicate.json",
        repo=tmp_path,
        stdout=StringIO(),
        stderr=StringIO(),
        environment=_probe_environment(bootstrap),
    ) == 0
    assert github_attestation_probe_prepare_main(
        subject_path=tmp_path / "rogue-subject.json",
        predicate_path=tmp_path / "rogue-predicate.json",
        repo=tmp_path,
        stdout=StringIO(),
        stderr=StringIO(),
        environment=_probe_environment("refs/heads/codex/rogue"),
    ) == 2


def test_github_attestation_probe_verifies_exact_predicate_and_transparency_timestamp(
    tmp_path: Path,
):
    _write_probe_task(tmp_path)
    environment = _probe_environment()
    subject_path = tmp_path / "subject.json"
    predicate_path = tmp_path / "predicate.json"
    bundle_path = tmp_path / "bundle.json"
    assert github_attestation_probe_prepare_main(
        subject_path=subject_path,
        predicate_path=predicate_path,
        repo=tmp_path,
        stdout=StringIO(),
        stderr=StringIO(),
        environment=environment,
    ) == 0
    bundle_path.write_text("{}", encoding="utf-8")
    subject = json.loads(subject_path.read_text(encoding="utf-8"))
    predicate = json.loads(predicate_path.read_text(encoding="utf-8"))
    subject_digest = hashlib.sha256(subject_path.read_bytes()).hexdigest()
    captured: dict[str, object] = {}

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        output = [
            {
                "attestation": {"bundle": "verified"},
                "verificationResult": {
                    "statement": {
                        "subject": [
                            {
                                "name": subject_path.name,
                                "digest": {"sha256": subject_digest},
                            }
                        ],
                        "predicateType": (
                            "https://github.com/IvesChenHX/multi-agent-collab/"
                            "attestations/authority-probe/v1"
                        ),
                        "predicate": predicate,
                    },
                    "verifiedTimestamps": [{"type": "rekor"}],
                },
            }
        ]
        return subprocess.CompletedProcess(argv, 0, json.dumps(output), "")

    stdout = StringIO()
    stderr = StringIO()
    exit_code = github_attestation_probe_verify_main(
        subject_path=subject_path,
        predicate_path=predicate_path,
        bundle_path=bundle_path,
        repo=tmp_path,
        stdout=stdout,
        stderr=stderr,
        environment=environment,
        run=run,
    )

    assert exit_code == 0
    assert stderr.getvalue() == ""
    argv = captured["argv"]
    assert isinstance(argv, list)
    assert argv[:3] == ["gh", "attestation", "verify"]
    assert "--deny-self-hosted-runners" in argv
    assert argv[argv.index("--signer-workflow") + 1] == (
        "IvesChenHX/multi-agent-collab/.github/workflows/governance-pr.yml"
    )
    assert argv[argv.index("--source-digest") + 1] == "a" * 40
    assert argv[argv.index("--source-ref") + 1] == "refs/heads/master"
    assert captured["kwargs"]["shell"] is False
    assert json.loads(stdout.getvalue())["subject_digest"] == f"sha256:{subject_digest}"


def test_github_attestation_probe_rejects_predicate_drift_before_verification(tmp_path: Path):
    _write_probe_task(tmp_path)
    environment = _probe_environment()
    subject_path = tmp_path / "subject.json"
    predicate_path = tmp_path / "predicate.json"
    bundle_path = tmp_path / "bundle.json"
    assert github_attestation_probe_prepare_main(
        subject_path=subject_path,
        predicate_path=predicate_path,
        repo=tmp_path,
        stdout=StringIO(),
        stderr=StringIO(),
        environment=environment,
    ) == 0
    predicate = json.loads(predicate_path.read_text(encoding="utf-8"))
    predicate["independence_level"] = "L3"
    predicate_path.write_text(json.dumps(predicate, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    bundle_path.write_text("{}", encoding="utf-8")

    exit_code = github_attestation_probe_verify_main(
        subject_path=subject_path,
        predicate_path=predicate_path,
        bundle_path=bundle_path,
        repo=tmp_path,
        stdout=StringIO(),
        stderr=StringIO(),
        environment=environment,
        run=lambda *_args, **_kwargs: pytest.fail("gh must not run for a drifted predicate"),
    )

    assert exit_code == 2


def test_attested_task_plan_round_trips_one_exact_create_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    request = AuthorityRequest(
        repository_identity="github:repository-id:1290429577",
        operation="task.create",
        task_id=TASK_ID,
        actor_claim={"id": "governance-owner", "kind": "human"},
        expected_revision=-1,
        idempotency_key="github-sigstore-task-create:987654:2",
        intent_digest=canonical_digest({"task": TASK_ID}),
        policy_digest="sha256:" + "1" * 64,
        ownership_digest="sha256:" + "2" * 64,
        audience="mac-mutation-gateway/v1",
    )
    command = CreateTask(
        task={"id": TASK_ID, "title": "successor"},
        initial_entities=(("scope-contract.yaml", {"task_id": TASK_ID}),),
        actor_claim={"id": "governance-owner", "kind": "human"},
        idempotency_key=request.idempotency_key,
        minimum_independence="L2",
        replay_intent={"title": "successor"},
    )
    prepared = SimpleNamespace(
        request=request,
        intent={"schema_version": 1, "task_id": TASK_ID},
        command=command,
    )
    monkeypatch.setattr(governance_pr, "_successor_create_command", lambda *_: command)

    class FakeGateway:
        def __init__(self, _repo: Path):
            pass

        def prepare(self, observed: CreateTask):
            assert governance_pr._serialize_create_task(observed) == governance_pr._serialize_create_task(command)
            return prepared

    monkeypatch.setattr(governance_pr, "MutationGateway", FakeGateway)
    output_dir = tmp_path / "prepared"
    stdout = StringIO()
    stderr = StringIO()

    exit_code = github_attested_task_prepare_main(
        output_dir=output_dir,
        repo=tmp_path,
        stdout=stdout,
        stderr=stderr,
        environment=_probe_environment(
            "refs/heads/codex/governance-authority-sigstore"
        ),
    )

    assert exit_code == 0
    assert stderr.getvalue() == ""
    plan = json.loads((output_dir / "plan.json").read_text(encoding="utf-8"))
    subject = json.loads((output_dir / "subject.json").read_text(encoding="utf-8"))
    predicate = json.loads((output_dir / "predicate.json").read_text(encoding="utf-8"))
    assert governance_pr._serialize_create_task(
        governance_pr._deserialize_create_task(plan["command"])
    ) == plan["command"]
    assert subject == request.as_dict()
    assert predicate["request_digest"] == request.request_digest
    assert predicate["binding_digest"] == request.binding_digest
    assert plan["verification_policy"]["source_ref"].endswith(
        "/codex/governance-authority-sigstore"
    )


def test_regression_successor_creation_is_exactly_scoped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    task_id = "TASK-01KY58ZZZZZZZZZZZZZZZZZZZZ-full-regression-closure-successor"
    captured: dict[str, object] = {}

    class FakeTaskService:
        def __init__(self, repo: Path):
            assert repo == tmp_path

        def build_create_command(self, **kwargs: object) -> CreateTask:
            captured.update(kwargs)
            return CreateTask(
                task={"id": task_id, "title": kwargs["title"]},
                initial_entities=((
                    "scope-contract.yaml",
                    {
                        "allowed_paths": list(kwargs["allowed_paths"]),
                        "risk_tags": [],
                    },
                ),),
                actor_claim=dict(kwargs["actor"]),
                idempotency_key=str(kwargs["idempotency_key"]),
                replay_intent={"title": kwargs["title"]},
            )

    monkeypatch.setattr(governance_pr, "TaskService", FakeTaskService)
    monkeypatch.setattr(
        governance_pr,
        "_github_probe_request",
        lambda *_: SimpleNamespace(task_id=SUCCESSOR_TASK_ID),
    )
    environment = _probe_environment(
        "refs/heads/codex/governance-authority-sigstore"
    )
    environment["MAC_AUTHORITY_SUCCESSOR_PROFILE"] = "full-regression"

    command = governance_pr._successor_create_command(environment, tmp_path)

    assert captured["title"] == "Full regression closure successor"
    assert captured["mode"] == "high_risk"
    assert captured["parent_task"] == SUCCESSOR_TASK_ID
    assert captured["supersedes"] == [SUCCESSOR_TASK_ID]
    assert captured["allowed_paths"] == REGRESSION_SCOPE_PATHS
    assert captured["owners"] == [
        "governance", "platform", "devex", "tests", "examples", "docs",
    ]
    assert "independent_review" in captured["required_gates"]
    assert "evidence_matches_current_commit" in captured["required_gates"]
    assert command.minimum_independence == "L2"
    scope = command.initial_entities[0][1]
    assert scope["allowed_paths"] == [
        *REGRESSION_SCOPE_PATHS,
        f"tasks/{task_id}/**",
        f"tasks/private/{task_id}/**",
    ]
    assert scope["risk_tags"] == ["auth_security", "compatibility", "data_migration"]


def test_regression_successor_scope_approval_is_exact_and_l2(
    tmp_path: Path,
):
    task_id = "TASK-01KY58ZZZZZZZZZZZZZZZZZZZZ-full-regression-closure-successor"
    task_dir = tmp_path / "tasks" / task_id
    task_dir.mkdir(parents=True)
    agents = tmp_path / ".agents"
    agents.mkdir()
    (agents / "config.yaml").write_text(
        yaml.safe_dump({
            "paths": {"ownership": ".agents/ownership.yaml"},
            "security": {"governance_sensitive_paths": []},
        }),
        encoding="utf-8",
    )
    (agents / "ownership.yaml").write_text(
        yaml.safe_dump({
            "owners": {
                "governance": {"approvers": ["governance-owner"]},
                "platform": {"approvers": ["platform-owner"]},
                "devex": {"approvers": ["devex-owner"]},
                "tests": {},
                "examples": {"approvers": ["platform-owner"]},
                "docs": {"approvers": ["repo-owner"]},
            },
        }),
        encoding="utf-8",
    )
    task = {
        "id": task_id,
        "title": "Full regression closure successor",
        "mode": "high_risk",
        "state": "triage",
        "revision": 0,
        "scope_contract_ref": f"tasks/{task_id}/scope-contract.yaml",
    }
    scope = {
        "id": "SCOPE-01KY58ZZZZZZZZZZZZZZZZZZZZ",
        "task_id": task_id,
        "version": 1,
        "status": "proposed",
        "proposed_by": "governance-owner",
        "approved_by": [],
        "allowed_paths": [
            *REGRESSION_SCOPE_PATHS,
            f"tasks/{task_id}/**",
            f"tasks/private/{task_id}/**",
        ],
        "owners": ["governance", "platform", "devex", "tests", "examples", "docs"],
        "risk_tags": ["auth_security", "compatibility", "data_migration"],
    }
    (task_dir / "task.yaml").write_text(yaml.safe_dump(task), encoding="utf-8")
    (task_dir / "scope-contract.yaml").write_text(yaml.safe_dump(scope), encoding="utf-8")
    environment = _probe_environment(
        "refs/heads/codex/governance-authority-sigstore"
    )
    environment["MAC_AUTHORITY_PROBE_TASK_ID"] = task_id
    environment["MAC_AUTHORITY_SUCCESSOR_PROFILE"] = "full-regression"

    command = governance_pr._successor_scope_approval_command(environment, tmp_path)

    assert command.expected_revision == 0
    assert command.minimum_independence == "L2"
    assert command.actor_claim == {"id": "repo-owner", "kind": "human"}
    assert command.payload["approval"]["actor"] == command.actor_claim
    assert command.payload["approval"]["independence_level"] == "L2"
    assert command.payload["scope"]["approved_by"] == ["repo-owner"]


def test_attested_scope_plan_round_trips_one_exact_approval_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    request = AuthorityRequest(
        repository_identity="github:repository-id:1290429577",
        operation="scope.approve",
        task_id=TASK_ID,
        actor_claim={"id": "repo-owner", "kind": "human"},
        expected_revision=0,
        idempotency_key="github-sigstore-scope-approve:987654:2",
        intent_digest=canonical_digest({"scope": TASK_ID}),
        policy_digest="sha256:" + "1" * 64,
        ownership_digest="sha256:" + "2" * 64,
        audience="mac-mutation-gateway/v1",
    )
    scope_path = tmp_path / "tasks" / TASK_ID / "scope-contract.yaml"
    approval_path = tmp_path / "tasks" / TASK_ID / "approvals" / "APR-example.json"
    command = AppendEvent(
        task_id=TASK_ID,
        event_type="scope_approved",
        payload={
            "scope_id": "SCOPE-example",
            "approval_id": "APR-example",
            "approval": {"id": "APR-example", "recorded_at": "unbound"},
        },
        actor_claim={"id": "repo-owner", "kind": "human"},
        expected_revision=0,
        idempotency_key=request.idempotency_key,
        operation="scope.approve",
        materializations=(
            (approval_path, {"id": "APR-example", "recorded_at": "unbound"}),
            (scope_path, {"task_id": TASK_ID, "status": "approved"}),
        ),
        replace_existing=frozenset({scope_path}),
        minimum_independence="L2",
        replay_intent={"independence_level_claim": "L2"},
    )
    prepared = SimpleNamespace(
        request=request,
        intent={"schema_version": 1, "task_id": TASK_ID, "operation": "scope.approve"},
        command=command,
    )
    def scope_command(
        *_: object,
        recorded_at: str,
    ) -> AppendEvent:
        payload = dict(command.payload)
        payload["approval"] = {
            **dict(payload["approval"]),
            "recorded_at": recorded_at,
        }
        materializations = tuple(
            (
                path,
                {**dict(value), "recorded_at": recorded_at}
                if path == approval_path
                else value,
            )
            for path, value in command.materializations
        )
        return AppendEvent(
            task_id=command.task_id,
            event_type=command.event_type,
            payload=payload,
            actor_claim=command.actor_claim,
            expected_revision=command.expected_revision,
            idempotency_key=command.idempotency_key,
            operation=command.operation,
            materializations=materializations,
            replace_existing=command.replace_existing,
            minimum_independence=command.minimum_independence,
            replay_intent=command.replay_intent,
        )

    monkeypatch.setattr(governance_pr, "_successor_scope_approval_command", scope_command)
    monkeypatch.setattr(governance_pr, "_sigstore_trust_environment", lambda: {})

    class FakeGateway:
        def __init__(self, _repo: Path):
            pass

        def prepare(self, observed: AppendEvent):
            approval = observed.payload["approval"]
            assert approval["recorded_at"] != "unbound"
            assert observed.materializations[0][1]["recorded_at"] == approval["recorded_at"]
            return prepared

    monkeypatch.setattr(governance_pr, "MutationGateway", FakeGateway)
    output_dir = tmp_path / "prepared-scope"
    stdout = StringIO()
    stderr = StringIO()

    exit_code = github_attested_scope_prepare_main(
        output_dir=output_dir,
        repo=tmp_path,
        stdout=stdout,
        stderr=stderr,
        environment=_probe_environment(
            "refs/heads/codex/governance-authority-sigstore"
        ),
    )

    assert exit_code == 0
    assert stderr.getvalue() == ""
    plan = json.loads((output_dir / "plan.json").read_text(encoding="utf-8"))
    restored = governance_pr._deserialize_append_event(plan["command"], tmp_path)
    assert governance_pr._serialize_append_event(restored, tmp_path) == plan["command"]
    assert plan["request"]["operation"] == "scope.approve"
    predicate = json.loads((output_dir / "predicate.json").read_text(encoding="utf-8"))
    assert plan["command"]["payload"]["approval"]["recorded_at"] == predicate["issued_at"]
    assert plan["command"]["materializations"][0][1]["recorded_at"] == predicate["issued_at"]
    assert json.loads(stdout.getvalue())["operation"] == "scope.approve"


def test_attested_ready_plan_round_trips_one_exact_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    context = TransitionContext(
        triage_complete=True,
        scope_approved=True,
        gates_selected=True,
    )
    command = Transition(
        task_id=TASK_ID,
        target="ready",
        context=context,
        actor_claim={"id": "governance-owner", "kind": "human"},
        expected_revision=1,
        idempotency_key="github-sigstore-task-ready:987654:2",
        operation="task.transition.ready",
        transition_metadata={},
        minimum_independence="L2",
        replay_intent={
            "target": "ready",
            "condition": [],
            "fact_id": None,
            "reason": None,
        },
    )
    request = AuthorityRequest(
        repository_identity="github:repository-id:1290429577",
        operation=command.operation,
        task_id=TASK_ID,
        actor_claim=command.actor_claim,
        expected_revision=command.expected_revision,
        idempotency_key=command.idempotency_key,
        intent_digest=canonical_digest({"transition": "ready"}),
        policy_digest="sha256:" + "1" * 64,
        ownership_digest="sha256:" + "2" * 64,
        audience="mac-mutation-gateway/v1",
    )
    prepared = SimpleNamespace(
        request=request,
        intent={"transition": "ready"},
        command=command,
    )
    monkeypatch.setattr(
        governance_pr,
        "_successor_ready_transition_command",
        lambda *_: command,
        raising=False,
    )

    class FakeGateway:
        def __init__(self, _repo: Path):
            pass

        def prepare(self, observed: Transition):
            assert observed == command
            return prepared

    monkeypatch.setattr(governance_pr, "MutationGateway", FakeGateway)
    output_dir = tmp_path / "prepared-ready"
    stdout = StringIO()
    stderr = StringIO()

    exit_code = governance_pr.github_attested_ready_prepare_main(
        output_dir=output_dir,
        repo=tmp_path,
        stdout=stdout,
        stderr=stderr,
        environment=_probe_environment(
            "refs/heads/codex/governance-authority-sigstore"
        ),
    )

    assert exit_code == 0
    assert stderr.getvalue() == ""
    plan = json.loads((output_dir / "plan.json").read_text(encoding="utf-8"))
    restored = governance_pr._deserialize_transition(plan["command"])
    assert governance_pr._serialize_transition(restored) == plan["command"]
    assert plan["command"]["command_type"] == "Transition"
    assert plan["command"]["operation"] == "task.transition.ready"
    assert plan["command"]["expected_revision"] == 1
    assert plan["command"]["minimum_independence"] == "L2"
    assert json.loads(stdout.getvalue())["operation"] == "task.transition.ready"


def test_attested_ready_prepare_derives_exact_transition_from_successor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    task_id = "TASK-01KY58ZZZZZZZZZZZZZZZZZZZZ-full-regression-closure-successor"
    task_dir = tmp_path / "tasks" / task_id
    task_dir.mkdir(parents=True)
    task, scope = _successor_documents(
        task_id,
        profile="full-regression",
        version=1,
    )
    (task_dir / "task.yaml").write_text(yaml.safe_dump(task), encoding="utf-8")
    (task_dir / "scope-contract.yaml").write_text(
        yaml.safe_dump(scope),
        encoding="utf-8",
    )
    context = TransitionContext(
        triage_complete=True,
        scope_approved=True,
        gates_selected=True,
    )
    observed_commands: list[Transition] = []

    def resolve_context(
        repo: Path,
        observed_task_id: str,
        target: str,
        actor: dict[str, str],
    ) -> TransitionContext:
        assert repo == tmp_path
        assert observed_task_id == task_id
        assert target == "ready"
        assert actor == {"id": "governance-owner", "kind": "human"}
        return context

    monkeypatch.setattr(
        governance_pr,
        "resolve_transition_context",
        resolve_context,
        raising=False,
    )
    monkeypatch.setattr(governance_pr, "_sigstore_trust_environment", lambda: {})

    class FakeGateway:
        def __init__(self, _repo: Path):
            pass

        def prepare(self, observed: Transition):
            observed_commands.append(observed)
            request = AuthorityRequest(
                repository_identity="github:repository-id:1290429577",
                operation=observed.operation,
                task_id=observed.task_id,
                actor_claim=observed.actor_claim,
                expected_revision=observed.expected_revision,
                idempotency_key=observed.idempotency_key,
                intent_digest=canonical_digest({"transition": "ready"}),
                policy_digest="sha256:" + "1" * 64,
                ownership_digest="sha256:" + "2" * 64,
                audience="mac-mutation-gateway/v1",
            )
            return SimpleNamespace(
                request=request,
                intent={"transition": "ready"},
                command=observed,
            )

    monkeypatch.setattr(governance_pr, "MutationGateway", FakeGateway)
    environment = _probe_environment(
        "refs/heads/codex/governance-authority-sigstore"
    )
    environment["MAC_AUTHORITY_PROBE_TASK_ID"] = task_id
    environment["MAC_AUTHORITY_SUCCESSOR_PROFILE"] = "full-regression"
    stdout = StringIO()
    stderr = StringIO()

    exit_code = governance_pr.github_attested_ready_prepare_main(
        output_dir=tmp_path / "prepared-ready",
        repo=tmp_path,
        stdout=stdout,
        stderr=stderr,
        environment=environment,
    )

    assert exit_code == 0
    assert stderr.getvalue() == ""
    assert len(observed_commands) == 1
    command = observed_commands[0]
    assert command.target == "ready"
    assert command.context == context
    assert command.expected_revision == 1
    assert command.operation == "task.transition.ready"
    assert command.minimum_independence == "L2"
    assert command.replay_intent == {
        "target": "ready",
        "condition": [],
        "fact_id": None,
        "reason": None,
    }


def test_execution_bootstrap_first_round_creates_one_exact_work_unit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    task_id = "TASK-01KY58ZZZZZZZZZZZZZZZZZZZZ-full-regression-closure-successor"
    task, scope = _successor_documents(
        task_id,
        profile="full-regression",
        version=1,
    )
    task["state"] = "ready"
    task["revision"] = 2
    aggregate = SimpleNamespace(
        task=task,
        scope=scope,
        entities={
            "work-units": {},
            "runs": {},
        },
        projection_drift=(),
    )
    monkeypatch.setattr(
        governance_pr.FilesystemTaskRepository,
        "load_verified_aggregate",
        lambda _self, observed_task_id: (
            aggregate
            if observed_task_id == task_id
            else pytest.fail("unexpected task id")
        ),
    )
    environment = _probe_environment(
        "refs/heads/codex/governance-authority-sigstore"
    )
    environment["MAC_AUTHORITY_PROBE_TASK_ID"] = task_id
    environment["MAC_AUTHORITY_SUCCESSOR_PROFILE"] = "full-regression"

    command = governance_pr._successor_execution_command(
        environment,
        tmp_path,
    )

    assert isinstance(command, AppendEvent)
    assert command.operation == "work_unit.create"
    assert command.event_type == "work_unit_created"
    assert command.expected_revision == 2
    assert command.minimum_independence == "L2"
    work_unit = command.payload["work_unit"]
    assert work_unit == command.materializations[0][1]
    assert work_unit["status"] == "pending"
    assert work_unit["owner"] == "tests"
    assert work_unit["allowed_paths"] == REGRESSION_SCOPE_PATHS
    assert work_unit["depends_on"] == []
    assert work_unit["acceptance_criteria"] == [
        "AC-001",
        "AC-002",
        "AC-003",
        "AC-004",
    ]
    assert command.replay_intent == {"work_unit": work_unit}


def test_execution_bootstrap_second_round_readies_only_the_exact_work_unit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    task_id = "TASK-01KY58ZZZZZZZZZZZZZZZZZZZZ-full-regression-closure-successor"
    task, scope = _successor_documents(
        task_id,
        profile="full-regression",
        version=1,
    )
    task["state"] = "ready"
    task["revision"] = 3
    work_unit_id = "WU-01KY58ZZZZZZZZZZZZZZZZZZZZ"
    work_unit = {
        "schema_version": 1,
        "id": work_unit_id,
        "task_id": task_id,
        "title": "Close the full regression suite",
        "status": "pending",
        "owner": "tests",
        "allowed_paths": REGRESSION_SCOPE_PATHS,
        "depends_on": [],
        "acceptance_criteria": [
            "AC-001",
            "AC-002",
            "AC-003",
            "AC-004",
        ],
        "expected_result": (
            f"tasks/{task_id}/results/"
            "RESULT-01KY58ZZZZZZZZZZZZZZZZZZZY.json"
        ),
    }
    aggregate = SimpleNamespace(
        task=task,
        scope=scope,
        entities={
            "work-units": {work_unit_id: work_unit},
            "runs": {},
        },
        projection_drift=(),
    )
    monkeypatch.setattr(
        governance_pr.FilesystemTaskRepository,
        "load_verified_aggregate",
        lambda _self, _task_id: aggregate,
    )
    environment = _probe_environment(
        "refs/heads/codex/governance-authority-sigstore"
    )
    environment["MAC_AUTHORITY_PROBE_TASK_ID"] = task_id
    environment["MAC_AUTHORITY_SUCCESSOR_PROFILE"] = "full-regression"

    command = governance_pr._successor_execution_command(
        environment,
        tmp_path,
    )

    assert isinstance(command, AppendEvent)
    assert command.operation == "work_unit.ready"
    assert command.event_type == "work_unit_created"
    assert command.expected_revision == 3
    readied = command.payload["work_unit"]
    assert readied == {**work_unit, "status": "ready"}
    assert command.materializations[0][1] == readied
    assert command.replace_existing == frozenset(
        {command.materializations[0][0]}
    )
    assert command.replay_intent == {"work_unit": readied}
    assert governance_pr._allowlisted_successor_execution_command(
        command,
        tmp_path,
        {
            "source_ref": environment["GITHUB_REF"],
            "source_digest": environment["GITHUB_SHA"],
        },
    )
def test_execution_bootstrap_third_round_registers_a_portable_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "Test"],
        check=True,
    )
    (tmp_path / "tracked.txt").write_text("bridge\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "tracked.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-qm", "bridge"],
        check=True,
    )
    head = subprocess.run(
        ["git", "-C", str(tmp_path), "rev-parse", "HEAD"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()
    task_id = "TASK-01KY58ZZZZZZZZZZZZZZZZZZZZ-full-regression-closure-successor"
    task, scope = _successor_documents(
        task_id,
        profile="full-regression",
        version=1,
    )
    task["state"] = "ready"
    task["revision"] = 4
    task["policy_ref"]["source_commit"] = head
    task["ownership_ref"]["source_commit"] = head
    scope["base_commit"] = head
    work_unit_id = "WU-01KY58ZZZZZZZZZZZZZZZZZZZZ"
    work_unit = {
        "schema_version": 1,
        "id": work_unit_id,
        "task_id": task_id,
        "title": "Close the full regression suite",
        "status": "ready",
        "owner": "tests",
        "allowed_paths": REGRESSION_SCOPE_PATHS,
        "depends_on": [],
        "acceptance_criteria": [
            "AC-001",
            "AC-002",
            "AC-003",
            "AC-004",
        ],
        "expected_result": (
            f"tasks/{task_id}/results/"
            "RESULT-01KY58ZZZZZZZZZZZZZZZZZZZY.json"
        ),
    }
    aggregate = SimpleNamespace(
        task=task,
        scope=scope,
        entities={
            "work-units": {work_unit_id: work_unit},
            "runs": {},
        },
        projection_drift=(),
    )
    monkeypatch.setattr(
        governance_pr.FilesystemTaskRepository,
        "load_verified_aggregate",
        lambda _self, _task_id: aggregate,
    )
    environment = _probe_environment(
        "refs/heads/codex/governance-authority-sigstore"
    )
    environment["GITHUB_SHA"] = head
    environment["MAC_AUTHORITY_PROBE_TASK_ID"] = task_id
    environment["MAC_AUTHORITY_SUCCESSOR_PROFILE"] = "full-regression"

    command = governance_pr._successor_execution_command(
        environment,
        tmp_path,
    )

    assert isinstance(command, AppendEvent)
    assert command.operation == "run.register"
    assert command.event_type == "run_started"
    assert command.expected_revision == 4
    assert command.minimum_independence == "L2"
    run = command.payload["run"]
    assert run["actor"] == {"id": "governance-owner", "kind": "human"}
    assert run["runtime"] == {
        "profile": "local-multi",
        "execution_context_id": "github-actions-987654-2",
    }
    assert run["independence_level"] == "L0"
    assert command.payload["work_unit"] == {**work_unit, "status": "running"}
    assert command.payload["baseline_subject"] == GitRepository(
        tmp_path
    ).commit_subject(head)
    assert command.payload["worktree_identity"] == {
        "kind": "portable",
        "repository_identity": "github:repository-id:1290429577",
        "source_ref": "refs/heads/codex/governance-authority-sigstore",
    }
    assert command.payload["repository_binding"] == {
        "kind": "portable",
        "repository_identity": "github:repository-id:1290429577",
        "source_ref": "refs/heads/codex/governance-authority-sigstore",
        "source_digest": head,
        "approved_base_resolved": True,
        "baseline_subject_bound": True,
        "baseline_descends_from_approved_base": True,
        "source_ref_resolved": True,
        "baseline_reachable_from_source_ref": True,
        "source_ref_commit_sha": head,
        "source_ref_tree_sha": GitRepository(tmp_path).commit_subject(head)[
            "tree_sha"
        ],
    }
    assert governance_pr._allowlisted_successor_execution_command(
        command,
        tmp_path,
        {
            "source_ref": environment["GITHUB_REF"],
            "source_digest": environment["GITHUB_SHA"],
        },
    )
    policy = {
        "source_ref": environment["GITHUB_REF"],
        "source_digest": environment["GITHUB_SHA"],
    }
    for field, value in (
        ("repository_identity", "github:repository-id:attacker"),
        ("source_ref", "refs/heads/attacker"),
        ("source_digest", "f" * 40),
    ):
        payload = deepcopy(command.payload)
        payload["repository_binding"][field] = value
        if field != "source_digest":
            payload["worktree_identity"][field] = value
        assert not governance_pr._allowlisted_successor_execution_command(
            replace(command, payload=payload),
            tmp_path,
            policy,
        )
    payload = deepcopy(command.payload)
    payload["baseline_subject"]["commit"] = "f" * 40
    assert not governance_pr._allowlisted_successor_execution_command(
        replace(command, payload=payload),
        tmp_path,
        policy,
    )


def test_portable_run_plan_deserializes_and_is_allowlisted_in_another_worktree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    source = tmp_path / "source"
    linked = tmp_path / "linked"
    source.mkdir()
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(
        ["git", "-C", str(source), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(source), "config", "user.name", "Test"],
        check=True,
    )
    (source / "tracked.txt").write_text("bridge\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(source), "add", "tracked.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(source), "commit", "-qm", "bridge"],
        check=True,
    )
    head = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "-C", str(source), "worktree", "add", "--detach", str(linked), head],
        check=True,
        capture_output=True,
    )
    task_id = "TASK-01KY58ZZZZZZZZZZZZZZZZZZZZ-full-regression-closure-successor"
    task, scope = _successor_documents(
        task_id,
        profile="full-regression",
        version=1,
    )
    task["state"] = "ready"
    task["revision"] = 4
    task["policy_ref"]["source_commit"] = head
    task["ownership_ref"]["source_commit"] = head
    scope["base_commit"] = head
    work_unit_id = "WU-01KY58ZZZZZZZZZZZZZZZZZZZZ"
    work_unit = {
        "schema_version": 1,
        "id": work_unit_id,
        "task_id": task_id,
        "title": "Close the full regression suite",
        "status": "ready",
        "owner": "tests",
        "allowed_paths": REGRESSION_SCOPE_PATHS,
        "depends_on": [],
        "acceptance_criteria": ["AC-001", "AC-002", "AC-003", "AC-004"],
        "expected_result": (
            f"tasks/{task_id}/results/"
            "RESULT-01KY58ZZZZZZZZZZZZZZZZZZZY.json"
        ),
    }
    aggregate = SimpleNamespace(
        task=task,
        scope=scope,
        entities={"work-units": {work_unit_id: work_unit}, "runs": {}},
        projection_drift=(),
    )
    monkeypatch.setattr(
        governance_pr.FilesystemTaskRepository,
        "load_verified_aggregate",
        lambda _self, _task_id: aggregate,
    )
    environment = _probe_environment(
        "refs/heads/codex/governance-authority-sigstore"
    )
    environment["GITHUB_SHA"] = head
    environment["MAC_AUTHORITY_PROBE_TASK_ID"] = task_id
    environment["MAC_AUTHORITY_SUCCESSOR_PROFILE"] = "full-regression"

    prepared = governance_pr._successor_execution_command(
        environment,
        source,
        occurred_at="2026-07-23T00:00:00Z",
    )
    assert isinstance(prepared, AppendEvent)
    restored = governance_pr._deserialize_append_event(
        governance_pr._serialize_append_event(prepared, source),
        linked,
    )

    assert all(
        path.is_relative_to(linked)
        for path, _document in restored.materializations
    )
    assert governance_pr._allowlisted_successor_execution_command(
        restored,
        linked,
        {
            "source_ref": environment["GITHUB_REF"],
            "source_digest": head,
        },
    )


def test_execution_bootstrap_fourth_round_uses_the_real_executing_guard_shape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    task_id = "TASK-01KY58ZZZZZZZZZZZZZZZZZZZZ-full-regression-closure-successor"
    task, scope = _successor_documents(
        task_id,
        profile="full-regression",
        version=1,
    )
    task["state"] = "ready"
    task["revision"] = 5
    work_unit_id = "WU-01KY58ZZZZZZZZZZZZZZZZZZZZ"
    work_unit = {
        "schema_version": 1,
        "id": work_unit_id,
        "task_id": task_id,
        "title": "Close the full regression suite",
        "status": "running",
        "owner": "tests",
        "allowed_paths": REGRESSION_SCOPE_PATHS,
        "depends_on": [],
        "acceptance_criteria": [
            "AC-001",
            "AC-002",
            "AC-003",
            "AC-004",
        ],
        "expected_result": (
            f"tasks/{task_id}/results/"
            "RESULT-01KY58ZZZZZZZZZZZZZZZZZZZY.json"
        ),
    }
    run_id = "RUN-01KY58ZZZZZZZZZZZZZZZZZZZZ"
    run = {
        "schema_version": 1,
        "id": run_id,
        "task_id": task_id,
        "work_unit_id": work_unit_id,
        "status": "running",
        "actor": {"id": "governance-owner", "kind": "human"},
        "runtime": {
            "profile": "local-multi",
            "execution_context_id": "github-actions-987654-2",
        },
        "independence_level": "L0",
        "started_at": "2026-07-23T00:00:00Z",
        "finished_at": None,
        "exit_code": None,
    }
    aggregate = SimpleNamespace(
        task=task,
        scope=scope,
        entities={
            "work-units": {work_unit_id: work_unit},
            "runs": {run_id: run},
        },
        projection_drift=(),
    )
    monkeypatch.setattr(
        governance_pr.FilesystemTaskRepository,
        "load_verified_aggregate",
        lambda _self, _task_id: aggregate,
    )
    context = TransitionContext(
        runtime_satisfied=True,
        executor_run_created=True,
        dependencies_complete=True,
        baseline_recorded=True,
        work_unit_dependencies_complete=True,
    )
    observed: list[tuple[Path, str, str, dict[str, str]]] = []

    def resolve_context(
        repo: Path,
        observed_task_id: str,
        target: str,
        actor: dict[str, str],
    ) -> TransitionContext:
        observed.append((repo, observed_task_id, target, actor))
        return context

    monkeypatch.setattr(
        governance_pr,
        "resolve_transition_context",
        resolve_context,
    )
    environment = _probe_environment(
        "refs/heads/codex/governance-authority-sigstore"
    )
    environment["MAC_AUTHORITY_PROBE_TASK_ID"] = task_id
    environment["MAC_AUTHORITY_SUCCESSOR_PROFILE"] = "full-regression"

    command = governance_pr._successor_execution_command(
        environment,
        tmp_path,
    )

    assert isinstance(command, Transition)
    assert observed == [
        (
            tmp_path,
            task_id,
            "executing",
            {"id": "governance-owner", "kind": "human"},
        )
    ]
    assert command.target == "executing"
    assert command.context == context
    assert command.expected_revision == 5
    assert command.operation == "task.transition.executing"
    assert command.minimum_independence == "L2"
    assert command.replay_intent == {
        "target": "executing",
        "condition": [],
        "fact_id": None,
        "reason": None,
    }
    assert governance_pr._allowlisted_successor_execution_command(
        command,
        tmp_path,
        {
            "source_ref": environment["GITHUB_REF"],
            "source_digest": environment["GITHUB_SHA"],
        },
    )


def test_attested_execution_prepare_round_trips_one_exact_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    task_dir = tmp_path / "tasks" / TASK_ID
    work_unit_id = "WU-01KY58ZZZZZZZZZZZZZZZZZZZZ"
    work_unit = {
        "schema_version": 1,
        "id": work_unit_id,
        "task_id": TASK_ID,
        "title": "Close the full regression suite",
        "status": "pending",
        "owner": "tests",
        "allowed_paths": REGRESSION_SCOPE_PATHS,
        "depends_on": [],
        "acceptance_criteria": ["AC-001", "AC-002", "AC-003", "AC-004"],
        "expected_result": (
            f"tasks/{TASK_ID}/results/"
            "RESULT-01KY58ZZZZZZZZZZZZZZZZZZZY.json"
        ),
    }
    path = task_dir / "work-units" / f"{work_unit_id}.yaml"
    observed_times: list[str | None] = []

    def build_command(
        _values: dict[str, str],
        _repo: Path,
        *,
        occurred_at: str | None = None,
    ) -> AppendEvent:
        observed_times.append(occurred_at)
        return AppendEvent(
            task_id=TASK_ID,
            event_type="work_unit_created",
            payload={
                "work_unit_id": work_unit_id,
                "work_unit": work_unit,
            },
            actor_claim={"id": "governance-owner", "kind": "human"},
            expected_revision=2,
            idempotency_key="github-sigstore-execution:work-unit-create:987654:2",
            operation="work_unit.create",
            materializations=((path, work_unit),),
            minimum_independence="L2",
            replay_intent={"work_unit": work_unit},
        )

    monkeypatch.setattr(
        governance_pr,
        "_successor_execution_command",
        build_command,
    )
    monkeypatch.setattr(
        governance_pr,
        "_sigstore_trust_environment",
        lambda: {},
    )

    class FakeGateway:
        def __init__(self, _repo: Path):
            pass

        def prepare(self, command: AppendEvent):
            intent = {
                "schema_version": 1,
                "operation": command.operation,
                "task_id": command.task_id,
            }
            request = AuthorityRequest(
                repository_identity="github:repository-id:1290429577",
                operation=command.operation,
                task_id=command.task_id,
                actor_claim=command.actor_claim,
                expected_revision=command.expected_revision,
                idempotency_key=command.idempotency_key,
                intent_digest=canonical_digest(intent),
                policy_digest="sha256:" + "1" * 64,
                ownership_digest="sha256:" + "2" * 64,
                audience="mac-mutation-gateway/v1",
            )
            return SimpleNamespace(
                request=request,
                intent=intent,
                command=command,
            )

    monkeypatch.setattr(governance_pr, "MutationGateway", FakeGateway)
    output_dir = tmp_path / "prepared-execution"
    stdout = StringIO()
    stderr = StringIO()

    exit_code = governance_pr.github_attested_execution_prepare_main(
        output_dir=output_dir,
        repo=tmp_path,
        stdout=stdout,
        stderr=stderr,
        environment=_probe_environment(
            "refs/heads/codex/governance-authority-sigstore"
        ),
    )

    assert exit_code == 0
    assert stderr.getvalue() == ""
    assert len(observed_times) == 1
    assert observed_times[0] is not None
    plan = json.loads((output_dir / "plan.json").read_text(encoding="utf-8"))
    restored = governance_pr._deserialize_append_event(
        plan["command"],
        tmp_path,
    )
    assert restored.operation == "work_unit.create"
    assert restored.expected_revision == 2
    assert json.loads(stdout.getvalue())["operation"] == "work_unit.create"


def test_execution_apply_allowlist_rejects_revision_and_operation_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    task_id = "TASK-01KY58ZZZZZZZZZZZZZZZZZZZZ-full-regression-closure-successor"
    task, scope = _successor_documents(
        task_id,
        profile="full-regression",
        version=1,
    )
    task["state"] = "ready"
    task["revision"] = 2
    aggregate = SimpleNamespace(
        task=task,
        scope=scope,
        entities={"work-units": {}, "runs": {}},
        projection_drift=(),
    )
    monkeypatch.setattr(
        governance_pr.FilesystemTaskRepository,
        "load_verified_aggregate",
        lambda _self, _task_id: aggregate,
    )
    environment = _probe_environment(
        "refs/heads/codex/governance-authority-sigstore"
    )
    environment["MAC_AUTHORITY_PROBE_TASK_ID"] = task_id
    environment["MAC_AUTHORITY_SUCCESSOR_PROFILE"] = "full-regression"
    command = governance_pr._successor_execution_command(
        environment,
        tmp_path,
    )
    policy = {
        "source_ref": environment["GITHUB_REF"],
        "source_digest": environment["GITHUB_SHA"],
    }

    assert governance_pr._allowlisted_successor_execution_command(
        command,
        tmp_path,
        policy,
    )
    assert not governance_pr._allowlisted_successor_execution_command(
        replace(command, expected_revision=3),
        tmp_path,
        policy,
    )
    assert not governance_pr._allowlisted_successor_execution_command(
        replace(command, operation="work_unit.ready"),
        tmp_path,
        policy,
    )
    aggregate.entities["work-units"] = {
        "WU-01KY58ZZZZZZZZZZZZZZZZZZZX": {"status": "pending"}
    }
    assert not governance_pr._allowlisted_successor_execution_command(
        command,
        tmp_path,
        policy,
    )
    aggregate.entities["work-units"] = {}
    aggregate.entities["runs"] = {
        "RUN-01KY58ZZZZZZZZZZZZZZZZZZZX": {"status": "running"}
    }
    assert not governance_pr._allowlisted_successor_execution_command(
        command,
        tmp_path,
        policy,
    )
    aggregate.entities["runs"] = {}
    aggregate.projection_drift = ("task.yaml",)
    assert not governance_pr._allowlisted_successor_execution_command(
        command,
        tmp_path,
        policy,
    )


def test_execution_apply_installs_historical_sigstore_trust_before_allowlist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    task_id = "TASK-01KY58ZZZZZZZZZZZZZZZZZZZZ-full-regression-closure-successor"
    task, scope = _successor_documents(
        task_id,
        profile="full-regression",
        version=1,
    )
    task["state"] = "ready"
    task["revision"] = 2
    aggregate = SimpleNamespace(
        task=task,
        scope=scope,
        entities={"work-units": {}, "runs": {}},
        projection_drift=(),
    )
    monkeypatch.setattr(
        governance_pr.FilesystemTaskRepository,
        "load_verified_aggregate",
        lambda _self, _task_id: aggregate,
    )
    environment = _probe_environment(
        "refs/heads/codex/governance-authority-sigstore"
    )
    environment["MAC_AUTHORITY_PROBE_TASK_ID"] = task_id
    environment["MAC_AUTHORITY_SUCCESSOR_PROFILE"] = "full-regression"
    command = governance_pr._successor_execution_command(
        environment,
        tmp_path,
    )
    intent = {
        "schema_version": 1,
        "operation": command.operation,
        "task_id": task_id,
    }
    request = AuthorityRequest(
        repository_identity="github:repository-id:1290429577",
        operation=command.operation,
        task_id=task_id,
        actor_claim=command.actor_claim,
        expected_revision=command.expected_revision,
        idempotency_key=command.idempotency_key,
        intent_digest=canonical_digest(intent),
        policy_digest="sha256:" + "1" * 64,
        ownership_digest="sha256:" + "2" * 64,
        audience="mac-mutation-gateway/v1",
    )
    policy = {
        "schema_version": 2,
        "repository": "IvesChenHX/multi-agent-collab",
        "repository_identity": "github:repository-id:1290429577",
        "signer_workflow": (
            "IvesChenHX/multi-agent-collab/"
            ".github/workflows/governance-pr.yml"
        ),
        "source_ref": environment["GITHUB_REF"],
        "source_digest": environment["GITHUB_SHA"],
        "predicate_type": (
            "https://github.com/IvesChenHX/multi-agent-collab/"
            "attestations/mutation-authority/v1"
        ),
        "environment": "governance-authority",
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "deny_self_hosted_runners": True,
    }
    plan = {
        "schema_version": 1,
        "kind": "mac.prepared-mutation",
        "command": governance_pr._serialize_append_event(command, tmp_path),
        "request": request.as_dict(),
        "intent": intent,
        "verification_policy": policy,
    }
    predicate = {
        "schema_version": 1,
        "allowed": True,
        "authenticated": True,
        "issuer": policy["oidc_issuer"],
        "actor_id": "governance-owner",
        "actor_kind": "human",
        "independence_level": "L2",
        "issued_at": "2026-07-23T00:00:00Z",
        "expires_at": "2026-07-23T00:30:00Z",
        "request_digest": request.request_digest,
        "binding_digest": request.binding_digest,
        "environment": "governance-authority",
    }
    plan_path = tmp_path / "plan.json"
    predicate_path = tmp_path / "predicate.json"
    bundle_path = tmp_path / "bundle.json"
    plan_path.write_text(
        json.dumps(plan, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    predicate_path.write_text(
        json.dumps(predicate, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    bundle_path.write_text("{}", encoding="utf-8")
    verifier_environment = {
        governance_pr.SIGSTORE_VERIFIER_ARGV_ENV: '["trusted-verifier"]',
    }
    monkeypatch.setattr(
        governance_pr,
        "_sigstore_trust_environment",
        lambda: verifier_environment,
    )
    monkeypatch.delenv(
        governance_pr.SIGSTORE_VERIFIER_ARGV_ENV,
        raising=False,
    )
    real_allowlist = governance_pr._allowlisted_successor_execution_command

    def allowlist_after_trust(
        observed: AppendEvent | Transition,
        repo: Path,
        observed_policy: dict[str, object],
    ) -> bool:
        assert (
            governance_pr.os.environ[
                governance_pr.SIGSTORE_VERIFIER_ARGV_ENV
            ]
            == '["trusted-verifier"]'
        )
        return real_allowlist(observed, repo, observed_policy)

    monkeypatch.setattr(
        governance_pr,
        "_allowlisted_successor_execution_command",
        allowlist_after_trust,
    )

    class FakeGateway:
        def __init__(self, _repo: Path):
            pass

        def prepare(self, observed: AppendEvent):
            return SimpleNamespace(
                request=request,
                intent=intent,
                command=observed,
            )

        def execute(self, _observed: AppendEvent):
            return SimpleNamespace(
                projection={"id": task_id, "revision": 3},
                event={"event_id": "EVT-execution"},
                authority={
                    "attestation_id": "sigstore:execution",
                    "binding_digest": request.binding_digest,
                },
            )

    monkeypatch.setattr(governance_pr, "MutationGateway", FakeGateway)
    stderr = StringIO()

    exit_code = github_attested_task_apply_main(
        plan_path=plan_path,
        predicate_path=predicate_path,
        bundle_path=bundle_path,
        repo=tmp_path,
        stdout=StringIO(),
        stderr=stderr,
    )

    assert exit_code == 0
    assert stderr.getvalue() == ""
    assert governance_pr.SIGSTORE_VERIFIER_ARGV_ENV not in governance_pr.os.environ


@pytest.mark.parametrize("version", [1, 2, 3])
def test_ready_transition_accepts_each_exact_bootstrap_scope_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    version: int,
):
    task_id = "TASK-01KY58ZZZZZZZZZZZZZZZZZZZZ-github-authority-bootstrap-successor"
    task_dir = tmp_path / "tasks" / task_id
    task_dir.mkdir(parents=True)
    task, scope = _successor_documents(
        task_id,
        profile="bootstrap",
        version=version,
    )
    (task_dir / "task.yaml").write_text(yaml.safe_dump(task), encoding="utf-8")
    (task_dir / "scope-contract.yaml").write_text(
        yaml.safe_dump(scope),
        encoding="utf-8",
    )
    context = TransitionContext(
        triage_complete=True,
        scope_approved=True,
        gates_selected=True,
    )
    monkeypatch.setattr(governance_pr, "resolve_transition_context", lambda *_: context)

    command = governance_pr._successor_ready_transition_command(
        {
            "MAC_AUTHORITY_PROBE_TASK_ID": task_id,
            "MAC_AUTHORITY_SUCCESSOR_PROFILE": "bootstrap",
            "GITHUB_RUN_ID": "987654",
            "GITHUB_RUN_ATTEMPT": "2",
        },
        tmp_path,
    )

    assert command.target == "ready"
    assert command.expected_revision == version * 2 - 1
    assert command.context == context


@pytest.mark.parametrize(
    ("entity", "field", "invalid"),
    [
        ("task", "objective", "tampered"),
        ("task", "acceptance_criteria", []),
        ("task", "required_gates", ["approved_scope"]),
        ("task", "runtime_profile", "local-single"),
        ("task", "relationships", {}),
        ("scope", "owners", ["governance"]),
        ("scope", "allowed_operations", ["read"]),
        ("scope", "network_access", "full"),
        ("scope", "required_gates", ["targeted_tests"]),
        ("scope", "amendment_policy", {}),
    ],
)
def test_ready_transition_rejects_successor_profile_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entity: str,
    field: str,
    invalid: object,
):
    task_id = "TASK-01KY58ZZZZZZZZZZZZZZZZZZZZ-full-regression-closure-successor"
    task_dir = tmp_path / "tasks" / task_id
    task_dir.mkdir(parents=True)
    task, scope = _successor_documents(
        task_id,
        profile="full-regression",
        version=1,
    )
    target = task if entity == "task" else scope
    target[field] = invalid
    (task_dir / "task.yaml").write_text(yaml.safe_dump(task), encoding="utf-8")
    (task_dir / "scope-contract.yaml").write_text(
        yaml.safe_dump(scope),
        encoding="utf-8",
    )
    context = TransitionContext(
        triage_complete=True,
        scope_approved=True,
        gates_selected=True,
    )
    monkeypatch.setattr(governance_pr, "resolve_transition_context", lambda *_: context)

    with pytest.raises(
        ValueError,
        match="successor is not eligible for protected ready transition",
    ):
        governance_pr._successor_ready_transition_command(
            {
                "MAC_AUTHORITY_PROBE_TASK_ID": task_id,
                "MAC_AUTHORITY_SUCCESSOR_PROFILE": "full-regression",
                "GITHUB_RUN_ID": "987654",
                "GITHUB_RUN_ATTEMPT": "2",
            },
            tmp_path,
        )


def test_ready_transition_rejects_failed_machine_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    task_id = "TASK-01KY58ZZZZZZZZZZZZZZZZZZZZ-full-regression-closure-successor"
    task_dir = tmp_path / "tasks" / task_id
    task_dir.mkdir(parents=True)
    task, scope = _successor_documents(
        task_id,
        profile="full-regression",
        version=1,
    )
    (task_dir / "task.yaml").write_text(yaml.safe_dump(task), encoding="utf-8")
    (task_dir / "scope-contract.yaml").write_text(
        yaml.safe_dump(scope),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        governance_pr,
        "resolve_transition_context",
        lambda *_: TransitionContext(triage_complete=True, scope_approved=True),
    )

    with pytest.raises(ValueError, match="ready transition guards are not satisfied"):
        governance_pr._successor_ready_transition_command(
            {
                "MAC_AUTHORITY_PROBE_TASK_ID": task_id,
                "MAC_AUTHORITY_SUCCESSOR_PROFILE": "full-regression",
                "GITHUB_RUN_ID": "987654",
                "GITHUB_RUN_ATTEMPT": "2",
            },
            tmp_path,
        )


def test_attested_scope_amend_plan_round_trips_one_exact_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    request = AuthorityRequest(
        repository_identity="github:repository-id:1290429577",
        operation="scope.amend",
        task_id=TASK_ID,
        actor_claim={"id": "repo-owner", "kind": "human"},
        expected_revision=1,
        idempotency_key="github-sigstore-scope-amend:987654:2",
        intent_digest=canonical_digest({"scope": TASK_ID, "version": 2}),
        policy_digest="sha256:" + "1" * 64,
        ownership_digest="sha256:" + "2" * 64,
        audience="mac-mutation-gateway/v1",
    )
    scope_path = tmp_path / "tasks" / TASK_ID / "scope-contract.yaml"
    history_path = tmp_path / "tasks" / TASK_ID / "scope-history" / "scope-contract.v1.yaml"
    command = AppendEvent(
        task_id=TASK_ID,
        event_type="scope_proposed",
        payload={"scope_id": "SCOPE-example", "version": 2, "amendment": True, "scope": {"version": 2}},
        actor_claim={"id": "repo-owner", "kind": "human"},
        expected_revision=1,
        idempotency_key=request.idempotency_key,
        operation="scope.amend",
        materializations=((history_path, {"version": 1}), (scope_path, {"version": 2})),
        replace_existing=frozenset({scope_path}),
        minimum_independence="L2",
        replay_intent={
            "add": [
                "src/mac/migration.py",
                "tests/test_authorityless_v6_migration.py",
                "migration/v6-authorityless/**",
                "tasks-v6/**",
            ],
            "add_operation": [],
            "approver": ["repo-owner"],
            "risk_tag": ["data_migration"],
            "independent": True,
        },
    )
    prepared = SimpleNamespace(
        request=request,
        intent={"schema_version": 1, "task_id": TASK_ID, "operation": "scope.amend"},
        command=command,
    )
    monkeypatch.setattr(governance_pr, "_successor_scope_amend_command", lambda *_: command, raising=False)
    monkeypatch.setattr(governance_pr, "_sigstore_trust_environment", lambda: {})

    class FakeGateway:
        def __init__(self, _repo: Path):
            pass

        def prepare(self, observed: AppendEvent):
            assert governance_pr._serialize_append_event(observed, tmp_path) == governance_pr._serialize_append_event(command, tmp_path)
            return prepared

    monkeypatch.setattr(governance_pr, "MutationGateway", FakeGateway)
    output_dir = tmp_path / "prepared-amendment"
    stdout = StringIO()
    stderr = StringIO()

    exit_code = governance_pr.github_attested_scope_amend_prepare_main(
        output_dir=output_dir,
        repo=tmp_path,
        stdout=stdout,
        stderr=stderr,
        environment=_probe_environment("refs/heads/codex/governance-authority-sigstore"),
    )

    assert exit_code == 0
    assert stderr.getvalue() == ""
    plan = json.loads((output_dir / "plan.json").read_text(encoding="utf-8"))
    restored = governance_pr._deserialize_append_event(plan["command"], tmp_path)
    assert governance_pr._serialize_append_event(restored, tmp_path) == plan["command"]
    assert plan["request"]["operation"] == "scope.amend"
    assert json.loads(stdout.getvalue())["operation"] == "scope.amend"


def test_second_successor_scope_amendment_adds_only_cross_platform_ci(
    tmp_path: Path,
):
    project = Path(__file__).resolve().parents[2]
    repo = tmp_path / "repo"
    shutil.copytree(
        project / "tasks" / SUCCESSOR_TASK_ID,
        repo / "tasks" / SUCCESSOR_TASK_ID,
    )
    task_dir = repo / "tasks" / SUCCESSOR_TASK_ID
    v2_scope = yaml.safe_load(
        (task_dir / "scope-history/scope-contract.v2.yaml").read_text(
            encoding="utf-8"
        )
    )
    (task_dir / "scope-contract.yaml").write_text(
        yaml.safe_dump(v2_scope, sort_keys=False),
        encoding="utf-8",
    )
    task = yaml.safe_load((task_dir / "task.yaml").read_text(encoding="utf-8"))
    task["revision"] = 3
    (task_dir / "task.yaml").write_text(
        yaml.safe_dump(task, sort_keys=False),
        encoding="utf-8",
    )
    environment = _probe_environment(
        "refs/heads/codex/governance-authority-sigstore"
    )
    environment["MAC_AUTHORITY_PROBE_TASK_ID"] = SUCCESSOR_TASK_ID

    command = governance_pr._successor_scope_amend_command(environment, repo)

    assert command.expected_revision == 3
    assert command.replay_intent == {
        "add": [".github/workflows/ci.yml"],
        "add_operation": [],
        "approver": ["governance-owner"],
        "risk_tag": ["auth_security"],
        "independent": True,
    }
    assert command.payload["version"] == 3
    amended = command.payload["scope"]
    assert amended["version"] == 3
    assert amended["allowed_paths"][-1] == ".github/workflows/ci.yml"
    assert amended["risk_tags"] == ["auth_security", "data_migration"]
    assert governance_pr._allowlisted_successor_scope_amendment(command)


def test_github_trusted_validate_requires_exact_host_and_restores_environment(
    monkeypatch: pytest.MonkeyPatch,
):
    tracked = [
        governance_pr.AUTHORITY_REPOSITORY_IDENTITY_ENV,
        governance_pr.SIGSTORE_VERIFIER_ARGV_ENV,
        governance_pr.SIGSTORE_VERIFIER_MANIFEST_ENV,
        governance_pr.SIGSTORE_REPOSITORY_ENV,
        governance_pr.SIGSTORE_REPOSITORY_IDENTITY_ENV,
        governance_pr.SIGSTORE_SIGNER_WORKFLOW_ENV,
        governance_pr.SIGSTORE_PREDICATE_TYPE_ENV,
        governance_pr.SIGSTORE_ENVIRONMENT_ENV,
        governance_pr.SIGSTORE_OIDC_ISSUER_ENV,
    ]
    for name in tracked:
        monkeypatch.delenv(name, raising=False)
    calls: list[list[str]] = []

    def run(argv: list[str]) -> dict[str, object]:
        calls.append(argv)
        assert governance_pr.os.environ[
            governance_pr.AUTHORITY_REPOSITORY_IDENTITY_ENV
        ] == "github:repository-id:1290429577"
        assert governance_pr.os.environ[
            governance_pr.SIGSTORE_REPOSITORY_ENV
        ] == "IvesChenHX/multi-agent-collab"
        assert governance_pr.os.environ[
            governance_pr.SIGSTORE_REPOSITORY_IDENTITY_ENV
        ] == "github:repository-id:1290429577"
        return {
            "argv": argv,
            "exit_code": 0,
            "output": {"ok": True, "issues": []},
            "stdout": None,
            "stderr": None,
        }

    monkeypatch.setattr(governance_pr, "_run", run)
    rejected_stdout = StringIO()
    rejected_stderr = StringIO()

    rejected = governance_pr.github_trusted_validate_main(
        environment={
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "attacker/example",
            "GITHUB_REPOSITORY_ID": "1290429577",
        },
        stdout=rejected_stdout,
        stderr=rejected_stderr,
    )

    assert rejected == 9
    assert calls == []
    assert json.loads(rejected_stdout.getvalue())["error"]["code"] == (
        "CI_GITHUB_TRUST_INVALID"
    )

    stdout = StringIO()
    stderr = StringIO()
    accepted = governance_pr.github_trusted_validate_main(
        environment={
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "IvesChenHX/multi-agent-collab",
            "GITHUB_REPOSITORY_ID": "1290429577",
        },
        stdout=stdout,
        stderr=stderr,
    )

    assert accepted == 0
    assert calls == [["mac", "validate", "--json"]]
    assert json.loads(stdout.getvalue()) == {"ok": True, "issues": []}
    assert stderr.getvalue() == ""
    assert all(name not in governance_pr.os.environ for name in tracked)


def test_cross_platform_ci_uses_the_fail_closed_github_trust_wrapper():
    project = Path(__file__).resolve().parents[2]
    workflow = (project / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert (
        "uv run --frozen python scripts/ci/governance_pr.py "
        "--github-trusted-validate --json"
    ) in workflow
    assert "run: uv run --frozen mac validate --json" not in workflow
    assert "fetch-depth: 0" in workflow
    assert "run: uv run --frozen python -m pytest" in workflow


def test_attested_v2_scope_approval_uses_a_distinct_authorized_logical_actor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    task_dir = tmp_path / "tasks" / TASK_ID
    task_dir.mkdir(parents=True)
    agents = tmp_path / ".agents"
    agents.mkdir()
    (agents / "config.yaml").write_text(
        yaml.safe_dump({
            "paths": {"ownership": ".agents/ownership.yaml"},
            "security": {"governance_sensitive_paths": [".github/workflows/*governance*"]},
        }),
        encoding="utf-8",
    )
    (agents / "ownership.yaml").write_text(
        yaml.safe_dump({
            "owners": {
                "governance": {"approvers": ["governance-owner"]},
                "platform": {"approvers": ["platform-owner"]},
                "security": {"approvers": ["security-owner"]},
                "devex": {"approvers": ["devex-owner"]},
                "tests": {},
                "docs": {"approvers": ["repo-owner"]},
            },
        }),
        encoding="utf-8",
    )
    base_paths = [
        "src/mac/authority.py",
        "src/mac/repository.py",
        "src/mac/application/task_service.py",
        "src/mac/cli.py",
        "scripts/ci/governance_pr.py",
        ".github/workflows/governance-pr.yml",
        "tests/operations/test_governance_pr.py",
        "tests/security/test_authority_commands.py",
        "docs/pilot/alpha-close-report.md",
        f"tasks/{TASK_ID}/**",
        f"tasks/private/{TASK_ID}/**",
    ]
    additions = [
        "src/mac/migration.py",
        "tests/test_authorityless_v6_migration.py",
        "migration/v6-authorityless/**",
        "tasks-v6/**",
    ]
    task = {
        "id": TASK_ID,
        "title": "GitHub authority bootstrap successor",
        "mode": "high_risk",
        "state": "triage",
        "revision": 2,
        "scope_contract_ref": f"tasks/{TASK_ID}/scope-contract.yaml",
    }
    scope = {
        "id": "SCOPE-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        "task_id": TASK_ID,
        "version": 2,
        "status": "proposed",
        "proposed_by": "repo-owner",
        "approved_by": [],
        "allowed_paths": [*base_paths, *additions],
        "owners": ["governance", "platform", "security", "devex", "tests", "docs"],
        "risk_tags": ["data_migration"],
    }
    (task_dir / "task.yaml").write_text(yaml.safe_dump(task), encoding="utf-8")
    (task_dir / "scope-contract.yaml").write_text(yaml.safe_dump(scope), encoding="utf-8")
    observed: list[AppendEvent] = []

    class FakeGateway:
        def __init__(self, _repo: Path):
            pass

        def prepare(self, command: AppendEvent):
            observed.append(command)
            intent = {"schema_version": 1, "task_id": TASK_ID, "operation": command.operation}
            request = AuthorityRequest(
                repository_identity="github:repository-id:1290429577",
                operation=command.operation,
                task_id=TASK_ID,
                actor_claim=command.actor_claim,
                expected_revision=command.expected_revision,
                idempotency_key=command.idempotency_key,
                intent_digest=canonical_digest(intent),
                policy_digest="sha256:" + "1" * 64,
                ownership_digest="sha256:" + "2" * 64,
                audience="mac-mutation-gateway/v1",
            )
            return SimpleNamespace(request=request, intent=intent, command=command)

    monkeypatch.setattr(governance_pr, "MutationGateway", FakeGateway)
    monkeypatch.setattr(governance_pr, "_sigstore_trust_environment", lambda: {})
    stdout = StringIO()
    stderr = StringIO()

    exit_code = github_attested_scope_prepare_main(
        output_dir=tmp_path / "prepared-v2-approval",
        repo=tmp_path,
        stdout=stdout,
        stderr=stderr,
        environment=_probe_environment("refs/heads/codex/governance-authority-sigstore"),
    )

    assert exit_code == 0
    assert stderr.getvalue() == ""
    assert len(observed) == 1
    assert observed[0].actor_claim == {"id": "governance-owner", "kind": "human"}
    assert observed[0].payload["approval"]["actor"] == observed[0].actor_claim
    assert observed[0].payload["approval"]["independence_level"] == "L2"


def test_github_validation_trust_requires_exact_actions_repository(
    monkeypatch: pytest.MonkeyPatch,
):
    isolated_environment: dict[str, str] = {}
    monkeypatch.setattr(governance_pr.os, "environ", isolated_environment)
    monkeypatch.setattr(
        governance_pr,
        "_sigstore_trust_environment",
        lambda: {governance_pr.SIGSTORE_REPOSITORY_ENV: "trusted"},
    )
    wrong = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "attacker/fork",
        "GITHUB_REPOSITORY_ID": "1",
    }
    governance_pr._configure_github_validation_trust(wrong)
    assert governance_pr.AUTHORITY_REPOSITORY_IDENTITY_ENV not in isolated_environment

    exact = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "IvesChenHX/multi-agent-collab",
        "GITHUB_REPOSITORY_ID": "1290429577",
    }
    governance_pr._configure_github_validation_trust(exact)
    assert isolated_environment[governance_pr.AUTHORITY_REPOSITORY_IDENTITY_ENV] == (
        "github:repository-id:1290429577"
    )
    assert isolated_environment[governance_pr.SIGSTORE_REPOSITORY_ENV] == "trusted"


def test_attested_task_apply_revalidates_plan_before_atomic_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    request = AuthorityRequest(
        repository_identity="github:repository-id:1290429577",
        operation="task.create",
        task_id=TASK_ID,
        actor_claim={"id": "governance-owner", "kind": "human"},
        expected_revision=-1,
        idempotency_key="github-sigstore-task-create:987654:2",
        intent_digest=canonical_digest({"task": TASK_ID}),
        policy_digest="sha256:" + "1" * 64,
        ownership_digest="sha256:" + "2" * 64,
        audience="mac-mutation-gateway/v1",
    )
    command = CreateTask(
        task={"id": TASK_ID, "title": "successor"},
        initial_entities=(("scope-contract.yaml", {"task_id": TASK_ID}),),
        actor_claim={"id": "governance-owner", "kind": "human"},
        idempotency_key=request.idempotency_key,
        minimum_independence="L2",
        replay_intent={"title": "successor"},
    )
    intent = {"schema_version": 1, "task_id": TASK_ID}
    plan = {
        "schema_version": 1,
        "kind": "mac.prepared-mutation",
        "command": governance_pr._serialize_create_task(command),
        "request": request.as_dict(),
        "intent": intent,
        "verification_policy": {
            "schema_version": 2,
            "repository": "IvesChenHX/multi-agent-collab",
            "repository_identity": "github:repository-id:1290429577",
            "signer_workflow": "IvesChenHX/multi-agent-collab/.github/workflows/governance-pr.yml",
            "source_ref": "refs/heads/codex/governance-authority-sigstore",
            "source_digest": "a" * 40,
            "predicate_type": (
                "https://github.com/IvesChenHX/multi-agent-collab/"
                "attestations/mutation-authority/v1"
            ),
            "environment": "governance-authority",
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "deny_self_hosted_runners": True,
        },
    }
    predicate = {
        "schema_version": 1,
        "allowed": True,
        "authenticated": True,
        "issuer": "https://token.actions.githubusercontent.com",
        "actor_id": "governance-owner",
        "actor_kind": "human",
        "independence_level": "L2",
        "issued_at": "2026-07-22T00:00:00Z",
        "expires_at": "2026-07-22T00:30:00Z",
        "request_digest": request.request_digest,
        "binding_digest": request.binding_digest,
        "environment": "governance-authority",
    }
    plan_path = tmp_path / "plan.json"
    predicate_path = tmp_path / "predicate.json"
    bundle_path = tmp_path / "bundle.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    predicate_path.write_text(json.dumps(predicate, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    bundle_path.write_text("{}", encoding="utf-8")
    calls: list[str] = []

    class FakeGateway:
        def __init__(self, _repo: Path):
            pass

        def prepare(self, observed: CreateTask):
            calls.append("prepare")
            assert observed.idempotency_key == command.idempotency_key
            return SimpleNamespace(request=request, intent=intent, command=observed)

        def execute(self, observed: CreateTask):
            calls.append("execute")
            assert observed.idempotency_key == command.idempotency_key
            return SimpleNamespace(
                projection={"id": TASK_ID, "revision": 0},
                event={"event_id": "EVT-test"},
                authority={
                    "attestation_id": "sigstore:test",
                    "binding_digest": request.binding_digest,
                },
            )

    monkeypatch.setattr(governance_pr, "MutationGateway", FakeGateway)
    monkeypatch.setattr(governance_pr, "command_manifest_digest", lambda _: "sha256:" + "b" * 64)
    stdout = StringIO()
    stderr = StringIO()

    exit_code = github_attested_task_apply_main(
        plan_path=plan_path,
        predicate_path=predicate_path,
        bundle_path=bundle_path,
        repo=tmp_path,
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 0
    assert calls == ["prepare", "execute"]
    assert json.loads(stdout.getvalue())["task_id"] == TASK_ID
    assert stderr.getvalue() == ""


def test_attested_apply_accepts_only_the_exact_ready_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    task_id = "TASK-01KY58ZZZZZZZZZZZZZZZZZZZZ-full-regression-closure-successor"
    task_dir = tmp_path / "tasks" / task_id
    task_dir.mkdir(parents=True)
    task, scope = _successor_documents(
        task_id,
        profile="full-regression",
        version=1,
    )
    (task_dir / "task.yaml").write_text(yaml.safe_dump(task), encoding="utf-8")
    (task_dir / "scope-contract.yaml").write_text(
        yaml.safe_dump(scope),
        encoding="utf-8",
    )
    context = TransitionContext(
        triage_complete=True,
        scope_approved=True,
        gates_selected=True,
    )
    command = Transition(
        task_id=task_id,
        target="ready",
        context=context,
        actor_claim={"id": "governance-owner", "kind": "human"},
        expected_revision=1,
        idempotency_key="github-sigstore-task-ready:987654:2",
        operation="task.transition.ready",
        transition_metadata={},
        minimum_independence="L2",
        replay_intent={
            "target": "ready",
            "condition": [],
            "fact_id": None,
            "reason": None,
        },
    )
    intent = {"schema_version": 1, "task_id": task_id, "target": "ready"}
    request = AuthorityRequest(
        repository_identity="github:repository-id:1290429577",
        operation=command.operation,
        task_id=task_id,
        actor_claim=command.actor_claim,
        expected_revision=1,
        idempotency_key=command.idempotency_key,
        intent_digest=canonical_digest(intent),
        policy_digest="sha256:" + "1" * 64,
        ownership_digest="sha256:" + "2" * 64,
        audience="mac-mutation-gateway/v1",
    )
    plan = {
        "schema_version": 1,
        "kind": "mac.prepared-mutation",
        "command": governance_pr._serialize_transition(command),
        "request": request.as_dict(),
        "intent": intent,
        "verification_policy": {
            "schema_version": 2,
            "repository": "IvesChenHX/multi-agent-collab",
            "repository_identity": "github:repository-id:1290429577",
            "signer_workflow": "IvesChenHX/multi-agent-collab/.github/workflows/governance-pr.yml",
            "source_ref": "refs/heads/codex/governance-authority-sigstore",
            "source_digest": "a" * 40,
            "predicate_type": (
                "https://github.com/IvesChenHX/multi-agent-collab/"
                "attestations/mutation-authority/v1"
            ),
            "environment": "governance-authority",
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "deny_self_hosted_runners": True,
        },
    }
    predicate = {
        "schema_version": 1,
        "allowed": True,
        "authenticated": True,
        "issuer": "https://token.actions.githubusercontent.com",
        "actor_id": "governance-owner",
        "actor_kind": "human",
        "independence_level": "L2",
        "issued_at": "2026-07-22T00:00:00Z",
        "expires_at": "2026-07-22T00:30:00Z",
        "request_digest": request.request_digest,
        "binding_digest": request.binding_digest,
        "environment": "governance-authority",
    }
    plan_path = tmp_path / "plan.json"
    predicate_path = tmp_path / "predicate.json"
    bundle_path = tmp_path / "bundle.json"
    plan_path.write_text(
        json.dumps(plan, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    predicate_path.write_text(
        json.dumps(predicate, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    bundle_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        governance_pr,
        "resolve_transition_context",
        lambda *_: context,
    )
    calls: list[str] = []

    class FakeGateway:
        def __init__(self, _repo: Path):
            pass

        def prepare(self, observed: Transition):
            calls.append("prepare")
            assert observed == command
            return SimpleNamespace(request=request, intent=intent, command=observed)

        def execute(self, observed: Transition):
            calls.append("execute")
            assert observed == command
            return SimpleNamespace(
                projection={"id": task_id, "revision": 2},
                event={"event_id": "EVT-ready"},
                authority={
                    "attestation_id": "sigstore:ready",
                    "binding_digest": request.binding_digest,
                },
            )

    monkeypatch.setattr(governance_pr, "MutationGateway", FakeGateway)
    monkeypatch.setattr(
        governance_pr,
        "command_manifest_digest",
        lambda _: "sha256:" + "b" * 64,
    )
    stdout = StringIO()
    stderr = StringIO()

    accepted = github_attested_task_apply_main(
        plan_path=plan_path,
        predicate_path=predicate_path,
        bundle_path=bundle_path,
        repo=tmp_path,
        stdout=stdout,
        stderr=stderr,
    )

    assert accepted == 0
    assert calls == ["prepare", "execute"]
    assert json.loads(stdout.getvalue())["revision"] == 2

    tampered = json.loads(plan_path.read_text(encoding="utf-8"))
    tampered["command"]["target"] = "executing"
    plan_path.write_text(
        json.dumps(tampered, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    calls.clear()
    rejected = github_attested_task_apply_main(
        plan_path=plan_path,
        predicate_path=predicate_path,
        bundle_path=bundle_path,
        repo=tmp_path,
        stdout=StringIO(),
        stderr=StringIO(),
    )

    assert rejected == 2
    assert calls == []

    plan_path.write_text(
        json.dumps(plan, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    task["objective"] = "tampered successor profile"
    (task_dir / "task.yaml").write_text(
        yaml.safe_dump(task),
        encoding="utf-8",
    )
    profile_rejected = github_attested_task_apply_main(
        plan_path=plan_path,
        predicate_path=predicate_path,
        bundle_path=bundle_path,
        repo=tmp_path,
        stdout=StringIO(),
        stderr=StringIO(),
    )

    assert profile_rejected == 2
    assert calls == []


def test_attested_apply_accepts_only_the_exact_scope_amendment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    additions = [
        "src/mac/migration.py",
        "tests/test_authorityless_v6_migration.py",
        "migration/v6-authorityless/**",
        "tasks-v6/**",
    ]
    base_paths = [
        "src/mac/authority.py",
        "src/mac/repository.py",
        "src/mac/application/task_service.py",
        "src/mac/cli.py",
        "scripts/ci/governance_pr.py",
        ".github/workflows/governance-pr.yml",
        "tests/operations/test_governance_pr.py",
        "tests/security/test_authority_commands.py",
        "docs/pilot/alpha-close-report.md",
        f"tasks/{TASK_ID}/**",
        f"tasks/private/{TASK_ID}/**",
    ]
    replay_intent = {
        "add": additions,
        "add_operation": [],
        "approver": ["repo-owner"],
        "risk_tag": ["data_migration"],
        "independent": True,
    }
    old_scope = {
        "id": "SCOPE-example",
        "task_id": TASK_ID,
        "version": 1,
        "status": "approved",
        "approved_by": ["repo-owner"],
        "allowed_paths": base_paths,
        "risk_tags": [],
    }
    new_scope = {
        "id": "SCOPE-example",
        "task_id": TASK_ID,
        "version": 2,
        "status": "proposed",
        "proposed_by": "repo-owner",
        "approved_by": [],
        "allowed_paths": [*base_paths, *additions],
        "risk_tags": ["data_migration"],
    }
    scope_path = tmp_path / "tasks" / TASK_ID / "scope-contract.yaml"
    history_path = tmp_path / "tasks" / TASK_ID / "scope-history" / "scope-contract.v1.yaml"
    command = AppendEvent(
        task_id=TASK_ID,
        event_type="scope_proposed",
        payload={
            "scope_id": "SCOPE-example",
            "version": 2,
            "amendment": True,
            "scope": new_scope,
        },
        actor_claim={"id": "repo-owner", "kind": "human"},
        expected_revision=1,
        idempotency_key="github-sigstore-scope-amend:987654:2",
        operation="scope.amend",
        materializations=((history_path, old_scope), (scope_path, new_scope)),
        replace_existing=frozenset({scope_path}),
        minimum_independence="L2",
        replay_intent=replay_intent,
    )
    intent = {"schema_version": 1, "task_id": TASK_ID, "operation": "scope.amend"}
    request = AuthorityRequest(
        repository_identity="github:repository-id:1290429577",
        operation="scope.amend",
        task_id=TASK_ID,
        actor_claim={"id": "repo-owner", "kind": "human"},
        expected_revision=1,
        idempotency_key=command.idempotency_key,
        intent_digest=canonical_digest(intent),
        policy_digest="sha256:" + "1" * 64,
        ownership_digest="sha256:" + "2" * 64,
        audience="mac-mutation-gateway/v1",
    )
    plan = {
        "schema_version": 1,
        "kind": "mac.prepared-mutation",
        "command": governance_pr._serialize_append_event(command, tmp_path),
        "request": request.as_dict(),
        "intent": intent,
        "verification_policy": {
            "schema_version": 2,
            "repository": "IvesChenHX/multi-agent-collab",
            "repository_identity": "github:repository-id:1290429577",
            "signer_workflow": "IvesChenHX/multi-agent-collab/.github/workflows/governance-pr.yml",
            "source_ref": "refs/heads/codex/governance-authority-sigstore",
            "source_digest": "a" * 40,
            "predicate_type": (
                "https://github.com/IvesChenHX/multi-agent-collab/"
                "attestations/mutation-authority/v1"
            ),
            "environment": "governance-authority",
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "deny_self_hosted_runners": True,
        },
    }
    predicate = {
        "schema_version": 1,
        "allowed": True,
        "authenticated": True,
        "issuer": "https://token.actions.githubusercontent.com",
        "actor_id": "repo-owner",
        "actor_kind": "human",
        "independence_level": "L2",
        "issued_at": "2026-07-22T00:00:00Z",
        "expires_at": "2026-07-22T00:30:00Z",
        "request_digest": request.request_digest,
        "binding_digest": request.binding_digest,
        "environment": "governance-authority",
    }
    plan_path = tmp_path / "plan.json"
    predicate_path = tmp_path / "predicate.json"
    bundle_path = tmp_path / "bundle.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    predicate_path.write_text(json.dumps(predicate, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    bundle_path.write_text("{}", encoding="utf-8")
    calls: list[str] = []

    class FakeGateway:
        def __init__(self, _repo: Path):
            pass

        def prepare(self, observed: AppendEvent):
            calls.append("prepare")
            return SimpleNamespace(request=request, intent=intent, command=observed)

        def execute(self, observed: AppendEvent):
            calls.append("execute")
            assert observed.replay_intent == replay_intent
            return SimpleNamespace(
                projection={"id": TASK_ID, "revision": 2},
                event={"event_id": "EVT-test"},
                authority={"attestation_id": "sigstore:test", "binding_digest": request.binding_digest},
            )

    monkeypatch.setattr(governance_pr, "MutationGateway", FakeGateway)
    monkeypatch.setattr(governance_pr, "command_manifest_digest", lambda _: "sha256:" + "b" * 64)
    stdout = StringIO()
    stderr = StringIO()

    exit_code = github_attested_task_apply_main(
        plan_path=plan_path,
        predicate_path=predicate_path,
        bundle_path=bundle_path,
        repo=tmp_path,
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 0
    assert calls == ["prepare", "execute"]
    assert json.loads(stdout.getvalue())["revision"] == 2
    assert stderr.getvalue() == ""


def test_governance_workflow_isolates_oidc_from_pull_request_code():
    workflow = yaml.safe_load(
        Path(".github/workflows/governance-pr.yml").read_text(encoding="utf-8")
    )
    trigger = workflow.get("on", workflow.get(True))
    dispatch_inputs = trigger["workflow_dispatch"]["inputs"]
    assert dispatch_inputs["authority_transition_successor_ready"] == {
        "description": "Prepare, sign, and export the successor triage-to-ready mutation",
        "required": False,
        "type": "boolean",
        "default": False,
    }
    assert dispatch_inputs["authority_advance_successor_execution"] == {
        "description": "Prepare, sign, and export exactly one successor execution bootstrap mutation",
        "required": False,
        "type": "boolean",
        "default": False,
    }
    assert workflow["permissions"] == {"contents": "read"}
    governance = workflow["jobs"]["governance"]
    assert "environment" not in governance
    assert "permissions" not in governance
    authority = workflow["jobs"]["authority-probe"]
    assert authority["environment"] == "governance-authority"
    assert authority["env"]["MAC_AUTHORITY_REPOSITORY_IDENTITY"] == (
        "github:repository-id:${{ github.repository_id }}"
    )
    assert authority["env"]["MAC_AUTHORITY_SUCCESSOR_PROFILE"] == (
        "${{ inputs.authority_successor_profile || 'bootstrap' }}"
    )
    assert authority["permissions"] == {
        "contents": "read",
        "id-token": "write",
        "attestations": "write",
    }
    assert "workflow_dispatch" in authority["if"]
    assert "authority_probe" in authority["if"]
    checkout = authority["steps"][0]
    assert checkout["uses"] == (
        "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd"
    )
    assert checkout["with"]["ref"] == "${{ github.sha }}"
    assert checkout["with"]["fetch-depth"] == 0
    assert checkout["with"]["persist-credentials"] is False
    rendered = json.dumps(authority, sort_keys=True)
    assert "pull_request.head" not in rendered
    assert "PR_HEAD" not in rendered
    assert "MAC_AUTHORITY_BROKER_ENDPOINT" not in rendered
    attest = next(step for step in authority["steps"] if step.get("id") == "authority-attestation")
    assert attest["uses"] == "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6"
    assert attest["with"]["predicate-type"].endswith("/authority-probe/v1")
    assert "bundle-path" in rendered
    mutation_attest = next(step for step in authority["steps"] if step.get("id") == "mutation-attestation")
    assert mutation_attest["uses"] == "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6"
    upload = next(step for step in authority["steps"] if str(step.get("uses", "")).startswith("actions/upload-artifact@"))
    assert upload["uses"] == "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
    assert "authority_create_successor" in authority["if"]
    assert "authority_approve_successor_scope" in authority["if"]
    assert "authority_amend_successor_scope" in authority["if"]
    assert "authority_transition_successor_ready" in authority["if"]
    assert "authority_advance_successor_execution" in authority["if"]
    ready_prepare = next(
        step
        for step in authority["steps"]
        if step.get("name") == "Prepare the exact successor ready transition"
    )
    assert ready_prepare["if"] == "${{ inputs.authority_transition_successor_ready }}"
    assert "--github-attested-ready-prepare" in ready_prepare["run"]
    execution_prepare = next(
        step
        for step in authority["steps"]
        if step.get("name") == "Prepare one exact successor execution bootstrap mutation"
    )
    assert execution_prepare["if"] == "${{ inputs.authority_advance_successor_execution }}"
    assert "--github-attested-execution-prepare" in execution_prepare["run"]
    for step_id in ("mutation-attestation",):
        step = next(step for step in authority["steps"] if step.get("id") == step_id)
        assert "authority_transition_successor_ready" in step["if"]
    collect = next(
        step
        for step in authority["steps"]
        if step.get("name") == "Collect the non-secret authority bundle"
    )
    assert "authority_transition_successor_ready" in collect["if"]
    assert "authority_transition_successor_ready" in upload["if"]
    assert "authority_advance_successor_execution" in mutation_attest["if"]
    assert "authority_advance_successor_execution" in collect["if"]
    assert "authority_advance_successor_execution" in upload["if"]


def test_governance_entrypoint_routes_attested_ready_prepare(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    observed: list[Path] = []

    def ready_prepare(*, output_dir: Path) -> int:
        observed.append(output_dir)
        return 17

    monkeypatch.setattr(
        governance_pr,
        "github_attested_ready_prepare_main",
        ready_prepare,
    )

    exit_code = governance_pr.main([
        "--github-attested-ready-prepare",
        "--out",
        str(tmp_path / "ready"),
    ])

    assert exit_code == 17
    assert observed == [tmp_path / "ready"]


def test_governance_entrypoint_routes_attested_execution_prepare(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    observed: list[Path] = []

    def execution_prepare(*, output_dir: Path) -> int:
        observed.append(output_dir)
        return 19

    monkeypatch.setattr(
        governance_pr,
        "github_attested_execution_prepare_main",
        execution_prepare,
        raising=False,
    )

    exit_code = governance_pr.main([
        "--github-attested-execution-prepare",
        "--out",
        str(tmp_path / "execution"),
    ])

    assert exit_code == 19
    assert observed == [tmp_path / "execution"]


def test_discover_task_ids_from_changed_v6_task_metadata():
    paths = [f"tasks/{TASK_ID}-refund-auth/events/EVT-example.json", "src/mac/domain/task.py"]

    assert discover_task_ids(paths, []) == [f"{TASK_ID}-refund-auth"]


def test_explicit_task_id_covers_pr_without_changed_task_metadata():
    assert discover_task_ids(["src/mac/domain/task.py"], [TASK_ID]) == [TASK_ID]


def test_advisory_reports_but_does_not_block():
    ok, exit_code = evaluate("advisory", [{"exit_code": 6}], [])

    assert ok is True
    assert exit_code == 0


def test_enforced_fails_closed_without_task_context():
    ok, exit_code = evaluate("enforced", [{"exit_code": 0}], [])

    assert ok is False
    assert exit_code == 7


def test_enforced_preserves_stable_scope_exit_code():
    ok, exit_code = evaluate("enforced", [{"exit_code": 0}, {"exit_code": 6}], [TASK_ID])

    assert ok is False
    assert exit_code == 6


def test_evidence_gate_accepts_metadata_only_successor_commit_and_rejects_new_code(tmp_path: Path, monkeypatch):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "test"], check=True)
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.py").write_text("v1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "src/app.py"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "code"], check=True)
    commit = subprocess.run(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], check=True, text=True, capture_output=True).stdout.strip()
    tree = subprocess.run(["git", "-C", str(tmp_path), "rev-parse", "HEAD^{tree}"], check=True, text=True, capture_output=True).stdout.strip()
    task_directory = f"{TASK_ID}-refund-auth"
    task_dir = tmp_path / "tasks" / task_directory
    (task_dir / "runs").mkdir(parents=True)
    (task_dir / "evidence").mkdir()
    policy = "sha256:" + "a" * 64
    task = {"id": TASK_ID, "required_gates": ["targeted_tests"], "acceptance_criteria": [{"id": "AC-001", "required": True}], "policy_ref": {"combined_digest": policy}}
    (task_dir / "task.yaml").write_text(yaml.safe_dump(task), encoding="utf-8")
    run_id = "RUN-01K0W4Z36K3W5C2R0A3M8N9P7T"
    (task_dir / "runs" / f"{run_id}.json").write_text(json.dumps({"id": run_id, "status": "succeeded"}), encoding="utf-8")
    evidence = {"id": "EVD-01K0W4Z36K3W5C2R0A3M8N9P7X", "kind": "command", "run_id": run_id, "subject": {"type": "commit", "commit_sha": commit, "tree_sha": tree}, "policy_digest": policy, "claims": [{"gate": "targeted_tests"}, {"acceptance_criterion": "AC-001"}], "execution": {"exit_code": 0}, "validity": {"status": "valid", "invalidated_by": []}}
    (task_dir / "evidence" / f"{evidence['id']}.json").write_text(json.dumps(evidence), encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", f"tasks/{task_directory}"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "evidence metadata"], check=True)
    monkeypatch.chdir(tmp_path)

    accepted = check_current_evidence(Path("."), task_directory, "HEAD")
    assert accepted["exit_code"] == 0

    (tmp_path / "src/app.py").write_text("v2\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "src/app.py"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "new code"], check=True)
    rejected = check_current_evidence(Path("."), task_directory, "HEAD")
    assert rejected["exit_code"] == 7


def test_enforced_main_executes_and_blocks_on_current_evidence_gate(tmp_path: Path, monkeypatch):
    config = tmp_path / "config.yaml"
    config.write_text("governance_level: enforced\n", encoding="utf-8")
    task_directory = f"{TASK_ID}-refund-auth"
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        governance_pr,
        "_git_changed_paths",
        lambda base, head: [f"tasks/{task_directory}/events/EVT-example.json"],
    )
    monkeypatch.setattr(
        governance_pr,
        "_run",
        lambda argv: {"argv": argv, "exit_code": 0, "output": {"ok": True}, "stdout": None, "stderr": None},
    )

    def reject_current_evidence(repo: Path, directory: str, head: str):
        calls.append((directory, head))
        return {"argv": ["evidence-gate", directory, head], "exit_code": 7, "output": {"ok": False}, "stdout": None, "stderr": None}

    monkeypatch.setattr(governance_pr, "check_current_evidence", reject_current_evidence)

    exit_code = governance_pr.main(
        ["--base", "base", "--head", "head", "--config", str(config), "--json"]
    )

    assert exit_code == 7
    assert calls == [(task_directory, "head")]
