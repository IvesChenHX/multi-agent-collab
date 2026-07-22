import hashlib
import json
import subprocess
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
    github_attestation_probe_prepare_main,
    github_attestation_probe_verify_main,
    github_oidc_broker_exchange,
    github_oidc_broker_main,
    github_oidc_probe_main,
)
from mac.authority import AuthorityRequest, canonical_digest


TASK_ID = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"


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


def _probe_environment() -> dict[str, str]:
    return {
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


def test_governance_workflow_isolates_oidc_from_pull_request_code():
    workflow = yaml.safe_load(
        Path(".github/workflows/governance-pr.yml").read_text(encoding="utf-8")
    )
    assert workflow["permissions"] == {"contents": "read"}
    governance = workflow["jobs"]["governance"]
    assert "environment" not in governance
    assert "permissions" not in governance
    authority = workflow["jobs"]["authority-probe"]
    assert authority["environment"] == "governance-authority"
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
    assert checkout["with"]["persist-credentials"] is False
    rendered = json.dumps(authority, sort_keys=True)
    assert "pull_request.head" not in rendered
    assert "PR_HEAD" not in rendered
    assert "MAC_AUTHORITY_BROKER_ENDPOINT" not in rendered
    attest = next(step for step in authority["steps"] if step.get("id") == "authority-attestation")
    assert attest["uses"] == "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6"
    assert attest["with"]["predicate-type"].endswith("/authority-probe/v1")
    assert "bundle-path" in rendered


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
