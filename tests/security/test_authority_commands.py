from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


_BROKER_MODE_ENV = "MAC_AUTHORITY_BROKER_CONTEXT_TEST_MODE"
_BROKER_INDEPENDENCE_ENV = "MAC_AUTHORITY_BROKER_CONTEXT_TEST_INDEPENDENCE"
_TEST_KEY_ID = "test-rs256-2026"
_TEST_RSA_N_B64 = "vflgpk3NdE7v-NoV4i6SSck5iyF82i3hn27NBoJCev2cDAd7VLwPv0P9yfrufsov9AFhZHZD0FJphCQYlo4nkZkNIr0fIyygUShdojVfBiDh73FERogmd4b1HhRTf-DXj0_n2HZOipWHm8NVj1OHzmpTnmFD2NH1w7eE4xIEz4QSCfKH8ZByMU5bb4FTYmKk8TPbPxYRc0UUX9SBo6pGDzEWaAF1XJhQc77CIHaDcnWFrK35bOpcc3yk3We-CAYvZPk2TQKM8BCvKUeWh5d45QDcZxko_GV4OiDOGElL1i0-e3MWSIpeBeLEnbz_MhMaC8eFGLmXKytqnPylPM4Xhw"
_TEST_RSA_E_B64 = "AQAB"
_TEST_RSA_D_B64 = "BrxvJkml8-5rArDnWIpimrktQ115nUB5OpT_ZUnjH5Qa7C_e7XJwDU3uef-RMbyFL_eIkFTDmZrPR2WcQmJiAGVws_87hmmQebA4hoYYvqsV0WhIja1Jzkn7xDt5ea3rfTDN8LzCxi-Z8lz3wLBE8kqOeOD_OqxSZ_eVTHpMFcUlogfZhk5UShR52ldpiihPB7amjSuEz0zWOdFYd-YJLWLH20rm_Et25FB9RfMAEUkXarKTvDu_8T8CVzWLhp5k9NBArtGKnLbi9s_5oHlEyhaOHN4uNdcYzx3wvjmM-m2dheXfMSLK1OIuSWg-9lt-LfU5sV2xNCW6x6G_KIFH-Q"
_RSA_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _base64url_int(value: str) -> int:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return int.from_bytes(base64.urlsafe_b64decode((value + padding).encode("ascii")), "big")


def _rsa_sign(message: bytes) -> bytes:
    modulus = _base64url_int(_TEST_RSA_N_B64)
    private_exponent = _base64url_int(_TEST_RSA_D_B64)
    size = (modulus.bit_length() + 7) // 8
    digest_info = _RSA_SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    padding_length = size - len(digest_info) - 3
    encoded = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
    return pow(int.from_bytes(encoded, "big"), private_exponent, modulus).to_bytes(size, "big")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes, *, domain: bytes = b"") -> str:
    return "sha256:" + hashlib.sha256(domain + value).hexdigest()


def _render_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _mismatched_request(request: dict[str, Any], mode: str) -> dict[str, Any]:
    result = copy.deepcopy(request)
    mutations: dict[str, tuple[str, Any]] = {
        "wrong_actor": ("actor_claim", {"id": "mismatched-actor", "kind": "agent"}),
        "wrong_operation": ("operation", "finding.resolve"),
        "wrong_task": ("task_id", "TASK-MISMATCHED"),
        "wrong_idempotency": ("idempotency_key", "mismatched-idempotency"),
        "wrong_intent": ("intent_digest", "sha256:" + "0" * 64),
        "wrong_policy": ("policy_digest", "sha256:" + "1" * 64),
        "wrong_ownership": ("ownership_digest", "sha256:" + "2" * 64),
        "wrong_repository": ("repository_identity", "mismatched-repository"),
    }
    if mode == "wrong_revision":
        result["expected_revision"] = int(result["expected_revision"]) + 1
    elif mode in mutations:
        key, value = mutations[mode]
        result[key] = value
    return result


def _broker_main() -> int:
    try:
        request = json.loads(sys.stdin.read())
        issuer = os.environ["MAC_AUTHORITY_EXPECTED_ISSUER"]
        broker_digest = os.environ["MAC_AUTHORITY_BROKER_MANIFEST_SHA256"]
    except (KeyError, ValueError, json.JSONDecodeError):
        return 2
    if not isinstance(request, dict):
        return 2

    mode = os.environ.get(_BROKER_MODE_ENV, "allow")
    if mode == "require_oidc_environment" and (
        os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
        != "https://pipelines.actions.githubusercontent.com/oidc?job=trusted"
        or os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != "github-oidc-request-token"
        or os.environ.get("GITHUB_TOKEN") is not None
    ):
        return 2
    bound_request = _mismatched_request(request, mode)
    now = datetime.now(timezone.utc)
    issued = now - timedelta(seconds=5)
    expires = now + timedelta(minutes=5)
    if mode == "expired":
        issued = now - timedelta(hours=2)
        expires = now - timedelta(hours=1)
    actor = dict(bound_request.get("actor_claim") or {})
    payload = {
        "schema_version": 1,
        "algorithm": "RS256",
        "key_id": _TEST_KEY_ID,
        "allowed": mode != "deny",
        "authenticated": mode != "unauthenticated",
        "issuer": issuer if mode != "wrong_issuer" else "untrusted-test-issuer",
        "audience": bound_request.get("audience") if mode != "wrong_audience" else "wrong-audience",
        "attestation_id": "ATT-" + _sha256(_canonical_json(bound_request)).split(":", 1)[1][:24],
        "actor_id": actor.get("id", ""),
        "actor_kind": actor.get("kind", ""),
        "independence_level": os.environ.get(_BROKER_INDEPENDENCE_ENV, "L3"),
        "issued_at": _render_time(issued),
        "expires_at": _render_time(expires),
        "request": bound_request,
        "request_digest": _sha256(_canonical_json(bound_request)),
        "binding_digest": _sha256(_canonical_json(bound_request), domain=b"mac-authority-binding-v1\x00"),
        "broker_digest": broker_digest,
    }
    signature = _rsa_sign(_canonical_json(payload))
    if mode == "bad_signature":
        signature = bytes([signature[0] ^ 0xFF, *signature[1:]])
    response = {"payload": payload, "signature": base64.b64encode(signature).decode("ascii")}
    sys.stdout.write(_canonical_json(response).decode("utf-8") + "\n")
    return 0


def _sigstore_verifier_main() -> int:
    try:
        subject_path = Path(sys.argv[2])
        bundle_path = Path(sys.argv[sys.argv.index("--bundle") + 1])
        predicate_type = sys.argv[sys.argv.index("--predicate-type") + 1]
        subject = subject_path.read_bytes()
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        predicate = bundle["test_predicate"]
    except (IndexError, KeyError, OSError, ValueError, json.JSONDecodeError):
        return 2
    output = [
        {
            "attestation": {"bundle": "test"},
            "verificationResult": {
                "statement": {
                    "subject": [{
                        "name": subject_path.name,
                        "digest": {"sha256": hashlib.sha256(subject).hexdigest()},
                    }],
                    "predicateType": predicate_type,
                    "predicate": predicate,
                },
                "verifiedTimestamps": [{"type": "test-transparency-log"}],
                "signature": {
                    "certificate": {
                        "issuer": "https://token.actions.githubusercontent.com",
                        "sourceRepository": "IvesChenHX/multi-agent-collab",
                        "sourceDigest": "a" * 40,
                    }
                },
            },
        }
    ]
    sys.stdout.write(json.dumps(output, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(
        _sigstore_verifier_main()
        if len(sys.argv) > 1 and sys.argv[1] == "--sigstore-verifier"
        else _broker_main()
    )

import pytest

from mac.authority import (
    BROKER_ARGV_ENV,
    BROKER_MANIFEST_ENV,
    EXPECTED_ISSUER_ENV,
    PUBLIC_KEYRING_ENV,
    SIGSTORE_BUNDLE_ENV,
    SIGSTORE_ENVIRONMENT_ENV,
    SIGSTORE_OIDC_ISSUER_ENV,
    SIGSTORE_PREDICATE_ENV,
    SIGSTORE_PREDICATE_TYPE_ENV,
    SIGSTORE_REPOSITORY_ENV,
    SIGSTORE_SIGNER_WORKFLOW_ENV,
    SIGSTORE_SOURCE_DIGEST_ENV,
    SIGSTORE_SOURCE_REF_ENV,
    SIGSTORE_VERIFIER_ARGV_ENV,
    SIGSTORE_VERIFIER_MANIFEST_ENV,
    AuthorityRequest,
    SigstoreAuthorityAdapter,
    SubprocessAuthorityAdapter,
    authority_audit_record,
    canonical_digest,
    command_manifest_digest,
    current_authority_verifier,
    governance_sensitive,
    require_authority,
    trusted_authority_verifier,
    verify_authority_audit_record,
)
from mac.application.task_service import TaskService
from mac.cli import (
    approval_record,
    finding_open,
    finding_waive,
    init_command,
    result_submit,
    run_register,
    scope_approve,
    scope_propose,
    task_cancel,
    task_new,
    task_supersede,
    task_transition,
    work_unit_new,
    work_unit_ready,
)
from mac.errors import MacError
from mac.io import atomic_write_json, load_data
from mac.repository import FilesystemTaskRepository


_BROKER = Path(__file__).resolve()
_HOST_ENV = (BROKER_ARGV_ENV, BROKER_MANIFEST_ENV, PUBLIC_KEYRING_ENV, EXPECTED_ISSUER_ENV)


def configure_test_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure the external signed broker through host environment only."""

    argv = [sys.executable, "-I", str(_BROKER)]
    monkeypatch.setenv(BROKER_ARGV_ENV, json.dumps(argv))
    monkeypatch.setenv(BROKER_MANIFEST_ENV, command_manifest_digest(argv))
    keyring = {
        "schema_version": 1,
        "keys": [{
            "key_id": _TEST_KEY_ID,
            "algorithm": "RS256",
            "n": _TEST_RSA_N_B64,
            "e": _TEST_RSA_E_B64,
        }],
    }
    monkeypatch.setenv(
        PUBLIC_KEYRING_ENV,
        base64.b64encode(_canonical_json(keyring)).decode("ascii"),
    )
    monkeypatch.setenv(EXPECTED_ISSUER_ENV, "test-host-authority")
    monkeypatch.delenv(_BROKER_MODE_ENV, raising=False)
    monkeypatch.delenv(_BROKER_INDEPENDENCE_ENV, raising=False)


def remove_test_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _HOST_ENV:
        monkeypatch.delenv(name, raising=False)


def disable_test_mutation_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disable new authority decisions without erasing historical trust roots."""

    for name in (BROKER_ARGV_ENV, BROKER_MANIFEST_ENV, _BROKER_MODE_ENV, _BROKER_INDEPENDENCE_ENV):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _host_authority_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_test_authority(monkeypatch)


def _authority_request() -> AuthorityRequest:
    return AuthorityRequest(
        repository_identity="repo:sha256:0123456789abcdef",
        operation="result.submit",
        task_id="TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        actor_claim={"id": "executor-7", "kind": "agent"},
        expected_revision=12,
        idempotency_key="submit-result-12",
        intent_digest=canonical_digest({"result_id": "RESULT-01K0W4Z36K3W5C2R0A3M8N9P7Q"}),
        policy_digest=canonical_digest({"policy": "frozen"}),
        ownership_digest=canonical_digest({"ownership": "frozen"}),
        audience="mac-mutation-gateway/v1",
    )


def _configured_adapter(monkeypatch: pytest.MonkeyPatch) -> SubprocessAuthorityAdapter:
    configure_test_authority(monkeypatch)
    return current_authority_verifier()


def _configure_sigstore_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: AuthorityRequest,
) -> None:
    now = datetime.now(timezone.utc)
    predicate = {
        "schema_version": 1,
        "allowed": True,
        "authenticated": True,
        "issuer": "https://token.actions.githubusercontent.com",
        "actor_id": request.actor_claim["id"],
        "actor_kind": request.actor_claim["kind"],
        "independence_level": "L2",
        "issued_at": _render_time(now - timedelta(seconds=5)),
        "expires_at": _render_time(now + timedelta(minutes=5)),
        "request_digest": request.request_digest,
        "binding_digest": request.binding_digest,
        "environment": "governance-authority",
    }
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "test_predicate": predicate,
    }
    predicate_path = tmp_path / "predicate.json"
    bundle_path = tmp_path / "bundle.json"
    predicate_path.write_bytes(_canonical_json(predicate))
    bundle_path.write_bytes(_canonical_json(bundle))
    argv = [sys.executable, "-I", str(_BROKER), "--sigstore-verifier"]
    monkeypatch.setenv(SIGSTORE_VERIFIER_ARGV_ENV, json.dumps(argv, separators=(",", ":")))
    monkeypatch.setenv(SIGSTORE_VERIFIER_MANIFEST_ENV, command_manifest_digest(argv))
    monkeypatch.setenv(SIGSTORE_REPOSITORY_ENV, "IvesChenHX/multi-agent-collab")
    monkeypatch.setenv(
        SIGSTORE_SIGNER_WORKFLOW_ENV,
        "IvesChenHX/multi-agent-collab/.github/workflows/governance-pr.yml",
    )
    monkeypatch.setenv(
        SIGSTORE_PREDICATE_TYPE_ENV,
        "https://github.com/IvesChenHX/multi-agent-collab/attestations/mutation-authority/v1",
    )
    monkeypatch.setenv(SIGSTORE_ENVIRONMENT_ENV, "governance-authority")
    monkeypatch.setenv(SIGSTORE_OIDC_ISSUER_ENV, "https://token.actions.githubusercontent.com")
    monkeypatch.setenv(SIGSTORE_SOURCE_REF_ENV, "refs/heads/master")
    monkeypatch.setenv(SIGSTORE_SOURCE_DIGEST_ENV, "a" * 40)
    monkeypatch.setenv(SIGSTORE_PREDICATE_ENV, str(predicate_path))
    monkeypatch.setenv(SIGSTORE_BUNDLE_ENV, str(bundle_path))


def test_missing_host_configuration_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _HOST_ENV:
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(MacError) as captured:
        current_authority_verifier()

    assert captured.value.code == "AUTHORITY_CONFIGURATION_MISSING"
    assert "secret" not in str(captured.value).lower()


def test_broker_command_must_match_host_pinned_manifest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(BROKER_MANIFEST_ENV, "sha256:" + "0" * 64)

    with pytest.raises(MacError) as captured:
        current_authority_verifier()

    assert captured.value.code == "AUTHORITY_BROKER_MANIFEST_MISMATCH"
    assert str(_BROKER) not in str(captured.value)
    assert sys.executable not in str(captured.value)


def test_broker_receives_only_the_required_github_oidc_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "https://pipelines.actions.githubusercontent.com/oidc?job=trusted",
    )
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "github-oidc-request-token")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-cross-the-broker-seam")
    monkeypatch.setenv(_BROKER_MODE_ENV, "require_oidc_environment")

    fact = _configured_adapter(monkeypatch).authorize(request=_authority_request())

    assert fact.allowed is True


def test_successful_response_creates_a_sealed_verified_fact(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = _configured_adapter(monkeypatch)
    request = _authority_request()

    fact = require_authority(adapter, request=request, minimum_independence="L2")

    assert fact.actor_id == request.actor_claim["id"]
    assert fact.actor_kind == request.actor_claim["kind"]
    assert fact.operation == request.operation
    assert fact.task_id == request.task_id
    assert fact.expected_revision == request.expected_revision
    assert fact.idempotency_key == request.idempotency_key
    assert fact.request_digest == request.request_digest
    assert fact.binding_digest == request.binding_digest
    assert fact.broker_digest.startswith("sha256:")
    assert fact.trust_digest.startswith("sha256:")


def test_sigstore_bundle_creates_a_durable_non_secret_authority_fact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _authority_request()
    _configure_sigstore_authority(tmp_path, monkeypatch, request)

    adapter = current_authority_verifier()
    assert type(adapter) is SigstoreAuthorityAdapter
    fact = require_authority(adapter, request=request, minimum_independence="L2")
    audit = authority_audit_record(fact)

    assert audit["store_contract_version"] == 3
    assert audit["signature_algorithm"] == "sigstore-keyless"
    assert audit["actor_id"] == request.actor_claim["id"]
    assert audit["binding_digest"] == request.binding_digest
    assert set(audit["signed_envelope"]) == {
        "subject",
        "predicate",
        "bundle",
        "verification_policy",
    }
    rendered = json.dumps(audit, sort_keys=True)
    assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in rendered
    assert "GITHUB_TOKEN" not in rendered

    monkeypatch.delenv(SIGSTORE_BUNDLE_ENV)
    monkeypatch.delenv(SIGSTORE_PREDICATE_ENV)
    monkeypatch.delenv(SIGSTORE_SOURCE_REF_ENV)
    monkeypatch.delenv(SIGSTORE_SOURCE_DIGEST_ENV)
    verify_authority_audit_record(audit, request)

    portable_verifier = tmp_path / "portable-sigstore-verifier.py"
    shutil.copyfile(_BROKER, portable_verifier)
    portable_argv = [
        sys.executable, "-I", str(portable_verifier), "--sigstore-verifier",
    ]
    assert command_manifest_digest(portable_argv) != (
        audit["signed_envelope"]["verification_policy"]["verifier_manifest"]
    )
    monkeypatch.setenv(
        SIGSTORE_VERIFIER_ARGV_ENV,
        json.dumps(portable_argv, separators=(",", ":")),
    )
    monkeypatch.setenv(
        SIGSTORE_VERIFIER_MANIFEST_ENV,
        command_manifest_digest(portable_argv),
    )
    verify_authority_audit_record(audit, request)


def test_sigstore_historical_verification_rejects_predicate_or_bundle_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _authority_request()
    _configure_sigstore_authority(tmp_path, monkeypatch, request)
    fact = require_authority(current_authority_verifier(), request=request, minimum_independence="L2")
    audit = authority_audit_record(fact)
    monkeypatch.delenv(SIGSTORE_BUNDLE_ENV)
    monkeypatch.delenv(SIGSTORE_PREDICATE_ENV)

    predicate_drift = copy.deepcopy(audit)
    predicate_drift["signed_envelope"]["predicate"]["actor_id"] = "attacker"
    with pytest.raises(MacError) as predicate_error:
        verify_authority_audit_record(predicate_drift, request)
    assert predicate_error.value.code in {
        "AUTHORITY_BINDING_MISMATCH",
        "AUTHORITY_SIGNATURE_INVALID",
    }

    bundle_drift = copy.deepcopy(audit)
    bundle_drift["signed_envelope"]["bundle"]["extra"] = "tampered"
    with pytest.raises(MacError) as bundle_error:
        verify_authority_audit_record(bundle_drift, request)
    assert bundle_error.value.code == "AUTHORITY_BINDING_MISMATCH"


def test_sigstore_ready_signature_cannot_authorize_executing_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ready_request = replace(
        _authority_request(),
        operation="task.transition.ready",
        expected_revision=4,
        idempotency_key="github-sigstore-ready:987654:2",
        intent_digest=canonical_digest({"target": "ready"}),
    )
    _configure_sigstore_authority(tmp_path, monkeypatch, ready_request)
    ready_fact = require_authority(
        current_authority_verifier(),
        request=ready_request,
        minimum_independence="L2",
    )
    ready_audit = authority_audit_record(ready_fact)
    monkeypatch.delenv(SIGSTORE_BUNDLE_ENV)
    monkeypatch.delenv(SIGSTORE_PREDICATE_ENV)
    executing_request = replace(
        ready_request,
        operation="task.transition.executing",
        expected_revision=5,
        idempotency_key="github-sigstore-execution:task-executing:987654:2",
        intent_digest=canonical_digest({"target": "executing"}),
    )

    with pytest.raises(MacError) as captured:
        verify_authority_audit_record(ready_audit, executing_request)

    assert captured.value.code == "AUTHORITY_BINDING_MISMATCH"


@pytest.mark.parametrize(
    "mode",
    [
        "wrong_actor",
        "wrong_operation",
        "wrong_task",
        "wrong_revision",
        "wrong_idempotency",
        "wrong_intent",
        "wrong_policy",
        "wrong_ownership",
        "wrong_repository",
    ],
)
def test_signed_response_with_wrong_request_binding_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    adapter = _configured_adapter(monkeypatch)
    monkeypatch.setenv(_BROKER_MODE_ENV, mode)

    with pytest.raises(MacError) as captured:
        adapter.authorize(request=_authority_request())

    assert captured.value.code == "AUTHORITY_BINDING_MISMATCH"


def test_bad_signature_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = _configured_adapter(monkeypatch)
    monkeypatch.setenv(_BROKER_MODE_ENV, "bad_signature")

    with pytest.raises(MacError) as captured:
        adapter.authorize(request=_authority_request())

    assert captured.value.code == "AUTHORITY_SIGNATURE_INVALID"


def test_expired_fact_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = _configured_adapter(monkeypatch)
    monkeypatch.setenv(_BROKER_MODE_ENV, "expired")

    with pytest.raises(MacError) as captured:
        adapter.authorize(request=_authority_request())

    assert captured.value.code == "AUTHORITY_ATTESTATION_EXPIRED"


def test_denial_and_insufficient_independence_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = _configured_adapter(monkeypatch)
    monkeypatch.setenv(_BROKER_MODE_ENV, "deny")
    with pytest.raises(MacError) as denied:
        adapter.authorize(request=_authority_request())
    assert denied.value.code == "ACTOR_AUTHORITY_DENIED"

    monkeypatch.setenv(_BROKER_MODE_ENV, "allow")
    monkeypatch.setenv(_BROKER_INDEPENDENCE_ENV, "L1")
    with pytest.raises(MacError) as independence:
        adapter.authorize(request=_authority_request(), minimum_independence="L2")
    assert independence.value.code == "ACTOR_AUTHORITY_DENIED"


@pytest.mark.parametrize("mode", ["wrong_issuer", "wrong_audience"])
def test_issuer_and_audience_are_verified(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    adapter = _configured_adapter(monkeypatch)
    monkeypatch.setenv(_BROKER_MODE_ENV, mode)

    with pytest.raises(MacError) as captured:
        adapter.authorize(request=_authority_request())

    assert captured.value.code == "AUTHORITY_ISSUER_MISMATCH"


def test_private_signing_key_and_broker_command_are_not_persisted_or_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _configured_adapter(monkeypatch)
    fact = adapter.authorize(request=_authority_request())
    audit = authority_audit_record(fact)
    rendered = json.dumps(audit, sort_keys=True)

    assert _TEST_RSA_D_B64 not in rendered
    assert str(_BROKER) not in rendered
    assert sys.executable not in rendered
    assert "signature" not in audit
    assert "payload" not in audit
    assert "stdout" not in audit

    monkeypatch.setenv(_BROKER_MODE_ENV, "bad_signature")
    with pytest.raises(MacError) as captured:
        adapter.authorize(request=_authority_request())
    error = str(captured.value)
    assert _TEST_RSA_D_B64 not in error
    assert str(_BROKER) not in error
    assert sys.executable not in error


def test_historical_envelope_uses_only_the_public_keyring_not_the_live_broker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _authority_request()
    fact = _configured_adapter(monkeypatch).authorize(request=request)
    audit = authority_audit_record(fact)
    public_keyring = base64.b64decode(
        os.environ[PUBLIC_KEYRING_ENV].encode("ascii"),
        validate=True,
    ).decode("utf-8")
    assert _TEST_RSA_D_B64 not in public_keyring

    monkeypatch.delenv(BROKER_ARGV_ENV)
    monkeypatch.delenv(BROKER_MANIFEST_ENV)
    verify_authority_audit_record(audit, request)

    tampered = copy.deepcopy(audit)
    signature = base64.b64decode(
        tampered["signed_envelope"]["signature"].encode("ascii"),
        validate=True,
    )
    tampered["signed_envelope"]["signature"] = base64.b64encode(
        bytes([signature[0] ^ 0x01, *signature[1:]])
    ).decode("ascii")
    with pytest.raises(MacError) as captured:
        verify_authority_audit_record(tampered, request)
    assert captured.value.code == "AUTHORITY_SIGNATURE_INVALID"


def test_arbitrary_in_process_verifier_installation_is_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = _configured_adapter(monkeypatch)
    with pytest.raises(MacError) as install:
        trusted_authority_verifier(adapter)
    assert install.value.code == "AUTHORITY_VERIFIER_INSTALLATION_DISABLED"

    class FakeVerifier:
        pass

    with pytest.raises(MacError) as fake:
        require_authority(FakeVerifier(), request=_authority_request())  # type: ignore[arg-type]
    assert fake.value.code == "AUTHORITY_VERIFIER_REQUIRED"


def test_governance_sensitive_paths_use_gitignore_semantics() -> None:
    config = {
        "security": {
            "governance_sensitive_paths": ["AGENTS.md", ".agents/**", "schemas/**"],
        }
    }

    assert governance_sensitive({"allowed_paths": [".agents/config.yaml"]}, config)
    assert governance_sensitive({"allowed_paths": ["schemas/task.schema.json"]}, config)
    assert not governance_sensitive({"allowed_paths": ["src/mac/policy.py"]}, config)
    assert not governance_sensitive({"allowed_paths": ["agentz/config.yaml"]}, config)


def test_authority_decision_must_bind_actor_operation_and_task(monkeypatch: pytest.MonkeyPatch) -> None:
    request = AuthorityRequest(
        repository_identity="repo:test-authority-command",
        operation="scope.approve",
        task_id="TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        actor_claim={"id": "platform-owner", "kind": "human"},
        expected_revision=3,
        idempotency_key="approve-exact-binding",
        intent_digest=canonical_digest({"scope": 1}),
        policy_digest=canonical_digest({"policy": 1}),
        ownership_digest=canonical_digest({"ownership": 1}),
        audience="mac-mutation-gateway/v1",
    )
    adapter = _configured_adapter(monkeypatch)
    decision = require_authority(adapter, request=request, minimum_independence="L2")
    assert decision.actor_id == "platform-owner"
    assert decision.operation == "scope.approve"
    assert decision.task_id == request.task_id

    monkeypatch.setenv(_BROKER_MODE_ENV, "wrong_actor")
    with pytest.raises(MacError) as captured:
        require_authority(adapter, request=request)
    assert captured.value.code == "AUTHORITY_BINDING_MISMATCH"

    with pytest.raises(MacError) as missing:
        require_authority(None, request=request)
    assert missing.value.code == "AUTHORITY_VERIFIER_REQUIRED"


def test_scope_approve_rejects_self_reported_actor_without_trusted_verifier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    init_command(repo=tmp_path, project="authority-regression", json_output=True)
    created = TaskService(tmp_path).create(
        title="authority regression",
        mode="high_risk",
        objective="prove scope approval authority",
        acceptance=["trusted approval"],
        allowed_paths=["AGENTS.md"],
        owners=["governance"],
        runtime_profile="local-single",
        required_gates=["targeted_tests", "independent_review"],
        actor={"id": "proposer", "kind": "human"},
        idempotency_key="authority-task",
    )

    disable_test_mutation_broker(monkeypatch)
    with pytest.raises(MacError) as captured:
        scope_approve(
            str(created["task"]["id"]),
            expected_revision=0,
            idempotency_key="self-reported-scope-approval",
            actor="governance-owner",
            independence_level="L2",
            repo=tmp_path,
            json_output=True,
        )

    assert captured.value.code == "AUTHORITY_CONFIGURATION_MISSING"


def test_task_new_requires_trusted_proposer_and_persists_initial_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    init_command(repo=tmp_path, project="trusted-task-create", json_output=True)

    remove_test_authority(monkeypatch)
    with pytest.raises(MacError) as missing:
        task_new(
            title="untrusted task",
            objective="must not be created",
            mode="standard",
            allow=["src/**"],
            owner=["backend"],
            acceptance=["not created"],
            runtime_profile="local-single",
            gate=["targeted_tests"],
            parent_task=None,
            supersedes=[],
            actor="proposer",
            idempotency_key="untrusted-task-create",
            repo=tmp_path,
            json_output=True,
        )
    assert missing.value.code == "AUTHORITY_CONFIGURATION_MISSING"
    assert not list((tmp_path / "tasks").glob("TASK-*"))

    configure_test_authority(monkeypatch)
    monkeypatch.setenv(_BROKER_INDEPENDENCE_ENV, "L1")
    task_new(
        title="trusted task",
        objective="bind its proposer",
        mode="standard",
        allow=["src/**"],
        owner=["backend"],
        acceptance=["created by trusted proposer"],
        runtime_profile="local-single",
        gate=["targeted_tests"],
        parent_task=None,
        supersedes=[],
        actor="proposer",
        idempotency_key="trusted-task-create",
        repo=tmp_path,
        json_output=True,
    )

    task_dir = next((tmp_path / "tasks").glob("TASK-*"))
    event = FilesystemTaskRepository(tmp_path).list_events(task_dir.name)[0]
    assert event["event_type"] == "task_created"
    authority = event["payload"]["authority"]
    assert authority["allowed"] is True
    assert authority["authenticated"] is True
    assert authority["issuer"] == "test-host-authority"
    assert authority["actor_id"] == "proposer"
    assert authority["actor_kind"] == "human"
    assert authority["operation"] == "task.create"
    assert authority["task_id"] == task_dir.name
    assert authority["independence_level"] == "L1"
    assert authority["binding_digest"].startswith("sha256:")


def test_scope_proposer_cannot_be_spoofed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    init_command(repo=tmp_path, project="trusted-scope-proposer", json_output=True)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "test"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "freeze governance"], check=True)
    created = TaskService(tmp_path).create(
        title="scope binding",
        mode="standard",
        objective="prevent separation-of-duty spoofing",
        acceptance=["proposer is authenticated"],
        allowed_paths=["src/**"],
        owners=["governance"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "initial-proposer", "kind": "human"},
        idempotency_key="scope-proposer-task",
    )
    task_id = str(created["task"]["id"])
    disable_test_mutation_broker(monkeypatch)
    with pytest.raises(MacError) as missing:
        scope_propose(
            task_id,
            allow=["src/**"],
            deny=[],
            owner=["governance"],
            expected_revision=0,
            idempotency_key="spoofed-scope-proposer",
            actor="someone-else",
            repo=tmp_path,
            json_output=True,
        )
    assert missing.value.code == "AUTHORITY_CONFIGURATION_MISSING"

    configure_test_authority(monkeypatch)
    monkeypatch.setenv(_BROKER_INDEPENDENCE_ENV, "L1")
    scope_propose(
        task_id,
        allow=["src/**"],
        deny=[],
        owner=["governance"],
        expected_revision=0,
        idempotency_key="trusted-scope-proposer",
        actor="governance-owner",
        repo=tmp_path,
        json_output=True,
    )

    with pytest.raises(MacError) as same_actor:
        scope_approve(
            task_id,
            expected_revision=1,
            idempotency_key="same-actor-approval",
            actor="governance-owner",
            independence_level="L1",
            repo=tmp_path,
            json_output=True,
        )
    assert same_actor.value.code == "SCOPE_APPROVER_UNAUTHORIZED"

    proposal_event = FilesystemTaskRepository(tmp_path).list_events(task_id)[-1]
    assert proposal_event["payload"]["authority"]["operation"] == "scope.propose"
    assert proposal_event["payload"]["authority"]["authenticated"] is True


def test_scope_approve_persists_authenticated_issuer_and_attested_independence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    init_command(repo=tmp_path, project="authority-audit", json_output=True)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "test"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "freeze governance"], check=True)
    created = TaskService(tmp_path).create(
        title="authority audit",
        mode="high_risk",
        objective="persist trusted authority",
        acceptance=["auditable approval"],
        allowed_paths=["AGENTS.md"],
        owners=["governance"],
        runtime_profile="local-single",
        required_gates=["targeted_tests", "independent_review"],
        actor={"id": "proposer", "kind": "human"},
        idempotency_key="authority-audit-task",
    )
    task_id = str(created["task"]["id"])
    monkeypatch.setenv(_BROKER_INDEPENDENCE_ENV, "L2")
    capsys.readouterr()
    scope_approve(
        task_id,
        expected_revision=0,
        idempotency_key="trusted-scope-approval",
        actor="governance-owner",
        independence_level="L1",
        repo=tmp_path,
        json_output=True,
    )
    first_output = json.loads(capsys.readouterr().out.strip().splitlines()[-1])

    repository = FilesystemTaskRepository(tmp_path)
    event = repository.list_events(task_id)[-1]
    authority = event["payload"]["authority"]
    assert authority["allowed"] is True
    assert authority["authenticated"] is True
    assert authority["issuer"] == "test-host-authority"
    assert authority["actor_id"] == "governance-owner"
    assert authority["actor_kind"] == "human"
    assert authority["operation"] == "scope.approve"
    assert authority["task_id"] == task_id
    assert authority["independence_level"] == "L2"
    assert authority["request_digest"].startswith("sha256:")
    assert event["payload"]["approval"]["independence_level"] == "L2"
    assert first_output["approval"] == event["payload"]["approval"]
    assert first_output["scope"] == event["payload"]["scope"]
    approval_path = repository.task_dir(task_id) / "approvals" / f"{first_output['approval']['id']}.json"
    assert load_data(approval_path) == first_output["approval"]

    scope_approve(
        task_id,
        expected_revision=0,
        idempotency_key="trusted-scope-approval",
        actor="governance-owner",
        independence_level="L1",
        repo=tmp_path,
        json_output=True,
    )
    retry_output = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert retry_output["approval"] == first_output["approval"]
    assert retry_output["scope"] == first_output["scope"]
    assert len(list((repository.task_dir(task_id) / "approvals").glob("*.json"))) == 1


def test_authority_sensitive_cli_mutations_all_fail_closed_without_runtime_verifier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    init_command(repo=tmp_path, project="authority-boundary", json_output=True)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "test"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "init"], check=True)
    created = TaskService(tmp_path).create(
        title="boundary",
        mode="standard",
        objective="exercise authority-sensitive commands",
        acceptance=["commands fail closed"],
        allowed_paths=["AGENTS.md"],
        owners=["governance"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "proposer", "kind": "human"},
        idempotency_key="authority-boundary-task",
    )
    task_id = str(created["task"]["id"])
    scope_approve(
        task_id,
        expected_revision=0,
        idempotency_key="authority-boundary-scope",
        actor="governance-owner",
        independence_level="L2",
        repo=tmp_path,
        json_output=True,
    )
    successor_id = str(TaskService(tmp_path).create(
        title="valid successor",
        mode="standard",
        objective="provide a real supersession target",
        acceptance=["successor exists"],
        allowed_paths=["AGENTS.md"],
        owners=["governance"],
        runtime_profile="local-single",
        required_gates=["targeted_tests"],
        actor={"id": "proposer", "kind": "human"},
        idempotency_key="authority-boundary-successor",
    )["task"]["id"])
    work_unit_new(
        task_id,
        title="valid work unit",
        owner="governance",
        allow=["AGENTS.md"],
        depends_on=[],
        expected_revision=1,
        idempotency_key="authority-boundary-work-unit",
        actor="governance-owner",
        repo=tmp_path,
        json_output=True,
    )
    work_unit_id = next((tmp_path / "tasks" / task_id / "work-units").glob("*.yaml")).stem
    work_unit_ready(
        task_id,
        work_unit_id,
        expected_revision=2,
        idempotency_key="authority-boundary-work-unit-ready",
        actor="governance-owner",
        repo=tmp_path,
        json_output=True,
    )
    finding_open(
        task_id,
        title="waivable fixture",
        risk="bounded operational risk",
        severity="major",
        category="operations",
        blocking_effect="waiver_allowed",
        owner="governance",
        invalidates=["targeted_tests"],
        expected_revision=3,
        idempotency_key="authority-boundary-finding",
        actor="governance-owner",
        repo=tmp_path,
        json_output=True,
    )
    finding_id = next((tmp_path / "tasks" / task_id / "findings").glob("*.json")).stem

    disable_test_mutation_broker(monkeypatch)
    commands = [
        ("transition", lambda: task_transition(task_id, "ready", 4, "transition-without-verifier", "governance-owner", [], None, None, tmp_path, True)),
        ("cancel", lambda: task_cancel(task_id, 4, "cancel-without-verifier", "governance-owner", tmp_path, True)),
        ("supersede", lambda: task_supersede(task_id, successor_id, 4, "supersede-without-verifier", "governance-owner", tmp_path, True)),
        ("waive", lambda: finding_waive(task_id, finding_id, "risk", ["control"], "2099-01-01T00:00:00Z", 4, "risk-without-verifier", "governance-owner", tmp_path, True)),
        ("approval", lambda: approval_record(task_id, "close", "approved", "HEAD", "governance-owner", "L1", 4, "approval-without-verifier", tmp_path, True)),
        ("run", lambda: run_register(task_id, work_unit_id, "local-single", "context", None, None, tmp_path, None, "reviewer", "agent", "L2", 4, "run-without-verifier", tmp_path, True)),
    ]
    for name, command in commands:
        with pytest.raises(MacError) as captured:
            command()
        assert captured.value.code == "AUTHORITY_CONFIGURATION_MISSING", (name, captured.value.as_dict())


def test_result_submit_rejects_untrusted_identifiers_before_path_construction(tmp_path) -> None:
    task_id = "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q"
    result_path = tmp_path / "untrusted-result.json"
    atomic_write_json(
        result_path,
        {
            "task_id": task_id,
            "run_id": "../private/secret",
            "work_unit_id": "WU-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        },
    )

    with pytest.raises(MacError) as captured:
        result_submit(
            task_id,
            result_path,
            expected_revision=0,
            idempotency_key="unsafe-result",
            actor="executor",
            repo=tmp_path,
            json_output=True,
        )

    assert captured.value.code == "RESULT_RUN_ID_UNSAFE"
