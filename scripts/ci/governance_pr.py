"""Run the v6 governance checks for a pull request base/head pair."""

from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
from typing import Any, Callable, Mapping, TextIO
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import yaml

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
    canonical_digest,
    command_manifest_digest,
    current_authority_verifier,
    scope_approval_subject,
    require_authority,
    valid_scope_approvals,
)
from mac.application.task_service import TaskService
from mac.errors import ExitCode, MacError
from mac.git import GitRepository
from mac.ids import prefixed
from mac.io import load_data
from mac.repository import (
    AUTHORITY_REPOSITORY_IDENTITY_ENV,
    AppendEvent,
    CreateTask,
    FilesystemTaskRepository,
    MutationGateway,
    utc_now,
)
from mac.scope import amend_scope


_TASK_DIRECTORY = re.compile(r"^tasks/(?P<directory>TASK-(?P<ulid>[0-9A-HJKMNP-TV-Z]{26})(?:-[^/]+)?)/")
_TASK_ID = re.compile(r"^TASK-[0-9A-HJKMNP-TV-Z]{26}(?:-[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?)?$")
_LEVEL = re.compile(r"^\s*governance_level\s*:\s*(observe|advisory|enforced|regulated)\s*$", re.MULTILINE)
_OIDC_AUDIENCE_PREFIX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_OIDC_REQUEST_URL_ENV = "ACTIONS_ID_TOKEN_REQUEST_URL"
_OIDC_REQUEST_TOKEN_ENV = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
_BROKER_ENDPOINT_ENV = "MAC_AUTHORITY_BROKER_CONTEXT_ENDPOINT"
_BROKER_OIDC_AUDIENCE_ENV = "MAC_AUTHORITY_BROKER_CONTEXT_OIDC_AUDIENCE"
_GITHUB_ACTIONS_HOST_SUFFIX = ".actions.githubusercontent.com"
_MAX_AUTHORITY_DOCUMENT_BYTES = 1_000_000
_MAX_OIDC_RESPONSE_BYTES = 64_000
_HTTPS_TIMEOUT_SECONDS = 15.0
_EXPECTED_GITHUB_REPOSITORY = "IvesChenHX/multi-agent-collab"
_EXPECTED_GITHUB_REPOSITORY_ID = "1290429577"
_EXPECTED_GITHUB_ACTOR_ID = "166317138"
_EXPECTED_GITHUB_REF = "refs/heads/master"
_EXPECTED_GITHUB_BOOTSTRAP_REF = (
    "refs/heads/codex/governance-authority-sigstore"
)
_EXPECTED_GITHUB_SIGNER_WORKFLOW = (
    "IvesChenHX/multi-agent-collab/.github/workflows/governance-pr.yml"
)
_EXPECTED_GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
_AUTHORITY_ATTESTATION_PREDICATE_TYPE = (
    "https://github.com/IvesChenHX/multi-agent-collab/attestations/authority-probe/v1"
)
_MUTATION_ATTESTATION_PREDICATE_TYPE = (
    "https://github.com/IvesChenHX/multi-agent-collab/attestations/mutation-authority/v1"
)
_GIT_OBJECT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_MAX_ATTESTATION_BUNDLE_BYTES = 8_000_000
_SUCCESSOR_SCOPE_BASE_PATHS = (
    "src/mac/authority.py",
    "src/mac/repository.py",
    "src/mac/application/task_service.py",
    "src/mac/cli.py",
    "scripts/ci/governance_pr.py",
    ".github/workflows/governance-pr.yml",
    "tests/operations/test_governance_pr.py",
    "tests/security/test_authority_commands.py",
    "docs/pilot/alpha-close-report.md",
)
_SUCCESSOR_SCOPE_AMENDMENT_PATHS = (
    "src/mac/migration.py",
    "tests/test_authorityless_v6_migration.py",
    "migration/v6-authorityless/**",
    "tasks-v6/**",
)
_SUCCESSOR_SCOPE_SECOND_AMENDMENT_PATHS = (
    ".github/workflows/ci.yml",
)


class _RejectRedirects(HTTPRedirectHandler):
    """Never forward an OIDC bearer token across an HTTP redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _validated_https_url(raw: object, *, github_actions: bool, allow_query: bool) -> str:
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ValueError("authority OIDC bridge configuration is invalid")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError:
        raise ValueError("authority OIDC bridge configuration is invalid") from None
    hostname = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in {None, 443}
        or (not allow_query and parsed.query)
        or (github_actions and not hostname.endswith(_GITHUB_ACTIONS_HOST_SUFFIX))
    ):
        raise ValueError("authority OIDC bridge configuration is invalid")
    return raw


def _https_json(
    *,
    url: str,
    method: str,
    headers: Mapping[str, str],
    body: bytes | None,
    max_response_bytes: int,
) -> object:
    request = Request(url, data=body, headers=dict(headers), method=method)
    try:
        with build_opener(_RejectRedirects()).open(request, timeout=_HTTPS_TIMEOUT_SECONDS) as response:
            content_type = str(response.headers.get("Content-Type", "")).lower()
            raw = response.read(max_response_bytes + 1)
    except (HTTPError, URLError, OSError, TimeoutError):
        raise RuntimeError("trusted authority OIDC exchange failed") from None
    if len(raw) > max_response_bytes or not content_type.startswith("application/json"):
        raise RuntimeError("trusted authority OIDC exchange failed")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise RuntimeError("trusted authority OIDC exchange failed") from None


def _authority_request_from_document(document: object) -> AuthorityRequest:
    required = {
        "schema_version",
        "repository_identity",
        "operation",
        "task_id",
        "actor_claim",
        "expected_revision",
        "idempotency_key",
        "intent_digest",
        "policy_digest",
        "ownership_digest",
        "audience",
    }
    if not isinstance(document, dict) or set(document) != required or document.get("schema_version") != 1:
        raise ValueError("authority OIDC request is invalid")
    return AuthorityRequest(
        repository_identity=document["repository_identity"],
        operation=document["operation"],
        task_id=document["task_id"],
        actor_claim=document["actor_claim"],
        expected_revision=document["expected_revision"],
        idempotency_key=document["idempotency_key"],
        intent_digest=document["intent_digest"],
        policy_digest=document["policy_digest"],
        ownership_digest=document["ownership_digest"],
        audience=document["audience"],
    )


def _oidc_request_url(raw: object, audience: str) -> str:
    validated = _validated_https_url(raw, github_actions=True, allow_query=True)
    parsed = urlsplit(validated)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    if any(key == "audience" for key, _ in query):
        raise ValueError("authority OIDC bridge configuration is invalid")
    query.append(("audience", audience))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def github_oidc_broker_exchange(
    document: object,
    *,
    environment: Mapping[str, str] | None = None,
    request_json: Callable[..., object] = _https_json,
) -> dict[str, Any]:
    """Exchange a GitHub Actions OIDC identity for one signed broker decision.

    The OIDC JWT remains a bearer credential: it is sent only in the HTTPS
    Authorization header and is never returned, logged, or persisted.
    """

    request = _authority_request_from_document(document)
    values = os.environ if environment is None else environment
    request_token = values.get(_OIDC_REQUEST_TOKEN_ENV, "")
    audience_prefix = values.get(_BROKER_OIDC_AUDIENCE_ENV, "")
    broker_manifest = values.get(BROKER_MANIFEST_ENV, "")
    if (
        not request_token
        or "\x00" in request_token
        or _OIDC_AUDIENCE_PREFIX.fullmatch(audience_prefix) is None
        or _SHA256_DIGEST.fullmatch(broker_manifest) is None
    ):
        raise ValueError("authority OIDC bridge configuration is invalid")
    endpoint = _validated_https_url(
        values.get(_BROKER_ENDPOINT_ENV),
        github_actions=False,
        allow_query=False,
    )
    oidc_audience = f"{audience_prefix}:{request.binding_digest}:{broker_manifest}"
    oidc_response = request_json(
        url=_oidc_request_url(values.get(_OIDC_REQUEST_URL_ENV), oidc_audience),
        method="GET",
        headers={
            "Accept": "application/json",
            "Authorization": f"bearer {request_token}",
        },
        body=None,
        max_response_bytes=_MAX_OIDC_RESPONSE_BYTES,
    )
    if not isinstance(oidc_response, dict) or set(oidc_response) != {"value"}:
        raise RuntimeError("trusted authority OIDC exchange failed")
    oidc_token = oidc_response.get("value")
    if (
        not isinstance(oidc_token, str)
        or len(oidc_token.encode("utf-8")) > _MAX_OIDC_RESPONSE_BYTES
        or len(oidc_token.split(".")) != 3
        or any(character.isspace() or character == "\x00" for character in oidc_token)
    ):
        raise RuntimeError("trusted authority OIDC exchange failed")
    broker_body = json.dumps(
        {
            "schema_version": 1,
            "broker_manifest_digest": broker_manifest,
            "request": request.as_dict(),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    response = request_json(
        url=endpoint,
        method="POST",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {oidc_token}",
            "Content-Type": "application/json",
            "X-MAC-Authority-Binding": request.binding_digest,
            "X-MAC-Broker-Manifest": broker_manifest,
            "X-MAC-Authority-Request": request.request_digest,
        },
        body=broker_body,
        max_response_bytes=_MAX_AUTHORITY_DOCUMENT_BYTES,
    )
    if not isinstance(response, dict):
        raise RuntimeError("trusted authority OIDC exchange failed")
    return response


def github_oidc_broker_main(
    *,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    environment: Mapping[str, str] | None = None,
    request_json: Callable[..., object] = _https_json,
) -> int:
    """Subprocess broker bridge used by ``SubprocessAuthorityAdapter``."""

    try:
        raw = stdin.read(_MAX_AUTHORITY_DOCUMENT_BYTES + 2)
        if raw.endswith("\n"):
            raw = raw[:-1]
        if not raw or len(raw.encode("utf-8")) > _MAX_AUTHORITY_DOCUMENT_BYTES:
            raise ValueError("invalid authority request")
        document = json.loads(raw)
        canonical = json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        if raw != canonical:
            raise ValueError("invalid authority request")
        response = github_oidc_broker_exchange(
            document,
            environment=environment,
            request_json=request_json,
        )
        stdout.write(
            json.dumps(
                response,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        )
        return 0
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError):
        stderr.write("trusted authority OIDC bridge failed\n")
        return 2


def _required_environment(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "")
    if not value or "\x00" in value:
        raise ValueError("authority probe environment is invalid")
    return value


def _github_probe_request(values: Mapping[str, str], repo: Path) -> AuthorityRequest:
    repository = _required_environment(values, "GITHUB_REPOSITORY")
    repository_id = _required_environment(values, "GITHUB_REPOSITORY_ID")
    actor_id = _required_environment(values, "GITHUB_ACTOR_ID")
    event_name = _required_environment(values, "GITHUB_EVENT_NAME")
    ref = _required_environment(values, "GITHUB_REF")
    workflow_ref = _required_environment(values, "GITHUB_WORKFLOW_REF")
    run_id = _required_environment(values, "GITHUB_RUN_ID")
    run_attempt = _required_environment(values, "GITHUB_RUN_ATTEMPT")
    task_id = _required_environment(values, "MAC_AUTHORITY_PROBE_TASK_ID")
    if (
        repository != _EXPECTED_GITHUB_REPOSITORY
        or repository_id != _EXPECTED_GITHUB_REPOSITORY_ID
        or actor_id != _EXPECTED_GITHUB_ACTOR_ID
        or event_name != "workflow_dispatch"
        or ref not in {_EXPECTED_GITHUB_REF, _EXPECTED_GITHUB_BOOTSTRAP_REF}
        or workflow_ref
        != f"{_EXPECTED_GITHUB_SIGNER_WORKFLOW}@{ref}"
        or not run_id.isdigit()
        or not run_attempt.isdigit()
        or _TASK_ID.fullmatch(task_id) is None
    ):
        raise ValueError("authority probe environment is invalid")
    root = repo.resolve()
    task_path = (root / "tasks" / task_id / "task.yaml").resolve()
    try:
        task_path.relative_to(root)
    except ValueError:
        raise ValueError("authority probe Task is invalid") from None
    if not task_path.is_file():
        raise ValueError("authority probe Task is invalid")
    task = yaml.safe_load(task_path.read_text(encoding="utf-8"))
    if not isinstance(task, dict) or task.get("id") != task_id:
        raise ValueError("authority probe Task is invalid")
    policy_digest = str((task.get("policy_ref") or {}).get("combined_digest", ""))
    ownership_digest = str((task.get("ownership_ref") or {}).get("combined_digest", ""))
    revision = task.get("revision")
    if (
        _SHA256_DIGEST.fullmatch(policy_digest) is None
        or _SHA256_DIGEST.fullmatch(ownership_digest) is None
        or isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision < 0
    ):
        raise ValueError("authority probe Task is invalid")
    return AuthorityRequest(
        repository_identity=f"github:repository-id:{repository_id}",
        operation="authority.probe",
        task_id=task_id,
        actor_claim={"id": actor_id, "kind": "human"},
        expected_revision=revision,
        idempotency_key=f"github-oidc-probe:{run_id}:{run_attempt}",
        intent_digest=canonical_digest(
            {
                "event_name": event_name,
                "ref": ref,
                "repository_id": repository_id,
                "run_attempt": run_attempt,
                "run_id": run_id,
                "workflow_ref": workflow_ref,
            }
        ),
        policy_digest=policy_digest,
        ownership_digest=ownership_digest,
        audience="mac-mutation-gateway/v1",
    )


def github_oidc_probe_main(
    *,
    repo: Path = Path("."),
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    environment: Mapping[str, str] | None = None,
) -> int:
    """Exercise the full OIDC-to-signed-decision path without mutating Task state."""

    values = dict(os.environ if environment is None else environment)
    previous: dict[str, str | None] = {}
    try:
        request = _github_probe_request(values, repo)
        bridge_argv = [
            sys.executable,
            "-I",
            str(Path(__file__).resolve()),
            "--github-oidc-broker",
        ]
        assignments = {
            BROKER_ARGV_ENV: json.dumps(bridge_argv, separators=(",", ":")),
            BROKER_MANIFEST_ENV: command_manifest_digest(bridge_argv),
        }
        for name, value in values.items():
            if (
                name in {
                    _OIDC_REQUEST_URL_ENV,
                    _OIDC_REQUEST_TOKEN_ENV,
                    EXPECTED_ISSUER_ENV,
                    PUBLIC_KEYRING_ENV,
                    _BROKER_ENDPOINT_ENV,
                    _BROKER_OIDC_AUDIENCE_ENV,
                }
                or name.startswith("MAC_AUTHORITY_BROKER_CONTEXT_")
            ):
                assignments[name] = value
        for name, value in assignments.items():
            previous[name] = os.environ.get(name)
            os.environ[name] = value
        decision = require_authority(
            current_authority_verifier(),
            request=request,
            minimum_independence="L2",
        )
        stdout.write(
            json.dumps(
                {
                    "ok": True,
                    "actor_id": decision.actor_id,
                    "attestation_id": decision.attestation_id,
                    "binding_digest": decision.binding_digest,
                    "broker_digest": decision.broker_digest,
                    "independence_level": decision.independence_level,
                    "issuer": decision.issuer,
                    "key_id": decision.key_id,
                    "request_digest": decision.request_digest,
                    "task_id": decision.task_id,
                    "trust_digest": decision.trust_digest,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        return 0
    except (MacError, OSError, TypeError, ValueError, yaml.YAMLError):
        stderr.write("trusted authority OIDC probe failed\n")
        return 2
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _github_attestation_probe_documents(
    values: Mapping[str, str],
    repo: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    request = _github_probe_request(values, repo)
    source_digest = _required_environment(values, "GITHUB_SHA").lower()
    if _GIT_OBJECT_ID.fullmatch(source_digest) is None:
        raise ValueError("authority attestation probe environment is invalid")
    subject = {
        "schema_version": 1,
        "kind": "mac.authority.probe",
        "request": request.as_dict(),
        "request_digest": request.request_digest,
        "binding_digest": request.binding_digest,
    }
    predicate = {
        "schema_version": 1,
        "claim": "github-environment-authority-probe",
        "environment": "governance-authority",
        "independence_level": "L2",
        "request_digest": request.request_digest,
        "binding_digest": request.binding_digest,
        "source": {
            "repository": _EXPECTED_GITHUB_REPOSITORY,
            "repository_id": _EXPECTED_GITHUB_REPOSITORY_ID,
            "ref": _required_environment(values, "GITHUB_REF"),
            "workflow": _EXPECTED_GITHUB_SIGNER_WORKFLOW,
            "workflow_digest": source_digest,
        },
    }
    return subject, predicate


def _canonical_document_bytes(document: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(document),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _write_new_canonical_document(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(_canonical_document_bytes(document))


def github_attestation_probe_prepare_main(
    *,
    subject_path: Path,
    predicate_path: Path,
    repo: Path = Path("."),
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    environment: Mapping[str, str] | None = None,
) -> int:
    """Prepare a non-secret, exactly-bound subject for GitHub attestation."""

    try:
        subject, predicate = _github_attestation_probe_documents(
            os.environ if environment is None else environment,
            repo,
        )
        _write_new_canonical_document(subject_path, subject)
        _write_new_canonical_document(predicate_path, predicate)
        stdout.write(
            json.dumps(
                {
                    "ok": True,
                    "subject_digest": "sha256:"
                    + hashlib.sha256(_canonical_document_bytes(subject)).hexdigest(),
                    "request_digest": subject["request_digest"],
                    "binding_digest": subject["binding_digest"],
                    "predicate_type": _AUTHORITY_ATTESTATION_PREDICATE_TYPE,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        return 0
    except (OSError, TypeError, ValueError, yaml.YAMLError):
        stderr.write("trusted authority attestation preparation failed\n")
        return 2


def _verification_results(document: object) -> list[Mapping[str, Any]]:
    if not isinstance(document, list) or not document:
        raise ValueError("authority attestation verification is invalid")
    if not all(isinstance(item, Mapping) for item in document):
        raise ValueError("authority attestation verification is invalid")
    return list(document)


def github_attestation_probe_verify_main(
    *,
    subject_path: Path,
    predicate_path: Path,
    bundle_path: Path,
    repo: Path = Path("."),
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    environment: Mapping[str, str] | None = None,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> int:
    """Verify the Sigstore bundle and its exact authority-probe predicate."""

    try:
        values = os.environ if environment is None else environment
        subject, predicate = _github_attestation_probe_documents(values, repo)
        expected_subject = _canonical_document_bytes(subject)
        expected_predicate = dict(predicate)
        if subject_path.read_bytes() != expected_subject:
            raise ValueError("authority attestation subject is invalid")
        if predicate_path.read_bytes() != _canonical_document_bytes(predicate):
            raise ValueError("authority attestation predicate is invalid")
        if (
            not bundle_path.is_file()
            or bundle_path.stat().st_size <= 0
            or bundle_path.stat().st_size > _MAX_ATTESTATION_BUNDLE_BYTES
        ):
            raise ValueError("authority attestation bundle is invalid")
        source_digest = _required_environment(values, "GITHUB_SHA").lower()
        source_ref = _required_environment(values, "GITHUB_REF")
        completed = run(
            [
                "gh",
                "attestation",
                "verify",
                str(subject_path),
                "--repo",
                _EXPECTED_GITHUB_REPOSITORY,
                "--bundle",
                str(bundle_path),
                "--predicate-type",
                _AUTHORITY_ATTESTATION_PREDICATE_TYPE,
                "--signer-workflow",
                _EXPECTED_GITHUB_SIGNER_WORKFLOW,
                "--source-ref",
                source_ref,
                "--source-digest",
                source_digest,
                "--cert-oidc-issuer",
                _EXPECTED_GITHUB_OIDC_ISSUER,
                "--deny-self-hosted-runners",
                "--format",
                "json",
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            shell=False,
            timeout=30,
        )
        if completed.returncode != 0 or len(completed.stdout.encode("utf-8")) > _MAX_ATTESTATION_BUNDLE_BYTES:
            raise ValueError("authority attestation verification failed")
        results = _verification_results(json.loads(completed.stdout))
        subject_sha256 = hashlib.sha256(expected_subject).hexdigest()
        matches = []
        for item in results:
            result = item.get("verificationResult")
            if not isinstance(result, Mapping):
                continue
            statement = result.get("statement")
            timestamps = result.get("verifiedTimestamps")
            if not isinstance(statement, Mapping) or not isinstance(timestamps, list) or not timestamps:
                continue
            subjects = statement.get("subject")
            if (
                statement.get("predicateType") == _AUTHORITY_ATTESTATION_PREDICATE_TYPE
                and statement.get("predicate") == expected_predicate
                and isinstance(subjects, list)
                and any(
                    isinstance(candidate, Mapping)
                    and isinstance(candidate.get("digest"), Mapping)
                    and candidate["digest"].get("sha256") == subject_sha256
                    for candidate in subjects
                )
            ):
                matches.append(item)
        if len(matches) != 1:
            raise ValueError("authority attestation binding is invalid")
        stdout.write(
            json.dumps(
                {
                    "ok": True,
                    "subject_digest": f"sha256:{subject_sha256}",
                    "request_digest": subject["request_digest"],
                    "binding_digest": subject["binding_digest"],
                    "predicate_type": _AUTHORITY_ATTESTATION_PREDICATE_TYPE,
                    "signer_workflow": _EXPECTED_GITHUB_SIGNER_WORKFLOW,
                    "source_digest": source_digest,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        return 0
    except (
        OSError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ):
        stderr.write("trusted authority attestation verification failed\n")
        return 2


def _render_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _serialize_create_task(command: CreateTask) -> dict[str, Any]:
    return {
        "command_type": "CreateTask",
        "task": dict(command.task),
        "initial_entities": [
            [path, dict(value)] for path, value in command.initial_entities
        ],
        "actor_claim": dict(command.actor_claim),
        "idempotency_key": command.idempotency_key,
        "operation": command.operation,
        "minimum_independence": command.minimum_independence,
        "replay_intent": dict(command.replay_intent or {}),
    }


def _deserialize_create_task(document: object) -> CreateTask:
    required = {
        "command_type", "task", "initial_entities", "actor_claim",
        "idempotency_key", "operation", "minimum_independence", "replay_intent",
    }
    if not isinstance(document, dict) or set(document) != required or document.get("command_type") != "CreateTask":
        raise ValueError("prepared mutation command is invalid")
    entities = document.get("initial_entities")
    if (
        not isinstance(document.get("task"), dict)
        or not isinstance(document.get("actor_claim"), dict)
        or not isinstance(document.get("replay_intent"), dict)
        or not isinstance(entities, list)
        or not entities
        or any(
            not isinstance(item, list)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not isinstance(item[1], dict)
            for item in entities
        )
    ):
        raise ValueError("prepared mutation command is invalid")
    return CreateTask(
        task=document["task"],
        initial_entities=tuple((item[0], item[1]) for item in entities),
        actor_claim=document["actor_claim"],
        idempotency_key=str(document.get("idempotency_key", "")),
        operation=str(document.get("operation", "")),
        minimum_independence=(
            str(document["minimum_independence"])
            if document.get("minimum_independence") is not None
            else None
        ),
        replay_intent=document["replay_intent"],
    )


def _prepared_repo_path(repo: Path, value: object, *, task_id: str) -> Path:
    if not isinstance(value, str):
        raise ValueError("prepared mutation path is invalid")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.parts[:2] != ("tasks", task_id)
    ):
        raise ValueError("prepared mutation path is invalid")
    root = repo.resolve()
    candidate = root.joinpath(*relative.parts)
    try:
        candidate.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise ValueError("prepared mutation path is invalid") from exc
    return candidate


def _serialize_append_event(command: AppendEvent, repo: Path) -> dict[str, Any]:
    root = repo.resolve()

    def relative(path: Path) -> str:
        try:
            value = path.resolve(strict=False).relative_to(root).as_posix()
        except ValueError as exc:
            raise ValueError("prepared mutation path is outside the repository") from exc
        _prepared_repo_path(root, value, task_id=command.task_id)
        return value

    return {
        "command_type": "AppendEvent",
        "task_id": command.task_id,
        "event_type": command.event_type,
        "payload": dict(command.payload),
        "actor_claim": dict(command.actor_claim),
        "expected_revision": command.expected_revision,
        "idempotency_key": command.idempotency_key,
        "operation": command.operation,
        "run_id": command.run_id,
        "event_id": command.event_id,
        "materializations": [
            [relative(path), dict(value)] for path, value in command.materializations
        ],
        "replace_existing": sorted(relative(path) for path in command.replace_existing),
        "minimum_independence": command.minimum_independence,
        "replay_intent": dict(command.replay_intent or {}),
    }


def _deserialize_append_event(document: object, repo: Path) -> AppendEvent:
    required = {
        "command_type", "task_id", "event_type", "payload", "actor_claim",
        "expected_revision", "idempotency_key", "operation", "run_id", "event_id",
        "materializations", "replace_existing", "minimum_independence", "replay_intent",
    }
    if not isinstance(document, dict) or set(document) != required or document.get("command_type") != "AppendEvent":
        raise ValueError("prepared mutation command is invalid")
    task_id = document.get("task_id")
    materializations = document.get("materializations")
    replacements = document.get("replace_existing")
    expected_revision = document.get("expected_revision")
    if (
        not isinstance(task_id, str)
        or _TASK_ID.fullmatch(task_id) is None
        or not isinstance(document.get("event_type"), str)
        or not isinstance(document.get("payload"), dict)
        or not isinstance(document.get("actor_claim"), dict)
        or type(expected_revision) is not int
        or not isinstance(document.get("idempotency_key"), str)
        or not isinstance(document.get("operation"), str)
        or document.get("run_id") is not None and not isinstance(document.get("run_id"), str)
        or document.get("event_id") is not None and not isinstance(document.get("event_id"), str)
        or not isinstance(document.get("replay_intent"), dict)
        or not isinstance(materializations, list)
        or not materializations
        or any(
            not isinstance(item, list)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not isinstance(item[1], dict)
            for item in materializations
        )
        or not isinstance(replacements, list)
        or any(not isinstance(item, str) for item in replacements)
    ):
        raise ValueError("prepared mutation command is invalid")
    return AppendEvent(
        task_id=task_id,
        event_type=document["event_type"],
        payload=document["payload"],
        actor_claim=document["actor_claim"],
        expected_revision=expected_revision,
        idempotency_key=document["idempotency_key"],
        operation=document["operation"],
        run_id=document["run_id"],
        event_id=document["event_id"],
        materializations=tuple(
            (_prepared_repo_path(repo, item[0], task_id=task_id), item[1])
            for item in materializations
        ),
        replace_existing=frozenset(
            _prepared_repo_path(repo, item, task_id=task_id) for item in replacements
        ),
        minimum_independence=(
            str(document["minimum_independence"])
            if document.get("minimum_independence") is not None
            else None
        ),
        replay_intent=document["replay_intent"],
    )


def _serialize_mutation(command: CreateTask | AppendEvent, repo: Path) -> dict[str, Any]:
    if isinstance(command, CreateTask):
        return _serialize_create_task(command)
    if isinstance(command, AppendEvent):
        return _serialize_append_event(command, repo)
    raise ValueError("unsupported prepared mutation command")


def _deserialize_mutation(document: object, repo: Path) -> CreateTask | AppendEvent:
    command_type = document.get("command_type") if isinstance(document, dict) else None
    if command_type == "CreateTask":
        return _deserialize_create_task(document)
    if command_type == "AppendEvent":
        return _deserialize_append_event(document, repo)
    raise ValueError("prepared mutation command is invalid")


def _mutation_verification_policy(values: Mapping[str, str]) -> dict[str, Any]:
    source_ref = _required_environment(values, "GITHUB_REF")
    source_digest = _required_environment(values, "GITHUB_SHA").lower()
    if (
        source_ref not in {_EXPECTED_GITHUB_REF, _EXPECTED_GITHUB_BOOTSTRAP_REF}
        or _GIT_OBJECT_ID.fullmatch(source_digest) is None
    ):
        raise ValueError("prepared mutation signer context is invalid")
    return {
        "schema_version": 1,
        "repository": _EXPECTED_GITHUB_REPOSITORY,
        "signer_workflow": _EXPECTED_GITHUB_SIGNER_WORKFLOW,
        "source_ref": source_ref,
        "source_digest": source_digest,
        "predicate_type": _MUTATION_ATTESTATION_PREDICATE_TYPE,
        "environment": "governance-authority",
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "deny_self_hosted_runners": True,
    }


def _successor_create_command(values: Mapping[str, str], repo: Path) -> CreateTask:
    probe = _github_probe_request(values, repo)
    parent_task = probe.task_id
    command = TaskService(repo).build_create_command(
        title="GitHub authority bootstrap successor",
        mode="high_risk",
        objective=(
            "Create the first GitHub-Sigstore-authorized governance successor and "
            "complete the two-phase Mutation Gateway trust loop."
        ),
        acceptance=[
            "Every persisted mutation carries a verified non-secret Sigstore authority bundle.",
            "Scope approval and replay succeed against the exact signed mutation intent.",
            "No OIDC bearer token or GitHub token enters Task, Event, Evidence, logs, or Git.",
            "Governance-sensitive changes receive L2 review before merge.",
        ],
        allowed_paths=list(_SUCCESSOR_SCOPE_BASE_PATHS),
        allowed_operations=["read", "write", "execute_tests", "generate_artifacts"],
        owners=["governance", "platform", "security", "devex", "tests", "docs"],
        runtime_profile="local-multi",
        required_gates=[
            "targeted_tests", "negative_security_tests", "secret_scan", "scope_guard",
            "compatibility_review", "independent_review", "rollback_plan",
            "rollback_verification", "evidence_matches_current_commit",
        ],
        actor={"id": "governance-owner", "kind": "human"},
        idempotency_key=(
            "github-sigstore-task-create:"
            f"{_required_environment(values, 'GITHUB_RUN_ID')}:"
            f"{_required_environment(values, 'GITHUB_RUN_ATTEMPT')}"
        ),
        parent_task=parent_task,
        supersedes=[parent_task],
    )
    task_id = str(command.task["id"])
    scope_path, scope = command.initial_entities[0]
    adjusted_scope = dict(scope)
    adjusted_scope["allowed_paths"] = [
        *adjusted_scope["allowed_paths"],
        f"tasks/{task_id}/**",
        f"tasks/private/{task_id}/**",
    ]
    return replace(
        command,
        initial_entities=((scope_path, adjusted_scope),),
        minimum_independence="L2",
    )


def _successor_scope_approval_command(
    values: Mapping[str, str], repo: Path,
) -> AppendEvent:
    task_id = _required_environment(values, "MAC_AUTHORITY_PROBE_TASK_ID")
    if _TASK_ID.fullmatch(task_id) is None:
        raise ValueError("scope approval task identifier is invalid")
    repository = FilesystemTaskRepository(repo)
    directory = repository.task_dir(task_id)
    task = load_data(directory / "task.yaml")
    scope = load_data(directory / "scope-contract.yaml")
    expected_paths = [
        *_SUCCESSOR_SCOPE_BASE_PATHS,
        f"tasks/{task_id}/**",
        f"tasks/private/{task_id}/**",
    ]
    version = scope.get("version")
    exact_scope_version = (
        version == 1
        and scope.get("proposed_by") == "governance-owner"
        and scope.get("allowed_paths") == expected_paths
        and scope.get("risk_tags") == []
    ) or (
        version == 2
        and scope.get("proposed_by") == "repo-owner"
        and scope.get("allowed_paths") == [*expected_paths, *_SUCCESSOR_SCOPE_AMENDMENT_PATHS]
        and scope.get("risk_tags") == ["data_migration"]
    ) or (
        version == 3
        and scope.get("proposed_by") == "repo-owner"
        and scope.get("allowed_paths") == [
            *expected_paths,
            *_SUCCESSOR_SCOPE_AMENDMENT_PATHS,
            *_SUCCESSOR_SCOPE_SECOND_AMENDMENT_PATHS,
        ]
        and scope.get("risk_tags") == ["auth_security", "data_migration"]
    )
    if (
        task.get("id") != task_id
        or task.get("title") != "GitHub authority bootstrap successor"
        or task.get("mode") != "high_risk"
        or task.get("state") != "triage"
        or type(task.get("revision")) is not int
        or scope.get("task_id") != task_id
        or scope.get("status") != "proposed"
        or not exact_scope_version
    ):
        raise ValueError("successor scope is not eligible for protected approval")
    actor = {
        "id": "repo-owner" if version == 1 else "governance-owner",
        "kind": "human",
    }
    approval = {
        "schema_version": 1,
        "id": prefixed("APR"),
        "task_id": task_id,
        "kind": "scope",
        "actor": actor,
        "decision": "approved",
        "subject_ref": scope_approval_subject(task, scope),
        "independence_level": "L2",
        "recorded_at": utc_now(),
    }
    config = load_data(repo / ".agents/config.yaml")
    ownership = load_data(repo / str(config["paths"]["ownership"]))
    if not valid_scope_approvals(task, scope, [approval], ownership, config):
        raise ValueError("protected scope approval actor is not authorized")
    approved_scope = deepcopy(scope)
    approved_scope["status"] = "approved"
    approved_scope["approved_by"] = [actor["id"]]
    scope_path = directory / "scope-contract.yaml"
    approval_path = directory / "approvals" / f"{approval['id']}.json"
    return AppendEvent(
        task_id=task_id,
        event_type="scope_approved",
        payload={
            "scope_id": scope["id"],
            "version": scope["version"],
            "approval_id": approval["id"],
            "approval": approval,
            "scope": approved_scope,
        },
        actor_claim=actor,
        expected_revision=task["revision"],
        idempotency_key=(
            "github-sigstore-scope-approve:"
            f"{_required_environment(values, 'GITHUB_RUN_ID')}:"
            f"{_required_environment(values, 'GITHUB_RUN_ATTEMPT')}"
        ),
        operation="scope.approve",
        materializations=((approval_path, approval), (scope_path, approved_scope)),
        replace_existing=frozenset({scope_path}),
        minimum_independence="L2",
        replay_intent={"independence_level_claim": "L2"},
    )


def _successor_scope_amend_command(
    values: Mapping[str, str], repo: Path,
) -> AppendEvent:
    task_id = _required_environment(values, "MAC_AUTHORITY_PROBE_TASK_ID")
    if _TASK_ID.fullmatch(task_id) is None:
        raise ValueError("scope amendment task identifier is invalid")
    repository = FilesystemTaskRepository(repo)
    directory = repository.task_dir(task_id)
    task = load_data(directory / "task.yaml")
    old_scope = load_data(directory / "scope-contract.yaml")
    expected_paths = [
        *_SUCCESSOR_SCOPE_BASE_PATHS,
        f"tasks/{task_id}/**",
        f"tasks/private/{task_id}/**",
    ]
    version = old_scope.get("version")
    if version == 1:
        eligible_revision = 1
        eligible_paths = expected_paths
        eligible_approvers = ["repo-owner"]
        eligible_risk_tags: list[str] = []
        amendment_paths = list(_SUCCESSOR_SCOPE_AMENDMENT_PATHS)
        amendment_approvers = ["repo-owner"]
        added_risk_tags = ["data_migration"]
    elif version == 2:
        eligible_revision = 3
        eligible_paths = [*expected_paths, *_SUCCESSOR_SCOPE_AMENDMENT_PATHS]
        eligible_approvers = ["governance-owner"]
        eligible_risk_tags = ["data_migration"]
        amendment_paths = list(_SUCCESSOR_SCOPE_SECOND_AMENDMENT_PATHS)
        amendment_approvers = ["governance-owner"]
        added_risk_tags = ["auth_security"]
    else:
        raise ValueError("successor scope is not eligible for protected amendment")
    if (
        task.get("id") != task_id
        or task.get("title") != "GitHub authority bootstrap successor"
        or task.get("mode") != "high_risk"
        or task.get("state") != "triage"
        or task.get("revision") != eligible_revision
        or old_scope.get("task_id") != task_id
        or old_scope.get("status") != "approved"
        or old_scope.get("approved_by") != eligible_approvers
        or old_scope.get("allowed_paths") != eligible_paths
        or old_scope.get("risk_tags") != eligible_risk_tags
    ):
        raise ValueError("successor scope is not eligible for protected amendment")
    actor = {"id": "repo-owner", "kind": "human"}
    replay_intent = {
        "add": amendment_paths,
        "add_operation": [],
        "approver": amendment_approvers,
        "risk_tag": added_risk_tags,
        "independent": True,
    }
    amended_scope = amend_scope(
        old_scope,
        add_paths=replay_intent["add"],
        add_operations=replay_intent["add_operation"],
        actor=actor["id"],
        approvers=replay_intent["approver"],
        added_risk_tags=replay_intent["risk_tag"],
        independent_approval=True,
    )
    scope_path = directory / "scope-contract.yaml"
    history_path = directory / "scope-history" / f"scope-contract.v{version}.yaml"
    return AppendEvent(
        task_id=task_id,
        event_type="scope_proposed",
        payload={
            "scope_id": amended_scope["id"],
            "version": amended_scope["version"],
            "amendment": True,
            "scope": amended_scope,
        },
        actor_claim=actor,
        expected_revision=task["revision"],
        idempotency_key=(
            "github-sigstore-scope-amend:"
            f"{_required_environment(values, 'GITHUB_RUN_ID')}:"
            f"{_required_environment(values, 'GITHUB_RUN_ATTEMPT')}"
        ),
        operation="scope.amend",
        materializations=((history_path, old_scope), (scope_path, amended_scope)),
        replace_existing=frozenset({scope_path}),
        minimum_independence="L2",
        replay_intent=replay_intent,
    )


def _sigstore_trust_environment() -> dict[str, str]:
    verifier_argv = ["gh", "attestation", "verify"]
    return {
        SIGSTORE_VERIFIER_ARGV_ENV: json.dumps(verifier_argv, separators=(",", ":")),
        SIGSTORE_VERIFIER_MANIFEST_ENV: command_manifest_digest(verifier_argv),
        SIGSTORE_REPOSITORY_ENV: _EXPECTED_GITHUB_REPOSITORY,
        SIGSTORE_SIGNER_WORKFLOW_ENV: _EXPECTED_GITHUB_SIGNER_WORKFLOW,
        SIGSTORE_PREDICATE_TYPE_ENV: _MUTATION_ATTESTATION_PREDICATE_TYPE,
        SIGSTORE_ENVIRONMENT_ENV: "governance-authority",
        SIGSTORE_OIDC_ISSUER_ENV: _EXPECTED_GITHUB_OIDC_ISSUER,
    }


def _github_validation_trust_environment(
    values: Mapping[str, str],
) -> dict[str, str]:
    if (
        values.get("GITHUB_ACTIONS", "").lower() != "true"
        or values.get("GITHUB_REPOSITORY") != _EXPECTED_GITHUB_REPOSITORY
        or values.get("GITHUB_REPOSITORY_ID") != _EXPECTED_GITHUB_REPOSITORY_ID
    ):
        return {}
    return {
        AUTHORITY_REPOSITORY_IDENTITY_ENV: (
            f"github:repository-id:{_EXPECTED_GITHUB_REPOSITORY_ID}"
        ),
        **_sigstore_trust_environment(),
    }


def _configure_github_validation_trust(values: Mapping[str, str]) -> None:
    """Promote the stable repository identity only on the exact GitHub host."""

    os.environ.update(_github_validation_trust_environment(values))


def _write_attested_mutation_plan(
    command: CreateTask | AppendEvent,
    *,
    output_dir: Path,
    repo: Path,
    values: Mapping[str, str],
) -> tuple[AuthorityRequest, Mapping[str, Any]]:
    prepared = MutationGateway(repo).prepare(command)
    policy = _mutation_verification_policy(values)
    now = datetime.now(timezone.utc)
    predicate = {
        "schema_version": 1,
        "allowed": True,
        "authenticated": True,
        "issuer": policy["oidc_issuer"],
        "actor_id": prepared.request.actor_claim["id"],
        "actor_kind": prepared.request.actor_claim["kind"],
        "independence_level": "L2",
        "issued_at": _render_time(now - timedelta(seconds=5)),
        "expires_at": _render_time(now + timedelta(minutes=30)),
        "request_digest": prepared.request.request_digest,
        "binding_digest": prepared.request.binding_digest,
        "environment": policy["environment"],
    }
    plan = {
        "schema_version": 1,
        "kind": "mac.prepared-mutation",
        "command": _serialize_mutation(command, repo),
        "request": prepared.request.as_dict(),
        "intent": dict(prepared.intent),
        "verification_policy": policy,
    }
    _write_new_canonical_document(output_dir / "plan.json", plan)
    _write_new_canonical_document(output_dir / "subject.json", prepared.request.as_dict())
    _write_new_canonical_document(output_dir / "predicate.json", predicate)
    return prepared.request, policy


def github_attested_task_prepare_main(
    *,
    output_dir: Path,
    repo: Path = Path("."),
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    environment: Mapping[str, str] | None = None,
) -> int:
    """Prepare one exact task.create plan for protected Sigstore signing."""

    try:
        values = os.environ if environment is None else environment
        command = _successor_create_command(values, repo)
        request, _ = _write_attested_mutation_plan(
            command, output_dir=output_dir, repo=repo, values=values,
        )
        stdout.write(json.dumps({
            "ok": True,
            "task_id": command.task["id"],
            "request_digest": request.request_digest,
            "binding_digest": request.binding_digest,
            "predicate_type": _MUTATION_ATTESTATION_PREDICATE_TYPE,
        }, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except (MacError, OSError, TypeError, ValueError, yaml.YAMLError):
        stderr.write("trusted attested task preparation failed\n")
        return 2


def github_attested_scope_prepare_main(
    *,
    output_dir: Path,
    repo: Path = Path("."),
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    environment: Mapping[str, str] | None = None,
) -> int:
    """Prepare one exact scope.approve plan after replaying persisted authority."""

    previous: dict[str, str | None] = {}
    try:
        values = os.environ if environment is None else environment
        assignments = _sigstore_trust_environment()
        for name, value in assignments.items():
            previous[name] = os.environ.get(name)
            os.environ[name] = value
        command = _successor_scope_approval_command(values, repo)
        request, _ = _write_attested_mutation_plan(
            command, output_dir=output_dir, repo=repo, values=values,
        )
        stdout.write(json.dumps({
            "ok": True,
            "task_id": command.task_id,
            "operation": command.operation,
            "request_digest": request.request_digest,
            "binding_digest": request.binding_digest,
            "predicate_type": _MUTATION_ATTESTATION_PREDICATE_TYPE,
        }, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except (MacError, OSError, subprocess.SubprocessError, TypeError, ValueError, yaml.YAMLError):
        stderr.write("trusted attested scope preparation failed\n")
        return 2
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def github_attested_scope_amend_prepare_main(
    *,
    output_dir: Path,
    repo: Path = Path("."),
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    environment: Mapping[str, str] | None = None,
) -> int:
    """Prepare the exact v2 Scope amendment for protected Sigstore signing."""

    previous: dict[str, str | None] = {}
    try:
        values = os.environ if environment is None else environment
        assignments = _sigstore_trust_environment()
        for name, value in assignments.items():
            previous[name] = os.environ.get(name)
            os.environ[name] = value
        command = _successor_scope_amend_command(values, repo)
        request, _ = _write_attested_mutation_plan(
            command, output_dir=output_dir, repo=repo, values=values,
        )
        stdout.write(json.dumps({
            "ok": True,
            "task_id": command.task_id,
            "operation": command.operation,
            "request_digest": request.request_digest,
            "binding_digest": request.binding_digest,
            "predicate_type": _MUTATION_ATTESTATION_PREDICATE_TYPE,
        }, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except (MacError, OSError, subprocess.SubprocessError, TypeError, ValueError, yaml.YAMLError):
        stderr.write("trusted attested scope amendment preparation failed\n")
        return 2
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _load_json_document(path: Path, *, canonical: bool, maximum: int) -> dict[str, Any]:
    raw = path.read_bytes()
    if not raw or len(raw) > maximum:
        raise ValueError("prepared mutation artifact is invalid")
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict) or (canonical and raw != _canonical_document_bytes(document)):
        raise ValueError("prepared mutation artifact is invalid")
    return document


def _allowlisted_successor_scope_amendment(command: AppendEvent) -> bool:
    task_id = command.task_id
    expected_paths = [
        *_SUCCESSOR_SCOPE_BASE_PATHS,
        f"tasks/{task_id}/**",
        f"tasks/private/{task_id}/**",
    ]
    payload = command.payload
    amended = payload.get("scope") if isinstance(payload, Mapping) else None
    target_version = payload.get("version") if isinstance(payload, Mapping) else None
    if target_version == 2:
        prior_version = 1
        expected_revision = 1
        prior_paths = expected_paths
        prior_approved_by = ["repo-owner"]
        prior_risk_tags: list[str] = []
        additions = list(_SUCCESSOR_SCOPE_AMENDMENT_PATHS)
        approvers = ["repo-owner"]
        added_risk_tags = ["data_migration"]
        amended_risk_tags = ["data_migration"]
    elif target_version == 3:
        prior_version = 2
        expected_revision = 3
        prior_paths = [*expected_paths, *_SUCCESSOR_SCOPE_AMENDMENT_PATHS]
        prior_approved_by = ["governance-owner"]
        prior_risk_tags = ["data_migration"]
        additions = list(_SUCCESSOR_SCOPE_SECOND_AMENDMENT_PATHS)
        approvers = ["governance-owner"]
        added_risk_tags = ["auth_security"]
        amended_risk_tags = ["auth_security", "data_migration"]
    else:
        return False
    exact_replay_intent = {
        "add": additions,
        "add_operation": [],
        "approver": approvers,
        "risk_tag": added_risk_tags,
        "independent": True,
    }
    if (
        command.operation != "scope.amend"
        or command.event_type != "scope_proposed"
        or dict(command.actor_claim) != {"id": "repo-owner", "kind": "human"}
        or command.expected_revision != expected_revision
        or command.minimum_independence != "L2"
        or command.replay_intent != exact_replay_intent
        or not command.idempotency_key.startswith("github-sigstore-scope-amend:")
        or not isinstance(amended, Mapping)
        or set(payload) != {"scope_id", "version", "amendment", "scope"}
        or payload.get("amendment") is not True
        or payload.get("version") != target_version
        or payload.get("scope_id") != amended.get("id")
        or amended.get("task_id") != task_id
        or amended.get("version") != target_version
        or amended.get("status") != "proposed"
        or amended.get("proposed_by") != "repo-owner"
        or amended.get("approved_by") != []
        or amended.get("allowed_paths") != [*prior_paths, *additions]
        or amended.get("risk_tags") != amended_risk_tags
        or len(command.materializations) != 2
        or len(command.replace_existing) != 1
    ):
        return False
    current_path = next(iter(command.replace_existing))
    current_suffix = ("tasks", task_id, "scope-contract.yaml")
    history_suffix = (
        "tasks", task_id, "scope-history", f"scope-contract.v{prior_version}.yaml",
    )
    if tuple(current_path.parts[-3:]) != current_suffix:
        return False
    by_path = {path: value for path, value in command.materializations}
    current = by_path.get(current_path)
    history = next(
        (value for path, value in command.materializations if tuple(path.parts[-4:]) == history_suffix),
        None,
    )
    return bool(
        current == dict(amended)
        and isinstance(history, Mapping)
        and history.get("id") == amended.get("id")
        and history.get("task_id") == task_id
        and history.get("version") == prior_version
        and history.get("status") == "approved"
        and history.get("approved_by") == prior_approved_by
        and history.get("allowed_paths") == prior_paths
        and history.get("risk_tags") == prior_risk_tags
    )


def _allowlisted_successor_scope_approval(command: AppendEvent) -> bool:
    payload = command.payload
    scope = payload.get("scope") if isinstance(payload, Mapping) else None
    approval = payload.get("approval") if isinstance(payload, Mapping) else None
    if not isinstance(scope, Mapping) or not isinstance(approval, Mapping):
        return False
    version = scope.get("version")
    expected_actor = (
        "repo-owner" if version == 1
        else "governance-owner" if version in {2, 3}
        else ""
    )
    task_id = command.task_id
    expected_paths = [
        *_SUCCESSOR_SCOPE_BASE_PATHS,
        f"tasks/{task_id}/**",
        f"tasks/private/{task_id}/**",
    ]
    if version == 2:
        expected_paths.extend(_SUCCESSOR_SCOPE_AMENDMENT_PATHS)
    elif version == 3:
        expected_paths.extend(_SUCCESSOR_SCOPE_AMENDMENT_PATHS)
        expected_paths.extend(_SUCCESSOR_SCOPE_SECOND_AMENDMENT_PATHS)
    return bool(
        expected_actor
        and command.operation == "scope.approve"
        and command.event_type == "scope_approved"
        and dict(command.actor_claim) == {"id": expected_actor, "kind": "human"}
        and command.minimum_independence == "L2"
        and command.replay_intent == {"independence_level_claim": "L2"}
        and command.idempotency_key.startswith("github-sigstore-scope-approve:")
        and set(payload) == {"scope_id", "version", "approval_id", "approval", "scope"}
        and payload.get("scope_id") == scope.get("id")
        and payload.get("version") == version
        and payload.get("approval_id") == approval.get("id")
        and scope.get("task_id") == task_id
        and scope.get("status") == "approved"
        and scope.get("approved_by") == [expected_actor]
        and scope.get("proposed_by") == ("governance-owner" if version == 1 else "repo-owner")
        and scope.get("allowed_paths") == expected_paths
        and scope.get("risk_tags") == (
            [] if version == 1
            else ["data_migration"] if version == 2
            else ["auth_security", "data_migration"]
        )
        and approval.get("task_id") == task_id
        and approval.get("kind") == "scope"
        and approval.get("actor") == {"id": expected_actor, "kind": "human"}
        and approval.get("decision") == "approved"
        and approval.get("independence_level") == "L2"
        and len(command.replace_existing) == 1
        and len(command.materializations) == 2
    )


def github_attested_task_apply_main(
    *,
    plan_path: Path,
    predicate_path: Path,
    bundle_path: Path,
    repo: Path = Path("."),
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Verify and atomically apply one allowlisted exact attested mutation plan."""

    previous: dict[str, str | None] = {}
    try:
        plan = _load_json_document(plan_path, canonical=True, maximum=_MAX_AUTHORITY_DOCUMENT_BYTES)
        predicate = _load_json_document(predicate_path, canonical=True, maximum=_MAX_AUTHORITY_DOCUMENT_BYTES)
        bundle = _load_json_document(bundle_path, canonical=False, maximum=_MAX_ATTESTATION_BUNDLE_BYTES)
        if set(plan) != {"schema_version", "kind", "command", "request", "intent", "verification_policy"} or plan.get("schema_version") != 1 or plan.get("kind") != "mac.prepared-mutation":
            raise ValueError("prepared mutation plan is invalid")
        planned_request = plan.get("request")
        expected_repository_identity = f"github:repository-id:{_EXPECTED_GITHUB_REPOSITORY_ID}"
        if (
            not isinstance(planned_request, dict)
            or planned_request.get("repository_identity") != expected_repository_identity
        ):
            raise ValueError("prepared mutation repository identity is invalid")
        policy = plan.get("verification_policy")
        if not isinstance(policy, dict) or set(policy) != {
            "schema_version", "repository", "signer_workflow", "source_ref", "source_digest",
            "predicate_type", "environment", "oidc_issuer", "deny_self_hosted_runners",
        }:
            raise ValueError("prepared mutation verification policy is invalid")
        if (
            policy.get("schema_version") != 1
            or policy.get("repository") != _EXPECTED_GITHUB_REPOSITORY
            or policy.get("signer_workflow") != _EXPECTED_GITHUB_SIGNER_WORKFLOW
            or policy.get("source_ref") not in {_EXPECTED_GITHUB_REF, _EXPECTED_GITHUB_BOOTSTRAP_REF}
            or _GIT_OBJECT_ID.fullmatch(str(policy.get("source_digest", ""))) is None
            or policy.get("predicate_type") != _MUTATION_ATTESTATION_PREDICATE_TYPE
            or policy.get("environment") != "governance-authority"
            or policy.get("oidc_issuer") != "https://token.actions.githubusercontent.com"
            or policy.get("deny_self_hosted_runners") is not True
        ):
            raise ValueError("prepared mutation verification policy is invalid")
        command = _deserialize_mutation(plan["command"], repo)
        if isinstance(command, CreateTask):
            if command.operation != "task.create" or command.minimum_independence != "L2":
                raise ValueError("prepared task mutation is not allowlisted")
        elif command.operation == "scope.amend":
            if not _allowlisted_successor_scope_amendment(command):
                raise ValueError("prepared scope amendment is not allowlisted")
        elif not _allowlisted_successor_scope_approval(command):
            raise ValueError("prepared scope mutation is not allowlisted")
        with tempfile.TemporaryDirectory(prefix="mac-attested-task-") as directory:
            canonical_bundle = Path(directory) / "bundle.json"
            canonical_bundle.write_bytes(_canonical_document_bytes(bundle))
            assignments = {
                **_sigstore_trust_environment(),
                AUTHORITY_REPOSITORY_IDENTITY_ENV: expected_repository_identity,
                SIGSTORE_REPOSITORY_ENV: str(policy["repository"]),
                SIGSTORE_SIGNER_WORKFLOW_ENV: str(policy["signer_workflow"]),
                SIGSTORE_SOURCE_REF_ENV: str(policy["source_ref"]),
                SIGSTORE_SOURCE_DIGEST_ENV: str(policy["source_digest"]),
                SIGSTORE_PREDICATE_TYPE_ENV: str(policy["predicate_type"]),
                SIGSTORE_ENVIRONMENT_ENV: str(policy["environment"]),
                SIGSTORE_OIDC_ISSUER_ENV: str(policy["oidc_issuer"]),
                SIGSTORE_PREDICATE_ENV: str(predicate_path.resolve()),
                SIGSTORE_BUNDLE_ENV: str(canonical_bundle),
            }
            for name, value in assignments.items():
                if name not in previous:
                    previous[name] = os.environ.get(name)
                os.environ[name] = value
            prepared = MutationGateway(repo).prepare(command)
            if prepared.request.as_dict() != plan.get("request") or dict(prepared.intent) != plan.get("intent"):
                raise ValueError("prepared mutation plan no longer matches repository state")
            result = MutationGateway(repo).execute(command)
        stdout.write(json.dumps({
            "ok": True,
            "task_id": result.projection["id"],
            "revision": result.projection["revision"],
            "event_id": (result.event or {}).get("event_id"),
            "attestation_id": result.authority.get("attestation_id"),
            "binding_digest": result.authority.get("binding_digest"),
        }, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except (MacError, OSError, subprocess.SubprocessError, TypeError, ValueError, json.JSONDecodeError):
        stderr.write("trusted attested mutation application failed\n")
        return 2
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _git_changed_paths(base: str, head: str) -> list[str]:
    completed = subprocess.run(
        ["git", "diff", "--name-only", "-z", f"{base}...{head}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git diff failed: {message}")
    return [item.decode("utf-8") for item in completed.stdout.split(b"\0") if item]


def discover_task_ids(paths: list[str], explicit: list[str]) -> list[str]:
    task_ids = set(explicit)
    for path in paths:
        normalized = PurePosixPath(path.replace("\\", "/")).as_posix()
        match = _TASK_DIRECTORY.match(normalized)
        if match:
            task_ids.add(match.group("directory"))
    invalid = sorted(identifier for identifier in task_ids if not _TASK_ID.fullmatch(identifier))
    if invalid:
        raise ValueError(f"invalid v6 task identifiers: {', '.join(invalid)}")
    return sorted(task_ids)


def read_governance_level(config: Path) -> str:
    override = os.environ.get("MAC_GOVERNANCE_LEVEL", "").strip()
    if override:
        if override not in {"observe", "advisory", "enforced", "regulated"}:
            raise ValueError(f"invalid MAC_GOVERNANCE_LEVEL: {override!r}")
        return override
    text = config.read_text(encoding="utf-8")
    match = _LEVEL.search(text)
    if not match:
        raise ValueError(f"governance_level is missing from {config}")
    return match.group(1)


def _run(argv: list[str]) -> dict[str, Any]:
    completed = subprocess.run(argv, check=False, text=True, encoding="utf-8", capture_output=True)
    parsed: object = None
    if completed.stdout.strip():
        try:
            parsed = json.loads(completed.stdout)
        except json.JSONDecodeError:
            parsed = None
    return {
        "argv": argv,
        "exit_code": completed.returncode,
        "output": parsed,
        "stdout": completed.stdout.strip() if parsed is None else None,
        "stderr": completed.stderr.strip() or None,
    }


def github_trusted_validate_main(
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    environment: Mapping[str, str] | None = None,
) -> int:
    """Run repository validation with trust bound to the exact GitHub host."""

    values = os.environ if environment is None else environment
    assignments = _github_validation_trust_environment(values)
    if not assignments:
        stdout.write(json.dumps({
            "ok": False,
            "error": {
                "code": "CI_GITHUB_TRUST_INVALID",
                "message": "trusted GitHub repository identity is unavailable",
            },
        }, separators=(",", ":")) + "\n")
        return int(ExitCode.SECURITY)
    previous = {name: os.environ.get(name) for name in assignments}
    try:
        os.environ.update(assignments)
        check = _run(["mac", "validate", "--json"])
        output = check.get("output")
        if isinstance(output, Mapping):
            stdout.write(json.dumps(dict(output), ensure_ascii=False, separators=(",", ":")) + "\n")
        else:
            stdout.write(json.dumps({
                "ok": False,
                "error": {
                    "code": "CI_VALIDATION_OUTPUT_INVALID",
                    "message": "repository validation did not return JSON",
                },
            }, separators=(",", ":")) + "\n")
        if check.get("stderr"):
            stderr.write(str(check["stderr"]) + "\n")
        exit_code = check.get("exit_code")
        return int(exit_code) if type(exit_code) is int else int(ExitCode.INTERNAL)
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def check_current_evidence(repo: Path, task_directory: str, head: str) -> dict[str, Any]:
    """Fail unless Evidence covers claims at the PR head's current code subject."""
    task_dir = repo / "tasks" / task_directory
    task_path = task_dir / "task.yaml"
    if not task_path.is_file():
        return {"argv": ["evidence-gate", task_directory], "exit_code": 7, "output": {"ok": False, "error": "task.yaml is missing"}, "stdout": None, "stderr": None}
    task = yaml.safe_load(task_path.read_text(encoding="utf-8"))
    subject = GitRepository(repo).current_code_subject(task_directory, head)
    commit_sha = subject["commit_sha"].lower()
    tree_sha = subject["tree_sha"].lower()
    required = {str(value) for value in task.get("required_gates", [])}
    required.update(str(item["id"]) for item in task.get("acceptance_criteria", []) if item.get("required"))
    policy_digest = str((task.get("policy_ref") or {}).get("combined_digest", ""))
    runs: dict[str, dict[str, Any]] = {}
    for path in sorted((task_dir / "runs").glob("*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        runs[str(value.get("id"))] = value
    covered: set[str] = set()
    accepted_ids: list[str] = []
    rejected: dict[str, list[str]] = {}
    for path in sorted((task_dir / "evidence").glob("*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        reasons: list[str] = []
        subject = value.get("subject") or {}
        if value.get("validity", {}).get("status") != "valid" or value.get("validity", {}).get("invalidated_by"):
            reasons.append("invalid status")
        if subject != {"type": "commit", "commit_sha": commit_sha, "tree_sha": tree_sha}:
            reasons.append("not bound to PR head current code subject")
        if value.get("policy_digest") != policy_digest:
            reasons.append("policy digest mismatch")
        run_id = value.get("run_id")
        if value.get("kind") != "manual" and (not run_id or runs.get(str(run_id), {}).get("status") != "succeeded"):
            reasons.append("run missing or unsuccessful")
        if value.get("kind") in {"command", "ci", "static_analysis", "deployment"} and (value.get("execution") or {}).get("exit_code") != 0:
            reasons.append("execution failed")
        evidence_id = str(value.get("id", path.stem))
        if reasons:
            rejected[evidence_id] = reasons
            continue
        accepted_ids.append(evidence_id)
        for claim in value.get("claims", []):
            covered.update(str(claim[key]) for key in ("gate", "acceptance_criterion") if claim.get(key))
    missing = sorted(required - covered)
    ok = not missing
    return {
        "argv": ["evidence-gate", task_directory, head],
        "exit_code": 0 if ok else 7,
        "output": {"ok": ok, "task_directory": task_directory, "head_commit": commit_sha, "accepted_evidence": accepted_ids, "rejected_evidence": rejected, "covered": sorted(covered), "missing": missing},
        "stdout": None,
        "stderr": None,
    }


def evaluate(level: str, checks: list[dict[str, Any]], task_ids: list[str]) -> tuple[bool, int]:
    failed = any(check["exit_code"] != 0 for check in checks)
    missing_task = not task_ids
    if level in {"observe", "advisory"}:
        return True, 0
    if missing_task:
        return False, 7
    if failed:
        nonzero = next(int(check["exit_code"]) for check in checks if check["exit_code"] != 0)
        return False, nonzero if 1 < nonzero <= 20 else 20
    return True, 0


def main(argv: list[str] | None = None) -> int:
    normalized_argv = list(sys.argv[1:] if argv is None else argv)
    if normalized_argv == ["--github-oidc-broker"]:
        return github_oidc_broker_main()
    if normalized_argv == ["--github-oidc-probe"]:
        return github_oidc_probe_main()
    if normalized_argv == ["--github-trusted-validate", "--json"]:
        return github_trusted_validate_main()
    if normalized_argv and normalized_argv[0] == "--github-attestation-probe-prepare":
        probe_parser = argparse.ArgumentParser()
        probe_parser.add_argument("--github-attestation-probe-prepare", action="store_true")
        probe_parser.add_argument("--subject", type=Path, required=True)
        probe_parser.add_argument("--predicate", type=Path, required=True)
        probe_args = probe_parser.parse_args(normalized_argv)
        return github_attestation_probe_prepare_main(
            subject_path=probe_args.subject,
            predicate_path=probe_args.predicate,
        )
    if normalized_argv and normalized_argv[0] == "--github-attestation-probe-verify":
        probe_parser = argparse.ArgumentParser()
        probe_parser.add_argument("--github-attestation-probe-verify", action="store_true")
        probe_parser.add_argument("--subject", type=Path, required=True)
        probe_parser.add_argument("--predicate", type=Path, required=True)
        probe_parser.add_argument("--bundle", type=Path, required=True)
        probe_args = probe_parser.parse_args(normalized_argv)
        return github_attestation_probe_verify_main(
            subject_path=probe_args.subject,
            predicate_path=probe_args.predicate,
            bundle_path=probe_args.bundle,
        )
    if normalized_argv and normalized_argv[0] == "--github-attested-task-prepare":
        mutation_parser = argparse.ArgumentParser()
        mutation_parser.add_argument("--github-attested-task-prepare", action="store_true")
        mutation_parser.add_argument("--out", type=Path, required=True)
        mutation_args = mutation_parser.parse_args(normalized_argv)
        return github_attested_task_prepare_main(output_dir=mutation_args.out)
    if normalized_argv and normalized_argv[0] == "--github-attested-scope-prepare":
        mutation_parser = argparse.ArgumentParser()
        mutation_parser.add_argument("--github-attested-scope-prepare", action="store_true")
        mutation_parser.add_argument("--out", type=Path, required=True)
        mutation_args = mutation_parser.parse_args(normalized_argv)
        return github_attested_scope_prepare_main(output_dir=mutation_args.out)
    if normalized_argv and normalized_argv[0] == "--github-attested-scope-amend-prepare":
        mutation_parser = argparse.ArgumentParser()
        mutation_parser.add_argument("--github-attested-scope-amend-prepare", action="store_true")
        mutation_parser.add_argument("--out", type=Path, required=True)
        mutation_args = mutation_parser.parse_args(normalized_argv)
        return github_attested_scope_amend_prepare_main(output_dir=mutation_args.out)
    if normalized_argv and normalized_argv[0] == "--github-attested-task-apply":
        mutation_parser = argparse.ArgumentParser()
        mutation_parser.add_argument("--github-attested-task-apply", action="store_true")
        mutation_parser.add_argument("--plan", type=Path, required=True)
        mutation_parser.add_argument("--predicate", type=Path, required=True)
        mutation_parser.add_argument("--bundle", type=Path, required=True)
        mutation_args = mutation_parser.parse_args(normalized_argv)
        return github_attested_task_apply_main(
            plan_path=mutation_args.plan,
            predicate_path=mutation_args.predicate,
            bundle_path=mutation_args.bundle,
        )
    _configure_github_validation_trust(os.environ)
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--task-id", action="append", default=[])
    parser.add_argument("--config", type=Path, default=Path(".agents/config.yaml"))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(normalized_argv)
    explicit = list(args.task_id)
    explicit.extend(
        item for item in re.split(r"[,\s]+", os.environ.get("MAC_TASK_IDS", "")) if item
    )
    try:
        level = read_governance_level(args.config)
        changed_paths = _git_changed_paths(args.base, args.head)
        task_ids = discover_task_ids(changed_paths, explicit)
        checks = [_run(["mac", "validate", "--json"])]
        checks.extend(
            _run(
                [
                    "mac",
                    "scope",
                    "check",
                    task_id,
                    "--base",
                    args.base,
                    "--head",
                    args.head,
                    "--json",
                ]
            )
            for task_id in task_ids
        )
        checks.extend(check_current_evidence(Path("."), task_id, args.head) for task_id in task_ids)
        ok, exit_code = evaluate(level, checks, task_ids)
        report = {
            "ok": ok,
            "governance_level": level,
            "base": args.base,
            "head": args.head,
            "task_ids": task_ids,
            "changed_path_count": len(changed_paths),
            "checks": checks,
            "warnings": (
                ["No v6 task was associated with this PR; set MAC_TASK_IDS or commit task metadata."]
                if not task_ids
                else []
            ),
        }
    except (OSError, RuntimeError, ValueError) as exc:
        report = {
            "ok": False,
            "error": {"code": "CI_GOVERNANCE_INTERNAL", "message": str(exc)},
        }
        exit_code = 20
    if args.json:
        print(json.dumps(report, ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
