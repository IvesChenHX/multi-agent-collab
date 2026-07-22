"""Run the v6 governance checks for a pull request base/head pair."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
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
    AuthorityRequest,
    canonical_digest,
    command_manifest_digest,
    current_authority_verifier,
    require_authority,
)
from mac.errors import MacError
from mac.git import GitRepository


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
_GIT_OBJECT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_MAX_ATTESTATION_BUNDLE_BYTES = 8_000_000


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
