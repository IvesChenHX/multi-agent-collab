from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping, NoReturn, Sequence

from pathspec import GitIgnoreSpec

from .errors import ExitCode, MacError
from .io import load_data


_LEVEL = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_VERIFIED_SEAL = object()
_ADAPTER_SEAL = object()
_MAX_BROKER_RESPONSE_BYTES = 1_000_000
_BROKER_TIMEOUT_SECONDS = 15.0

BROKER_ARGV_ENV = "MAC_AUTHORITY_BROKER_ARGV"
BROKER_MANIFEST_ENV = "MAC_AUTHORITY_BROKER_MANIFEST_SHA256"
PUBLIC_KEYRING_ENV = "MAC_AUTHORITY_PUBLIC_KEYRING_B64"
EXPECTED_ISSUER_ENV = "MAC_AUTHORITY_EXPECTED_ISSUER"
BROKER_CONTEXT_PREFIX = "MAC_AUTHORITY_BROKER_CONTEXT_"
SIGSTORE_BUNDLE_ENV = "MAC_AUTHORITY_SIGSTORE_BUNDLE"
SIGSTORE_PREDICATE_ENV = "MAC_AUTHORITY_SIGSTORE_PREDICATE"
SIGSTORE_VERIFIER_ARGV_ENV = "MAC_AUTHORITY_SIGSTORE_VERIFIER_ARGV"
SIGSTORE_VERIFIER_MANIFEST_ENV = "MAC_AUTHORITY_SIGSTORE_VERIFIER_MANIFEST_SHA256"
SIGSTORE_REPOSITORY_ENV = "MAC_AUTHORITY_SIGSTORE_REPOSITORY"
SIGSTORE_REPOSITORY_IDENTITY_ENV = "MAC_AUTHORITY_SIGSTORE_REPOSITORY_IDENTITY"
SIGSTORE_SIGNER_WORKFLOW_ENV = "MAC_AUTHORITY_SIGSTORE_SIGNER_WORKFLOW"
SIGSTORE_SOURCE_REF_ENV = "MAC_AUTHORITY_SIGSTORE_SOURCE_REF"
SIGSTORE_SOURCE_DIGEST_ENV = "MAC_AUTHORITY_SIGSTORE_SOURCE_DIGEST"
SIGSTORE_PREDICATE_TYPE_ENV = "MAC_AUTHORITY_SIGSTORE_PREDICATE_TYPE"
SIGSTORE_ENVIRONMENT_ENV = "MAC_AUTHORITY_SIGSTORE_ENVIRONMENT"
SIGSTORE_OIDC_ISSUER_ENV = "MAC_AUTHORITY_SIGSTORE_OIDC_ISSUER"
_MAX_SIGSTORE_BUNDLE_BYTES = 8_000_000
_GIT_OBJECT_ID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_GITHUB_REPOSITORY_IDENTITY = re.compile(
    r"github:repository-id:[1-9][0-9]{0,19}\Z"
)


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


def canonical_digest(value: Any) -> str:
    """Return the canonical digest used for mutation intent documents."""

    return _sha256(_canonical_json(value))


def _security_error(code: str, message: str, *, task_id: str | None = None) -> MacError:
    return MacError(code, message, exit_code=ExitCode.SECURITY, task_id=task_id)


def _safe_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise _security_error("AUTHORITY_REQUEST_INVALID", f"authority {field} is required")
    return value


def _safe_digest(value: object, field: str) -> str:
    result = str(value)
    if _DIGEST.fullmatch(result) is None:
        raise _security_error("AUTHORITY_REQUEST_INVALID", f"authority {field} must be a canonical SHA-256 digest")
    return result


@dataclass(frozen=True, slots=True)
class AuthorityRequest:
    """The exact, canonical mutation authority binding sent to the broker."""

    repository_identity: str
    operation: str
    task_id: str
    actor_claim: Mapping[str, str]
    expected_revision: int
    idempotency_key: str
    intent_digest: str
    policy_digest: str
    ownership_digest: str
    audience: str

    def __post_init__(self) -> None:
        actor = dict(self.actor_claim)
        if set(actor) != {"id", "kind"}:
            raise _security_error(
                "AUTHORITY_REQUEST_INVALID",
                "authority actor claim must contain exactly id and kind",
                task_id=str(self.task_id) if self.task_id else None,
            )
        normalized_actor = {
            "id": _safe_text(actor.get("id"), "actor id"),
            "kind": _safe_text(actor.get("kind"), "actor kind"),
        }
        if isinstance(self.expected_revision, bool) or not isinstance(self.expected_revision, int) or self.expected_revision < -1:
            raise _security_error(
                "AUTHORITY_REQUEST_INVALID",
                "authority expected revision must be an integer greater than or equal to -1",
                task_id=str(self.task_id) if self.task_id else None,
            )
        object.__setattr__(self, "repository_identity", _safe_text(self.repository_identity, "repository identity"))
        object.__setattr__(self, "operation", _safe_text(self.operation, "operation"))
        object.__setattr__(self, "task_id", _safe_text(self.task_id, "Task id"))
        object.__setattr__(self, "actor_claim", MappingProxyType(normalized_actor))
        object.__setattr__(self, "idempotency_key", _safe_text(self.idempotency_key, "idempotency key"))
        object.__setattr__(self, "intent_digest", _safe_digest(self.intent_digest, "intent digest"))
        object.__setattr__(self, "policy_digest", _safe_digest(self.policy_digest, "policy digest"))
        object.__setattr__(self, "ownership_digest", _safe_digest(self.ownership_digest, "ownership digest"))
        object.__setattr__(self, "audience", _safe_text(self.audience, "audience"))

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "repository_identity": self.repository_identity,
            "operation": self.operation,
            "task_id": self.task_id,
            "actor_claim": dict(self.actor_claim),
            "expected_revision": self.expected_revision,
            "idempotency_key": self.idempotency_key,
            "intent_digest": self.intent_digest,
            "policy_digest": self.policy_digest,
            "ownership_digest": self.ownership_digest,
            "audience": self.audience,
        }

    @property
    def request_digest(self) -> str:
        return _sha256(_canonical_json(self.as_dict()))

    @property
    def binding_digest(self) -> str:
        return _sha256(_canonical_json(self.as_dict()), domain=b"mac-authority-binding-v1\x00")


@dataclass(frozen=True, slots=True, init=False)
class VerifiedAuthority:
    """A non-secret authority fact that can only result from broker verification."""

    actor_id: str
    actor_kind: str
    issuer: str
    attestation_id: str
    independence_level: str
    issued_at: str
    expires_at: str
    repository_identity: str
    operation: str
    task_id: str
    expected_revision: int
    idempotency_key: str
    intent_digest: str
    policy_digest: str
    ownership_digest: str
    audience: str
    request_digest: str
    binding_digest: str
    broker_digest: str
    trust_digest: str
    signature_algorithm: str
    key_id: str
    signed_payload_json: str
    signed_signature: str
    store_contract_version: int
    signed_bundle_json: str | None
    sigstore_policy_json: str | None
    _verification_marker: object

    def __init__(
        self,
        *,
        actor_id: str,
        actor_kind: str,
        issuer: str,
        attestation_id: str,
        independence_level: str,
        issued_at: str,
        expires_at: str,
        request: AuthorityRequest,
        broker_digest: str,
        trust_digest: str,
        signature_algorithm: str,
        key_id: str,
        signed_payload_json: str,
        signed_signature: str,
        _seal: object,
        store_contract_version: int = 2,
        signed_bundle_json: str | None = None,
        sigstore_policy_json: str | None = None,
    ) -> None:
        if _seal is not _VERIFIED_SEAL:
            raise TypeError("VerifiedAuthority values are created only by successful broker verification")
        values = {
            "actor_id": actor_id,
            "actor_kind": actor_kind,
            "issuer": issuer,
            "attestation_id": attestation_id,
            "independence_level": independence_level,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "repository_identity": request.repository_identity,
            "operation": request.operation,
            "task_id": request.task_id,
            "expected_revision": request.expected_revision,
            "idempotency_key": request.idempotency_key,
            "intent_digest": request.intent_digest,
            "policy_digest": request.policy_digest,
            "ownership_digest": request.ownership_digest,
            "audience": request.audience,
            "request_digest": request.request_digest,
            "binding_digest": request.binding_digest,
            "broker_digest": broker_digest,
            "trust_digest": trust_digest,
            "signature_algorithm": signature_algorithm,
            "key_id": key_id,
            "signed_payload_json": signed_payload_json,
            "signed_signature": signed_signature,
            "store_contract_version": store_contract_version,
            "signed_bundle_json": signed_bundle_json,
            "sigstore_policy_json": sigstore_policy_json,
            "_verification_marker": _VERIFIED_SEAL,
        }
        for name, value in values.items():
            object.__setattr__(self, name, value)

    def __init_subclass__(cls, **_: Any) -> NoReturn:
        raise TypeError("VerifiedAuthority is sealed")

    @property
    def allowed(self) -> bool:
        return True

    @property
    def authenticated(self) -> bool:
        return True

    @property
    def reason(self) -> str:
        return ""


# Compatibility for callers that only use the old return type as an annotation.
# Direct construction now fails because VerifiedAuthority requires the private seal.
AuthorityDecision = VerifiedAuthority


def _resolved_command_manifest(argv: Sequence[str]) -> tuple[tuple[str, ...], str]:
    if not argv or any(not isinstance(value, str) or not value or "\x00" in value for value in argv):
        raise _security_error("AUTHORITY_CONFIGURATION_INVALID", "authority broker command configuration is invalid")
    executable = shutil.which(argv[0])
    if executable is None:
        candidate = Path(argv[0])
        executable = str(candidate.resolve()) if candidate.is_file() else None
    if executable is None:
        raise _security_error("AUTHORITY_BROKER_UNAVAILABLE", "authority broker executable is unavailable")

    resolved: list[str] = []
    files: list[dict[str, Any]] = []
    for index, value in enumerate(argv):
        candidate = Path(executable) if index == 0 else Path(value)
        if candidate.is_file():
            path = candidate.resolve()
            try:
                content = path.read_bytes()
            except OSError:
                raise _security_error("AUTHORITY_BROKER_UNAVAILABLE", "authority broker command cannot be verified") from None
            rendered = str(path)
            resolved.append(rendered)
            files.append(
                {
                    "index": index,
                    "path": rendered,
                    "size": len(content),
                    "digest": _sha256(content),
                }
            )
        else:
            resolved.append(value)
    manifest = {
        "schema_version": 1,
        "resolved_argv": resolved,
        "files": files,
    }
    return tuple(resolved), _sha256(_canonical_json(manifest))


def command_manifest_digest(argv: Sequence[str]) -> str:
    """Digest the resolved broker argv and every existing file argument."""

    return _resolved_command_manifest(argv)[1]


@dataclass(frozen=True, slots=True)
class _RsaPublicKey:
    key_id: str
    algorithm: str
    modulus: int
    exponent: int
    size_bytes: int
    digest: str


_RSA_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _decode_base64url(value: object) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("non-canonical base64url")
    padding = "=" * ((4 - len(value) % 4) % 4)
    decoded = base64.urlsafe_b64decode((value + padding).encode("ascii"))
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise ValueError("non-canonical base64url")
    return decoded


def _decode_public_keyring(encoded: str) -> dict[str, _RsaPublicKey]:
    try:
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeEncodeError, UnicodeDecodeError, binascii.Error, json.JSONDecodeError, ValueError):
        raise _security_error("AUTHORITY_CONFIGURATION_INVALID", "authority public keyring is invalid") from None
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "keys"}
        or document.get("schema_version") != 1
        or not isinstance(document.get("keys"), list)
        or not document["keys"]
        or len(document["keys"]) > 32
        or _canonical_json(document) != raw
    ):
        raise _security_error("AUTHORITY_CONFIGURATION_INVALID", "authority public keyring is invalid")
    result: dict[str, _RsaPublicKey] = {}
    try:
        for item in document["keys"]:
            if not isinstance(item, dict) or set(item) != {"key_id", "algorithm", "n", "e"}:
                raise ValueError("invalid key")
            key_id = _safe_text(item.get("key_id"), "key id")
            algorithm = str(item.get("algorithm", ""))
            if algorithm != "RS256" or key_id in result:
                raise ValueError("invalid key")
            modulus_bytes = _decode_base64url(item.get("n"))
            exponent_bytes = _decode_base64url(item.get("e"))
            modulus = int.from_bytes(modulus_bytes, "big")
            exponent = int.from_bytes(exponent_bytes, "big")
            if modulus.bit_length() < 2048 or modulus.bit_length() > 8192 or exponent < 3 or exponent % 2 == 0:
                raise ValueError("weak key")
            normalized = {
                "key_id": key_id,
                "algorithm": algorithm,
                "n": str(item["n"]),
                "e": str(item["e"]),
            }
            result[key_id] = _RsaPublicKey(
                key_id,
                algorithm,
                modulus,
                exponent,
                len(modulus_bytes),
                canonical_digest(normalized),
            )
    except (TypeError, ValueError):
        raise _security_error("AUTHORITY_CONFIGURATION_INVALID", "authority public keyring is invalid") from None
    return result


def _decode_signature(value: object, *, task_id: str) -> bytes:
    if not isinstance(value, str):
        raise _security_error("AUTHORITY_SIGNATURE_INVALID", "authority broker signature is invalid", task_id=task_id)
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise _security_error("AUTHORITY_SIGNATURE_INVALID", "authority broker signature is invalid", task_id=task_id) from None


def _verify_rs256(key: _RsaPublicKey, message: bytes, signature: bytes) -> bool:
    if len(signature) != key.size_bytes:
        return False
    signature_value = int.from_bytes(signature, "big")
    if signature_value <= 0 or signature_value >= key.modulus:
        return False
    encoded = pow(signature_value, key.exponent, key.modulus).to_bytes(key.size_bytes, "big")
    digest_info = _RSA_SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    padding_length = key.size_bytes - len(digest_info) - 3
    if padding_length < 8:
        return False
    expected = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
    return hmac.compare_digest(encoded, expected)


def _parse_time(value: object, field: str, *, task_id: str) -> datetime:
    if not isinstance(value, str):
        raise _security_error("AUTHORITY_RESPONSE_INVALID", f"authority response {field} is invalid", task_id=task_id)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise _security_error("AUTHORITY_RESPONSE_INVALID", f"authority response {field} is invalid", task_id=task_id) from None
    if parsed.tzinfo is None:
        raise _security_error("AUTHORITY_RESPONSE_INVALID", f"authority response {field} is invalid", task_id=task_id)
    return parsed.astimezone(timezone.utc)


class SubprocessAuthorityAdapter:
    """Production Adapter for a host-configured, asymmetrically signed broker."""

    __slots__ = ("_argv", "_expected_manifest", "_expected_issuer", "_public_keys", "_adapter_marker")

    def __init__(
        self,
        *,
        argv: tuple[str, ...],
        expected_manifest: str,
        expected_issuer: str,
        public_keys: Mapping[str, _RsaPublicKey],
        _seal: object,
    ) -> None:
        if _seal is not _ADAPTER_SEAL:
            raise TypeError("SubprocessAuthorityAdapter must be loaded from the host environment")
        self._argv = argv
        self._expected_manifest = expected_manifest
        self._expected_issuer = expected_issuer
        self._public_keys = MappingProxyType(dict(public_keys))
        self._adapter_marker = _ADAPTER_SEAL

    def __init_subclass__(cls, **_: Any) -> NoReturn:
        raise TypeError("SubprocessAuthorityAdapter is sealed")

    def __repr__(self) -> str:
        return "SubprocessAuthorityAdapter(configured=True)"

    @classmethod
    def from_host_environment(cls) -> SubprocessAuthorityAdapter:
        raw_argv = os.environ.get(BROKER_ARGV_ENV)
        expected_manifest = os.environ.get(BROKER_MANIFEST_ENV)
        encoded_keyring = os.environ.get(PUBLIC_KEYRING_ENV)
        expected_issuer = os.environ.get(EXPECTED_ISSUER_ENV)
        if not all((raw_argv, expected_manifest, encoded_keyring, expected_issuer)):
            raise _security_error(
                "AUTHORITY_CONFIGURATION_MISSING",
                "trusted authority broker configuration is unavailable",
            )
        try:
            decoded_argv = json.loads(str(raw_argv))
        except (json.JSONDecodeError, TypeError, ValueError):
            raise _security_error("AUTHORITY_CONFIGURATION_INVALID", "authority broker command configuration is invalid") from None
        if not isinstance(decoded_argv, list) or not decoded_argv or any(not isinstance(value, str) for value in decoded_argv):
            raise _security_error("AUTHORITY_CONFIGURATION_INVALID", "authority broker command configuration is invalid")
        if _DIGEST.fullmatch(str(expected_manifest)) is None:
            raise _security_error("AUTHORITY_CONFIGURATION_INVALID", "authority broker manifest configuration is invalid")
        issuer = _safe_text(expected_issuer, "expected issuer")
        resolved_argv, observed_manifest = _resolved_command_manifest(decoded_argv)
        if not hmac.compare_digest(observed_manifest, str(expected_manifest)):
            raise _security_error(
                "AUTHORITY_BROKER_MANIFEST_MISMATCH",
                "authority broker command does not match the host-pinned manifest",
            )
        return cls(
            argv=tuple(decoded_argv),
            expected_manifest=observed_manifest,
            expected_issuer=issuer,
            public_keys=_decode_public_keyring(str(encoded_keyring)),
            _seal=_ADAPTER_SEAL,
        )

    @classmethod
    def from_trust_environment(cls) -> SubprocessAuthorityAdapter:
        encoded_keyring = os.environ.get(PUBLIC_KEYRING_ENV)
        expected_issuer = os.environ.get(EXPECTED_ISSUER_ENV)
        if not all((encoded_keyring, expected_issuer)):
            raise _security_error(
                "AUTHORITY_CONFIGURATION_MISSING",
                "trusted authority verification configuration is unavailable",
            )
        return cls(
            argv=(),
            expected_manifest="",
            expected_issuer=_safe_text(expected_issuer, "expected issuer"),
            public_keys=_decode_public_keyring(str(encoded_keyring)),
            _seal=_ADAPTER_SEAL,
        )

    def _response(self, request: AuthorityRequest) -> Mapping[str, Any]:
        resolved_argv, observed_manifest = _resolved_command_manifest(self._argv)
        if not hmac.compare_digest(observed_manifest, self._expected_manifest):
            raise _security_error(
                "AUTHORITY_BROKER_MANIFEST_MISMATCH",
                "authority broker command no longer matches the host-pinned manifest",
                task_id=request.task_id,
            )
        try:
            safe_environment_names = {
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
                "COMSPEC", "HOME", "LANG", "LOCALAPPDATA", "PATH", "PATHEXT",
                "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE", "WINDIR",
                BROKER_MANIFEST_ENV, EXPECTED_ISSUER_ENV, PUBLIC_KEYRING_ENV,
            }
            broker_environment = {
                key: value
                for key, value in os.environ.items()
                if key.upper() in safe_environment_names
                or key.upper().startswith("LC_")
                or key.startswith(BROKER_CONTEXT_PREFIX)
            }
            completed = subprocess.run(
                list(resolved_argv),
                input=_canonical_json(request.as_dict()).decode("utf-8") + "\n",
                text=True,
                capture_output=True,
                shell=False,
                env=broker_environment,
                timeout=_BROKER_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise _security_error(
                "AUTHORITY_BROKER_UNAVAILABLE",
                "authority broker invocation failed",
                task_id=request.task_id,
            ) from None
        if completed.returncode != 0:
            raise _security_error(
                "AUTHORITY_BROKER_UNAVAILABLE",
                "authority broker did not return a decision",
                task_id=request.task_id,
            )
        raw = completed.stdout[:-1] if completed.stdout.endswith("\n") else completed.stdout
        if not raw or len(raw.encode("utf-8")) > _MAX_BROKER_RESPONSE_BYTES:
            raise _security_error("AUTHORITY_RESPONSE_INVALID", "authority broker response is invalid", task_id=request.task_id)
        try:
            response = json.loads(raw)
            canonical = _canonical_json(response).decode("utf-8")
        except (json.JSONDecodeError, TypeError, ValueError):
            raise _security_error("AUTHORITY_RESPONSE_INVALID", "authority broker response is invalid", task_id=request.task_id) from None
        if raw != canonical or not isinstance(response, dict):
            raise _security_error("AUTHORITY_RESPONSE_INVALID", "authority broker response is invalid", task_id=request.task_id)
        return response

    def authorize(
        self,
        *,
        request: AuthorityRequest,
        minimum_independence: str | None = None,
    ) -> VerifiedAuthority:
        if type(self) is not SubprocessAuthorityAdapter or self._adapter_marker is not _ADAPTER_SEAL:
            raise _security_error("AUTHORITY_VERIFIER_REQUIRED", "a production authority Adapter is required", task_id=request.task_id)
        if minimum_independence is not None and minimum_independence not in _LEVEL:
            raise _security_error("AUTHORITY_REQUEST_INVALID", "minimum independence level is invalid", task_id=request.task_id)
        response = self._response(request)
        if set(response) != {"payload", "signature"}:
            raise _security_error("AUTHORITY_RESPONSE_INVALID", "authority broker response is invalid", task_id=request.task_id)
        payload = response.get("payload")
        signature = response.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, str):
            raise _security_error("AUTHORITY_RESPONSE_INVALID", "authority broker response is invalid", task_id=request.task_id)
        key_id = str(payload.get("key_id", ""))
        algorithm = str(payload.get("algorithm", ""))
        key = self._public_keys.get(key_id)
        observed_signature = _decode_signature(signature, task_id=request.task_id)
        if (
            key is None
            or algorithm != key.algorithm
            or not _verify_rs256(key, _canonical_json(payload), observed_signature)
        ):
            raise _security_error("AUTHORITY_SIGNATURE_INVALID", "authority broker signature is invalid", task_id=request.task_id)

        required_keys = {
            "schema_version",
            "algorithm",
            "key_id",
            "allowed",
            "authenticated",
            "issuer",
            "audience",
            "attestation_id",
            "actor_id",
            "actor_kind",
            "independence_level",
            "issued_at",
            "expires_at",
            "request",
            "request_digest",
            "binding_digest",
            "broker_digest",
        }
        if set(payload) != required_keys or payload.get("schema_version") != 1:
            raise _security_error("AUTHORITY_RESPONSE_INVALID", "authority broker response is invalid", task_id=request.task_id)
        if payload.get("request") != request.as_dict():
            raise _security_error("AUTHORITY_BINDING_MISMATCH", "authority fact does not bind the requested mutation", task_id=request.task_id)
        if payload.get("request_digest") != request.request_digest or payload.get("binding_digest") != request.binding_digest:
            raise _security_error("AUTHORITY_BINDING_MISMATCH", "authority fact digest does not bind the requested mutation", task_id=request.task_id)
        if payload.get("issuer") != self._expected_issuer or payload.get("audience") != request.audience:
            raise _security_error("AUTHORITY_ISSUER_MISMATCH", "authority fact issuer or audience is not trusted", task_id=request.task_id)
        if payload.get("broker_digest") != self._expected_manifest:
            raise _security_error("AUTHORITY_BROKER_MANIFEST_MISMATCH", "authority fact does not bind the invoked broker", task_id=request.task_id)
        if payload.get("actor_id") != request.actor_claim["id"] or payload.get("actor_kind") != request.actor_claim["kind"]:
            raise _security_error("AUTHORITY_BINDING_MISMATCH", "authority fact does not bind the requested actor", task_id=request.task_id)
        if payload.get("allowed") is not True or payload.get("authenticated") is not True:
            raise _security_error("ACTOR_AUTHORITY_DENIED", "authority broker denied the requested mutation", task_id=request.task_id)

        independence = str(payload.get("independence_level", ""))
        if independence not in _LEVEL or (
            minimum_independence is not None and not level_at_least(independence, minimum_independence)
        ):
            raise _security_error("ACTOR_AUTHORITY_DENIED", "authority fact does not satisfy required independence", task_id=request.task_id)
        issued = _parse_time(payload.get("issued_at"), "issued_at", task_id=request.task_id)
        expires = _parse_time(payload.get("expires_at"), "expires_at", task_id=request.task_id)
        now = datetime.now(timezone.utc)
        if issued > now + timedelta(seconds=30) or expires <= issued or expires <= now:
            raise _security_error("AUTHORITY_ATTESTATION_EXPIRED", "authority fact is not currently valid", task_id=request.task_id)
        attestation_id = payload.get("attestation_id")
        if not isinstance(attestation_id, str) or not attestation_id or "\x00" in attestation_id:
            raise _security_error("AUTHORITY_RESPONSE_INVALID", "authority attestation id is invalid", task_id=request.task_id)

        return VerifiedAuthority(
            actor_id=str(payload["actor_id"]),
            actor_kind=str(payload["actor_kind"]),
            issuer=str(payload["issuer"]),
            attestation_id=attestation_id,
            independence_level=independence,
            issued_at=str(payload["issued_at"]),
            expires_at=str(payload["expires_at"]),
            request=request,
            broker_digest=str(payload["broker_digest"]),
            trust_digest=key.digest,
            signature_algorithm=algorithm,
            key_id=key_id,
            signed_payload_json=_canonical_json(payload).decode("utf-8"),
            signed_signature=signature,
            _seal=_VERIFIED_SEAL,
        )

    def verify_persisted_envelope(
        self,
        envelope: Mapping[str, Any],
        *,
        request: AuthorityRequest,
        audit: Mapping[str, Any],
    ) -> None:
        """Verify a historical broker envelope without requiring it to be unexpired now."""

        if set(envelope) != {"payload", "signature"}:
            raise _security_error("AUTHORITY_SIGNATURE_INVALID", "persisted authority envelope is invalid", task_id=request.task_id)
        payload = envelope.get("payload")
        signature = envelope.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, str):
            raise _security_error("AUTHORITY_SIGNATURE_INVALID", "persisted authority envelope is invalid", task_id=request.task_id)
        required_keys = {
            "schema_version", "algorithm", "key_id", "allowed", "authenticated",
            "issuer", "audience", "attestation_id", "actor_id", "actor_kind",
            "independence_level", "issued_at", "expires_at", "request",
            "request_digest", "binding_digest", "broker_digest",
        }
        key_id = str(payload.get("key_id", ""))
        algorithm = str(payload.get("algorithm", ""))
        key = self._public_keys.get(key_id)
        observed_signature = _decode_signature(signature, task_id=request.task_id)
        if (
            set(payload) != required_keys
            or payload.get("schema_version") != 1
            or key is None
            or algorithm != key.algorithm
            or not _verify_rs256(key, _canonical_json(payload), observed_signature)
        ):
            raise _security_error("AUTHORITY_SIGNATURE_INVALID", "persisted authority signature is invalid", task_id=request.task_id)
        if (
            payload.get("request") != request.as_dict()
            or payload.get("request_digest") != request.request_digest
            or payload.get("binding_digest") != request.binding_digest
            or payload.get("issuer") != self._expected_issuer
            or audit.get("issuer") != payload.get("issuer")
            or payload.get("audience") != request.audience
            or payload.get("allowed") is not True
            or payload.get("authenticated") is not True
            or payload.get("actor_id") != audit.get("actor_id")
            or payload.get("actor_kind") != audit.get("actor_kind")
            or payload.get("attestation_id") != audit.get("attestation_id")
            or payload.get("independence_level") != audit.get("independence_level")
            or payload.get("issued_at") != audit.get("issued_at")
            or payload.get("expires_at") != audit.get("expires_at")
            or payload.get("broker_digest") != audit.get("broker_digest")
            or audit.get("trust_digest") != key.digest
            or audit.get("signature_algorithm") != algorithm
            or audit.get("key_id") != key_id
        ):
            raise _security_error(
                "AUTHORITY_BINDING_MISMATCH",
                "persisted authority envelope does not bind its audit record",
                task_id=request.task_id,
            )
        issued = _parse_time(payload.get("issued_at"), "issued_at", task_id=request.task_id)
        expires = _parse_time(payload.get("expires_at"), "expires_at", task_id=request.task_id)
        if expires <= issued:
            raise _security_error("AUTHORITY_RESPONSE_INVALID", "persisted authority lifetime is invalid", task_id=request.task_id)


@dataclass(frozen=True, slots=True)
class _SigstoreVerificationPolicy:
    repository: str
    repository_identity: str | None
    signer_workflow: str
    source_ref: str
    source_digest: str
    predicate_type: str
    environment: str
    oidc_issuer: str
    verifier_manifest: str

    def as_dict(self) -> dict[str, str | int | bool]:
        document: dict[str, str | int | bool] = {
            "schema_version": (
                2 if self.repository_identity is not None else 1
            ),
            "repository": self.repository,
            "signer_workflow": self.signer_workflow,
            "source_ref": self.source_ref,
            "source_digest": self.source_digest,
            "predicate_type": self.predicate_type,
            "environment": self.environment,
            "oidc_issuer": self.oidc_issuer,
            "deny_self_hosted_runners": True,
            "verifier_manifest": self.verifier_manifest,
        }
        if self.repository_identity is not None:
            document["repository_identity"] = self.repository_identity
        return document


def _safe_sigstore_name(value: object, field: str) -> str:
    result = _safe_text(value, field)
    if len(result) > 512 or any(character.isspace() for character in result):
        raise _security_error("AUTHORITY_CONFIGURATION_INVALID", f"authority {field} is invalid")
    return result


def _load_canonical_json_file(path_value: object, *, maximum: int, field: str) -> tuple[dict[str, Any], str]:
    path = Path(_safe_text(path_value, field))
    try:
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise _security_error("AUTHORITY_CONFIGURATION_INVALID", f"authority {field} is invalid") from None
    if (
        not raw
        or len(raw) > maximum
        or not isinstance(document, dict)
        or _canonical_json(document) != raw
    ):
        raise _security_error("AUTHORITY_CONFIGURATION_INVALID", f"authority {field} is invalid")
    return document, raw.decode("utf-8")


def _sigstore_policy_from_document(
    document: Mapping[str, Any],
) -> _SigstoreVerificationPolicy:
    required_v1 = {
        "schema_version",
        "repository",
        "signer_workflow",
        "source_ref",
        "source_digest",
        "predicate_type",
        "environment",
        "oidc_issuer",
        "deny_self_hosted_runners",
        "verifier_manifest",
    }
    schema_version = document.get("schema_version")
    required = (
        required_v1 | {"repository_identity"}
        if schema_version == 2
        else required_v1
    )
    if (
        set(document) != required
        or schema_version not in {1, 2}
        or document.get("deny_self_hosted_runners") is not True
    ):
        raise _security_error("AUTHORITY_CONFIGURATION_INVALID", "authority Sigstore policy is invalid")
    verifier_manifest = str(document.get("verifier_manifest", "")).lower()
    if _DIGEST.fullmatch(verifier_manifest) is None:
        raise _security_error("AUTHORITY_CONFIGURATION_INVALID", "authority Sigstore verifier manifest is invalid")
    source_digest = str(document.get("source_digest", "")).lower()
    if _GIT_OBJECT_ID.fullmatch(source_digest) is None:
        raise _security_error("AUTHORITY_CONFIGURATION_INVALID", "authority Sigstore source digest is invalid")
    repository_identity = (
        _safe_sigstore_name(
            document.get("repository_identity"),
            "Sigstore repository identity",
        )
        if schema_version == 2
        else None
    )
    if (
        repository_identity is not None
        and _GITHUB_REPOSITORY_IDENTITY.fullmatch(repository_identity) is None
    ):
        raise _security_error(
            "AUTHORITY_CONFIGURATION_INVALID",
            "authority Sigstore repository identity is invalid",
        )
    return _SigstoreVerificationPolicy(
        repository=_safe_sigstore_name(document.get("repository"), "Sigstore repository"),
        repository_identity=repository_identity,
        signer_workflow=_safe_sigstore_name(document.get("signer_workflow"), "Sigstore signer workflow"),
        source_ref=_safe_sigstore_name(document.get("source_ref"), "Sigstore source ref"),
        source_digest=source_digest,
        predicate_type=_safe_sigstore_name(document.get("predicate_type"), "Sigstore predicate type"),
        environment=_safe_sigstore_name(document.get("environment"), "Sigstore environment"),
        oidc_issuer=_safe_sigstore_name(document.get("oidc_issuer"), "Sigstore OIDC issuer"),
        verifier_manifest=verifier_manifest,
    )


class SigstoreAuthorityAdapter:
    """Production Adapter for GitHub Artifact Attestation authority bundles."""

    __slots__ = (
        "_argv",
        "_verifier_manifest",
        "_expected_repository",
        "_expected_repository_identity",
        "_expected_signer_workflow",
        "_expected_predicate_type",
        "_expected_environment",
        "_expected_oidc_issuer",
        "_live_policy",
        "_live_bundle",
        "_live_predicate",
        "_adapter_marker",
    )

    def __init__(
        self,
        *,
        argv: tuple[str, ...],
        verifier_manifest: str,
        expected_repository: str,
        expected_repository_identity: str,
        expected_signer_workflow: str,
        expected_predicate_type: str,
        expected_environment: str,
        expected_oidc_issuer: str,
        live_policy: _SigstoreVerificationPolicy | None,
        live_bundle: Mapping[str, Any] | None,
        live_predicate: Mapping[str, Any] | None,
        _seal: object,
    ) -> None:
        if _seal is not _ADAPTER_SEAL:
            raise TypeError("SigstoreAuthorityAdapter must be loaded from the host environment")
        self._argv = argv
        self._verifier_manifest = verifier_manifest
        self._expected_repository = expected_repository
        self._expected_repository_identity = expected_repository_identity
        self._expected_signer_workflow = expected_signer_workflow
        self._expected_predicate_type = expected_predicate_type
        self._expected_environment = expected_environment
        self._expected_oidc_issuer = expected_oidc_issuer
        self._live_policy = live_policy
        self._live_bundle = dict(live_bundle) if live_bundle is not None else None
        self._live_predicate = dict(live_predicate) if live_predicate is not None else None
        self._adapter_marker = _ADAPTER_SEAL

    def __init_subclass__(cls, **_: Any) -> NoReturn:
        raise TypeError("SigstoreAuthorityAdapter is sealed")

    def __repr__(self) -> str:
        return "SigstoreAuthorityAdapter(configured=True)"

    @classmethod
    def _configuration(cls) -> tuple[tuple[str, ...], str, dict[str, str]]:
        raw_argv = os.environ.get(SIGSTORE_VERIFIER_ARGV_ENV)
        expected_manifest = os.environ.get(SIGSTORE_VERIFIER_MANIFEST_ENV)
        names = {
            "repository": SIGSTORE_REPOSITORY_ENV,
            "repository_identity": SIGSTORE_REPOSITORY_IDENTITY_ENV,
            "signer_workflow": SIGSTORE_SIGNER_WORKFLOW_ENV,
            "predicate_type": SIGSTORE_PREDICATE_TYPE_ENV,
            "environment": SIGSTORE_ENVIRONMENT_ENV,
            "oidc_issuer": SIGSTORE_OIDC_ISSUER_ENV,
        }
        values = {key: os.environ.get(name, "") for key, name in names.items()}
        if not raw_argv or not expected_manifest or not all(values.values()):
            raise _security_error(
                "AUTHORITY_CONFIGURATION_MISSING",
                "trusted Sigstore authority verification configuration is unavailable",
            )
        if (
            _GITHUB_REPOSITORY_IDENTITY.fullmatch(
                values["repository_identity"]
            )
            is None
        ):
            raise _security_error(
                "AUTHORITY_CONFIGURATION_INVALID",
                "authority Sigstore repository identity is invalid",
            )
        try:
            decoded_argv = json.loads(raw_argv)
        except (json.JSONDecodeError, TypeError, ValueError):
            raise _security_error("AUTHORITY_CONFIGURATION_INVALID", "authority Sigstore verifier is invalid") from None
        if not isinstance(decoded_argv, list) or not decoded_argv or any(not isinstance(value, str) for value in decoded_argv):
            raise _security_error("AUTHORITY_CONFIGURATION_INVALID", "authority Sigstore verifier is invalid")
        resolved, observed = _resolved_command_manifest(decoded_argv)
        if _DIGEST.fullmatch(expected_manifest) is None or not hmac.compare_digest(observed, expected_manifest):
            raise _security_error("AUTHORITY_BROKER_MANIFEST_MISMATCH", "authority Sigstore verifier is not host-pinned")
        return resolved, observed, {
            key: _safe_sigstore_name(value, f"Sigstore {key}") for key, value in values.items()
        }

    @classmethod
    def from_host_environment(cls) -> SigstoreAuthorityAdapter:
        argv, manifest, values = cls._configuration()
        bundle, _ = _load_canonical_json_file(
            os.environ.get(SIGSTORE_BUNDLE_ENV),
            maximum=_MAX_SIGSTORE_BUNDLE_BYTES,
            field="Sigstore bundle",
        )
        predicate, _ = _load_canonical_json_file(
            os.environ.get(SIGSTORE_PREDICATE_ENV),
            maximum=_MAX_BROKER_RESPONSE_BYTES,
            field="Sigstore predicate",
        )
        source_ref = _safe_sigstore_name(os.environ.get(SIGSTORE_SOURCE_REF_ENV), "Sigstore source ref")
        source_digest = str(os.environ.get(SIGSTORE_SOURCE_DIGEST_ENV, "")).lower()
        if _GIT_OBJECT_ID.fullmatch(source_digest) is None:
            raise _security_error("AUTHORITY_CONFIGURATION_INVALID", "authority Sigstore source digest is invalid")
        policy = _SigstoreVerificationPolicy(
            repository=values["repository"],
            repository_identity=values["repository_identity"],
            signer_workflow=values["signer_workflow"],
            source_ref=source_ref,
            source_digest=source_digest,
            predicate_type=values["predicate_type"],
            environment=values["environment"],
            oidc_issuer=values["oidc_issuer"],
            verifier_manifest=manifest,
        )
        return cls(
            argv=argv,
            verifier_manifest=manifest,
            expected_repository=values["repository"],
            expected_repository_identity=values["repository_identity"],
            expected_signer_workflow=values["signer_workflow"],
            expected_predicate_type=values["predicate_type"],
            expected_environment=values["environment"],
            expected_oidc_issuer=values["oidc_issuer"],
            live_policy=policy,
            live_bundle=bundle,
            live_predicate=predicate,
            _seal=_ADAPTER_SEAL,
        )

    @classmethod
    def from_trust_environment(cls) -> SigstoreAuthorityAdapter:
        argv, manifest, values = cls._configuration()
        return cls(
            argv=argv,
            verifier_manifest=manifest,
            expected_repository=values["repository"],
            expected_repository_identity=values["repository_identity"],
            expected_signer_workflow=values["signer_workflow"],
            expected_predicate_type=values["predicate_type"],
            expected_environment=values["environment"],
            expected_oidc_issuer=values["oidc_issuer"],
            live_policy=None,
            live_bundle=None,
            live_predicate=None,
            _seal=_ADAPTER_SEAL,
        )

    def _validate_policy(
        self, policy: _SigstoreVerificationPolicy, *, historical: bool,
    ) -> None:
        if (
            policy.repository != self._expected_repository
            or (
                not historical
                and policy.repository_identity
                != self._expected_repository_identity
            )
            or (
                historical
                and policy.repository_identity
                not in {None, self._expected_repository_identity}
            )
            or policy.signer_workflow != self._expected_signer_workflow
            or policy.predicate_type != self._expected_predicate_type
            or policy.environment != self._expected_environment
            or policy.oidc_issuer != self._expected_oidc_issuer
            or (not historical and policy.verifier_manifest != self._verifier_manifest)
        ):
            raise _security_error("AUTHORITY_ISSUER_MISMATCH", "Sigstore authority policy is not trusted")

    def _verify_bundle(
        self,
        *,
        request: AuthorityRequest,
        predicate: Mapping[str, Any],
        bundle: Mapping[str, Any],
        policy: _SigstoreVerificationPolicy,
        historical: bool,
    ) -> tuple[Mapping[str, Any], str, str]:
        self._validate_policy(policy, historical=historical)
        if (
            policy.repository_identity is not None
            and policy.repository_identity != request.repository_identity
        ):
            raise _security_error(
                "AUTHORITY_BINDING_MISMATCH",
                "Sigstore authority repository identity is not exactly bound",
                task_id=request.task_id,
            )
        expected_predicate_keys = {
            "schema_version", "allowed", "authenticated", "issuer", "actor_id",
            "actor_kind", "independence_level", "issued_at", "expires_at",
            "request_digest", "binding_digest", "environment",
        }
        if (
            set(predicate) != expected_predicate_keys
            or predicate.get("schema_version") != 1
            or predicate.get("allowed") is not True
            or predicate.get("authenticated") is not True
            or predicate.get("issuer") != policy.oidc_issuer
            or predicate.get("actor_id") != request.actor_claim["id"]
            or predicate.get("actor_kind") != request.actor_claim["kind"]
            or predicate.get("request_digest") != request.request_digest
            or predicate.get("binding_digest") != request.binding_digest
            or predicate.get("environment") != policy.environment
        ):
            raise _security_error("AUTHORITY_BINDING_MISMATCH", "Sigstore authority predicate is not exactly bound", task_id=request.task_id)
        independence = str(predicate.get("independence_level", ""))
        if independence not in _LEVEL:
            raise _security_error("AUTHORITY_RESPONSE_INVALID", "Sigstore authority independence is invalid", task_id=request.task_id)
        issued = _parse_time(predicate.get("issued_at"), "issued_at", task_id=request.task_id)
        expires = _parse_time(predicate.get("expires_at"), "expires_at", task_id=request.task_id)
        now = datetime.now(timezone.utc)
        if expires <= issued or (not historical and (issued > now + timedelta(seconds=30) or expires <= now)):
            raise _security_error("AUTHORITY_ATTESTATION_EXPIRED", "Sigstore authority fact is not currently valid", task_id=request.task_id)

        resolved, observed = _resolved_command_manifest(self._argv)
        if not hmac.compare_digest(observed, self._verifier_manifest):
            raise _security_error("AUTHORITY_BROKER_MANIFEST_MISMATCH", "authority Sigstore verifier changed", task_id=request.task_id)
        subject_bytes = _canonical_json(request.as_dict())
        bundle_bytes = _canonical_json(dict(bundle))
        with tempfile.TemporaryDirectory(prefix="mac-sigstore-") as directory:
            root = Path(directory)
            subject_path = root / "authority-request.json"
            bundle_path = root / "attestation.json"
            subject_path.write_bytes(subject_bytes)
            bundle_path.write_bytes(bundle_bytes)
            argv = [
                *resolved,
                str(subject_path),
                "--repo", policy.repository,
                "--bundle", str(bundle_path),
                "--predicate-type", policy.predicate_type,
                "--signer-workflow", policy.signer_workflow,
                "--source-ref", policy.source_ref,
                "--source-digest", policy.source_digest,
                "--cert-oidc-issuer", policy.oidc_issuer,
                "--deny-self-hosted-runners",
                "--format", "json",
            ]
            safe_names = {
                "COMSPEC", "HOME", "LANG", "LOCALAPPDATA", "PATH", "PATHEXT",
                "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE", "WINDIR",
            }
            safe_environment = {
                key: value for key, value in os.environ.items()
                if key.upper() in safe_names or key.upper().startswith("LC_")
            }
            try:
                completed = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    shell=False,
                    env=safe_environment,
                    timeout=30,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                raise _security_error("AUTHORITY_BROKER_UNAVAILABLE", "Sigstore verifier invocation failed", task_id=request.task_id) from None
        if completed.returncode != 0 or len(completed.stdout.encode("utf-8")) > _MAX_SIGSTORE_BUNDLE_BYTES:
            raise _security_error("AUTHORITY_SIGNATURE_INVALID", "Sigstore authority bundle is invalid", task_id=request.task_id)
        try:
            results = json.loads(completed.stdout)
        except (json.JSONDecodeError, TypeError, ValueError):
            raise _security_error("AUTHORITY_SIGNATURE_INVALID", "Sigstore verifier output is invalid", task_id=request.task_id) from None
        if not isinstance(results, list) or not results:
            raise _security_error("AUTHORITY_SIGNATURE_INVALID", "Sigstore verifier output is invalid", task_id=request.task_id)
        subject_digest = hashlib.sha256(subject_bytes).hexdigest()
        matches: list[Mapping[str, Any]] = []
        for item in results:
            if not isinstance(item, Mapping):
                continue
            result = item.get("verificationResult")
            if not isinstance(result, Mapping):
                continue
            statement = result.get("statement")
            timestamps = result.get("verifiedTimestamps")
            subjects = statement.get("subject") if isinstance(statement, Mapping) else None
            if (
                isinstance(statement, Mapping)
                and statement.get("predicateType") == policy.predicate_type
                and statement.get("predicate") == dict(predicate)
                and isinstance(timestamps, list)
                and timestamps
                and isinstance(subjects, list)
                and any(
                    isinstance(candidate, Mapping)
                    and isinstance(candidate.get("digest"), Mapping)
                    and candidate["digest"].get("sha256") == subject_digest
                    for candidate in subjects
                )
            ):
                matches.append(result)
        if len(matches) != 1:
            raise _security_error("AUTHORITY_BINDING_MISMATCH", "Sigstore authority bundle does not bind one exact decision", task_id=request.task_id)
        signature = matches[0].get("signature")
        certificate = signature.get("certificate") if isinstance(signature, Mapping) else None
        if not isinstance(certificate, Mapping) or not certificate:
            raise _security_error("AUTHORITY_SIGNATURE_INVALID", "Sigstore authority certificate is missing", task_id=request.task_id)
        return matches[0], canonical_digest(dict(certificate)), canonical_digest(dict(bundle))

    def authorize(
        self,
        *,
        request: AuthorityRequest,
        minimum_independence: str | None = None,
    ) -> VerifiedAuthority:
        if (
            type(self) is not SigstoreAuthorityAdapter
            or self._adapter_marker is not _ADAPTER_SEAL
            or self._live_policy is None
            or self._live_bundle is None
            or self._live_predicate is None
        ):
            raise _security_error("AUTHORITY_VERIFIER_REQUIRED", "a live Sigstore authority bundle is required", task_id=request.task_id)
        _, trust_digest, bundle_digest = self._verify_bundle(
            request=request,
            predicate=self._live_predicate,
            bundle=self._live_bundle,
            policy=self._live_policy,
            historical=False,
        )
        independence = str(self._live_predicate["independence_level"])
        if minimum_independence is not None and not level_at_least(independence, minimum_independence):
            raise _security_error("ACTOR_AUTHORITY_DENIED", "Sigstore authority does not satisfy required independence", task_id=request.task_id)
        return VerifiedAuthority(
            actor_id=str(self._live_predicate["actor_id"]),
            actor_kind=str(self._live_predicate["actor_kind"]),
            issuer=str(self._live_predicate["issuer"]),
            attestation_id=f"sigstore:{bundle_digest}",
            independence_level=independence,
            issued_at=str(self._live_predicate["issued_at"]),
            expires_at=str(self._live_predicate["expires_at"]),
            request=request,
            broker_digest=canonical_digest(self._live_policy.as_dict()),
            trust_digest=trust_digest,
            signature_algorithm="sigstore-keyless",
            key_id=bundle_digest,
            signed_payload_json=_canonical_json(self._live_predicate).decode("utf-8"),
            signed_signature="",
            store_contract_version=3,
            signed_bundle_json=_canonical_json(self._live_bundle).decode("utf-8"),
            sigstore_policy_json=_canonical_json(self._live_policy.as_dict()).decode("utf-8"),
            _seal=_VERIFIED_SEAL,
        )

    def verify_persisted_envelope(
        self,
        envelope: Mapping[str, Any],
        *,
        request: AuthorityRequest,
        audit: Mapping[str, Any],
    ) -> None:
        if set(envelope) != {"subject", "predicate", "bundle", "verification_policy"}:
            raise _security_error("AUTHORITY_SIGNATURE_INVALID", "persisted Sigstore envelope is invalid", task_id=request.task_id)
        subject = envelope.get("subject")
        predicate = envelope.get("predicate")
        bundle = envelope.get("bundle")
        policy_document = envelope.get("verification_policy")
        if (
            subject != request.as_dict()
            or not isinstance(predicate, Mapping)
            or not isinstance(bundle, Mapping)
            or not isinstance(policy_document, Mapping)
        ):
            raise _security_error("AUTHORITY_BINDING_MISMATCH", "persisted Sigstore envelope is not bound", task_id=request.task_id)
        policy = _sigstore_policy_from_document(policy_document)
        _, trust_digest, bundle_digest = self._verify_bundle(
            request=request,
            predicate=predicate,
            bundle=bundle,
            policy=policy,
            historical=True,
        )
        expected = {
            "store_contract_version": 3,
            "issuer": predicate.get("issuer"),
            "actor_id": predicate.get("actor_id"),
            "actor_kind": predicate.get("actor_kind"),
            "independence_level": predicate.get("independence_level"),
            "issued_at": predicate.get("issued_at"),
            "expires_at": predicate.get("expires_at"),
            "attestation_id": f"sigstore:{bundle_digest}",
            "broker_digest": canonical_digest(policy.as_dict()),
            "trust_digest": trust_digest,
            "signature_algorithm": "sigstore-keyless",
            "key_id": bundle_digest,
        }
        if any(audit.get(key) != value for key, value in expected.items()):
            raise _security_error("AUTHORITY_BINDING_MISMATCH", "persisted Sigstore audit fact is inconsistent", task_id=request.task_id)


ProductionAuthorityAdapter = SubprocessAuthorityAdapter | SigstoreAuthorityAdapter


def current_authority_verifier() -> ProductionAuthorityAdapter:
    """Load the production Adapter exclusively from the host environment."""

    if os.environ.get(SIGSTORE_BUNDLE_ENV) or os.environ.get(SIGSTORE_PREDICATE_ENV):
        return SigstoreAuthorityAdapter.from_host_environment()
    return SubprocessAuthorityAdapter.from_host_environment()


def trusted_authority_verifier(_: object) -> NoReturn:
    """Removed compatibility stub; arbitrary in-process verifier installation is forbidden."""

    raise _security_error(
        "AUTHORITY_VERIFIER_INSTALLATION_DISABLED",
        "arbitrary in-process authority verifier installation is disabled",
    )


def require_authority(
    verifier: ProductionAuthorityAdapter | None,
    *,
    request: AuthorityRequest | None = None,
    actor_claim: Mapping[str, Any] | None = None,
    operation: str | None = None,
    task_id: str | None = None,
    repository_identity: str | None = None,
    expected_revision: int | None = None,
    idempotency_key: str | None = None,
    intent_digest: str | None = None,
    policy_digest: str | None = None,
    ownership_digest: str | None = None,
    audience: str | None = None,
    minimum_independence: str | None = None,
) -> VerifiedAuthority:
    if type(verifier) not in {SubprocessAuthorityAdapter, SigstoreAuthorityAdapter}:
        raise _security_error(
            "AUTHORITY_VERIFIER_REQUIRED",
            "a host-configured production authority Adapter is required for this mutation",
            task_id=task_id or (request.task_id if request is not None else None),
        )
    if request is None:
        values = (
            actor_claim,
            operation,
            task_id,
            repository_identity,
            expected_revision,
            idempotency_key,
            intent_digest,
            policy_digest,
            ownership_digest,
            audience,
        )
        if any(value is None for value in values):
            raise _security_error(
                "AUTHORITY_REQUEST_INCOMPLETE",
                "the mutation authority request is missing an exact binding",
                task_id=task_id,
            )
        request = AuthorityRequest(
            repository_identity=str(repository_identity),
            operation=str(operation),
            task_id=str(task_id),
            actor_claim={str(key): str(value) for key, value in dict(actor_claim or {}).items()},
            expected_revision=int(expected_revision),
            idempotency_key=str(idempotency_key),
            intent_digest=str(intent_digest),
            policy_digest=str(policy_digest),
            ownership_digest=str(ownership_digest),
            audience=str(audience),
        )
    return verifier.authorize(request=request, minimum_independence=minimum_independence)


def authority_audit_record(decision: VerifiedAuthority) -> dict[str, Any]:
    """Return only the verified, non-secret authority fact safe to persist."""

    if type(decision) is not VerifiedAuthority or decision._verification_marker is not _VERIFIED_SEAL:
        raise _security_error("AUTHORITY_FACT_UNVERIFIED", "an unverified authority fact cannot be persisted")
    record = {
        "store_contract_version": decision.store_contract_version,
        "allowed": True,
        "authenticated": True,
        "issuer": decision.issuer,
        "attestation_id": decision.attestation_id,
        "actor_id": decision.actor_id,
        "actor_kind": decision.actor_kind,
        "operation": decision.operation,
        "task_id": decision.task_id,
        "independence_level": decision.independence_level,
        "issued_at": decision.issued_at,
        "expires_at": decision.expires_at,
        "repository_identity": decision.repository_identity,
        "expected_revision": decision.expected_revision,
        "idempotency_key": decision.idempotency_key,
        "intent_digest": decision.intent_digest,
        "policy_digest": decision.policy_digest,
        "ownership_digest": decision.ownership_digest,
        "audience": decision.audience,
        "request_digest": decision.request_digest,
        "binding_digest": decision.binding_digest,
        "broker_digest": decision.broker_digest,
        "trust_digest": decision.trust_digest,
        "signature_algorithm": decision.signature_algorithm,
        "key_id": decision.key_id,
    }
    if decision.store_contract_version == 2:
        record["signed_envelope"] = {
            "payload": json.loads(decision.signed_payload_json),
            "signature": decision.signed_signature,
        }
        return record
    if (
        decision.store_contract_version == 3
        and decision.signed_bundle_json is not None
        and decision.sigstore_policy_json is not None
    ):
        record["signed_envelope"] = {
            "subject": {
                "schema_version": 1,
                "repository_identity": decision.repository_identity,
                "operation": decision.operation,
                "task_id": decision.task_id,
                "actor_claim": {"id": decision.actor_id, "kind": decision.actor_kind},
                "expected_revision": decision.expected_revision,
                "idempotency_key": decision.idempotency_key,
                "intent_digest": decision.intent_digest,
                "policy_digest": decision.policy_digest,
                "ownership_digest": decision.ownership_digest,
                "audience": decision.audience,
            },
            "predicate": json.loads(decision.signed_payload_json),
            "bundle": json.loads(decision.signed_bundle_json),
            "verification_policy": json.loads(decision.sigstore_policy_json),
        }
        return record
    raise _security_error("AUTHORITY_FACT_UNVERIFIED", "authority fact uses an unsupported Store contract")


def verify_authority_audit_record(
    audit: Mapping[str, Any],
    request: AuthorityRequest,
) -> None:
    """Verify a persisted historical authority fact using the host-pinned broker trust root."""

    envelope = audit.get("signed_envelope")
    if not isinstance(envelope, Mapping):
        raise _security_error(
            "AUTHORITY_SIGNATURE_MISSING",
            "persisted authority fact has no signed broker envelope",
            task_id=request.task_id,
        )
    version = audit.get("store_contract_version")
    if version == 2:
        verifier: ProductionAuthorityAdapter = SubprocessAuthorityAdapter.from_trust_environment()
    elif version == 3:
        verifier = SigstoreAuthorityAdapter.from_trust_environment()
    else:
        raise _security_error(
            "AUTHORITY_VERSION_UNSUPPORTED",
            "persisted authority fact uses an unsupported Store contract",
            task_id=request.task_id,
        )
    verifier.verify_persisted_envelope(envelope, request=request, audit=audit)


def level_at_least(actual: str | None, required: str) -> bool:
    return _LEVEL.get(str(actual), -1) >= _LEVEL.get(required, len(_LEVEL))


def owner_approvers(scope: Mapping[str, Any], ownership: Mapping[str, Any]) -> set[str]:
    result: set[str] = set()
    definitions = ownership.get("owners") or {}
    for owner in scope.get("owners", []):
        definition = definitions.get(str(owner)) or {}
        result.update(str(actor) for actor in definition.get("approvers", []))
    return result


def governance_sensitive(scope: Mapping[str, Any], config: Mapping[str, Any]) -> bool:
    patterns = ((config.get("security") or {}).get("governance_sensitive_paths") or [])
    if not patterns:
        return False
    matcher = GitIgnoreSpec.from_lines(patterns)
    return any(matcher.match_file(str(path)) for path in scope.get("allowed_paths", []))


def scope_approval_subject(task: Mapping[str, Any], scope: Mapping[str, Any]) -> str:
    """Return the immutable subject an Approval must bind for this Scope version."""

    proposal = dict(scope)
    proposal["status"] = "proposed"
    proposal.pop("approved_by", None)
    return (
        f"{task.get('scope_contract_ref', 'scope-contract.yaml')}"
        f"#scope={scope.get('id')};version={scope.get('version')};digest={canonical_digest(proposal)}"
    )


def scope_binding(scope: Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical immutable binding used by Evidence and Risk Acceptance."""

    return {
        "paths": [str(value) for value in scope.get("allowed_paths", [])],
        "versions": [
            f"{scope.get('id', '')}:v{int(scope.get('version', 0))}:{canonical_digest(dict(scope))}"
        ],
    }


def scope_binding_matches(candidate: Mapping[str, Any] | None, scope: Mapping[str, Any]) -> bool:
    expected = scope_binding(scope)
    if dict(candidate or {}) == expected:
        return True
    return int(scope.get("version", 0)) == 1 and dict(candidate or {}) == {"paths": expected["paths"]}


def valid_scope_approvals(
    task: Mapping[str, Any], scope: Mapping[str, Any], approvals: Iterable[Mapping[str, Any]],
    ownership: Mapping[str, Any], config: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    authorized = owner_approvers(scope, ownership)
    required = "L2" if governance_sensitive(scope, config) or task.get("mode") == "high_risk" else "L1"
    proposer = str(scope.get("proposed_by", ""))
    expected_subject = scope_approval_subject(task, scope)
    legacy_subjects = (
        {"scope-contract.yaml", str(task.get("scope_contract_ref", ""))}
        if scope.get("version") == 1
        else set()
    )
    result: list[Mapping[str, Any]] = []
    for approval in approvals:
        actor = str((approval.get("actor") or {}).get("id", ""))
        if (
            approval.get("kind") == "scope"
            and approval.get("decision") == "approved"
            and actor in authorized
            and actor != proposer
            and level_at_least(approval.get("independence_level"), required)
            and str(approval.get("subject_ref")) in {expected_subject, *legacy_subjects}
        ):
            result.append(approval)
    return result


def actor_authorized_for_scope(actor: str, scope: Mapping[str, Any], ownership: Mapping[str, Any]) -> bool:
    return actor in owner_approvers(scope, ownership)


def load_runtime_profiles(repo: Path, config: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    root = repo / str((config.get("paths") or {}).get("runtime_profiles", ".agents/runtime-profiles"))
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(root.glob("*.yaml")):
        profile = load_data(path)
        result[str(profile.get("id"))] = profile
    return result
