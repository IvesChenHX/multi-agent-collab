from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .io import load_data, normalize_data
from .application.governance import evaluate_evidence
from .application.close import evaluate_repository_close
from .git import GitRepository
from .security import parse_yaml_safely, redact_sensitive
from .errors import ExitCode, MacError


@dataclass(frozen=True, slots=True)
class AuditBundleLimits:
    """Resource limits enforced while producing and before reading an archive."""

    max_entries: int = 512
    max_entry_bytes: int = 1_048_576
    max_total_uncompressed_bytes: int = 32 * 1_048_576
    max_archive_bytes: int = 16 * 1_048_576
    max_compression_ratio: float = 1_000.0
    max_name_bytes: int = 512


DEFAULT_AUDIT_BUNDLE_LIMITS = AuditBundleLimits()
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class _AuditSource:
    path: Path
    relative: str
    identity: tuple[int, int, int, int, int, int]


def _load_many(directory: Path, pattern: str) -> list[dict[str, Any]]:
    return [load_data(path) for path in sorted(directory.glob(pattern)) if path.is_file()]


def render_task_report(task_dir: Path) -> str:
    task = load_data(task_dir / "task.yaml")
    scope = load_data(task_dir / "scope-contract.yaml") if (task_dir / "scope-contract.yaml").is_file() else {}
    evidence = _load_many(task_dir, "evidence/*.json")
    findings = _load_many(task_dir, "findings/*.json")
    repo = task_dir.resolve().parents[1]
    runs = {str(item["id"]): item for item in _load_many(task_dir, "runs/*.json")}
    git = GitRepository(repo)
    changes = git.workspace_changes(task_id=str(task["id"]))
    subject = git.current_code_subject(str(task["id"])) if not changes else git.workspace_subject(task_id=str(task["id"]))
    valid_items = [item for item in evidence if evaluate_evidence(item, current_subject=subject, policy_digest=str((task.get("policy_ref") or {}).get("combined_digest", "")), runs=runs).ok]
    valid_claims = sorted({str(value) for item in valid_items for claim in item.get("claims", []) for value in claim.values()})
    lines = [f"# {task['id']}: {task['title']}", "", f"- Mode: `{task['mode']}`", f"- State: `{task['state']}`", f"- Revision: `{task['revision']}`", f"- Scope: `{scope.get('status', 'missing')}` v{scope.get('version', '?')}", "", "## Objective", "", str(task["objective"]), "", "## Evidence coverage", ""]
    lines.extend(f"- `{claim}`" for claim in valid_claims or ["none"])
    lines.extend(["", "## Open findings", ""])
    open_findings = [item for item in findings if item.get("status") in {"open", "fixing"}]
    lines.extend(f"- **{item['severity']}** `{item['id']}` {item['title']}" for item in open_findings)
    if not open_findings:
        lines.append("- none")
    if task.get("state") in {"completed", "completed_with_risk"} and task.get("legacy_integrity") == "full":
        close = evaluate_repository_close(repo, str(task["id"]), str((task.get("terminal") or {}).get("closed_by", "")))
        lines.extend(["", "## Close recomputation", "", f"- Machine decision: `{'pass' if close.ok else 'fail'}`"])
        lines.extend(f"- `{issue.code}` {issue.message}" for issue in close.issues)
    return "\n".join(lines) + "\n"


def build_index(repo: Path) -> list[dict[str, Any]]:
    rows = []
    for task_path in sorted((repo / "tasks").glob("TASK-*/task.yaml")):
        task = load_data(task_path)
        rows.append({key: task.get(key) for key in ("id", "title", "mode", "state", "revision", "updated_at", "legacy_id") if task.get(key) is not None})
    return sorted(rows, key=lambda row: str(row["id"]))


def _parse_structured_bytes(content: bytes, path: Path) -> dict[str, Any]:
    if path.suffix.lower() == ".json":
        value = json.loads(content.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"{path} must contain an object")
    else:
        value = parse_yaml_safely(content)
    return normalize_data(value)


def _redact_file(
    path: Path,
    source_name: str,
    *,
    content: bytes | None = None,
) -> tuple[bytes, list[dict[str, str]]]:
    raw_bytes = path.read_bytes() if content is None else content
    if len(raw_bytes) > 1_048_576:
        raise MacError(
            "AUDIT_BUNDLE_ENTRY_TOO_LARGE",
            f"audit source exceeds the 1 MiB structured-input limit: {source_name}",
            exit_code=ExitCode.SECURITY,
            path=source_name,
        )
    try:
        value = _parse_structured_bytes(raw_bytes, path)
    except Exception:
        raw = raw_bytes.decode("utf-8")
        result = redact_sensitive(raw)
        return str(result.value).encode("utf-8"), [{"source_path": source_name, "field": field} for field in result.redacted_paths]
    result = redact_sensitive(value)
    if path.suffix == ".json":
        content = json.dumps(result.value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    else:
        from .io import dump_yaml

        content = dump_yaml(result.value)
    return content.encode("utf-8"), [{"source_path": source_name, "field": field} for field in result.redacted_paths]


def _bundle_digest_payload(manifest: Mapping[str, Any], entries: Mapping[str, str]) -> dict[str, Any]:
    return {
        "schema_version": manifest.get("schema_version"),
        "digest_algorithm": manifest.get("digest_algorithm"),
        "task_id": manifest.get("task_id"),
        "entries": dict(entries),
        "contains_confidential": manifest.get("contains_confidential"),
        "redact_manifest": manifest.get("redact_manifest"),
        "signature": manifest.get("signature"),
    }


def _aggregate_digest(manifest: Mapping[str, Any], entries: Mapping[str, str]) -> str:
    algorithm = manifest.get("digest_algorithm")
    if algorithm in {None, "sha256-entry-map-v1"}:
        canonical_entries = json.dumps(dict(entries), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical_entries).hexdigest()
    if algorithm != "sha256-manifest-v2":
        raise MacError("AUDIT_BUNDLE_DIGEST_ALGORITHM_UNSUPPORTED", f"unsupported audit digest algorithm: {algorithm!r}", exit_code=ExitCode.CORRUPTION)
    payload = _bundle_digest_payload(manifest, entries)
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _check_bundle_limits(entries: Mapping[str, bytes], limits: AuditBundleLimits, *, include_manifest: bool) -> None:
    count = len(entries) + (1 if include_manifest else 0)
    if count > limits.max_entries:
        raise MacError("AUDIT_BUNDLE_TOO_MANY_ENTRIES", f"audit bundle contains {count} entries; limit is {limits.max_entries}", exit_code=ExitCode.SECURITY)
    total = 0
    for name, content in entries.items():
        if len(name.encode("utf-8")) > limits.max_name_bytes:
            raise MacError("AUDIT_BUNDLE_ENTRY_NAME_TOO_LONG", f"audit entry name exceeds limit: {name}", exit_code=ExitCode.SECURITY)
        if len(content) > limits.max_entry_bytes:
            raise MacError("AUDIT_BUNDLE_ENTRY_TOO_LARGE", f"audit entry exceeds {limits.max_entry_bytes} bytes: {name}", exit_code=ExitCode.SECURITY)
        total += len(content)
    if total > limits.max_total_uncompressed_bytes:
        raise MacError("AUDIT_BUNDLE_TOTAL_TOO_LARGE", f"audit bundle expands to {total} bytes; limit is {limits.max_total_uncompressed_bytes}", exit_code=ExitCode.SECURITY)


def _source_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _is_link_or_reparse(value: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(value.st_mode) or bool(getattr(value, "st_file_attributes", 0) & reparse_flag)


def _checked_source_stat(task_dir: Path, path: Path) -> os.stat_result:
    try:
        relative = path.relative_to(task_dir)
    except ValueError as exc:
        raise MacError(
            "AUDIT_BUNDLE_SOURCE_ESCAPE",
            f"audit source escapes task directory: {path}",
            exit_code=ExitCode.SECURITY,
        ) from exc
    current = task_dir
    try:
        for part in relative.parts:
            current /= part
            current_stat = current.lstat()
            if _is_link_or_reparse(current_stat):
                raise MacError(
                    "AUDIT_BUNDLE_SOURCE_SYMLINK",
                    f"audit source must not traverse a symlink or reparse point: {current}",
                    exit_code=ExitCode.SECURITY,
                )
        path.resolve(strict=True).relative_to(task_dir)
    except MacError:
        raise
    except (OSError, ValueError) as exc:
        raise MacError(
            "AUDIT_BUNDLE_SOURCE_ESCAPE",
            f"audit source escapes task directory: {path}",
            exit_code=ExitCode.SECURITY,
        ) from exc
    if not stat.S_ISREG(current_stat.st_mode):
        raise MacError(
            "AUDIT_BUNDLE_SOURCE_NOT_REGULAR",
            f"audit source must be a regular file: {path}",
            exit_code=ExitCode.SECURITY,
        )
    return current_stat


def _preflight_audit_sources(
    task_dir: Path,
    patterns: list[str],
    limits: AuditBundleLimits,
) -> list[_AuditSource]:
    generated_entries = 2  # redact-manifest.json and manifest.json
    if generated_entries > limits.max_entries:
        raise MacError(
            "AUDIT_BUNDLE_TOO_MANY_ENTRIES",
            f"audit bundle contains at least {generated_entries} entries; limit is {limits.max_entries}",
            exit_code=ExitCode.SECURITY,
        )
    sources: list[_AuditSource] = []
    names: set[str] = set()
    source_total = 0
    for pattern in patterns:
        for path in task_dir.glob(pattern):
            source_stat = _checked_source_stat(task_dir, path)
            relative = path.relative_to(task_dir).as_posix()
            if "private" in PurePosixPath(relative).parts or relative in names:
                continue
            names.add(relative)
            if len(relative.encode("utf-8")) > limits.max_name_bytes:
                raise MacError(
                    "AUDIT_BUNDLE_ENTRY_NAME_TOO_LONG",
                    f"audit entry name exceeds limit: {relative}",
                    exit_code=ExitCode.SECURITY,
                )
            planned_count = len(sources) + generated_entries + 1
            if planned_count > limits.max_entries:
                raise MacError(
                    "AUDIT_BUNDLE_TOO_MANY_ENTRIES",
                    f"audit bundle contains at least {planned_count} entries; limit is {limits.max_entries}",
                    exit_code=ExitCode.SECURITY,
                )
            if source_stat.st_size > limits.max_entry_bytes:
                raise MacError(
                    "AUDIT_BUNDLE_ENTRY_TOO_LARGE",
                    f"audit source exceeds {limits.max_entry_bytes} bytes: {relative}",
                    exit_code=ExitCode.SECURITY,
                    path=relative,
                )
            source_total += source_stat.st_size
            if source_total > limits.max_total_uncompressed_bytes:
                raise MacError(
                    "AUDIT_BUNDLE_TOTAL_TOO_LARGE",
                    f"audit sources total {source_total} bytes; limit is {limits.max_total_uncompressed_bytes}",
                    exit_code=ExitCode.SECURITY,
                )
            sources.append(_AuditSource(path, relative, _source_identity(source_stat)))
    return sorted(sources, key=lambda item: item.relative)


def _read_open_audit_source(handle: Any, source: _AuditSource, max_bytes: int) -> bytes:
    """Read through a bounded seam; identity checks remain with the caller."""
    return handle.read(max(max_bytes, 0) + 1)


def _read_audit_source(source: _AuditSource, task_dir: Path, limits: AuditBundleLimits) -> bytes:
    before = _checked_source_stat(task_dir, source.path)
    if _source_identity(before) != source.identity:
        raise MacError(
            "AUDIT_BUNDLE_SOURCE_CHANGED",
            f"audit source changed after preflight: {source.relative}",
            exit_code=ExitCode.SECURITY,
            path=source.relative,
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(source.path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            opened = os.fstat(handle.fileno())
            content = _read_open_audit_source(handle, source, limits.max_entry_bytes)
            after_read = os.fstat(handle.fileno())
    except OSError as exc:
        raise MacError(
            "AUDIT_BUNDLE_SOURCE_CHANGED",
            f"audit source could not be read from its frozen identity: {source.relative}",
            exit_code=ExitCode.SECURITY,
            path=source.relative,
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(content) > limits.max_entry_bytes:
        raise MacError(
            "AUDIT_BUNDLE_ENTRY_TOO_LARGE",
            f"audit source exceeds {limits.max_entry_bytes} bytes: {source.relative}",
            exit_code=ExitCode.SECURITY,
            path=source.relative,
        )
    try:
        current = _checked_source_stat(task_dir, source.path)
    except MacError as exc:
        raise MacError(
            "AUDIT_BUNDLE_SOURCE_CHANGED",
            f"audit source changed while it was read: {source.relative}",
            exit_code=ExitCode.SECURITY,
            path=source.relative,
        ) from exc
    identities = (source.identity, _source_identity(opened), _source_identity(after_read), _source_identity(current))
    if len(set(identities)) != 1:
        raise MacError(
            "AUDIT_BUNDLE_SOURCE_CHANGED",
            f"audit source changed while it was read: {source.relative}",
            exit_code=ExitCode.SECURITY,
            path=source.relative,
        )
    return content


def _append_bounded_entry(
    entries: dict[str, bytes],
    name: str,
    content: bytes,
    running_total: int,
    limits: AuditBundleLimits,
) -> int:
    if len(name.encode("utf-8")) > limits.max_name_bytes:
        raise MacError("AUDIT_BUNDLE_ENTRY_NAME_TOO_LONG", f"audit entry name exceeds limit: {name}", exit_code=ExitCode.SECURITY)
    if len(content) > limits.max_entry_bytes:
        raise MacError("AUDIT_BUNDLE_ENTRY_TOO_LARGE", f"audit entry exceeds {limits.max_entry_bytes} bytes: {name}", exit_code=ExitCode.SECURITY)
    running_total += len(content)
    if running_total > limits.max_total_uncompressed_bytes:
        raise MacError("AUDIT_BUNDLE_TOTAL_TOO_LARGE", f"audit bundle expands to {running_total} bytes; limit is {limits.max_total_uncompressed_bytes}", exit_code=ExitCode.SECURITY)
    entries[name] = content
    return running_total


def build_audit_bundle(
    task_dir: Path,
    out_path: Path,
    *,
    redact: bool = True,
    limits: AuditBundleLimits = DEFAULT_AUDIT_BUNDLE_LIMITS,
) -> dict[str, Any]:
    task_dir = task_dir.resolve()
    allowed = ["task.yaml", "scope-contract.yaml", "events/*.json", "work-units/*.yaml", "runs/*.json", "results/*.json", "findings/*.json", "evidence/*.json", "approvals/*.json", "risk-acceptances/*.json"]
    sources = _preflight_audit_sources(task_dir, allowed, limits)
    entries: dict[str, bytes] = {}
    redactions: list[dict[str, str]] = []
    running_total = 0
    for source in sources:
        raw_content = _read_audit_source(source, task_dir, limits)
        if redact:
            content, found = _redact_file(source.path, source.relative, content=raw_content)
            redactions.extend(found)
        else:
            content = raw_content
        running_total = _append_bounded_entry(entries, source.relative, content, running_total, limits)
    redact_manifest = (json.dumps(redactions, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    running_total = _append_bounded_entry(entries, "redact-manifest.json", redact_manifest, running_total, limits)
    entry_digests = {name: "sha256:" + hashlib.sha256(content).hexdigest() for name, content in entries.items()}
    task_data = _parse_structured_bytes(entries["task.yaml"], Path("task.yaml"))
    manifest: dict[str, Any] = {
        "schema_version": 1, "digest_algorithm": "sha256-manifest-v2", "task_id": task_data.get("id"),
        "entries": entry_digests, "contains_confidential": not redact,
        "redact_manifest": redactions, "signature": {"status": "unsigned", "scheme": "none"},
    }
    manifest["bundle_digest"] = _aggregate_digest(manifest, entry_digests)
    manifest_content = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    _append_bounded_entry(entries, "manifest.json", manifest_content, running_total, limits)
    _check_bundle_limits(entries, limits, include_manifest=False)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, content in sorted(entries.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)); info.compress_type = zipfile.ZIP_DEFLATED; info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    if out_path.stat().st_size > limits.max_archive_bytes:
        raise MacError("AUDIT_BUNDLE_ARCHIVE_TOO_LARGE", f"audit archive exceeds {limits.max_archive_bytes} bytes", exit_code=ExitCode.SECURITY)
    return manifest


def _load_trust_anchor(anchor: Path | Mapping[str, Any]) -> tuple[str, str | None, str]:
    if isinstance(anchor, Mapping):
        value = anchor
        source = "trust_anchor"
    else:
        try:
            raw = anchor.read_bytes()
        except OSError as exc:
            raise MacError("AUDIT_BUNDLE_TRUST_ANCHOR_INVALID", str(exc), exit_code=ExitCode.SECURITY) from exc
        if len(raw) > 65_536:
            raise MacError("AUDIT_BUNDLE_TRUST_ANCHOR_INVALID", "trust anchor exceeds 64 KiB", exit_code=ExitCode.SECURITY)
        try:
            decoded = raw.decode("utf-8").strip()
            parsed = json.loads(decoded)
        except json.JSONDecodeError:
            parsed = {"bundle_digest": decoded}
        except UnicodeError as exc:
            raise MacError("AUDIT_BUNDLE_TRUST_ANCHOR_INVALID", str(exc), exit_code=ExitCode.SECURITY) from exc
        if not isinstance(parsed, Mapping):
            raise MacError("AUDIT_BUNDLE_TRUST_ANCHOR_INVALID", "trust anchor must be an object or digest", exit_code=ExitCode.SECURITY)
        value = parsed
        source = str(anchor)
    digest = value.get("bundle_digest")
    task_id = value.get("task_id")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise MacError("AUDIT_BUNDLE_TRUST_ANCHOR_INVALID", "trust anchor requires a sha256 bundle_digest", exit_code=ExitCode.SECURITY)
    if task_id is not None and not isinstance(task_id, str):
        raise MacError("AUDIT_BUNDLE_TRUST_ANCHOR_INVALID", "trust anchor task_id must be a string", exit_code=ExitCode.SECURITY)
    return digest, task_id, source


def _resolve_trust_anchor(
    expected_digest: str | None,
    trust_anchor: Path | Mapping[str, Any] | None,
) -> tuple[str, str | None, str]:
    direct = expected_digest or os.environ.get("MAC_AUDIT_BUNDLE_EXPECTED_DIGEST")
    external = trust_anchor
    if external is None and (configured := os.environ.get("MAC_AUDIT_BUNDLE_TRUST_ANCHOR")):
        external = Path(configured)
    anchored: tuple[str, str | None, str] | None = _load_trust_anchor(external) if external is not None else None
    if direct is not None:
        direct = direct.strip()
        if not _SHA256.fullmatch(direct):
            raise MacError("AUDIT_BUNDLE_TRUST_ANCHOR_INVALID", "expected digest must be sha256:<64 lowercase hex>", exit_code=ExitCode.SECURITY)
        if anchored is not None and not hmac.compare_digest(direct, anchored[0]):
            raise MacError("AUDIT_BUNDLE_TRUST_ANCHOR_CONFLICT", "expected digest and trust anchor disagree", exit_code=ExitCode.SECURITY)
        return direct, anchored[1] if anchored else None, anchored[2] if anchored else "expected_digest"
    if anchored is not None:
        return anchored
    raise MacError(
        "AUDIT_BUNDLE_TRUST_ANCHOR_REQUIRED",
        "independent verification requires an external expected digest or trust anchor",
        exit_code=ExitCode.SECURITY,
    )


def verify_audit_bundle(
    bundle_path: Path,
    *,
    expected_digest: str | None = None,
    trust_anchor: Path | Mapping[str, Any] | None = None,
    limits: AuditBundleLimits = DEFAULT_AUDIT_BUNDLE_LIMITS,
) -> dict[str, Any]:
    """Verify a bounded archive against an independently supplied trust anchor."""
    trusted_digest, trusted_task_id, anchor_source = _resolve_trust_anchor(expected_digest, trust_anchor)
    try:
        archive_size = bundle_path.stat().st_size
    except OSError as exc:
        raise MacError("AUDIT_BUNDLE_UNREADABLE", str(exc), exit_code=ExitCode.CORRUPTION) from exc
    if archive_size > limits.max_archive_bytes:
        raise MacError("AUDIT_BUNDLE_ARCHIVE_TOO_LARGE", f"audit archive exceeds {limits.max_archive_bytes} bytes", exit_code=ExitCode.SECURITY)
    try:
        with zipfile.ZipFile(bundle_path) as archive:
            infos = archive.infolist()
            if len(infos) > limits.max_entries:
                raise MacError("AUDIT_BUNDLE_TOO_MANY_ENTRIES", f"audit bundle contains {len(infos)} entries; limit is {limits.max_entries}", exit_code=ExitCode.SECURITY)
            names = [item.filename for item in infos]
            if len(names) != len(set(names)):
                raise MacError("AUDIT_BUNDLE_DUPLICATE_ENTRY", "audit bundle contains duplicate entry names", exit_code=ExitCode.CORRUPTION)
            total_size = 0
            for info in infos:
                path = PurePosixPath(info.filename)
                if path.is_absolute() or ".." in path.parts or "." in path.parts or "\\" in info.filename or info.is_dir():
                    raise MacError("AUDIT_BUNDLE_UNSAFE_PATH", f"unsafe archive entry: {info.filename}", exit_code=ExitCode.SECURITY)
                if len(info.filename.encode("utf-8")) > limits.max_name_bytes:
                    raise MacError("AUDIT_BUNDLE_ENTRY_NAME_TOO_LONG", f"archive entry name exceeds limit: {info.filename}", exit_code=ExitCode.SECURITY)
                if info.flag_bits & 0x1:
                    raise MacError("AUDIT_BUNDLE_ENCRYPTED_ENTRY", f"encrypted archive entry is forbidden: {info.filename}", exit_code=ExitCode.SECURITY)
                if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise MacError("AUDIT_BUNDLE_COMPRESSION_UNSUPPORTED", f"unsupported compression for {info.filename}", exit_code=ExitCode.SECURITY)
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    raise MacError("AUDIT_BUNDLE_SYMLINK_ENTRY", f"symlink archive entry is forbidden: {info.filename}", exit_code=ExitCode.SECURITY)
                if info.file_size > limits.max_entry_bytes:
                    raise MacError("AUDIT_BUNDLE_ENTRY_TOO_LARGE", f"archive entry exceeds {limits.max_entry_bytes} bytes: {info.filename}", exit_code=ExitCode.SECURITY)
                total_size += info.file_size
                ratio = info.file_size / max(info.compress_size, 1)
                if ratio > limits.max_compression_ratio:
                    raise MacError("AUDIT_BUNDLE_COMPRESSION_RATIO", f"suspicious compression ratio for {info.filename}", exit_code=ExitCode.SECURITY)
            if total_size > limits.max_total_uncompressed_bytes:
                raise MacError("AUDIT_BUNDLE_TOTAL_TOO_LARGE", f"audit bundle expands to {total_size} bytes; limit is {limits.max_total_uncompressed_bytes}", exit_code=ExitCode.SECURITY)
            if "manifest.json" not in names:
                raise MacError("AUDIT_BUNDLE_MANIFEST_MISSING", "manifest.json is required", exit_code=ExitCode.CORRUPTION)
            manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
            if not isinstance(manifest, dict) or manifest.get("schema_version") != 1 or not isinstance(manifest.get("task_id"), str):
                raise MacError("AUDIT_BUNDLE_MANIFEST_INVALID", "manifest identity is invalid", exit_code=ExitCode.CORRUPTION)
            expected = manifest.get("entries")
            if not isinstance(expected, dict):
                raise MacError("AUDIT_BUNDLE_MANIFEST_INVALID", "manifest entries must be an object", exit_code=ExitCode.CORRUPTION)
            if any(not isinstance(name, str) or not isinstance(value, str) or not _SHA256.fullmatch(value) for name, value in expected.items()):
                raise MacError("AUDIT_BUNDLE_MANIFEST_INVALID", "manifest entry digests must be canonical sha256 values", exit_code=ExitCode.CORRUPTION)
            actual_names = set(names) - {"manifest.json"}
            if actual_names != set(expected):
                raise MacError("AUDIT_BUNDLE_ENTRY_SET_MISMATCH", "archive entry set differs from manifest", exit_code=ExitCode.CORRUPTION, details={"expected": sorted(expected), "actual": sorted(actual_names)})
            actual = {name: "sha256:" + hashlib.sha256(archive.read(name)).hexdigest() for name in sorted(actual_names)}
            mismatches = sorted(name for name in actual if actual[name] != expected[name])
            if mismatches:
                raise MacError("AUDIT_BUNDLE_ENTRY_DIGEST_MISMATCH", "audit bundle entry digest mismatch", exit_code=ExitCode.CORRUPTION, details={"entries": mismatches})
            digest = _aggregate_digest(manifest, actual)
            if digest != manifest.get("bundle_digest"):
                raise MacError("AUDIT_BUNDLE_DIGEST_MISMATCH", "audit bundle aggregate digest mismatch", exit_code=ExitCode.CORRUPTION)
            signature = manifest.get("signature")
            if signature != {"status": "unsigned", "scheme": "none"}:
                raise MacError("AUDIT_BUNDLE_SIGNATURE_STATUS_INVALID", "embedded signature claims are not independently verifiable", exit_code=ExitCode.CORRUPTION)
            if not hmac.compare_digest(digest, trusted_digest):
                raise MacError("AUDIT_BUNDLE_TRUST_ANCHOR_MISMATCH", "audit bundle does not match the external trust anchor", exit_code=ExitCode.CORRUPTION)
            if trusted_task_id is not None and trusted_task_id != manifest["task_id"]:
                raise MacError("AUDIT_BUNDLE_TRUST_ANCHOR_MISMATCH", "audit bundle task_id differs from the external trust anchor", exit_code=ExitCode.CORRUPTION)
            return {
                "ok": True,
                "bundle_digest": digest,
                "entry_count": len(actual),
                "signature": signature,
                "trust_anchor": {"source": anchor_source, "task_id": trusted_task_id},
                "compatibility": "legacy_entry_map_v1" if manifest.get("digest_algorithm") in {None, "sha256-entry-map-v1"} else "manifest_v2",
                "manifest": manifest,
            }
    except (UnicodeError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        raise MacError("AUDIT_BUNDLE_INVALID_ZIP", str(exc), exit_code=ExitCode.CORRUPTION) from exc
