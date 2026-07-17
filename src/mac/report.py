from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from .io import load_data
from .application.governance import evaluate_evidence
from .application.close import evaluate_repository_close
from .git import GitRepository
from .security import redact_sensitive
from .errors import ExitCode, MacError


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


def _redact_file(path: Path, source_name: str) -> tuple[bytes, list[dict[str, str]]]:
    try:
        value = load_data(path)
    except Exception:
        raw_bytes = path.read_bytes()
        if len(raw_bytes) > 1_048_576:
            raise MacError(
                "AUDIT_BUNDLE_ENTRY_TOO_LARGE",
                f"audit source exceeds the 1 MiB structured-input limit: {source_name}",
                exit_code=ExitCode.SECURITY,
                path=source_name,
            )
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


def build_audit_bundle(task_dir: Path, out_path: Path, *, redact: bool = True) -> dict[str, Any]:
    task_dir = task_dir.resolve()
    allowed = ["task.yaml", "scope-contract.yaml", "events/*.json", "work-units/*.yaml", "runs/*.json", "results/*.json", "findings/*.json", "evidence/*.json", "approvals/*.json", "risk-acceptances/*.json"]
    entries: dict[str, bytes] = {}
    redactions: list[dict[str, str]] = []
    for pattern in allowed:
        for path in sorted(task_dir.glob(pattern)):
            if not path.is_file() or "private" in path.parts:
                continue
            relative = path.relative_to(task_dir).as_posix()
            if redact:
                content, found = _redact_file(path, relative); redactions.extend(found)
            else:
                content = path.read_bytes()
            entries[relative] = content
    entries["redact-manifest.json"] = (json.dumps(redactions, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    entry_digests = {name: "sha256:" + hashlib.sha256(content).hexdigest() for name, content in entries.items()}
    bundle_digest = "sha256:" + hashlib.sha256(json.dumps(entry_digests, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    manifest: dict[str, Any] = {
        "schema_version": 1, "task_id": load_data(task_dir / "task.yaml").get("id"),
        "entries": entry_digests, "bundle_digest": bundle_digest, "contains_confidential": not redact,
        "redact_manifest": redactions, "signature": {"status": "unsigned", "scheme": "none"},
    }
    entries["manifest.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, content in sorted(entries.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)); info.compress_type = zipfile.ZIP_DEFLATED; info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    return manifest


def verify_audit_bundle(bundle_path: Path) -> dict[str, Any]:
    """Verify archive structure, every entry digest, and the aggregate bundle digest."""
    try:
        with zipfile.ZipFile(bundle_path) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            if len(names) != len(set(names)):
                raise MacError("AUDIT_BUNDLE_DUPLICATE_ENTRY", "audit bundle contains duplicate entry names", exit_code=ExitCode.CORRUPTION)
            for info in infos:
                path = PurePosixPath(info.filename)
                if path.is_absolute() or ".." in path.parts or "\\" in info.filename:
                    raise MacError("AUDIT_BUNDLE_UNSAFE_PATH", f"unsafe archive entry: {info.filename}", exit_code=ExitCode.SECURITY)
                if info.file_size > 16 * 1024 * 1024:
                    raise MacError("AUDIT_BUNDLE_ENTRY_TOO_LARGE", f"archive entry exceeds 16 MiB: {info.filename}", exit_code=ExitCode.SECURITY)
            if "manifest.json" not in names:
                raise MacError("AUDIT_BUNDLE_MANIFEST_MISSING", "manifest.json is required", exit_code=ExitCode.CORRUPTION)
            manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
            expected = manifest.get("entries")
            if not isinstance(expected, dict):
                raise MacError("AUDIT_BUNDLE_MANIFEST_INVALID", "manifest entries must be an object", exit_code=ExitCode.CORRUPTION)
            actual_names = set(names) - {"manifest.json"}
            if actual_names != set(expected):
                raise MacError("AUDIT_BUNDLE_ENTRY_SET_MISMATCH", "archive entry set differs from manifest", exit_code=ExitCode.CORRUPTION, details={"expected": sorted(expected), "actual": sorted(actual_names)})
            actual = {name: "sha256:" + hashlib.sha256(archive.read(name)).hexdigest() for name in sorted(actual_names)}
            mismatches = sorted(name for name in actual if actual[name] != expected[name])
            if mismatches:
                raise MacError("AUDIT_BUNDLE_ENTRY_DIGEST_MISMATCH", "audit bundle entry digest mismatch", exit_code=ExitCode.CORRUPTION, details={"entries": mismatches})
            digest = "sha256:" + hashlib.sha256(json.dumps(actual, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if digest != manifest.get("bundle_digest"):
                raise MacError("AUDIT_BUNDLE_DIGEST_MISMATCH", "audit bundle aggregate digest mismatch", exit_code=ExitCode.CORRUPTION)
            signature = manifest.get("signature")
            if not isinstance(signature, dict) or signature.get("status") not in {"unsigned", "verified"}:
                raise MacError("AUDIT_BUNDLE_SIGNATURE_STATUS_INVALID", "manifest must declare an honest signature status", exit_code=ExitCode.CORRUPTION)
            return {"ok": True, "bundle_digest": digest, "entry_count": len(actual), "signature": signature, "manifest": manifest}
    except zipfile.BadZipFile as exc:
        raise MacError("AUDIT_BUNDLE_INVALID_ZIP", str(exc), exit_code=ExitCode.CORRUPTION) from exc
