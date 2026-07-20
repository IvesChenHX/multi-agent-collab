from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

import mac.report as report_module
from mac.errors import MacError
from mac.report import AuditBundleLimits, build_audit_bundle, verify_audit_bundle


TOKEN = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"


def write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def make_audit_task(task_dir: Path) -> None:
    write_json(task_dir / "task.yaml", {"id": "TASK-audit", "title": f"secret {TOKEN}", "mode": "audit"})
    write_json(task_dir / "scope-contract.yaml", {"id": "SCOPE-audit", "status": "approved"})
    records = {
        "events/EVT-audit.json": {"event_id": "EVT-audit", "payload": {"message": "safe"}},
        "results/RESULT-audit.json": {"id": "RESULT-audit", "summary": f"token={TOKEN}"},
        "findings/FND-audit.json": {"id": "FND-audit", "risk": "safe"},
        "evidence/EVD-audit.json": {"id": "EVD-audit", "claims": [{"gate": "review"}]},
        "approvals/APR-audit.json": {"id": "APR-audit", "decision": "approved"},
    }
    for relative, value in records.items():
        write_json(task_dir / relative, value)
    private = task_dir / "private"
    private.mkdir()
    (private / "raw.log").write_text(f"confidential raw log {TOKEN}", encoding="utf-8")


def test_redacted_audit_bundle_has_complete_manifest_without_secrets_or_raw_logs(tmp_path: Path) -> None:
    task_dir = tmp_path / "TASK-audit"
    task_dir.mkdir()
    make_audit_task(task_dir)
    bundle = tmp_path / "audit.zip"

    manifest = build_audit_bundle(task_dir, bundle, redact=True)

    assert bundle.is_file()
    assert manifest["bundle_digest"].startswith("sha256:")
    assert len(manifest["bundle_digest"]) == 71
    assert manifest["contains_confidential"] is False
    assert manifest["redact_manifest"]
    assert manifest["signature"] == {"status": "unsigned", "scheme": "none"}

    with zipfile.ZipFile(bundle) as archive:
        names = set(archive.namelist())
        required = {
            "task.yaml",
            "scope-contract.yaml",
            "events/EVT-audit.json",
            "results/RESULT-audit.json",
            "findings/FND-audit.json",
            "evidence/EVD-audit.json",
            "approvals/APR-audit.json",
            "manifest.json",
            "redact-manifest.json",
        }
        assert required <= names
        assert "private/raw.log" not in names
        contents = b"".join(archive.read(name) for name in names)
        assert TOKEN.encode("utf-8") not in contents
        archived_manifest = json.loads(archive.read("manifest.json"))
        archived_redactions = json.loads(archive.read("redact-manifest.json"))

    assert archived_manifest["bundle_digest"] == manifest["bundle_digest"]
    assert archived_redactions == manifest["redact_manifest"]
    verified = verify_audit_bundle(bundle, expected_digest=manifest["bundle_digest"])
    assert verified["bundle_digest"] == manifest["bundle_digest"]
    assert verified["trust_anchor"]["source"] == "expected_digest"


def test_audit_bundle_verify_rejects_tampering(tmp_path: Path) -> None:
    task_dir = tmp_path / "TASK-audit"
    task_dir.mkdir()
    make_audit_task(task_dir)
    bundle = tmp_path / "audit.zip"
    build_audit_bundle(task_dir, bundle)
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(bundle) as source, zipfile.ZipFile(tampered, "w") as target:
        for name in source.namelist():
            content = source.read(name)
            target.writestr(name, b"tampered" if name == "task.yaml" else content)

    with pytest.raises(MacError) as caught:
        verify_audit_bundle(
            tampered,
            expected_digest=build_audit_bundle(task_dir, tmp_path / "trusted.zip")["bundle_digest"],
        )

    assert caught.value.code == "AUDIT_BUNDLE_ENTRY_DIGEST_MISMATCH"


def test_audit_bundle_verify_requires_an_external_trust_anchor(tmp_path: Path) -> None:
    task_dir = tmp_path / "TASK-audit"
    task_dir.mkdir()
    make_audit_task(task_dir)
    bundle = tmp_path / "audit.zip"
    build_audit_bundle(task_dir, bundle)

    with pytest.raises(MacError) as caught:
        verify_audit_bundle(bundle)

    assert caught.value.code == "AUDIT_BUNDLE_TRUST_ANCHOR_REQUIRED"


def test_audit_bundle_rejects_a_self_consistent_bundle_without_the_trusted_digest(tmp_path: Path) -> None:
    first_task = tmp_path / "TASK-audit-one"
    second_task = tmp_path / "TASK-audit-two"
    first_task.mkdir()
    second_task.mkdir()
    make_audit_task(first_task)
    make_audit_task(second_task)
    write_json(second_task / "task.yaml", {"id": "TASK-other", "title": "different", "mode": "audit"})
    first_bundle = tmp_path / "first.zip"
    second_bundle = tmp_path / "second.zip"
    trusted = build_audit_bundle(first_task, first_bundle)["bundle_digest"]
    build_audit_bundle(second_task, second_bundle)

    with pytest.raises(MacError) as caught:
        verify_audit_bundle(second_bundle, expected_digest=trusted)

    assert caught.value.code == "AUDIT_BUNDLE_TRUST_ANCHOR_MISMATCH"


def test_audit_bundle_enforces_archive_entry_and_total_limits_before_reading(tmp_path: Path) -> None:
    task_dir = tmp_path / "TASK-audit"
    task_dir.mkdir()
    make_audit_task(task_dir)
    bundle = tmp_path / "audit.zip"
    manifest = build_audit_bundle(task_dir, bundle)

    with pytest.raises(MacError) as caught:
        verify_audit_bundle(
            bundle,
            expected_digest=manifest["bundle_digest"],
            limits=AuditBundleLimits(max_entries=2),
        )

    assert caught.value.code == "AUDIT_BUNDLE_TOO_MANY_ENTRIES"


def test_audit_bundle_builder_rejects_entry_count_before_reading_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task_dir = tmp_path / "TASK-audit"
    task_dir.mkdir()
    make_audit_task(task_dir)

    def fail_if_read(*_args: object, **_kwargs: object) -> bytes:
        raise AssertionError("audit sources must not be read before entry-count preflight")

    monkeypatch.setattr(report_module, "_read_audit_source", fail_if_read)

    with pytest.raises(MacError) as caught:
        build_audit_bundle(
            task_dir,
            tmp_path / "audit.zip",
            limits=AuditBundleLimits(max_entries=2),
        )

    assert caught.value.code == "AUDIT_BUNDLE_TOO_MANY_ENTRIES"


def test_audit_bundle_builder_rejects_aggregate_size_before_reading_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task_dir = tmp_path / "TASK-audit"
    task_dir.mkdir()
    make_audit_task(task_dir)
    source_total = sum(
        path.stat().st_size
        for path in task_dir.rglob("*")
        if path.is_file() and "private" not in path.parts
    )

    def fail_if_read(*_args: object, **_kwargs: object) -> bytes:
        raise AssertionError("audit sources must not be read before aggregate-size preflight")

    monkeypatch.setattr(report_module, "_read_audit_source", fail_if_read)

    with pytest.raises(MacError) as caught:
        build_audit_bundle(
            task_dir,
            tmp_path / "audit.zip",
            limits=AuditBundleLimits(max_total_uncompressed_bytes=source_total - 1),
        )

    assert caught.value.code == "AUDIT_BUNDLE_TOTAL_TOO_LARGE"


def test_audit_bundle_builder_rejects_source_replaced_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task_dir = tmp_path / "TASK-audit"
    task_dir.mkdir()
    make_audit_task(task_dir)
    target = task_dir / "results/RESULT-audit.json"
    original_read = report_module._read_open_audit_source
    replaced = False

    def replace_after_read(handle: object, source: object, max_bytes: int) -> bytes:
        nonlocal replaced
        content = original_read(handle, source, max_bytes)
        if source.path == target and not replaced:  # type: ignore[attr-defined]
            replaced = True
            target.write_bytes(content + b" ")
        return content

    monkeypatch.setattr(report_module, "_read_open_audit_source", replace_after_read)

    with pytest.raises(MacError) as caught:
        build_audit_bundle(task_dir, tmp_path / "audit.zip", redact=False)

    assert caught.value.code == "AUDIT_BUNDLE_SOURCE_CHANGED"


def test_legacy_entry_map_bundle_remains_readable_only_with_its_external_digest(tmp_path: Path) -> None:
    task_dir = tmp_path / "TASK-audit"
    task_dir.mkdir()
    make_audit_task(task_dir)
    current = tmp_path / "current.zip"
    legacy = tmp_path / "legacy.zip"
    build_audit_bundle(task_dir, current)
    with zipfile.ZipFile(current) as source:
        contents = {name: source.read(name) for name in source.namelist()}
    manifest = json.loads(contents["manifest.json"])
    manifest.pop("digest_algorithm")
    canonical = json.dumps(manifest["entries"], sort_keys=True, separators=(",", ":")).encode()
    trusted = "sha256:" + hashlib.sha256(canonical).hexdigest()
    manifest["bundle_digest"] = trusted
    contents["manifest.json"] = (json.dumps(manifest, sort_keys=True) + "\n").encode()
    with zipfile.ZipFile(legacy, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in contents.items():
            archive.writestr(name, content)

    verified = verify_audit_bundle(legacy, expected_digest=trusted)

    assert verified["compatibility"] == "legacy_entry_map_v1"
