from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from mac.errors import MacError
from mac.report import build_audit_bundle, verify_audit_bundle


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
    assert verify_audit_bundle(bundle)["bundle_digest"] == manifest["bundle_digest"]


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
        verify_audit_bundle(tampered)

    assert caught.value.code == "AUDIT_BUNDLE_ENTRY_DIGEST_MISMATCH"
