from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any
import zipfile

from mac.errors import ExitCode, MacError
from mac.report import build_audit_bundle


def verify_audit_bundle(bundle_path: Path) -> dict[str, Any]:
    """Independently verify an audit archive without trusting builder state."""
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
            if not isinstance(manifest, dict) or not isinstance(manifest.get("entries"), dict):
                raise MacError("AUDIT_BUNDLE_MANIFEST_INVALID", "manifest entries must be an object", exit_code=ExitCode.CORRUPTION)
            expected = manifest["entries"]
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
            if signature != {"status": "unsigned", "scheme": "none"}:
                raise MacError("AUDIT_BUNDLE_SIGNATURE_UNVERIFIED", "signed status requires an external cryptographic verification result", exit_code=ExitCode.SECURITY)
            if "redact-manifest.json" in actual_names:
                redactions = json.loads(archive.read("redact-manifest.json").decode("utf-8"))
                if redactions != manifest.get("redact_manifest"):
                    raise MacError("AUDIT_BUNDLE_REDACT_MANIFEST_MISMATCH", "redaction manifest differs from the signed manifest view", exit_code=ExitCode.CORRUPTION)
            return {"ok": True, "bundle_digest": digest, "entry_count": len(actual), "signature": signature, "manifest": manifest}
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MacError("AUDIT_BUNDLE_MANIFEST_INVALID", str(exc), exit_code=ExitCode.CORRUPTION) from exc
    except zipfile.BadZipFile as exc:
        raise MacError("AUDIT_BUNDLE_INVALID_ZIP", str(exc), exit_code=ExitCode.CORRUPTION) from exc

__all__ = ["build_audit_bundle", "verify_audit_bundle"]
