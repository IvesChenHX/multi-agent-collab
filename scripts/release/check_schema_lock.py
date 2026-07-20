"""Fail validation and builds when the executable schema bundle drifts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import zipfile

try:
    from hatchling.builders.hooks.plugin.interface import BuildHookInterface
except ImportError:  # pragma: no cover - the CLI checker does not require hatchling
    class BuildHookInterface:  # type: ignore[no-redef]
        root = ""


SCHEMA_NAMES = frozenset(
    {
        "approval.schema.json",
        "common.schema.json",
        "config.schema.json",
        "event.schema.json",
        "evidence.schema.json",
        "finding.schema.json",
        "ownership.schema.json",
        "result.schema.json",
        "risk-acceptance.schema.json",
        "run.schema.json",
        "runtime-profile.schema.json",
        "scope-contract.schema.json",
        "task.schema.json",
        "workflow.schema.json",
        "work-unit.schema.json",
    }
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _canonical_digest(content: bytes) -> str:
    text = content.decode("utf-8")
    canonical = text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _locked_digests(lock_content: bytes) -> dict[str, str]:
    try:
        lock = json.loads(lock_content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"schema lock is not valid UTF-8 JSON: {exc}") from exc
    records = lock.get("files") if isinstance(lock, dict) else None
    if not isinstance(records, list):
        raise ValueError("schema lock files must be an array")
    expected: dict[str, str] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str) or not isinstance(record.get("sha256"), str):
            raise ValueError("every schema lock entry requires path and sha256")
        name = PurePosixPath(record["path"]).name
        if record["path"] != f"schemas/{name}" or name not in SCHEMA_NAMES:
            raise ValueError(f"schema lock path is not canonical: {record['path']!r}")
        if name in expected:
            raise ValueError(f"duplicate schema lock entry: {name}")
        if not _DIGEST.fullmatch(record["sha256"]):
            raise ValueError(f"invalid schema digest for {name}")
        expected[name] = record["sha256"]
    if set(expected) != SCHEMA_NAMES:
        missing = sorted(SCHEMA_NAMES - set(expected))
        extra = sorted(set(expected) - SCHEMA_NAMES)
        raise ValueError(f"schema lock coverage mismatch; missing={missing}, extra={extra}")
    return expected


def _check_bundle(schemas: dict[str, bytes], lock_content: bytes) -> None:
    expected = _locked_digests(lock_content)
    if set(schemas) != SCHEMA_NAMES:
        missing = sorted(SCHEMA_NAMES - set(schemas))
        extra = sorted(set(schemas) - SCHEMA_NAMES)
        raise ValueError(f"schema bundle coverage mismatch; missing={missing}, extra={extra}")
    for name in sorted(SCHEMA_NAMES):
        actual = _canonical_digest(schemas[name])
        if actual != expected[name]:
            raise ValueError(f"schema digest mismatch for {name}: expected {expected[name]}, got {actual}")


def check_repository_schema_lock(repo: Path) -> None:
    root = repo.resolve()
    schema_root = root / "schemas"
    lock_path = root / ".agents/schemas.lock.json"
    if not schema_root.is_dir():
        raise ValueError("schemas directory is missing")
    if not lock_path.is_file():
        raise ValueError(".agents/schemas.lock.json is missing")
    schemas = {path.name: path.read_bytes() for path in schema_root.glob("*.json") if path.is_file()}
    _check_bundle(schemas, lock_path.read_bytes())


def verify_built_artifact(artifact: Path) -> None:
    """Verify that a wheel/sdist contains exactly the locked executable schemas."""
    schemas: dict[str, bytes] = {}
    lock_content: bytes | None = None
    if artifact.suffix == ".whl":
        with zipfile.ZipFile(artifact) as archive:
            names = archive.namelist()
            for name in names:
                path = PurePosixPath(name)
                if len(path.parts) == 3 and path.parts[:2] == ("mac", "schemas") and path.name.endswith(".json"):
                    if path.name in schemas:
                        raise ValueError(f"duplicate packaged schema: {path.name}")
                    schemas[path.name] = archive.read(name)
                elif path.parts == ("mac", "schemas.lock.json"):
                    if lock_content is not None:
                        raise ValueError("duplicate packaged schema lock")
                    lock_content = archive.read(name)
    else:
        with tarfile.open(artifact, "r:*") as archive:
            for member in archive.getmembers():
                path = PurePosixPath(member.name)
                if not member.isfile():
                    continue
                if len(path.parts) == 3 and path.parts[1] == "schemas" and path.name.endswith(".json"):
                    extracted = archive.extractfile(member)
                    if extracted is None or path.name in schemas:
                        raise ValueError(f"invalid packaged schema: {path.name}")
                    schemas[path.name] = extracted.read()
                elif len(path.parts) == 3 and path.parts[1:] == (".agents", "schemas.lock.json"):
                    extracted = archive.extractfile(member)
                    if extracted is None or lock_content is not None:
                        raise ValueError("invalid packaged schema lock")
                    lock_content = extracted.read()
    if lock_content is None:
        raise ValueError(f"schema lock is missing from built artifact: {artifact}")
    _check_bundle(schemas, lock_content)


class CustomBuildHook(BuildHookInterface):
    """Hatch hook: fail both before and after artifact construction."""

    def initialize(self, version: str, build_data: dict[str, object]) -> None:
        check_repository_schema_lock(Path(self.root))

    def finalize(self, version: str, build_data: dict[str, object], artifact_path: str) -> None:
        verify_built_artifact(Path(artifact_path))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    try:
        check_repository_schema_lock(args.repo)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
