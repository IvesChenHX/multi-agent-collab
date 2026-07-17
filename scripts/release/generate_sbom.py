"""Generate a CycloneDX SBOM from the built wheel metadata.

The script intentionally reads the immutable wheel rather than the current
environment, so development-only packages do not leak into the release SBOM.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
import uuid
import zipfile


_REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _wheel_metadata(wheel: Path):
    with zipfile.ZipFile(wheel) as archive:
        candidates = sorted(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
        if len(candidates) != 1:
            raise ValueError(f"wheel must contain exactly one METADATA file: {wheel}")
        return BytesParser(policy=default).parsebytes(archive.read(candidates[0]))


def generate(wheel: Path) -> dict[str, object]:
    metadata = _wheel_metadata(wheel)
    name = metadata.get("Name")
    version = metadata.get("Version")
    if not name or not version:
        raise ValueError("wheel METADATA must contain Name and Version")
    normalized = re.sub(r"[-_.]+", "-", name).lower()
    root_ref = f"pkg:pypi/{normalized}@{version}"
    requirements = sorted(set(metadata.get_all("Requires-Dist", [])))
    components_by_name: dict[str, dict[str, object]] = {}
    for requirement in requirements:
        match = _REQUIREMENT_NAME.match(requirement)
        if not match:
            raise ValueError(f"cannot parse Requires-Dist entry: {requirement!r}")
        dependency_name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        bom_ref = f"pkg:pypi/{dependency_name}"
        component = components_by_name.setdefault(
            dependency_name,
            {
                "type": "library",
                "bom-ref": bom_ref,
                "name": dependency_name,
                "properties": [],
            },
        )
        properties = component["properties"]
        assert isinstance(properties, list)
        properties.append({"name": "mac:requires-dist", "value": requirement})
    components = [components_by_name[name] for name in sorted(components_by_name)]
    dependency_refs = [str(component["bom-ref"]) for component in components]
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"{root_ref}#{_sha256(wheel)}")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": {
                "type": "library",
                "bom-ref": root_ref,
                "name": name,
                "version": version,
                "purl": root_ref,
                "hashes": [{"alg": "SHA-256", "content": _sha256(wheel)}],
            },
        },
        "components": components,
        "dependencies": [{"ref": root_ref, "dependsOn": dependency_refs}],
    }


def find_wheel(directory: Path) -> Path:
    wheels = sorted(directory.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError(f"expected exactly one wheel in {directory}, found {len(wheels)}")
    return wheels[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--output", type=Path, default=Path("dist/sbom.cdx.json"))
    args = parser.parse_args(argv)
    try:
        wheel = args.wheel or find_wheel(args.dist_dir)
        document = generate(wheel)
        args.output.write_text(
            json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
