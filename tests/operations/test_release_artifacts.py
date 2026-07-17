from __future__ import annotations

from email.message import Message
from pathlib import Path
import zipfile

from scripts.release.check_release_version import check, project_version
from scripts.release.generate_hashes import digest_file, generate as generate_hashes
from scripts.release.generate_sbom import generate as generate_sbom


def _wheel(path: Path) -> Path:
    wheel = path / "mac_governance-1.2.3-py3-none-any.whl"
    metadata = Message()
    metadata["Metadata-Version"] = "2.4"
    metadata["Name"] = "mac-governance"
    metadata["Version"] = "1.2.3"
    metadata["Requires-Dist"] = "pydantic>=2"
    metadata["Requires-Dist"] = "typer>=0.12; python_version >= '3.11'"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("mac_governance-1.2.3.dist-info/METADATA", metadata.as_bytes())
    return wheel


def test_release_version_must_match_semver_tag(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "mac-governance"\nversion = "1.2.3"\n', encoding="utf-8")

    version = project_version(pyproject)
    check("v1.2.3", version)


def test_sbom_describes_built_wheel_and_runtime_requirements(tmp_path):
    wheel = _wheel(tmp_path)

    sbom = generate_sbom(wheel)

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.6"
    component = sbom["metadata"]["component"]
    assert component["name"] == "mac-governance"
    assert component["version"] == "1.2.3"
    assert component["hashes"][0]["content"] == digest_file(wheel)
    assert {item["name"] for item in sbom["components"]} == {"pydantic", "typer"}


def test_hash_manifest_is_sorted_and_does_not_hash_itself(tmp_path):
    (tmp_path / "z.whl").write_bytes(b"wheel")
    (tmp_path / "a.tar.gz").write_bytes(b"sdist")
    manifest = tmp_path / "SHA256SUMS"

    generate_hashes(tmp_path, manifest)
    first = manifest.read_text(encoding="utf-8")
    generate_hashes(tmp_path, manifest)

    assert manifest.read_text(encoding="utf-8") == first
    assert first.splitlines()[0].endswith("  a.tar.gz")
    assert "SHA256SUMS" not in first
