"""Fail a release when its tag does not match the package version."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
import tomllib


SEMVER_TAG = re.compile(
    r"^v(?P<version>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:[-+][0-9A-Za-z.-]+)?)$"
)


def project_version(pyproject: Path) -> str:
    with pyproject.open("rb") as handle:
        document = tomllib.load(handle)
    try:
        value = document["project"]["version"]
    except KeyError as exc:
        raise ValueError("pyproject.toml must define project.version") from exc
    if not isinstance(value, str) or not value:
        raise ValueError("project.version must be a non-empty string")
    return value


def check(tag: str, version: str) -> None:
    match = SEMVER_TAG.fullmatch(tag)
    if not match:
        raise ValueError(f"release tag must be SemVer with a v prefix: {tag!r}")
    if match.group("version") != version:
        raise ValueError(f"release tag {tag!r} does not match project version {version!r}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--pyproject", type=Path, default=Path("pyproject.toml"))
    args = parser.parse_args(argv)
    try:
        check(args.tag, project_version(args.pyproject))
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
