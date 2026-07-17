"""Generate a deterministic SHA-256 manifest for release files."""

from __future__ import annotations

import argparse
from hashlib import sha256
from pathlib import Path
import sys


def digest_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def generate(directory: Path, output: Path) -> None:
    files = sorted(
        path for path in directory.iterdir() if path.is_file() and path.resolve() != output.resolve()
    )
    if not files:
        raise ValueError(f"no release files found in {directory}")
    lines = [f"{digest_file(path)}  {path.name}" for path in files]
    output.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path, nargs="?", default=Path("dist"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    output = args.output or args.directory / "SHA256SUMS"
    try:
        generate(args.directory, output)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
