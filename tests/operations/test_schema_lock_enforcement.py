from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from mac.cli import init_command, main, validate_command
from mac.errors import MacError
import mac.schema_validation as schema_validation


def _initialized_repo(root: Path) -> None:
    init_command(repo=root, project="schema-lock", json_output=True)


def test_validate_cannot_bypass_repository_lock_with_schema_dir(tmp_path: Path) -> None:
    _initialized_repo(tmp_path)
    alternate = tmp_path / "alternate-schemas"
    shutil.copytree(tmp_path / "schemas", alternate)
    schema = alternate / "task.schema.json"
    schema.write_text(schema.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises(MacError) as caught:
        validate_command(repo=tmp_path, schema_dir=alternate, json_output=True)

    assert caught.value.code == "SCHEMA_LOCK_MISMATCH"


def test_cli_startup_checks_the_executable_schema_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _initialized_repo(tmp_path)
    schema = tmp_path / "schemas" / "task.schema.json"
    schema.write_text(schema.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    monkeypatch.setattr(schema_validation, "_default_schema_dir", lambda: tmp_path / "schemas")

    with pytest.raises(SystemExit) as caught:
        main(["--help"])

    assert caught.value.code == 3
