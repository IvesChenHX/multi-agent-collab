from __future__ import annotations

import json
import os
import tempfile
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml


def normalize_data(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): normalize_data(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [normalize_data(item) for item in value]
    return value


def load_data(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > 1_048_576:
        from .errors import ExitCode, MacError

        raise MacError("INPUT_TOO_LARGE", f"{path} exceeds the 1 MiB structured-input limit", exit_code=ExitCode.SECURITY, path=str(path))
    text = raw.decode("utf-8")
    if path.suffix.lower() == ".json":
        value = json.loads(text)
    else:
        from .security import parse_yaml_safely

        value = parse_yaml_safely(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return normalize_data(value)


def dump_yaml(data: dict[str, Any]) -> str:
    return yaml.safe_dump(normalize_data(data), allow_unicode=True, sort_keys=False)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(normalize_data(data), ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def atomic_write_yaml(path: Path, data: dict[str, Any]) -> None:
    atomic_write_text(path, dump_yaml(data))
