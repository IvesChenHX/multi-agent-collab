from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

import yaml
from yaml.tokens import AliasToken

from .errors import MacIssue
from .errors import ExitCode, MacError

_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"), re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]?([^\s,'\"]{8,})"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]
_SENSITIVE_KEYS = {"password", "passwd", "secret", "token", "api_key", "apikey", "authorization", "private_key", "raw_log"}


def parse_yaml_safely(source: str | bytes, *, max_bytes: int = 1_048_576) -> dict[str, Any]:
    raw = source if isinstance(source, bytes) else source.encode("utf-8")
    if len(raw) > max_bytes:
        raise MacError("INPUT_TOO_LARGE", "YAML input exceeds configured byte limit", exit_code=ExitCode.SECURITY)
    text = raw.decode("utf-8")
    if any(isinstance(token, AliasToken) for token in yaml.scan(text)):
        raise MacError("YAML_ALIAS_FORBIDDEN", "YAML aliases are forbidden", exit_code=ExitCode.SECURITY)
    value = yaml.safe_load(text)
    if not isinstance(value, dict):
        raise MacError("YAML_OBJECT_REQUIRED", "YAML document must be an object", exit_code=ExitCode.VALIDATION)
    return value


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def contains_secret(text: str) -> bool:
    if any(pattern.search(text) for pattern in _SECRET_PATTERNS):
        return True
    for token in re.findall(r"[A-Za-z0-9+/=_-]{32,}", text):
        if not token.startswith(("sha256", "TASK-", "EVT-", "RUN-", "EVD-", "SCOPE-", "WU-", "RESULT-", "FND-", "RISK-", "APR-", "LEASE-")) and _entropy(token) >= 4.2:
            return True
    return False


def validate_result_security(result: dict[str, Any]) -> list[MacIssue]:
    issues: list[MacIssue] = []
    for index, command in enumerate(result.get("commands", [])):
        argv = command.get("argv") if isinstance(command, dict) else None
        if not isinstance(argv, list) or not argv or not all(isinstance(value, str) for value in argv):
            issues.append(MacIssue("RESULT_UNSAFE_SHELL", "commands must use an argv array", field=f"commands.{index}.argv"))
            continue
        executable = argv[0].lower().replace("\\", "/").rsplit("/", 1)[-1]
        if executable in {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"} and any(value in {"-c", "-command", "/c"} for value in (item.lower() for item in argv[1:])):
            issues.append(MacIssue("RESULT_UNSAFE_SHELL", "shell evaluation is forbidden by default", field=f"commands.{index}.argv"))
    def walk(value: Any, path: str = "") -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, f"{path}.{key}".strip("."))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{path}.{index}".strip("."))
        elif isinstance(value, str) and contains_secret(value):
            issues.append(MacIssue("SECRET_DETECTED", "result contains a probable secret", path=path, field=path))
    walk(result)
    return issues


@dataclass(frozen=True, slots=True)
class RedactionResult:
    value: Any
    redacted_paths: tuple[str, ...]


def redact_sensitive(value: Any) -> RedactionResult:
    paths: list[str] = []
    def redact(item: Any, path: str = "") -> Any:
        if isinstance(item, dict):
            result = {}
            for key, child in item.items():
                child_path = f"{path}.{key}".strip(".")
                if str(key).lower() in _SENSITIVE_KEYS:
                    result[key] = "[REDACTED]"; paths.append(child_path)
                else:
                    result[key] = redact(child, child_path)
            return result
        if isinstance(item, list):
            return [redact(child, f"{path}.{index}".strip(".")) for index, child in enumerate(item)]
        if isinstance(item, str) and contains_secret(item):
            paths.append(path)
            redacted = item
            for pattern in _SECRET_PATTERNS:
                redacted = pattern.sub("[REDACTED]", redacted)
            if redacted == item:
                redacted = "[REDACTED]"
            return redacted
        return item
    return RedactionResult(redact(value), tuple(paths))
