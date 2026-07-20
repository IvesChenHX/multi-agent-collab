from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode
from yaml.tokens import (
    AliasToken,
    AnchorToken,
    BlockEndToken,
    BlockMappingStartToken,
    BlockSequenceStartToken,
    FlowMappingEndToken,
    FlowMappingStartToken,
    FlowSequenceEndToken,
    FlowSequenceStartToken,
    TagToken,
)

from .errors import MacIssue
from .errors import ExitCode, MacError

_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"), re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]?([^\s,'\"]{8,})"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]
_SENSITIVE_KEYS = {"password", "passwd", "secret", "token", "api_key", "apikey", "authorization", "private_key", "raw_log"}


class _RestrictedSafeLoader(yaml.SafeLoader):
    """SafeLoader variant that refuses duplicate mapping keys."""

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        if not isinstance(node, MappingNode):
            raise ConstructorError(None, None, "expected a mapping node", node.start_mark)
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in result
            except TypeError as exc:
                raise ConstructorError(
                    "while constructing a mapping", node.start_mark, "found an unhashable key", key_node.start_mark,
                ) from exc
            if duplicate:
                raise MacError(
                    "YAML_DUPLICATE_KEY",
                    f"duplicate YAML mapping key: {key!r}",
                    exit_code=ExitCode.SECURITY,
                )
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def parse_yaml_safely(
    source: str | bytes, *, max_bytes: int = 1_048_576, max_depth: int = 64,
) -> dict[str, Any]:
    raw = source if isinstance(source, bytes) else source.encode("utf-8")
    if len(raw) > max_bytes:
        raise MacError("INPUT_TOO_LARGE", "YAML input exceeds configured byte limit", exit_code=ExitCode.SECURITY)
    if max_depth < 1:
        raise ValueError("max_depth must be positive")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MacError("YAML_ENCODING_INVALID", "YAML input must be valid UTF-8", exit_code=ExitCode.VALIDATION) from exc
    depth = 0
    opening = (BlockMappingStartToken, BlockSequenceStartToken, FlowMappingStartToken, FlowSequenceStartToken)
    closing = (BlockEndToken, FlowMappingEndToken, FlowSequenceEndToken)
    try:
        for token in yaml.scan(text):
            if isinstance(token, (AliasToken, AnchorToken)):
                raise MacError(
                    "YAML_ALIAS_FORBIDDEN", "YAML anchors and aliases are forbidden", exit_code=ExitCode.SECURITY,
                )
            if isinstance(token, TagToken):
                raise MacError("YAML_TAG_FORBIDDEN", "explicit YAML tags are forbidden", exit_code=ExitCode.SECURITY)
            if isinstance(token, opening):
                depth += 1
                if depth > max_depth:
                    raise MacError(
                        "YAML_DEPTH_EXCEEDED",
                        "YAML nesting exceeds configured depth limit",
                        exit_code=ExitCode.SECURITY,
                    )
            elif isinstance(token, closing):
                depth -= 1
        value = yaml.load(text, Loader=_RestrictedSafeLoader)
    except MacError:
        raise
    except yaml.YAMLError as exc:
        raise MacError("YAML_INVALID", "YAML input is invalid", exit_code=ExitCode.VALIDATION) from exc
    if not isinstance(value, dict):
        raise MacError("YAML_OBJECT_REQUIRED", "YAML document must be an object", exit_code=ExitCode.VALIDATION)
    return value


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def contains_secret(text: str, *, include_entropy: bool = True) -> bool:
    if any(pattern.search(text) for pattern in _SECRET_PATTERNS):
        return True
    if not include_entropy:
        return False
    for token in re.findall(r"[A-Za-z0-9+/=_-]{32,}", text):
        if not token.startswith(("sha256", "TASK-", "EVT-", "RUN-", "EVD-", "SCOPE-", "WU-", "RESULT-", "FND-", "RISK-", "APR-", "LEASE-")) and _entropy(token) >= 4.2:
            return True
    return False


def _is_repository_path_field(path: str) -> bool:
    return path.startswith("changed_files.") or path == "raw_log_ref.path"


def _is_path_like_argv(path: str, value: str) -> bool:
    parts = path.split(".")
    return (
        len(parts) == 4
        and parts[0] == "commands"
        and parts[1].isdigit()
        and parts[2] == "argv"
        and parts[3].isdigit()
        and ("/" in value or "\\" in value)
    )


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
        elif isinstance(value, str):
            include_entropy = not (
                _is_repository_path_field(path) or _is_path_like_argv(path, value)
            )
            if contains_secret(value, include_entropy=include_entropy):
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
