from __future__ import annotations

import json
from pathlib import Path

import pytest

from mac.errors import MacError
from mac.security import parse_yaml_safely, redact_sensitive, validate_result_security


FIXTURES = Path(__file__).parents[1] / "fixtures" / "security"


def test_yaml_aliases_are_rejected_before_expansion() -> None:
    source = (FIXTURES / "alias-bomb.yaml").read_text(encoding="utf-8")

    with pytest.raises(MacError) as captured:
        parse_yaml_safely(source)

    assert captured.value.code == "YAML_ALIAS_FORBIDDEN"


def test_oversized_yaml_is_rejected_using_utf8_byte_size() -> None:
    source = "message: " + ("\u754c" * 400)
    assert len(source) < 1024
    assert len(source.encode("utf-8")) > 1024

    with pytest.raises(MacError) as captured:
        parse_yaml_safely(source, max_bytes=1024)

    assert captured.value.code == "INPUT_TOO_LARGE"


def test_result_shell_payload_is_reported_and_never_executed(tmp_path: Path) -> None:
    result = json.loads((FIXTURES / "malicious-result.json").read_text(encoding="utf-8"))
    marker = tmp_path / "should-not-exist.txt"
    result["commands"][0]["argv"][2] = f"printf compromised > {marker}"

    issues = validate_result_security(result)

    assert "RESULT_UNSAFE_SHELL" in {issue.code for issue in issues}
    assert not marker.exists()


def test_result_rejects_secret_patterns_and_high_entropy_tokens() -> None:
    tokens = (FIXTURES / "secret-corpus.txt").read_text(encoding="utf-8").splitlines()
    result = {
        "summary": tokens[0],
        "new_risks": tokens[1:],
        "commands": [],
        "changed_files": [],
    }

    issues = validate_result_security(result)

    assert "SECRET_DETECTED" in {issue.code for issue in issues}
    assert any(issue.path == "summary" for issue in issues)
    assert any(issue.path and issue.path.startswith("new_risks") for issue in issues)


def test_redaction_removes_secret_and_records_every_redacted_path() -> None:
    tokens = (FIXTURES / "secret-corpus.txt").read_text(encoding="utf-8").splitlines()
    source = {
        "summary": f"credential={tokens[0]}",
        "nested": {"authorization": f"Bearer {tokens[2]}"},
        "items": ["safe", tokens[3]],
    }

    redacted = redact_sensitive(source)
    serialized = json.dumps(redacted.value, sort_keys=True)

    assert all(token not in serialized for token in tokens)
    assert {"summary", "nested.authorization", "items.1"} <= set(redacted.redacted_paths)
