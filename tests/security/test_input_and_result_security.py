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


def test_yaml_duplicate_keys_are_rejected_instead_of_overwritten() -> None:
    with pytest.raises(MacError) as captured:
        parse_yaml_safely("key: first\nkey: second\n")

    assert captured.value.code == "YAML_DUPLICATE_KEY"


@pytest.mark.parametrize(
    ("source", "expected_code"),
    [
        ("key: !!str value\n", "YAML_TAG_FORBIDDEN"),
        ("key: &anchor value\n", "YAML_ALIAS_FORBIDDEN"),
    ],
)
def test_yaml_rejects_explicit_tags_and_anchors(source: str, expected_code: str) -> None:
    with pytest.raises(MacError) as captured:
        parse_yaml_safely(source)

    assert captured.value.code == expected_code


def test_yaml_rejects_excessive_nesting_before_construction() -> None:
    source = "root:\n  a:\n    b:\n      c:\n        value: true\n"

    with pytest.raises(MacError) as captured:
        parse_yaml_safely(source, max_depth=4)

    assert captured.value.code == "YAML_DEPTH_EXCEEDED"


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


def test_result_allows_long_governance_ids_in_repository_path_fields_and_argv() -> None:
    event_path = (
        "examples/v6/tasks/TASK-01KXXHKS63XE2A30229824FX0N-v6-alpha-pilot-ready/"
        "events/EVT-01KXXM0M9GS1TT5HGSA4Q6P8FE.json"
    )
    log_path = (
        "private/RUN-01KXXHVSJXA7X1PRGWJBKP35BC/"
        "RESULT-01KXXM0M9GS1TT5HGSA4Q6P8FF.json"
    )
    result = {
        "summary": "updated tracked examples",
        "commands": [{"argv": ["python", event_path], "exit_code": 0}],
        "changed_files": [event_path],
        "raw_log_ref": {"path": log_path, "digest": "sha256:" + ("a" * 64)},
    }

    issues = validate_result_security(result)

    assert not [issue for issue in issues if issue.code == "SECRET_DETECTED"]


def test_result_path_fields_and_path_like_argv_still_reject_explicit_credentials() -> None:
    result = {
        "summary": "credential safety regression",
        "commands": [{"argv": ["tool", "--output=logs/ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ/report.json"]}],
        "changed_files": ["examples/AKIAABCDEFGHIJKLMNOP/event.json"],
        "raw_log_ref": {"path": "private/token=supersecret123/report.log"},
    }

    issues = validate_result_security(result)
    secret_paths = {issue.path for issue in issues if issue.code == "SECRET_DETECTED"}

    assert {
        "commands.0.argv.1",
        "changed_files.0",
        "raw_log_ref.path",
    } <= secret_paths


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
