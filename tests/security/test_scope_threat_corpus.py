from __future__ import annotations

from pathlib import Path

import pytest

from mac.scope import Change, check_changes, check_paths


def issue_codes(result: object) -> set[str]:
    return {issue.code for issue in result.issues}


def scope_contract(*, allowed_paths: list[str] | None = None) -> dict[str, object]:
    return {
        "allowed_paths": allowed_paths or ["src/**"],
        "denied_paths": ["src/private/**"],
        "allowed_operations": ["read", "write", "delete"],
        "owners": ["backend"],
        "risk_tags": [],
        "required_gates": [],
    }


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "../outside.txt",
        "src/../../outside.txt",
        "/etc/passwd",
        r"C:\Windows\system.ini",
        r"\\server\share\payload.txt",
        "src/allowed.py\x00outside",
    ],
)
def test_scope_rejects_traversal_absolute_and_nul_paths(unsafe_path: str) -> None:
    result = check_paths([unsafe_path], scope_contract())

    assert not result.ok
    assert "SCOPE_PATH_UNSAFE" in issue_codes(result)
    assert result.allowed == []


def test_scope_rejects_symlink_that_resolves_outside_repository(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    (outside / "secret.py").write_text("SECRET = True\n", encoding="utf-8")
    link = repo / "src"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"test environment cannot create a directory symlink: {exc}")

    result = check_paths(["src/secret.py"], scope_contract(), repo_root=repo)

    assert not result.ok
    assert "SCOPE_SYMLINK_ESCAPE" in issue_codes(result)
    assert result.allowed == []


def test_scope_detects_case_insensitive_path_collision() -> None:
    changes = [
        Change(operation="add", path="src/Auth.py"),
        Change(operation="add", path="src/auth.py"),
    ]

    result = check_changes(changes, scope_contract())

    assert not result.ok
    assert "SCOPE_CASE_COLLISION" in issue_codes(result)


def test_scope_detects_unicode_normalization_collision() -> None:
    changes = [
        Change(operation="add", path="src/caf\u00e9.py"),
        Change(operation="add", path="src/cafe\u0301.py"),
    ]

    result = check_changes(changes, scope_contract())

    assert not result.ok
    assert "SCOPE_UNICODE_COLLISION" in issue_codes(result)


def test_rename_checks_old_and_new_owner_and_rejects_cross_owner_move() -> None:
    ownership = {
        "schema_version": 6,
        "matching": {
            "semantics": "gitwildmatch",
            "ambiguous": "error",
            "unassigned": "error",
            "case_sensitive": "auto",
        },
        "owners": {
            "backend": {
                "priority": 100,
                "implementation_role": "backend-implementer",
                "include": ["services/**"],
            },
            "web": {
                "priority": 100,
                "implementation_role": "frontend-implementer",
                "include": ["apps/web/**"],
            },
        },
    }
    contract = scope_contract(allowed_paths=["services/**", "apps/web/**"])
    contract["owners"] = ["backend", "web"]
    change = Change(
        operation="rename",
        old_path="services/payments.py",
        path="apps/web/payments.py",
    )

    result = check_changes([change], contract, ownership=ownership)

    assert not result.ok
    assert "SCOPE_RENAME_OWNER_CROSS" in issue_codes(result)


@pytest.mark.parametrize(
    "malicious_pattern",
    ["../**", "/etc/**", r"C:\Windows\**", "src/**\x00outside"],
)
def test_scope_rejects_malicious_glob_patterns(malicious_pattern: str) -> None:
    result = check_paths(["src/allowed.py"], scope_contract(allowed_paths=[malicious_pattern]))

    assert not result.ok
    assert "SCOPE_PATTERN_UNSAFE" in issue_codes(result)
    assert result.allowed == []


def test_active_task_cannot_use_broad_scope_to_modify_frozen_policy() -> None:
    result = check_changes(
        [Change(operation="modify", path="AGENTS.md")],
        scope_contract(allowed_paths=["**"]),
    )

    assert not result.ok
    assert "SCOPE_GOVERNANCE_SENSITIVE" in issue_codes(result)
