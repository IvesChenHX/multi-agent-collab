from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


TASK_ID = "TASK-01KXXHKS63XE2A30229824FX0N-v6-alpha-pilot-ready"
SOURCE_DIGEST = "sha256:0ff1e4d9d93a6bec402610914b7053a0f69b92de397c1ce90b2b12df232fc6a7"


def _source_bytes(path: Path) -> dict[str, bytes]:
    return {
        child.relative_to(path).as_posix(): child.read_bytes()
        for child in sorted(path.rglob("*"))
        if child.is_file()
    }


def _run_cli(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    project = Path(__file__).resolve().parents[1]
    return subprocess.run(
        [sys.executable, "-m", "mac.cli", *args],
        cwd=repo,
        env={**os.environ, "PYTHONPATH": str(project / "src")},
        text=True,
        capture_output=True,
    )


def test_cli_scan_classifies_authorityless_v6_history_without_writing() -> None:
    repo = Path(__file__).resolve().parents[1]
    environment = {**os.environ, "PYTHONPATH": str(repo / "src")}
    before = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z"],
        cwd=repo,
        check=True,
        capture_output=True,
    ).stdout

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "mac.cli",
            "migrate",
            "authorityless-v6",
            "--repo",
            str(repo),
            "--task-id",
            TASK_ID,
            "--scan",
            "--json",
        ],
        cwd=repo,
        env=environment,
        text=True,
        capture_output=True,
    )
    after = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z"],
        cwd=repo,
        check=True,
        capture_output=True,
    ).stdout

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "ok": True,
        "task_id": TASK_ID,
        "eligible": True,
        "classification": "metadata_only",
        "verification_status": "unverifiable",
        "reason": "EVENT_AUTHORITY_MISSING",
        "source_path": f"tasks/{TASK_ID}",
        "source_digest": SOURCE_DIGEST,
        "planned_writes": [],
    }
    assert after == before


def test_cli_scan_digest_is_stable_across_git_text_line_endings(tmp_path: Path) -> None:
    project = Path(__file__).resolve().parents[1]
    digests: list[str] = []

    for line_ending in (b"\n", b"\r\n"):
        repo = tmp_path / ("lf" if line_ending == b"\n" else "crlf")
        source = repo / "tasks" / TASK_ID
        shutil.copytree(project / "tasks" / TASK_ID, source)
        for path in sorted(child for child in source.rglob("*") if child.is_file()):
            canonical = path.read_bytes().replace(b"\r\n", b"\n")
            path.write_bytes(canonical.replace(b"\n", line_ending))

        scanned = _run_cli(
            repo,
            "migrate",
            "authorityless-v6",
            "--repo",
            str(repo),
            "--task-id",
            TASK_ID,
            "--scan",
            "--json",
        )

        assert scanned.returncode == 0, scanned.stderr
        digests.append(json.loads(scanned.stdout)["source_digest"])

    assert digests[0] == digests[1]


def test_cli_apply_preserves_source_and_idempotently_records_unverifiable_history(tmp_path: Path) -> None:
    project = Path(__file__).resolve().parents[1]
    repo = tmp_path / "repo"
    source = repo / "tasks" / TASK_ID
    shutil.copytree(project / "tasks" / TASK_ID, source)
    before = _source_bytes(source)

    command = (
        "migrate",
        "authorityless-v6",
        "--repo",
        str(repo),
        "--task-id",
        TASK_ID,
        "--apply",
        "--expected-source-digest",
        SOURCE_DIGEST,
        "--json",
    )
    created = _run_cli(repo, *command)

    assert created.returncode == 0, created.stderr
    created_payload = json.loads(created.stdout)
    assert created_payload == {
        "ok": True,
        "task_id": TASK_ID,
        "action": "created",
        "classification": "metadata_only",
        "verification_status": "unverifiable",
        "reason": "EVENT_AUTHORITY_MISSING",
        "source_path": f"tasks/{TASK_ID}",
        "source_digest": SOURCE_DIGEST,
        "manifest_path": f"migration/v6-authorityless/{TASK_ID}.json",
        "migrated_task_id": created_payload["migrated_task_id"],
        "migrated_task_path": f"tasks-v6/{created_payload['migrated_task_id']}",
    }
    assert _source_bytes(source) == before

    repeated = _run_cli(repo, *command)

    assert repeated.returncode == 0, repeated.stderr
    assert json.loads(repeated.stdout) == {**created_payload, "action": "unchanged"}
    assert _source_bytes(source) == before
    assert len(list((repo / "tasks-v6").glob("TASK-*"))) == 1


def test_cli_validate_accepts_only_the_bound_migration_as_an_unverifiable_warning(tmp_path: Path) -> None:
    project = Path(__file__).resolve().parents[1]
    repo = tmp_path / "repo"
    shutil.copytree(project / ".agents", repo / ".agents")
    shutil.copytree(project / "schemas", repo / "schemas")
    shutil.copytree(project / "tasks" / TASK_ID, repo / "tasks" / TASK_ID)

    applied = _run_cli(
        repo,
        "migrate",
        "authorityless-v6",
        "--repo",
        str(repo),
        "--task-id",
        TASK_ID,
        "--apply",
        "--expected-source-digest",
        SOURCE_DIGEST,
        "--json",
    )
    assert applied.returncode == 0, applied.stderr

    validated = _run_cli(repo, "validate", "--repo", str(repo), "--json")

    assert validated.returncode == 0, validated.stderr
    assert json.loads(validated.stdout) == {
        "ok": True,
        "issues": [
            {
                "code": "LEGACY_TASK_UNVERIFIABLE",
                "message": "authorityless v6 history is preserved as metadata and cannot prove historical verification",
                "path": f"tasks/{TASK_ID}",
                "severity": "warning",
                "task_id": TASK_ID,
                "details": {
                    "source_format": "v6",
                    "legacy_integrity": "metadata_only",
                    "verification_status": "unverifiable",
                    "reason": "EVENT_AUTHORITY_MISSING",
                    "source_digest": SOURCE_DIGEST,
                    "migration_record": f"migration/v6-authorityless/{TASK_ID}.json",
                    "migrated_task_id": json.loads(applied.stdout)["migrated_task_id"],
                },
            }
        ],
    }


def test_cli_validate_fails_closed_when_migrated_source_changes(tmp_path: Path) -> None:
    project = Path(__file__).resolve().parents[1]
    repo = tmp_path / "repo"
    shutil.copytree(project / ".agents", repo / ".agents")
    shutil.copytree(project / "schemas", repo / "schemas")
    source = repo / "tasks" / TASK_ID
    shutil.copytree(project / "tasks" / TASK_ID, source)
    applied = _run_cli(
        repo,
        "migrate",
        "authorityless-v6",
        "--repo",
        str(repo),
        "--task-id",
        TASK_ID,
        "--apply",
        "--expected-source-digest",
        SOURCE_DIGEST,
        "--json",
    )
    assert applied.returncode == 0, applied.stderr
    task_projection = source / "task.yaml"
    task_projection.write_bytes(task_projection.read_bytes() + b"\n")

    validated = _run_cli(repo, "validate", "--repo", str(repo), "--json")

    assert validated.returncode == 3
    issues = json.loads(validated.stdout)["issues"]
    assert any(issue["code"] == "MIGRATION_SOURCE_CHANGED" for issue in issues)
    assert any(issue["code"] == "EVENT_AUTHORITY_MISSING" for issue in issues)
    assert not any(issue["code"] == "LEGACY_TASK_UNVERIFIABLE" for issue in issues)


def test_cli_apply_recovers_a_published_task_when_manifest_write_was_interrupted(tmp_path: Path) -> None:
    project = Path(__file__).resolve().parents[1]
    repo = tmp_path / "repo"
    shutil.copytree(project / ".agents", repo / ".agents")
    shutil.copytree(project / "schemas", repo / "schemas")
    shutil.copytree(project / "tasks" / TASK_ID, repo / "tasks" / TASK_ID)
    command = (
        "migrate",
        "authorityless-v6",
        "--repo",
        str(repo),
        "--task-id",
        TASK_ID,
        "--apply",
        "--expected-source-digest",
        SOURCE_DIGEST,
        "--json",
    )
    created = _run_cli(repo, *command)
    assert created.returncode == 0, created.stderr
    manifest_path = repo / json.loads(created.stdout)["manifest_path"]
    manifest_path.unlink()

    recovered = _run_cli(repo, *command)
    validated = _run_cli(repo, "validate", "--repo", str(repo), "--json")

    assert recovered.returncode == 0, recovered.stderr
    assert json.loads(recovered.stdout)["action"] == "created"
    assert validated.returncode == 0, validated.stderr
    assert [issue["code"] for issue in json.loads(validated.stdout)["issues"]] == [
        "LEGACY_TASK_UNVERIFIABLE"
    ]
