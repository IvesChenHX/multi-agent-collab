from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": str(root / "src")}
    return subprocess.run(
        [sys.executable, "-m", "mac.cli", *args],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
    )


def test_cli_requires_frozen_repair_plan_and_explicit_run_finish_metadata(tmp_path: Path) -> None:
    repair = _run_cli(
        "doctor", "--repair-safe", "--apply", "--repo", str(tmp_path), "--json",
    )
    assert repair.returncode == 2
    assert json.loads(repair.stderr)["error"]["code"] == "DOCTOR_PLAN_DIGEST_REQUIRED"

    finish = _run_cli(
        "run", "finish", "TASK-01K0W4Z36K3W5C2R0A3M8N9P7Q",
        "RUN-01K0W4Z36K3W5C2R0A3M8N9P7Q", "--status", "succeeded", "--json",
    )
    assert finish.returncode == 2
    assert json.loads(finish.stderr)["error"]["code"] == "CLI_USAGE_ERROR"


def test_cli_bundle_verification_requires_external_trust_anchor(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.zip"
    bundle.write_bytes(b"not trusted")

    verified = _run_cli("report", "verify-bundle", str(bundle), "--json")

    assert verified.returncode == 9
    assert json.loads(verified.stderr)["error"]["code"] == "AUDIT_BUNDLE_TRUST_ANCHOR_REQUIRED"


def test_policy_compile_binds_the_selected_runtime_profile(tmp_path: Path) -> None:
    initialized = _run_cli("init", "--repo", str(tmp_path), "--json")
    assert initialized.returncode == 0, initialized.stderr
    profiles = tmp_path / ".agents/runtime-profiles"
    source = (profiles / "local-single.yaml").read_text(encoding="utf-8")
    (profiles / "isolated.yaml").write_text(
        source.replace("id: local-single", "id: isolated", 1),
        encoding="utf-8",
    )

    compiled = _run_cli(
        "policy", "compile", "--runtime-profile", "isolated",
        "--repo", str(tmp_path), "--json",
    )

    assert compiled.returncode == 0, compiled.stderr
    payload = json.loads(compiled.stdout)
    assert payload["runtime_profile"] == "isolated"
    assert ".agents/runtime-profiles/isolated.yaml" in {
        item["path"] for item in payload["policy_ref"]["files"]
    }
