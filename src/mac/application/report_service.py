from __future__ import annotations

from pathlib import Path
from typing import Any

from mac.report import build_audit_bundle, render_task_report, verify_audit_bundle


class ReportService:
    def render(self, task_dir: Path) -> str:
        return render_task_report(task_dir)

    def bundle(self, task_dir: Path, out_path: Path, *, redact: bool = True) -> dict[str, Any]:
        return build_audit_bundle(task_dir, out_path, redact=redact)

    def verify_bundle(self, bundle_path: Path) -> dict[str, Any]:
        return verify_audit_bundle(bundle_path)
