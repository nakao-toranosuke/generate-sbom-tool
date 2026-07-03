from __future__ import annotations

import os
import subprocess
from pathlib import Path

from src.core.projects.models import TrivyRunResult
from src.utils.redaction import redact_text


def run_trivy_fs(
    project_root: Path,
    output_file: Path,
    *,
    timeout_seconds: int = 3600,
    cache_dir: Path | None = None,
) -> TrivyRunResult:
    output_file.parent.mkdir(parents=True, exist_ok=True)

    command = [
        "trivy",
        "fs",
        "--format",
        "spdx-json",
        "--output",
        str(output_file),
        str(project_root),
    ]

    env = os.environ.copy()
    if cache_dir is not None:
        cache_dir.mkdir(parents=True, exist_ok=True)
        env["TRIVY_CACHE_DIR"] = str(cache_dir)

    try:
        completed = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
            env=env,
        )
    except FileNotFoundError:
        return TrivyRunResult(
            success=False,
            command=command,
            returncode=None,
            stdout="",
            stderr="trivy command was not found",
            output_file=None,
            error_summary="trivy command was not found",
        )
    except subprocess.TimeoutExpired as exc:
        return TrivyRunResult(
            success=False,
            command=command,
            returncode=None,
            stdout=redact_text(exc.stdout or ""),
            stderr=redact_text(exc.stderr or ""),
            output_file=None,
            error_summary=f"trivy fs timed out after {timeout_seconds} seconds",
        )

    stdout = redact_text(completed.stdout or "")
    stderr = redact_text(completed.stderr or "")
    success = completed.returncode == 0 and output_file.exists()

    return TrivyRunResult(
        success=success,
        command=command,
        returncode=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        output_file=output_file if success else None,
        error_summary=None if success else stderr.splitlines()[-1] if stderr else "trivy fs failed",
    )
