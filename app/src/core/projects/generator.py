from __future__ import annotations

from pathlib import Path

from src.core.projects.models import ProjectTarget, ProjectRunResult
from src.core.sbom_sanitizer import sanitize_sbom
from src.core.trivy_runner import run_trivy_fs
from src.naming.sbom_name import project_sbom_filename


def generate_project_sbom(
    *,
    job_id: str,
    target: ProjectTarget,
    out_dir: Path,
    work_dir: Path,
    timeout_seconds: int = 3600,
) -> ProjectRunResult:
    sbom_dir = out_dir / "sbom"
    error_dir = out_dir / "error"
    cache_dir = work_dir / "trivy-cache"
    raw_sbom = work_dir / "raw_sbom.spdx.json"

    filename = project_sbom_filename(target.output_label, target.project_name, target.project_version)
    sanitized_sbom = sbom_dir / filename

    trivy_result = run_trivy_fs(
        target.extracted_project_root,
        raw_sbom,
        timeout_seconds=timeout_seconds,
        cache_dir=cache_dir,
    )

    if not trivy_result.success:
        error_dir.mkdir(parents=True, exist_ok=True)
        (error_dir / "stdout.txt").write_text(trivy_result.stdout, encoding="utf-8")
        (error_dir / "stderr.txt").write_text(trivy_result.stderr, encoding="utf-8")
        return ProjectRunResult(
            success=False,
            job_id=job_id,
            status="FAILED_TOOL",
            artifact_zip=None,
            sbom_file=None,
            error_summary=trivy_result.error_summary,
            warnings=target.warnings,
            out_dir=out_dir,
        )

    sanitized = sanitize_sbom(
        raw_sbom,
        sanitized_sbom,
        document_name=f"{target.project_name}@{target.project_version}",
    )

    if not sanitized.success:
        error_dir.mkdir(parents=True, exist_ok=True)
        (error_dir / "postprocess_error.log").write_text(
            sanitized.error_summary or "postprocess failed",
            encoding="utf-8",
        )
        return ProjectRunResult(
            success=False,
            job_id=job_id,
            status="FAILED_TOOL",
            artifact_zip=None,
            sbom_file=None,
            error_summary=sanitized.error_summary,
            warnings=target.warnings,
            out_dir=out_dir,
        )

    return ProjectRunResult(
        success=True,
        job_id=job_id,
        status="SUCCESS",
        artifact_zip=None,
        sbom_file=sanitized.sbom_path,
        error_summary=None,
        warnings=target.warnings + sanitized.warnings,
        out_dir=out_dir,
    )
