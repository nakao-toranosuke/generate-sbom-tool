from __future__ import annotations

import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path

from src.core.projects.detector import (
    build_detection_warnings,
    detect_dependency_files,
    detect_dockerfiles,
    detect_ecosystems,
    detect_lockfile_status,
    detect_project_root,
)
from src.core.projects.generator import generate_project_sbom
from src.core.projects.manifest import detected_file_to_dict, write_project_detection_json
from src.core.projects.metadata import extract_project_metadata
from src.core.projects.models import (
    ProjectInspectionResult,
    ProjectMetadata,
    ProjectRunResult,
    ProjectTarget,
    ZipSafetyConfig,
)
from src.utils.fs import ensure_dir, safe_filename, utc_now_iso, write_json
from src.utils.redaction import redact_obj
from src.utils.runtime_versions import collect_runtime_versions
from src.utils.safe_zip_extract import ProjectZipValidationError, validate_and_extract_zip
from src.utils.waiting_semaphore import WaitingFileSemaphore


WORK_ROOT = Path("/tmp/work")
OUT_ROOT = Path("/tmp/out")
LOCK_ROOT = Path("/tmp/sbom-tool-locks")


def inspect_project_zip(
    original_filename: str,
    data: bytes,
    *,
    config: ZipSafetyConfig | None = None,
) -> ProjectInspectionResult:
    cfg = config or ZipSafetyConfig()

    with tempfile.TemporaryDirectory(prefix="sbom-preview-") as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "input.zip"
        zip_path.write_bytes(data)
        extract_root = tmp_path / "extracted"

        try:
            extract_result = validate_and_extract_zip(zip_path, extract_root, config=cfg)
            project_root = detect_project_root(extract_result.extracted_root)
            detected_files = detect_dependency_files(project_root, cfg)
            dockerfile_paths = detect_dockerfiles(project_root, cfg)
            ecosystems = detect_ecosystems(detected_files)
            lock_status = detect_lockfile_status(detected_files)
            warnings = build_detection_warnings(
                detected_files,
                dockerfile_paths,
                project_root,
                extract_result.extracted_root,
            )
            metadata = extract_project_metadata(project_root, detected_files)

            errors: list[str] = []
            if not detected_files:
                errors.append("No supported dependency definition files were detected.")

            project_root_path = (
                project_root.relative_to(extract_result.extracted_root).as_posix()
                if project_root != extract_result.extracted_root
                else "."
            )

            return ProjectInspectionResult(
                success=not errors,
                errors=errors,
                warnings=warnings,
                zip_size_bytes=len(data),
                project_root_path_in_zip=project_root_path,
                detected_ecosystems=ecosystems,
                detected_files=detected_files,
                lockfile_status=lock_status,
                dockerfile_detected=bool(dockerfile_paths),
                dockerfile_paths=dockerfile_paths,
                metadata=metadata,
            )
        except ProjectZipValidationError as exc:
            return ProjectInspectionResult(
                success=False,
                errors=[str(exc)],
                warnings=[],
                zip_size_bytes=len(data),
                project_root_path_in_zip=None,
                detected_ecosystems=[],
                detected_files=[],
                lockfile_status={},
                dockerfile_detected=False,
                dockerfile_paths=[],
                metadata=ProjectMetadata(),
            )


def _make_job_dirs(job_id: str) -> dict[str, Path]:
    work_dir = ensure_dir(WORK_ROOT / job_id)
    out_dir = ensure_dir(OUT_ROOT / job_id)
    return {
        "work_dir": work_dir,
        "out_dir": out_dir,
        "sbom_dir": ensure_dir(out_dir / "sbom"),
        "error_dir": ensure_dir(out_dir / "error"),
        "manifest_dir": ensure_dir(out_dir / "manifest"),
        "input_dir": ensure_dir(out_dir / "input"),
    }


def _build_artifact_zip(out_dir: Path, job_id: str) -> Path:
    artifact = out_dir / f"sbom_result_{job_id}.zip"
    with zipfile.ZipFile(artifact, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for dirname in ("sbom", "error", "manifest", "input"):
            base = out_dir / dirname
            if not base.exists():
                continue
            for path in base.rglob("*"):
                if path.is_file():
                    zf.write(path, path.relative_to(out_dir).as_posix())
    return artifact


def _write_input_summary(
    input_dir: Path,
    *,
    original_filename: str,
    inspection: ProjectInspectionResult,
) -> None:
    write_json(
        input_dir / "input_summary.json",
        {
            "original_zip_filename": original_filename,
            "zip_size_bytes": inspection.zip_size_bytes,
            "project_root_path_in_zip": inspection.project_root_path_in_zip,
            "detected_ecosystems": inspection.detected_ecosystems,
            "detected_files": [detected_file_to_dict(item) for item in inspection.detected_files],
        },
    )


def _write_result_manifest(
    manifest_dir: Path,
    *,
    job_id: str,
    started_at: str,
    result: ProjectRunResult,
    runtime_versions: dict,
) -> None:
    write_json(
        manifest_dir / "result_manifest.json",
        redact_obj(
            {
                "job_id": job_id,
                "started_at": started_at,
                "finished_at": utc_now_iso(),
                "input_mode": "project_zip",
                "status": result.status,
                "summary": {
                    "success": result.success,
                    "sbom_file": result.sbom_file.name if result.sbom_file else None,
                    "error_summary": result.error_summary,
                },
                "runtime_versions": runtime_versions,
                "warnings": result.warnings,
                "errors": [] if result.success else [result.error_summary],
            }
        ),
    )


def _failed_input_result(
    *,
    job_id: str,
    dirs: dict[str, Path],
    original_filename: str,
    inspection: ProjectInspectionResult,
    project_name: str,
    project_version: str,
    output_label: str,
    errors: list[str],
    started_at: str,
) -> ProjectRunResult:
    write_json(dirs["error_dir"] / "input_errors.json", {"errors": errors})
    write_project_detection_json(
        dirs["manifest_dir"] / "project_detection.json",
        inspection=inspection,
        original_zip_filename=original_filename,
        project_name=project_name,
        project_version=project_version,
        output_label=output_label,
        trivy_version=None,
        generated_sbom_file=None,
        postprocess_result=None,
    )

    result = ProjectRunResult(
        success=False,
        job_id=job_id,
        status="FAILED_INPUT",
        artifact_zip=None,
        sbom_file=None,
        error_summary="; ".join(errors),
        warnings=inspection.warnings,
        manifest_dir=dirs["manifest_dir"],
        out_dir=dirs["out_dir"],
    )

    _write_result_manifest(
        dirs["manifest_dir"],
        job_id=job_id,
        started_at=started_at,
        result=result,
        runtime_versions=collect_runtime_versions(),
    )

    result.artifact_zip = _build_artifact_zip(dirs["out_dir"], job_id)
    return result


def run_project_zip_job(
    *,
    original_filename: str,
    data: bytes,
    project_name: str,
    project_version: str,
    output_label: str,
    timeout_seconds: int = 3600,
    config: ZipSafetyConfig | None = None,
) -> ProjectRunResult:
    cfg = config or ZipSafetyConfig()
    job_id = uuid.uuid4().hex[:12]
    dirs = _make_job_dirs(job_id)
    started_at = utc_now_iso()

    semaphore = WaitingFileSemaphore(
        LOCK_ROOT / "jobs",
        limit=3,
        wait_seconds=1800,
        poll_seconds=2,
        stale_lock_seconds=7200,
    )

    with semaphore:
        try:
            zip_path = dirs["work_dir"] / safe_filename(original_filename, default="input.zip")
            zip_path.write_bytes(data)
            extract_root = dirs["work_dir"] / "extracted"

            extract_result = validate_and_extract_zip(zip_path, extract_root, config=cfg)
            project_root = detect_project_root(extract_result.extracted_root)
            detected_files = detect_dependency_files(project_root, cfg)
            dockerfile_paths = detect_dockerfiles(project_root, cfg)
            ecosystems = detect_ecosystems(detected_files)
            lock_status = detect_lockfile_status(detected_files)
            warnings = build_detection_warnings(
                detected_files,
                dockerfile_paths,
                project_root,
                extract_result.extracted_root,
            )
            metadata = extract_project_metadata(project_root, detected_files)

            project_root_path = (
                project_root.relative_to(extract_result.extracted_root).as_posix()
                if project_root != extract_result.extracted_root
                else "."
            )

            errors: list[str] = []
            if not detected_files:
                errors.append("No supported dependency definition files were detected.")
            if not project_name.strip():
                errors.append("Project name is required.")
            if not project_version.strip():
                errors.append("Project version is required.")
            if not output_label.strip():
                errors.append("Output label is required.")

            inspection = ProjectInspectionResult(
                success=not errors,
                errors=errors,
                warnings=warnings,
                zip_size_bytes=len(data),
                project_root_path_in_zip=project_root_path,
                detected_ecosystems=ecosystems,
                detected_files=detected_files,
                lockfile_status=lock_status,
                dockerfile_detected=bool(dockerfile_paths),
                dockerfile_paths=dockerfile_paths,
                metadata=metadata,
            )

            _write_input_summary(
                dirs["input_dir"],
                original_filename=original_filename,
                inspection=inspection,
            )

            if errors:
                return _failed_input_result(
                    job_id=job_id,
                    dirs=dirs,
                    original_filename=original_filename,
                    inspection=inspection,
                    project_name=project_name,
                    project_version=project_version,
                    output_label=output_label,
                    errors=errors,
                    started_at=started_at,
                )

            target = ProjectTarget(
                project_name=project_name.strip(),
                project_version=project_version.strip(),
                output_label=output_label.strip(),
                original_zip_filename=original_filename,
                zip_size_bytes=len(data),
                project_root_path_in_zip=inspection.project_root_path_in_zip or ".",
                extracted_project_root=project_root,
                detected_ecosystems=ecosystems,
                detected_files=detected_files,
                warnings=warnings,
                dockerfile_detected=bool(dockerfile_paths),
            )

            result = generate_project_sbom(
                job_id=job_id,
                target=target,
                out_dir=dirs["out_dir"],
                work_dir=dirs["work_dir"],
                timeout_seconds=timeout_seconds,
            )

            runtime_versions = collect_runtime_versions()
            write_project_detection_json(
                dirs["manifest_dir"] / "project_detection.json",
                inspection=inspection,
                original_zip_filename=original_filename,
                project_name=project_name,
                project_version=project_version,
                output_label=output_label,
                trivy_version=runtime_versions.get("trivy_version"),
                generated_sbom_file=result.sbom_file.name if result.sbom_file else None,
                postprocess_result={
                    "success": result.success,
                    "status": result.status,
                    "error_summary": result.error_summary,
                },
            )

            _write_result_manifest(
                dirs["manifest_dir"],
                job_id=job_id,
                started_at=started_at,
                result=result,
                runtime_versions=runtime_versions,
            )

            result.artifact_zip = _build_artifact_zip(dirs["out_dir"], job_id)
            result.manifest_dir = dirs["manifest_dir"]
            result.out_dir = dirs["out_dir"]
            return result

        except ProjectZipValidationError as exc:
            inspection = ProjectInspectionResult(
                success=False,
                errors=[str(exc)],
                warnings=[],
                zip_size_bytes=len(data),
                project_root_path_in_zip=None,
                detected_ecosystems=[],
                detected_files=[],
                lockfile_status={},
                dockerfile_detected=False,
                dockerfile_paths=[],
                metadata=ProjectMetadata(),
            )
            return _failed_input_result(
                job_id=job_id,
                dirs=dirs,
                original_filename=original_filename,
                inspection=inspection,
                project_name=project_name,
                project_version=project_version,
                output_label=output_label,
                errors=[str(exc)],
                started_at=started_at,
            )
        finally:
            shutil.rmtree(dirs["work_dir"], ignore_errors=True)
