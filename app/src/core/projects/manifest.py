from __future__ import annotations

from pathlib import Path
from typing import Any

from src.core.projects.models import ProjectInspectionResult, ProjectTarget
from src.utils.fs import write_json


def detected_file_to_dict(item) -> dict[str, str]:
    return {
        "path": item.path,
        "ecosystem": item.ecosystem,
        "kind": item.kind,
    }


def write_project_detection_json(
    path: Path,
    *,
    inspection: ProjectInspectionResult,
    original_zip_filename: str,
    project_name: str,
    project_version: str,
    output_label: str,
    trivy_version: str | None,
    generated_sbom_file: str | None,
    postprocess_result: dict[str, Any] | None,
) -> None:
    write_json(
        path,
        {
            "input_type": "project_zip",
            "original_zip_filename": original_zip_filename,
            "zip_size_bytes": inspection.zip_size_bytes,
            "project_name": project_name,
            "project_version": project_version,
            "output_label": output_label,
            "metadata_source": "manual_or_default",
            "auto_metadata": {
                "name": inspection.metadata.name,
                "version": inspection.metadata.version,
                "source_file": inspection.metadata.source_file,
                "source_type": inspection.metadata.source_type,
            },
            "project_root_path_in_zip": inspection.project_root_path_in_zip,
            "detected_ecosystems": inspection.detected_ecosystems,
            "detected_files": [detected_file_to_dict(item) for item in inspection.detected_files],
            "lockfile_status": inspection.lockfile_status,
            "dockerfile_detected": inspection.dockerfile_detected,
            "dockerfile_paths": inspection.dockerfile_paths,
            "warnings": inspection.warnings,
            "errors": inspection.errors,
            "trivy_version": trivy_version,
            "generated_sbom_file": generated_sbom_file,
            "postprocess_result": postprocess_result,
        },
    )


def project_target_to_dict(target: ProjectTarget) -> dict[str, Any]:
    return {
        "project_name": target.project_name,
        "project_version": target.project_version,
        "output_label": target.output_label,
        "original_zip_filename": target.original_zip_filename,
        "zip_size_bytes": target.zip_size_bytes,
        "project_root_path_in_zip": target.project_root_path_in_zip,
        "detected_ecosystems": target.detected_ecosystems,
        "detected_files": [detected_file_to_dict(item) for item in target.detected_files],
        "warnings": target.warnings,
        "dockerfile_detected": target.dockerfile_detected,
    }
