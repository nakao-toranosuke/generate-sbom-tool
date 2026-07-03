from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ZipSafetyConfig:
    max_zip_upload_mb: int = 200
    max_expanded_mb: int = 1024
    max_file_count: int = 30000
    max_single_file_mb: int = 200
    reject_symlink: bool = True
    reject_absolute_path: bool = True
    reject_path_traversal: bool = True
    exclude_dirs: tuple[str, ...] = (
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "target",
        "build",
        "dist",
        ".gradle",
        ".m2",
        "__pycache__",
        ".pytest_cache",
        "coverage",
        ".next",
    )


@dataclass
class ExtractResult:
    extracted_root: Path
    original_file_count: int
    extracted_file_count: int
    original_expanded_bytes: int
    extracted_bytes: int
    skipped_paths: list[str] = field(default_factory=list)


@dataclass
class DetectedFile:
    path: str
    ecosystem: str
    kind: str


@dataclass
class ProjectMetadata:
    name: str | None = None
    version: str | None = None
    source_file: str | None = None
    source_type: str | None = None


@dataclass
class ProjectInspectionResult:
    success: bool
    errors: list[str]
    warnings: list[str]
    zip_size_bytes: int
    project_root_path_in_zip: str | None
    detected_ecosystems: list[str]
    detected_files: list[DetectedFile]
    lockfile_status: dict[str, Any]
    dockerfile_detected: bool
    dockerfile_paths: list[str]
    metadata: ProjectMetadata


@dataclass
class ProjectTarget:
    project_name: str
    project_version: str
    output_label: str
    original_zip_filename: str
    zip_size_bytes: int
    project_root_path_in_zip: str
    extracted_project_root: Path
    detected_ecosystems: list[str]
    detected_files: list[DetectedFile]
    warnings: list[str]
    dockerfile_detected: bool
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrivyRunResult:
    success: bool
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    output_file: Path | None
    error_summary: str | None = None


@dataclass
class SanitizedSbomResult:
    success: bool
    sbom_path: Path | None
    removed_package_count: int = 0
    removed_relationship_count: int = 0
    warnings: list[str] = field(default_factory=list)
    document_describes: list[str] = field(default_factory=list)
    error_summary: str | None = None


@dataclass
class ProjectRunResult:
    success: bool
    job_id: str
    status: str
    artifact_zip: Path | None
    sbom_file: Path | None
    error_summary: str | None
    warnings: list[str] = field(default_factory=list)
    manifest_dir: Path | None = None
    out_dir: Path | None = None
