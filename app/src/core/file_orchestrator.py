from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from src.core.package_orchestrator import (
    _create_artifact_zip,
    _postprocess_spdx,
    _run_to_log,
    _safe_filename_part,
)


WORK_ROOT = Path(os.environ.get("SBOM_WORK_ROOT", "/tmp/work"))
OUT_ROOT = Path(os.environ.get("SBOM_OUT_ROOT", "/tmp/out"))

MAX_FILE_BYTES = int(os.environ.get("SBOM_FILE_MAX_BYTES", str(200 * 1024 * 1024)))


@dataclass(frozen=True)
class FileRequest:
    original_filename: str
    stored_filename: str
    display_name: str
    version: str
    output_label: str
    size_bytes: int


@dataclass
class FileJobResult:
    success: bool
    status: str
    job_id: str
    sbom_file: Path | None = None
    artifact_zip: Path | None = None
    manifest_file: Path | None = None
    error_summary: str | None = None
    warnings: list[str] = field(default_factory=list)


class FileGenerationError(RuntimeError):
    pass


def run_file_job(
    *,
    original_filename: str,
    data: bytes,
    output_label: str = "file",
    display_name: str | None = None,
    version: str | None = None,
) -> FileJobResult:
    job_id = uuid.uuid4().hex[:12]

    job_work_root = WORK_ROOT / job_id
    work_dir = job_work_root / "workspace"

    job_out_root = OUT_ROOT / job_id
    sbom_dir = job_out_root / "sbom"
    error_dir = job_out_root / "error"
    manifest_dir = job_out_root / "manifest"
    input_dir = job_out_root / "input"
    log_dir = job_out_root / "logs"

    for path in (work_dir, sbom_dir, error_dir, manifest_dir, input_dir, log_dir):
        path.mkdir(parents=True, exist_ok=True)

    request: FileRequest | None = None

    try:
        request = _normalize_file_request(
            original_filename=original_filename,
            data=data,
            output_label=output_label,
            display_name=display_name,
            version=version,
        )

        input_file = work_dir / request.stored_filename
        input_file.write_bytes(data)

        _write_input_summary(request, input_dir)

        raw_sbom = sbom_dir / "raw_sbom.spdx.json"
        final_sbom = sbom_dir / _output_filename(request)

        _run_trivy_file(input_file, raw_sbom, log_dir)
        _postprocess_spdx(raw_sbom, final_sbom)

        if raw_sbom.exists() and raw_sbom != final_sbom:
            raw_sbom.unlink()

        manifest_file = _write_manifest(
            request=request,
            job_id=job_id,
            status="SUCCESS",
            manifest_dir=manifest_dir,
            sbom_file=final_sbom,
            error_summary=None,
            warnings=[],
        )

        artifact_zip = _create_artifact_zip(job_id, job_out_root)

        return FileJobResult(
            success=True,
            status="SUCCESS",
            job_id=job_id,
            sbom_file=final_sbom,
            artifact_zip=artifact_zip,
            manifest_file=manifest_file,
            warnings=[],
        )

    except Exception as exc:
        error_summary = str(exc)
        (error_dir / "error_summary.txt").write_text(error_summary + "\n", encoding="utf-8")

        manifest_file = _write_manifest(
            request=request,
            job_id=job_id,
            status="FAILED",
            manifest_dir=manifest_dir,
            sbom_file=None,
            error_summary=error_summary,
            warnings=[],
        )

        artifact_zip = _create_artifact_zip(job_id, job_out_root)

        return FileJobResult(
            success=False,
            status="FAILED",
            job_id=job_id,
            artifact_zip=artifact_zip,
            manifest_file=manifest_file,
            error_summary=error_summary,
            warnings=[],
        )


def _normalize_file_request(
    *,
    original_filename: str,
    data: bytes,
    output_label: str,
    display_name: str | None,
    version: str | None,
) -> FileRequest:
    if not data:
        raise FileGenerationError("Input file is empty.")

    if len(data) > MAX_FILE_BYTES:
        raise FileGenerationError(
            f"Input file is too large. Max size is {MAX_FILE_BYTES} bytes."
        )

    safe_original = _original_basename(original_filename)
    stored_filename = _stored_filename(safe_original)

    normalized_display_name = (display_name or Path(safe_original).stem or "file").strip()
    normalized_version = (version or "unknown").strip()
    normalized_output_label = (output_label or "file").strip()

    if not normalized_display_name:
        normalized_display_name = "file"

    if not normalized_version:
        normalized_version = "unknown"

    if not normalized_output_label:
        normalized_output_label = "file"

    return FileRequest(
        original_filename=safe_original,
        stored_filename=stored_filename,
        display_name=normalized_display_name,
        version=normalized_version,
        output_label=normalized_output_label,
        size_bytes=len(data),
    )


def _original_basename(original_filename: str) -> str:
    value = (original_filename or "").replace("\\", "/").split("/")[-1].strip()

    if "\x00" in value:
        raise FileGenerationError("Input filename contains an invalid character.")

    if not value or value in {".", ".."}:
        raise FileGenerationError("Input filename is required.")

    return value


def _stored_filename(original_filename: str) -> str:
    path = Path(original_filename)
    stem = _safe_filename_part(path.stem or "input-file")
    suffix = re.sub(r"[^A-Za-z0-9.]+", "", path.suffix)[:32]
    return f"{stem}{suffix}" if suffix else stem


def _run_trivy_file(input_file: Path, output_path: Path, log_dir: Path) -> None:
    _run_to_log(
        [
            "trivy",
            "fs",
            "--quiet",
            "--format",
            "spdx-json",
            "--output",
            str(output_path),
            str(input_file),
        ],
        input_file.parent,
        log_dir / "trivy_file.log",
        timeout=1200,
    )

    if not output_path.exists():
        raise FileGenerationError("Trivy did not create an SPDX JSON file.")


def _write_input_summary(request: FileRequest, input_dir: Path) -> None:
    summary = {
        "mode": "file",
        "ecosystem": "file",
        "original_filename": request.original_filename,
        "stored_filename": request.stored_filename,
        "display_name": request.display_name,
        "version": request.version,
        "output_label": request.output_label,
        "size_bytes": request.size_bytes,
    }
    (input_dir / "input_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _write_manifest(
    *,
    request: FileRequest | None,
    job_id: str,
    status: str,
    manifest_dir: Path,
    sbom_file: Path | None,
    error_summary: str | None,
    warnings: list[str],
) -> Path:
    manifest = {
        "job_id": job_id,
        "status": status,
        "mode": "file",
        "ecosystem": "file",
        "ecosystem_label": "File",
        "original_filename": request.original_filename if request else None,
        "stored_filename": request.stored_filename if request else None,
        "display_name": request.display_name if request else None,
        "version": request.version if request else None,
        "output_label": request.output_label if request else None,
        "size_bytes": request.size_bytes if request else None,
        "sbom_file": sbom_file.name if sbom_file else None,
        "error_summary": error_summary,
        "warnings": warnings,
    }
    manifest_file = manifest_dir / "result_manifest.json"
    manifest_file.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest_file


def _output_filename(request: FileRequest) -> str:
    label = _safe_filename_part(request.output_label)
    ecosystem = "File"
    name = _safe_filename_part(request.display_name)
    version = _safe_filename_part(request.version)
    return f"{label}__{ecosystem}__{name}@{version}.spdx.json"
