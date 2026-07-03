from __future__ import annotations

import os
import re
import shutil
import stat
import zipfile
from pathlib import Path

from src.core.projects.models import ExtractResult, ZipSafetyConfig


class ProjectZipValidationError(ValueError):
    pass


_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def _is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _normalize_zip_name(name: str) -> str:
    return name.replace("\\", "/")


def _is_absolute_member(name: str) -> bool:
    normalized = _normalize_zip_name(name)
    return normalized.startswith("/") or normalized.startswith("//") or bool(_WINDOWS_DRIVE_RE.match(normalized))


def _has_path_traversal(name: str) -> bool:
    normalized = _normalize_zip_name(name)
    return any(part == ".." for part in normalized.split("/"))


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return stat.S_ISLNK(mode)


def _is_excluded(name: str, exclude_dirs: tuple[str, ...]) -> bool:
    parts = [part for part in _normalize_zip_name(name).split("/") if part]
    return any(part in exclude_dirs for part in parts)


def validate_and_extract_zip(
    zip_path: Path,
    dest_dir: Path,
    *,
    config: ZipSafetyConfig | None = None,
) -> ExtractResult:
    cfg = config or ZipSafetyConfig()

    zip_size_mb = zip_path.stat().st_size / (1024 * 1024)
    if zip_size_mb > cfg.max_zip_upload_mb:
        raise ProjectZipValidationError(
            f"ZIP size exceeds limit: {zip_size_mb:.1f}MB > {cfg.max_zip_upload_mb}MB"
        )

    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        raise ProjectZipValidationError("Invalid or broken ZIP file") from exc

    with zf:
        infos = zf.infolist()
        file_infos = [info for info in infos if not info.is_dir()]

        if len(file_infos) > cfg.max_file_count:
            raise ProjectZipValidationError(
                f"File count exceeds limit: {len(file_infos)} > {cfg.max_file_count}"
            )

        total_expanded = sum(info.file_size for info in file_infos)
        if total_expanded > cfg.max_expanded_mb * 1024 * 1024:
            raise ProjectZipValidationError(
                f"Expanded size exceeds limit: {total_expanded} bytes"
            )

        for info in file_infos:
            name = _normalize_zip_name(info.filename)

            if cfg.reject_absolute_path and _is_absolute_member(name):
                raise ProjectZipValidationError(f"Absolute path member is not allowed: {name}")

            if cfg.reject_path_traversal and _has_path_traversal(name):
                raise ProjectZipValidationError(f"Path traversal member is not allowed: {name}")

            if cfg.reject_symlink and _is_symlink(info):
                raise ProjectZipValidationError(
                    "ZIP contains symlink. Symlinks are not allowed for safety."
                )

            if info.file_size > cfg.max_single_file_mb * 1024 * 1024:
                raise ProjectZipValidationError(f"Single file exceeds limit: {name}")

        extracted_bytes = 0
        extracted_count = 0
        skipped_paths: list[str] = []
        root = dest_dir.resolve()
        root.mkdir(parents=True, exist_ok=True)

        for info in file_infos:
            name = _normalize_zip_name(info.filename)
            if _is_excluded(name, cfg.exclude_dirs):
                skipped_paths.append(name)
                continue

            target = (root / name).resolve()
            if not _is_relative_to(target, root):
                raise ProjectZipValidationError(f"Resolved path escapes extraction root: {name}")

            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)

            try:
                os.chmod(target, 0o600)
            except OSError:
                pass

            extracted_count += 1
            extracted_bytes += info.file_size

    return ExtractResult(
        extracted_root=dest_dir,
        original_file_count=len(file_infos),
        extracted_file_count=extracted_count,
        original_expanded_bytes=total_expanded,
        extracted_bytes=extracted_bytes,
        skipped_paths=skipped_paths,
    )
