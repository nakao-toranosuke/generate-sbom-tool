from __future__ import annotations

from src.utils.fs import safe_filename


def project_sbom_filename(output_label: str, project_name: str, version: str) -> str:
    label = safe_filename(output_label, default="output")
    name = safe_filename(project_name, default="project")
    ver = safe_filename(version, default="0.0.0")
    return f"{label}__Project__{name}@{ver}.spdx.json"
