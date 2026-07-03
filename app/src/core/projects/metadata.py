from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

from src.core.projects.models import DetectedFile, ProjectMetadata


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _xml_local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _find_child_text(root: ET.Element, name: str) -> str | None:
    for child in root:
        if _xml_local_name(child.tag) == name and child.text:
            return child.text.strip()
    return None


def _extract_package_json(project_root: Path, detected_files: list[DetectedFile]) -> ProjectMetadata | None:
    for item in detected_files:
        if Path(item.path).name == "package.json":
            path = project_root / item.path
            data = _load_json(path)
            name = data.get("name")
            version = data.get("version")
            if name or version:
                return ProjectMetadata(name=name, version=version, source_file=item.path, source_type="package.json")
    return None


def _extract_pyproject(project_root: Path, detected_files: list[DetectedFile]) -> ProjectMetadata | None:
    for item in detected_files:
        if Path(item.path).name == "pyproject.toml":
            path = project_root / item.path
            try:
                data = tomllib.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            project = data.get("project", {})
            name = project.get("name")
            version = project.get("version")
            if name or version:
                return ProjectMetadata(name=name, version=version, source_file=item.path, source_type="pyproject.toml")
    return None


def _extract_pom(project_root: Path, detected_files: list[DetectedFile]) -> ProjectMetadata | None:
    for item in detected_files:
        if Path(item.path).name == "pom.xml":
            path = project_root / item.path
            try:
                root = ET.fromstring(path.read_text(encoding="utf-8"))
            except Exception:
                continue

            artifact_id = _find_child_text(root, "artifactId")
            version = _find_child_text(root, "version")

            if not version:
                for child in root:
                    if _xml_local_name(child.tag) == "parent":
                        version = _find_child_text(child, "version")
                        break

            if artifact_id or version:
                return ProjectMetadata(name=artifact_id, version=version, source_file=item.path, source_type="pom.xml")
    return None


def _extract_go_mod(project_root: Path, detected_files: list[DetectedFile]) -> ProjectMetadata | None:
    for item in detected_files:
        if Path(item.path).name == "go.mod":
            path = project_root / item.path
            text = path.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"^module\s+(.+)$", text, flags=re.MULTILINE)
            if match:
                return ProjectMetadata(
                    name=match.group(1).strip(),
                    version=None,
                    source_file=item.path,
                    source_type="go.mod",
                )
    return None


def _extract_csproj(project_root: Path, detected_files: list[DetectedFile]) -> ProjectMetadata | None:
    for item in detected_files:
        if item.path.endswith((".csproj", ".fsproj", ".vbproj")):
            path = project_root / item.path
            try:
                root = ET.fromstring(path.read_text(encoding="utf-8"))
            except Exception:
                continue

            values: dict[str, str] = {}
            for elem in root.iter():
                local = _xml_local_name(elem.tag)
                if elem.text and local in {"AssemblyName", "Version", "PackageVersion"}:
                    values[local] = elem.text.strip()

            name = values.get("AssemblyName") or Path(item.path).stem
            version = values.get("Version") or values.get("PackageVersion")
            return ProjectMetadata(name=name, version=version, source_file=item.path, source_type=Path(item.path).suffix)
    return None


def extract_project_metadata(project_root: Path, detected_files: list[DetectedFile]) -> ProjectMetadata:
    for extractor in (
        _extract_package_json,
        _extract_pom,
        _extract_pyproject,
        _extract_go_mod,
        _extract_csproj,
    ):
        metadata = extractor(project_root, detected_files)
        if metadata:
            return metadata
    return ProjectMetadata()
