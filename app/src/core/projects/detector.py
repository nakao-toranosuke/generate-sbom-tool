from __future__ import annotations

import fnmatch
from pathlib import Path

from src.core.projects.models import DetectedFile, ZipSafetyConfig
from src.utils.fs import posix_relpath


_DETECTION_RULES: tuple[tuple[str, str, str], ...] = (
    ("requirements.txt", "Python", "manifest"),
    ("pyproject.toml", "Python", "manifest"),
    ("uv.lock", "Python", "lockfile"),
    ("poetry.lock", "Python", "lockfile"),
    ("Pipfile.lock", "Python", "lockfile"),
    ("package.json", "Node.js", "manifest"),
    ("package-lock.json", "Node.js", "lockfile"),
    ("yarn.lock", "Node.js", "lockfile"),
    ("pnpm-lock.yaml", "Node.js", "lockfile"),
    ("npm-shrinkwrap.json", "Node.js", "lockfile"),
    ("pom.xml", "Java", "manifest"),
    ("go.mod", "Go", "manifest"),
    ("go.sum", "Go", "lockfile"),
    ("composer.json", "PHP", "manifest"),
    ("composer.lock", "PHP", "lockfile"),
    ("Gemfile", "Ruby", "manifest"),
    ("Gemfile.lock", "Ruby", "lockfile"),
    ("Cargo.toml", "Rust", "manifest"),
    ("Cargo.lock", "Rust", "lockfile"),
    ("*.csproj", ".NET", "manifest"),
    ("*.fsproj", ".NET", "manifest"),
    ("*.vbproj", ".NET", "manifest"),
    ("packages.lock.json", ".NET", "lockfile"),
    ("packages.config", ".NET", "manifest"),
)


def detect_project_root(extracted_root: Path) -> Path:
    children = [child for child in extracted_root.iterdir() if child.name not in {".DS_Store"}]
    dirs = [child for child in children if child.is_dir()]
    files = [child for child in children if child.is_file()]
    if len(dirs) == 1 and not files:
        return dirs[0]
    return extracted_root


def _walk_files(root: Path, config: ZipSafetyConfig | None = None) -> list[Path]:
    cfg = config or ZipSafetyConfig()
    files: list[Path] = []
    for current, dirs, names in root.walk():
        dirs[:] = [d for d in dirs if d not in cfg.exclude_dirs]
        for name in names:
            files.append(current / name)
    return files


def detect_dependency_files(project_root: Path, config: ZipSafetyConfig | None = None) -> list[DetectedFile]:
    detected: list[DetectedFile] = []
    for path in _walk_files(project_root, config):
        filename = path.name
        rel = posix_relpath(path, project_root)
        for pattern, ecosystem, kind in _DETECTION_RULES:
            if fnmatch.fnmatch(filename, pattern):
                detected.append(DetectedFile(path=rel, ecosystem=ecosystem, kind=kind))
                break
    return sorted(detected, key=lambda item: (item.ecosystem, item.path))


def detect_ecosystems(detected_files: list[DetectedFile]) -> list[str]:
    return sorted({item.ecosystem for item in detected_files})


def detect_dockerfiles(project_root: Path, config: ZipSafetyConfig | None = None) -> list[str]:
    dockerfiles: list[str] = []
    for path in _walk_files(project_root, config):
        if path.name == "Dockerfile" or path.name.startswith("Dockerfile."):
            dockerfiles.append(posix_relpath(path, project_root))
    return sorted(dockerfiles)


def detect_lockfile_status(detected_files: list[DetectedFile]) -> dict[str, dict[str, object]]:
    status: dict[str, dict[str, object]] = {}
    for item in detected_files:
        entry = status.setdefault(
            item.ecosystem,
            {"has_manifest": False, "has_lockfile": False, "manifest_files": [], "lock_files": []},
        )
        if item.kind == "lockfile":
            entry["has_lockfile"] = True
            entry["lock_files"].append(item.path)
        else:
            entry["has_manifest"] = True
            entry["manifest_files"].append(item.path)
    return status


def build_detection_warnings(
    detected_files: list[DetectedFile],
    dockerfile_paths: list[str],
    project_root: Path,
    extracted_root: Path,
) -> list[str]:
    warnings: list[str] = []
    lock_status = detect_lockfile_status(detected_files)

    for ecosystem, status in lock_status.items():
        if status.get("has_manifest") and not status.get("has_lockfile"):
            warnings.append(f"{ecosystem}: lockfile was not detected.")

    if dockerfile_paths:
        warnings.append("Dockerfile was detected, but container image build is not performed.")

    if len(detect_ecosystems(detected_files)) > 1:
        warnings.append("Multiple ecosystems were detected. A single integrated SBOM will be generated.")

    if project_root == extracted_root:
        top_level_dirs = [p for p in extracted_root.iterdir() if p.is_dir()]
        if len(top_level_dirs) > 1:
            warnings.append("Multiple project candidates were detected. The common root will be scanned.")

    return warnings
