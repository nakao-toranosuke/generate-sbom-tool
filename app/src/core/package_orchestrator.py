from __future__ import annotations

import json
import os
import re
import subprocess
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path


WORK_ROOT = Path(os.environ.get("SBOM_WORK_ROOT", "/tmp/work"))
OUT_ROOT = Path(os.environ.get("SBOM_OUT_ROOT", "/tmp/out"))

ECOSYSTEM_LABELS = {
    "pypi": "Python",
    "npm": "Node.js",
    "maven": "Java",
    "composer": "PHP",
    "gem": "Ruby",
    "cargo": "Rust",
    "golang": "Go",
    "nuget": ".NET",
}

NOISE_PACKAGE_NAMES = {
    "sbom-stub",
    "local/sbom-stub",
    "standalone-pom",
    "uv.lock",
    "package-lock.json",
    "composer.lock",
    "gemfile.lock",
    "cargo.lock",
    "go.sum",
    "packages.lock.json",
    "pom.xml",
}


@dataclass(frozen=True)
class PackageRequest:
    ecosystem: str
    name: str
    version: str
    output_label: str = "package"
    group_id: str | None = None
    artifact_id: str | None = None


@dataclass
class PackageJobResult:
    success: bool
    status: str
    job_id: str
    sbom_file: Path | None = None
    artifact_zip: Path | None = None
    manifest_file: Path | None = None
    error_summary: str | None = None
    warnings: list[str] = field(default_factory=list)


class PackageGenerationError(RuntimeError):
    pass


def run_package_job(
    *,
    ecosystem: str,
    name: str,
    version: str,
    output_label: str = "package",
    group_id: str | None = None,
    artifact_id: str | None = None,
) -> PackageJobResult:
    request = PackageRequest(
        ecosystem=ecosystem,
        name=name,
        version=version,
        output_label=output_label,
        group_id=group_id,
        artifact_id=artifact_id,
    )
    return run_package_request(request)


def run_package_request(input_request: PackageRequest) -> PackageJobResult:
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

    request = input_request

    try:
        request = _normalize_request(input_request)
        _write_input_summary(request, input_dir)
        _prepare_workspace(request, work_dir, log_dir)

        raw_sbom = sbom_dir / "raw_sbom.spdx.json"
        final_sbom = sbom_dir / _output_filename(request)

        _run_trivy(work_dir, raw_sbom, log_dir)
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

        return PackageJobResult(
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

        return PackageJobResult(
            success=False,
            status="FAILED",
            job_id=job_id,
            artifact_zip=artifact_zip,
            manifest_file=manifest_file,
            error_summary=error_summary,
            warnings=[],
        )


def _normalize_request(request: PackageRequest) -> PackageRequest:
    ecosystem = request.ecosystem.strip().lower()
    if ecosystem == "go":
        ecosystem = "golang"

    name = request.name.strip()
    version = request.version.strip()
    output_label = request.output_label.strip() or "package"

    if ecosystem not in ECOSYSTEM_LABELS:
        allowed = ", ".join(sorted(ECOSYSTEM_LABELS))
        raise PackageGenerationError(f"Unsupported ecosystem: {request.ecosystem}. Allowed: {allowed}")

    if not name:
        raise PackageGenerationError("Package name is required.")

    if not version:
        raise PackageGenerationError("Package version is required.")

    group_id = request.group_id.strip() if request.group_id else None
    artifact_id = request.artifact_id.strip() if request.artifact_id else None

    if ecosystem == "maven":
        if not group_id or not artifact_id:
            parts = name.split(":")
            if len(parts) == 2 and parts[0].strip() and parts[1].strip():
                group_id = parts[0].strip()
                artifact_id = parts[1].strip()
            else:
                raise PackageGenerationError(
                    "Maven package must be specified as groupId:artifactId or with group_id and artifact_id."
                )
        name = f"{group_id}:{artifact_id}"

    return PackageRequest(
        ecosystem=ecosystem,
        name=name,
        version=version,
        output_label=output_label,
        group_id=group_id,
        artifact_id=artifact_id,
    )


def _prepare_workspace(request: PackageRequest, work_dir: Path, log_dir: Path) -> None:
    if request.ecosystem == "pypi":
        _prepare_python_workspace(request, work_dir, log_dir)
        return

    if request.ecosystem == "npm":
        _prepare_npm_workspace(request, work_dir, log_dir)
        return

    if request.ecosystem == "maven":
        _prepare_maven_workspace(request, work_dir, log_dir)
        return

    if request.ecosystem == "composer":
        _prepare_composer_workspace(request, work_dir, log_dir)
        return

    if request.ecosystem == "gem":
        _prepare_gem_workspace(request, work_dir, log_dir)
        return

    if request.ecosystem == "cargo":
        _prepare_cargo_workspace(request, work_dir, log_dir)
        return

    if request.ecosystem == "golang":
        _prepare_golang_workspace(request, work_dir, log_dir)
        return

    if request.ecosystem == "nuget":
        _prepare_nuget_workspace(request, work_dir, log_dir)
        return

    raise PackageGenerationError(f"Unsupported ecosystem: {request.ecosystem}")


def _prepare_python_workspace(request: PackageRequest, work_dir: Path, log_dir: Path) -> None:
    dependency = f"{request.name}=={request.version}"
    lines = [
        "[project]",
        'name = "sbom-stub"',
        'version = "0.0.0"',
        'requires-python = ">=3.14,<3.15"',
        "dependencies = [",
        f"    {json.dumps(dependency)},",
        "]",
        "",
        "[tool.uv]",
        "package = false",
        "",
    ]
    (work_dir / "pyproject.toml").write_text("\n".join(lines), encoding="utf-8")
    _run_to_log(["uv", "lock", "--no-progress"], work_dir, log_dir / "uv_lock.log", timeout=1200)


def _prepare_npm_workspace(request: PackageRequest, work_dir: Path, log_dir: Path) -> None:
    package_json = {
        "name": "sbom-stub",
        "version": "0.0.0",
        "private": True,
        "engines": {
            "node": ">=24.0.0 <25.0.0",
        },
        "dependencies": {
            request.name: request.version,
        },
    }
    (work_dir / "package.json").write_text(
        json.dumps(package_json, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    _run_to_log(
        [
            "npm",
            "install",
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ],
        work_dir,
        log_dir / "npm_install.log",
        timeout=1200,
    )


def _prepare_maven_workspace(request: PackageRequest, work_dir: Path, log_dir: Path) -> None:
    if not request.group_id or not request.artifact_id:
        raise PackageGenerationError("Maven groupId and artifactId are required.")

    lines = [
        '<project xmlns="http://maven.apache.org/POM/4.0.0"',
        '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
        '         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">',
        "  <modelVersion>4.0.0</modelVersion>",
        "  <groupId>local.sbom</groupId>",
        "  <artifactId>standalone-pom</artifactId>",
        "  <version>0.0.0</version>",
        "  <dependencies>",
        "    <dependency>",
        f"      <groupId>{_xml_escape(request.group_id)}</groupId>",
        f"      <artifactId>{_xml_escape(request.artifact_id)}</artifactId>",
        f"      <version>{_xml_escape(request.version)}</version>",
        "    </dependency>",
        "  </dependencies>",
        "</project>",
        "",
    ]
    (work_dir / "pom.xml").write_text("\n".join(lines), encoding="utf-8")
    _run_to_log(
        ["mvn", "-q", "-DskipTests", "dependency:tree", "-DoutputFile=dependency-tree.txt"],
        work_dir,
        log_dir / "maven_dependency_tree.log",
        timeout=1200,
    )


def _prepare_composer_workspace(request: PackageRequest, work_dir: Path, log_dir: Path) -> None:
    composer_json = {
        "name": "local/sbom-stub",
        "type": "project",
        "require": {
            request.name: request.version,
        },
        "config": {
            "allow-plugins": False,
        },
    }
    (work_dir / "composer.json").write_text(
        json.dumps(composer_json, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    _run_to_log(
        [
            "composer",
            "update",
            "--no-interaction",
            "--no-scripts",
            "--no-plugins",
            "--no-audit",
        ],
        work_dir,
        log_dir / "composer_update.log",
        timeout=1200,
    )


def _prepare_gem_workspace(request: PackageRequest, work_dir: Path, log_dir: Path) -> None:
    gemfile = (
        'source "https://rubygems.org"\n'
        "\n"
        f"gem {json.dumps(request.name)}, {json.dumps(request.version)}\n"
    )
    (work_dir / "Gemfile").write_text(gemfile, encoding="utf-8")
    _run_to_log(["bundle", "lock"], work_dir, log_dir / "bundle_lock.log", timeout=1200)


def _prepare_cargo_workspace(request: PackageRequest, work_dir: Path, log_dir: Path) -> None:
    dependency_version = request.version
    if not dependency_version.startswith(("=", ">", "<", "~", "^")):
        dependency_version = f"={dependency_version}"

    lines = [
        "[package]",
        'name = "sbom-stub"',
        'version = "0.0.0"',
        'edition = "2024"',
        "publish = false",
        "",
        "[dependencies]",
        f"{json.dumps(request.name)} = {json.dumps(dependency_version)}",
        "",
    ]
    (work_dir / "Cargo.toml").write_text("\n".join(lines), encoding="utf-8")

    src_dir = work_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "lib.rs").write_text("// dependency resolution stub\n", encoding="utf-8")

    _run_to_log(
        ["cargo", "generate-lockfile"],
        work_dir,
        log_dir / "cargo_generate_lockfile.log",
        timeout=1200,
    )


def _prepare_golang_workspace(request: PackageRequest, work_dir: Path, log_dir: Path) -> None:
    lines = [
        "module local/sbom-stub",
        "",
        "go 1.26",
        "",
        f"require {request.name} {request.version}",
        "",
    ]
    (work_dir / "go.mod").write_text("\n".join(lines), encoding="utf-8")
    _run_to_log(
        ["go", "mod", "download", "all"],
        work_dir,
        log_dir / "go_mod_download.log",
        timeout=1200,
    )


def _prepare_nuget_workspace(request: PackageRequest, work_dir: Path, log_dir: Path) -> None:
    lines = [
        '<Project Sdk="Microsoft.NET.Sdk">',
        "  <PropertyGroup>",
        "    <TargetFramework>net10.0</TargetFramework>",
        "    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>",
        "  </PropertyGroup>",
        "  <ItemGroup>",
        f'    <PackageReference Include="{_xml_escape(request.name)}" Version="{_xml_escape(request.version)}" />',
        "  </ItemGroup>",
        "</Project>",
        "",
    ]
    (work_dir / "sbom-stub.csproj").write_text("\n".join(lines), encoding="utf-8")
    _run_to_log(
        ["dotnet", "restore", "--use-lock-file"],
        work_dir,
        log_dir / "dotnet_restore.log",
        timeout=1200,
    )


def _run_trivy(work_dir: Path, output_path: Path, log_dir: Path) -> None:
    _run_to_log(
        [
            "trivy",
            "fs",
            "--quiet",
            "--format",
            "spdx-json",
            "--output",
            str(output_path),
            str(work_dir),
        ],
        work_dir,
        log_dir / "trivy_fs.log",
        timeout=1200,
    )

    if not output_path.exists():
        raise PackageGenerationError("Trivy did not create an SPDX JSON file.")


def _run_to_log(command: list[str], cwd: Path, log_file: Path, timeout: int) -> None:
    cache_root = cwd.parent / "cache"
    cache_root.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["CI"] = "true"
    env["UV_CACHE_DIR"] = str(cache_root / "uv")
    env["NPM_CONFIG_CACHE"] = str(cache_root / "npm")
    env["NPM_CONFIG_UPDATE_NOTIFIER"] = "false"

    home_dir = cache_root / "home"
    home_dir.mkdir(parents=True, exist_ok=True)
    env["HOME"] = str(home_dir)

    env["COMPOSER_CACHE_DIR"] = str(cache_root / "composer")
    env["COMPOSER_ALLOW_SUPERUSER"] = "1"

    env["BUNDLE_APP_CONFIG"] = str(cache_root / "bundle")
    env["BUNDLE_PATH"] = str(cache_root / "bundle_path")

    env["CARGO_HOME"] = str(cache_root / "cargo")

    env["GOPATH"] = str(cache_root / "go")
    env["GOMODCACHE"] = str(cache_root / "go" / "pkg" / "mod")

    env["DOTNET_CLI_HOME"] = str(cache_root / "dotnet_home")
    env["NUGET_PACKAGES"] = str(cache_root / "nuget")

    maven_opts = env.get("MAVEN_OPTS", "").strip()
    local_m2 = f"-Dmaven.repo.local={cache_root / 'm2'}"
    env["MAVEN_OPTS"] = f"{maven_opts} {local_m2}".strip()

    with log_file.open("w", encoding="utf-8") as handle:
        handle.write("$ " + " ".join(command) + "\n\n")
        try:
            completed = subprocess.run(
                command,
                cwd=str(cwd),
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            handle.write(f"\nCommand timed out after {timeout} seconds.\n")
            if exc.stdout:
                handle.write(str(exc.stdout))
            raise PackageGenerationError(f"Command timed out: {' '.join(command)}") from exc

        handle.write(completed.stdout or "")

    if completed.returncode != 0:
        raise PackageGenerationError(
            f"Command failed with exit code {completed.returncode}: {' '.join(command)}. "
            f"See log: {log_file}"
        )


def _postprocess_spdx(raw_path: Path, output_path: Path) -> None:
    data = json.loads(raw_path.read_text(encoding="utf-8"))

    packages = data.get("packages")
    if not isinstance(packages, list):
        packages = []

    remove_ids: set[str] = set()
    kept_packages: list[dict] = []

    for package in packages:
        package_name = str(package.get("name", "")).strip().lower()
        spdx_id = str(package.get("SPDXID", "")).strip()

        if package_name in NOISE_PACKAGE_NAMES and spdx_id:
            remove_ids.add(spdx_id)
            continue

        kept_packages.append(package)

    data["packages"] = kept_packages

    relationships = data.get("relationships")
    if isinstance(relationships, list):
        kept_relationships = []
        for relationship in relationships:
            left = str(relationship.get("spdxElementId", ""))
            right = str(relationship.get("relatedSpdxElement", ""))
            if left in remove_ids or right in remove_ids:
                continue
            kept_relationships.append(relationship)
        data["relationships"] = kept_relationships
    else:
        data["relationships"] = []

    describes = data.get("documentDescribes")
    if isinstance(describes, list):
        describes = [item for item in describes if item not in remove_ids]
    else:
        describes = []

    if not describes:
        for package in kept_packages:
            spdx_id = str(package.get("SPDXID", "")).strip()
            if spdx_id:
                describes = [spdx_id]
                break

    data["documentDescribes"] = describes

    for target in describes:
        exists = any(
            relationship.get("spdxElementId") == "SPDXRef-DOCUMENT"
            and relationship.get("relationshipType") == "DESCRIBES"
            and relationship.get("relatedSpdxElement") == target
            for relationship in data["relationships"]
        )
        if not exists:
            data["relationships"].append(
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": target,
                }
            )

    output_path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _write_input_summary(request: PackageRequest, input_dir: Path) -> None:
    summary = {
        "mode": "package",
        "ecosystem": request.ecosystem,
        "name": request.name,
        "version": request.version,
        "output_label": request.output_label,
        "group_id": request.group_id,
        "artifact_id": request.artifact_id,
    }
    (input_dir / "input_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _write_manifest(
    *,
    request: PackageRequest,
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
        "mode": "package",
        "ecosystem": request.ecosystem,
        "ecosystem_label": ECOSYSTEM_LABELS.get(request.ecosystem),
        "name": request.name,
        "version": request.version,
        "output_label": request.output_label,
        "group_id": request.group_id,
        "artifact_id": request.artifact_id,
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


def _create_artifact_zip(job_id: str, job_out_root: Path) -> Path:
    artifact_zip = job_out_root / f"sbom_result_{job_id}.zip"

    if artifact_zip.exists():
        artifact_zip.unlink()

    with zipfile.ZipFile(artifact_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for dirname in ("sbom", "error", "manifest", "input"):
            base = job_out_root / dirname
            if not base.exists():
                continue

            for path in sorted(base.rglob("*")):
                if path.is_file():
                    archive.write(path, f"{dirname}/{path.relative_to(base).as_posix()}")

    return artifact_zip


def _output_filename(request: PackageRequest) -> str:
    label = _safe_filename_part(request.output_label)
    ecosystem = _safe_filename_part(ECOSYSTEM_LABELS[request.ecosystem])
    name = _safe_filename_part(request.name)
    version = _safe_filename_part(request.version)
    return f"{label}__{ecosystem}__{name}@{version}.spdx.json"


def _safe_filename_part(value: str) -> str:
    value = value.strip()
    value = re.sub(r"[^A-Za-z0-9._@+-]+", "-", value)
    value = value.strip(".-")
    return value or "unnamed"


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )
