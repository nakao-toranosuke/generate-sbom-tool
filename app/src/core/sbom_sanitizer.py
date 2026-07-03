from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.core.projects.models import SanitizedSbomResult
from src.utils.fs import safe_filename


NOISE_NAMES = {
    "sbom-stub",
    "standalone-pom",
    "uv.lock",
    "package-lock.json",
    "composer.lock",
    "Gemfile.lock",
    "Cargo.lock",
    "go.sum",
    "packages.lock.json",
}


def _pkg_id(pkg: dict[str, Any]) -> str | None:
    return pkg.get("SPDXID") or pkg.get("spdxid")


def _pkg_name(pkg: dict[str, Any]) -> str:
    return str(pkg.get("name") or "").strip()


def _is_noise_package(pkg: dict[str, Any]) -> bool:
    name = _pkg_name(pkg)
    return name in NOISE_NAMES


def _select_described_package(packages: list[dict[str, Any]]) -> str | None:
    for pkg in packages:
        spdx_id = _pkg_id(pkg)
        if spdx_id and spdx_id != "SPDXRef-DOCUMENT":
            return spdx_id
    return None


def sanitize_sbom(
    raw_sbom_path: Path,
    output_path: Path,
    *,
    document_name: str,
) -> SanitizedSbomResult:
    try:
        data = json.loads(raw_sbom_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return SanitizedSbomResult(
            success=False,
            sbom_path=None,
            error_summary=f"failed to parse SPDX JSON: {exc}",
        )

    packages = data.get("packages")
    if not isinstance(packages, list):
        return SanitizedSbomResult(
            success=False,
            sbom_path=None,
            error_summary="SPDX JSON does not contain packages list",
        )

    removed_ids: set[str] = set()
    kept_packages: list[dict[str, Any]] = []

    for pkg in packages:
        spdx_id = _pkg_id(pkg)
        if _is_noise_package(pkg):
            if spdx_id:
                removed_ids.add(spdx_id)
            continue
        kept_packages.append(pkg)

    data["packages"] = kept_packages

    relationships = data.get("relationships", [])
    kept_relationships: list[dict[str, Any]] = []
    removed_relationship_count = 0

    if isinstance(relationships, list):
        for rel in relationships:
            left = rel.get("spdxElementId")
            right = rel.get("relatedSpdxElement")
            if left in removed_ids or right in removed_ids:
                removed_relationship_count += 1
                continue
            kept_relationships.append(rel)
        data["relationships"] = kept_relationships

    valid_ids = {_pkg_id(pkg) for pkg in kept_packages if _pkg_id(pkg)}
    describes = data.get("documentDescribes") or []
    if not isinstance(describes, list):
        describes = [describes]

    describes = [item for item in describes if item in valid_ids]
    if not describes:
        selected = _select_described_package(kept_packages)
        if selected:
            describes = [selected]

    if describes:
        data["documentDescribes"] = describes

    if describes:
        has_describes_rel = any(
            rel.get("spdxElementId") == "SPDXRef-DOCUMENT"
            and rel.get("relationshipType") == "DESCRIBES"
            and rel.get("relatedSpdxElement") in describes
            for rel in data.get("relationships", [])
        )
        if not has_describes_rel:
            data.setdefault("relationships", []).append(
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": describes[0],
                }
            )

    data["name"] = safe_filename(document_name, default="sbom-document")

    creation_info = data.setdefault("creationInfo", {})
    creators = creation_info.setdefault("creators", [])
    creator = "Tool: sbom-generator-v3.1-postprocess"
    if isinstance(creators, list) and creator not in creators:
        creators.append(creator)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    return SanitizedSbomResult(
        success=True,
        sbom_path=output_path,
        removed_package_count=len(removed_ids),
        removed_relationship_count=removed_relationship_count,
        document_describes=describes,
    )
