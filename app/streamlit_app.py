from __future__ import annotations

import io
import json
import uuid
import zipfile
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from src.core.file_orchestrator import run_file_job
from src.core.package_orchestrator import ECOSYSTEM_LABELS, run_package_job
from src.core.project_orchestrator import run_project_zip_job


EXPORT_ROOT = Path("/tmp/out/ui_exports")

TABLE_UPLOAD_MAX_MB = 50
FILE_UPLOAD_MAX_MB = 200
PROJECT_UPLOAD_MAX_MB = 200


def uploader_key(base_key: str) -> str:
    counter_key = f"{base_key}_reset_counter"

    if counter_key not in st.session_state:
        st.session_state[counter_key] = 0

    return f"{base_key}_{st.session_state[counter_key]}"


def render_upload_reset_control(base_key: str, label: str) -> None:
    st.caption(
        "If an upload fails, stalls, or the wrong file remains selected, "
        "reset this upload input and choose the file again."
    )

    if st.button(label, key=f"{base_key}_reset_button"):
        counter_key = f"{base_key}_reset_counter"
        st.session_state[counter_key] = st.session_state.get(counter_key, 0) + 1
        st.rerun()


def main() -> None:
    st.set_page_config(
        page_title="SBOM Generator",
        page_icon="📦",
        layout="wide",
    )

    st.title("SBOM Generator")
    st.caption("Generate SPDX JSON SBOM artifacts for packages, files, and project ZIP inputs.")

    package_tab, table_tab, file_tab, project_tab = st.tabs(
        [
            "Package input",
            "CSV/Excel input",
            "File input",
            "Project ZIP input",
        ]
    )

    with package_tab:
        render_package_tab()

    with table_tab:
        render_table_tab()

    with file_tab:
        render_file_tab()

    with project_tab:
        render_project_tab()


def render_package_tab() -> None:
    st.subheader("Package input")

    ecosystem_options = list(ECOSYSTEM_LABELS.keys())
    ecosystem = st.selectbox(
        "Ecosystem",
        ecosystem_options,
        format_func=lambda value: f"{value} / {ECOSYSTEM_LABELS[value]}",
        key="pkg_ecosystem",
    )

    col1, col2 = st.columns(2)

    with col1:
        name = st.text_input(
            "Package name",
            value="idna" if ecosystem == "pypi" else "",
            help="For Maven, use groupId:artifactId or fill groupId/artifactId below.",
            key="pkg_name",
        )
        version = st.text_input("Version", value="3.7" if ecosystem == "pypi" else "", key="pkg_version")

    with col2:
        output_label = st.text_input("Output label", value="package", key="pkg_output_label")
        group_id = st.text_input("Maven groupId", value="", key="pkg_group_id")
        artifact_id = st.text_input("Maven artifactId", value="", key="pkg_artifact_id")

    if st.button("Generate package SBOM", type="primary", key="pkg_generate"):
        with st.spinner("Generating package SBOM..."):
            result = run_package_job(
                ecosystem=ecosystem,
                name=name,
                version=version,
                output_label=output_label,
                group_id=group_id or None,
                artifact_id=artifact_id or None,
            )

        render_job_result(result, key_prefix="pkg_result")


def render_table_tab() -> None:
    st.subheader("CSV/Excel input")
    st.write(
        "Required columns: `ecosystem`, `name`, `version`. "
        "Optional columns: `output_label`, `group_id`, `artifact_id`."
    )

    render_upload_reset_control("table_upload", "Reset CSV/Excel upload input")

    uploaded = st.file_uploader(
        "Upload CSV or Excel",
        type=["csv", "xlsx"],
        key=uploader_key("table_upload"),
        max_upload_size=TABLE_UPLOAD_MAX_MB,
        help="Generation starts only after you click the generate button.",
    )

    if uploaded is None:
        render_table_template()
        return

    try:
        dataframe = read_uploaded_table(uploaded.name, uploaded.getvalue())
    except Exception as exc:
        st.error(f"Failed to read input table: {exc}")
        return

    if dataframe.empty:
        st.warning("Input table is empty.")
        return

    st.dataframe(dataframe, use_container_width=True)

    rows = normalize_table_rows(dataframe)

    issues = [row for row in rows if row["issues"]]
    valid_rows = [row for row in rows if not row["issues"]]

    if issues:
        st.warning(f"{len(issues)} row(s) have validation issues.")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "row_number": row["row_number"],
                        "issues": "; ".join(row["issues"]),
                    }
                    for row in issues
                ]
            ),
            use_container_width=True,
        )

    st.info(f"Valid rows: {len(valid_rows)} / {len(rows)}")

    if not valid_rows:
        return

    if st.button("Generate package SBOMs from table", type="primary", key="table_generate"):
        results = []
        progress = st.progress(0)

        for index, row in enumerate(valid_rows, start=1):
            with st.spinner(f"Generating row {row['row_number']}..."):
                result = run_package_job(
                    ecosystem=row["ecosystem"],
                    name=row["name"],
                    version=row["version"],
                    output_label=row["output_label"],
                    group_id=row["group_id"],
                    artifact_id=row["artifact_id"],
                )
            results.append((row, result))
            progress.progress(index / len(valid_rows))

        render_batch_results(results, key_prefix="table_results")


def render_table_template() -> None:
    template = pd.DataFrame(
        [
            {
                "ecosystem": "pypi",
                "name": "idna",
                "version": "3.7",
                "output_label": "pkg-pypi",
                "group_id": "",
                "artifact_id": "",
            },
            {
                "ecosystem": "npm",
                "name": "is-number",
                "version": "7.0.0",
                "output_label": "pkg-npm",
                "group_id": "",
                "artifact_id": "",
            },
            {
                "ecosystem": "maven",
                "name": "junit:junit",
                "version": "4.13.2",
                "output_label": "pkg-maven",
                "group_id": "",
                "artifact_id": "",
            },
        ]
    )

    st.write("Template preview")
    st.dataframe(template, use_container_width=True)

    csv_data = template.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download CSV template",
        data=csv_data,
        file_name="sbom_package_input_template.csv",
        mime="text/csv",
        key="table_template_download",
    )


def render_file_tab() -> None:
    st.subheader("File input")

    render_upload_reset_control("file_upload", "Reset file upload input")

    uploaded = st.file_uploader(
        "Upload a single file",
        type=None,
        key=uploader_key("file_upload"),
        max_upload_size=FILE_UPLOAD_MAX_MB,
        help="Generation starts only after you click the generate button.",
    )

    col1, col2 = st.columns(2)

    with col1:
        output_label = st.text_input("Output label", value="file", key="file_output_label")
        display_name = st.text_input("Display name", value="", key="file_display_name")

    with col2:
        version = st.text_input("Version", value="unknown", key="file_version")

    if uploaded is None:
        return

    st.write(
        {
            "filename": uploaded.name,
            "size_bytes": uploaded.size,
        }
    )

    if st.button("Generate file SBOM", type="primary", key="file_generate"):
        with st.spinner("Generating file SBOM..."):
            result = run_file_job(
                original_filename=uploaded.name,
                data=uploaded.getvalue(),
                output_label=output_label,
                display_name=display_name or None,
                version=version or None,
            )

        render_job_result(result, key_prefix="file_result")


def render_project_tab() -> None:
    st.subheader("Project ZIP input")

    render_upload_reset_control("project_zip_upload", "Reset project ZIP upload input")

    uploaded = st.file_uploader(
        "Upload project ZIP",
        type=["zip"],
        key=uploader_key("project_zip_upload"),
        max_upload_size=PROJECT_UPLOAD_MAX_MB,
        help="Generation starts only after you click the generate button.",
    )

    col1, col2 = st.columns(2)

    with col1:
        output_label = st.text_input("Output label", value="project", key="project_output_label")
        project_name = st.text_input("Project name", value="", key="project_name")

    with col2:
        project_version = st.text_input("Project version", value="unknown", key="project_version")

    if uploaded is None:
        return

    st.write(
        {
            "filename": uploaded.name,
            "size_bytes": uploaded.size,
        }
    )

    if st.button("Generate project ZIP SBOM", type="primary", key="project_generate"):
        with st.spinner("Generating project SBOM..."):
            result = run_project_zip_job(
                original_filename=uploaded.name,
                data=uploaded.getvalue(),
                project_name=project_name or None,
                project_version=project_version or None,
                output_label=output_label,
            )

        render_job_result(result, key_prefix="project_result")


def read_uploaded_table(filename: str, data: bytes) -> pd.DataFrame:
    suffix = Path(filename).suffix.lower()

    if suffix == ".csv":
        return pd.read_csv(io.BytesIO(data))

    if suffix == ".xlsx":
        return pd.read_excel(io.BytesIO(data))

    raise ValueError("Unsupported table format. Use CSV or XLSX.")


def normalize_table_rows(dataframe: pd.DataFrame) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    column_map = {normalize_column_name(column): column for column in dataframe.columns}

    for index, row in dataframe.iterrows():
        ecosystem = value_from_row(row, column_map, ["ecosystem", "language"])
        name = value_from_row(row, column_map, ["name", "package", "package_name", "target"])
        version = value_from_row(row, column_map, ["version", "package_version"])
        output_label = value_from_row(row, column_map, ["output_label", "file_label", "label"]) or "package"
        group_id = value_from_row(row, column_map, ["group_id", "groupid"])
        artifact_id = value_from_row(row, column_map, ["artifact_id", "artifactid"])

        issues = []

        if not ecosystem:
            issues.append("ecosystem is required")
        elif ecosystem not in ECOSYSTEM_LABELS and ecosystem != "go":
            issues.append(f"unsupported ecosystem: {ecosystem}")

        if not name:
            issues.append("name is required")

        if not version:
            issues.append("version is required")

        rows.append(
            {
                "row_number": int(index) + 2,
                "ecosystem": ecosystem,
                "name": name,
                "version": version,
                "output_label": output_label,
                "group_id": group_id or None,
                "artifact_id": artifact_id or None,
                "issues": issues,
            }
        )

    return rows


def normalize_column_name(value: Any) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def value_from_row(row: pd.Series, column_map: dict[str, Any], aliases: list[str]) -> str:
    for alias in aliases:
        column = column_map.get(alias)
        if column is None:
            continue

        value = row.get(column)

        if pd.isna(value):
            continue

        text = str(value).strip()

        if text:
            return text

    return ""


def render_job_result(result: Any, key_prefix: str) -> None:
    if result.success:
        st.success("Generation completed.")
    else:
        st.error("Generation failed.")

    summary = {
        "status": result.status,
        "job_id": result.job_id,
        "sbom_file": str(result.sbom_file) if result.sbom_file else None,
        "artifact_zip": str(result.artifact_zip) if result.artifact_zip else None,
        "error_summary": result.error_summary,
        "warnings": result.warnings,
    }

    st.json(summary)

    if result.artifact_zip and result.artifact_zip.exists():
        st.download_button(
            "Download result ZIP",
            data=result.artifact_zip.read_bytes(),
            file_name=result.artifact_zip.name,
            mime="application/zip",
            key=f"{key_prefix}_{result.job_id}_download",
        )


def render_batch_results(results: list[tuple[dict[str, Any], Any]], key_prefix: str) -> None:
    rows = []

    for row, result in results:
        rows.append(
            {
                "row_number": row["row_number"],
                "ecosystem": row["ecosystem"],
                "name": row["name"],
                "version": row["version"],
                "status": result.status,
                "job_id": result.job_id,
                "sbom_file": str(result.sbom_file) if result.sbom_file else None,
                "error_summary": result.error_summary,
            }
        )

    st.dataframe(pd.DataFrame(rows), use_container_width=True)

    failed = [item for item in results if not item[1].success]

    if failed:
        st.warning(f"{len(failed)} job(s) failed.")
    else:
        st.success("All jobs completed.")

    batch_zip = create_batch_zip(results)

    if batch_zip and batch_zip.exists():
        st.download_button(
            "Download batch result ZIP",
            data=batch_zip.read_bytes(),
            file_name=batch_zip.name,
            mime="application/zip",
            key=f"{key_prefix}_{batch_zip.stem}_download",
        )


def create_batch_zip(results: list[tuple[dict[str, Any], Any]]) -> Path | None:
    EXPORT_ROOT.mkdir(parents=True, exist_ok=True)
    batch_id = uuid.uuid4().hex[:12]
    batch_zip = EXPORT_ROOT / f"sbom_batch_result_{batch_id}.zip"

    manifest = []

    with zipfile.ZipFile(batch_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for row, result in results:
            manifest.append(
                {
                    "row_number": row["row_number"],
                    "ecosystem": row["ecosystem"],
                    "name": row["name"],
                    "version": row["version"],
                    "status": result.status,
                    "job_id": result.job_id,
                    "error_summary": result.error_summary,
                    "artifact_zip": result.artifact_zip.name if result.artifact_zip else None,
                }
            )

            if result.artifact_zip and result.artifact_zip.exists():
                arcname = f"jobs/row_{row['row_number']}_{result.job_id}/{result.artifact_zip.name}"
                archive.write(result.artifact_zip, arcname)

        archive.writestr(
            "batch_manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        )

    return batch_zip


if __name__ == "__main__":
    main()
