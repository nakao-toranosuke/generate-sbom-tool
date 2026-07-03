from __future__ import annotations

from pathlib import Path

import streamlit as st

from src.core.excel_normalizer import read_table
from src.core.project_orchestrator import inspect_project_zip, run_project_zip_job


st.set_page_config(page_title="SBOM Generator", layout="wide")


def _render_header() -> None:
    st.title("SBOM Generator")
    st.caption("Generate SBOM files in SPDX JSON format.")


def _render_package_tab() -> None:
    st.subheader("Package input")
    st.info("Package-based SBOM generation will be implemented in the package runner phase.")

    with st.form("package_input_form"):
        ecosystem = st.selectbox(
            "Ecosystem",
            ["pypi", "npm", "maven", "composer", "gem", "cargo", "golang", "nuget", "file"],
            key="package_ecosystem",
        )
        package_name = st.text_input("Package name", key="package_name")
        version = st.text_input("Version", key="package_version")
        output_label = st.text_input("Output label", key="package_output_label")
        submitted = st.form_submit_button("Add target", disabled=True)

    if submitted:
        st.warning("Package target queue is not enabled in this implementation block.")


def _render_csv_tab() -> None:
    st.subheader("CSV / Excel input")
    st.info("CSV/Excel parsing is available in this block. SBOM generation from rows will be implemented in the package runner phase.")

    uploaded = st.file_uploader(
        "Upload CSV or Excel file",
        type=["csv", "xlsx", "xlsm"],
        key="csv_excel_upload",
    )

    if uploaded is None:
        return

    try:
        data = uploaded.getvalue()
        df = read_table(uploaded.name, data)
    except Exception as exc:
        st.error(f"Failed to read input file: {exc}")
        return

    st.success(f"Loaded {len(df)} rows.")
    st.dataframe(df, use_container_width=True)


def _render_detection_summary(preview) -> None:
    if preview.errors:
        st.error("Input errors detected.")
        for error in preview.errors:
            st.write(f"- {error}")

    if preview.warnings:
        st.warning("Warnings")
        for warning in preview.warnings:
            st.write(f"- {warning}")

    st.write("Detected ecosystems")
    st.write(preview.detected_ecosystems or [])

    st.write("Detected dependency files")
    if preview.detected_files:
        st.dataframe(
            [
                {"path": item.path, "ecosystem": item.ecosystem, "kind": item.kind}
                for item in preview.detected_files
            ],
            use_container_width=True,
        )
    else:
        st.write("No supported dependency definition files detected.")

    if preview.dockerfile_detected:
        st.write("Dockerfile paths")
        st.write(preview.dockerfile_paths)


def _render_project_zip_tab() -> None:
    st.subheader("Project ZIP input")

    uploaded = st.file_uploader(
        "Upload project ZIP",
        type=["zip"],
        key="project_zip_upload",
    )

    if uploaded is None:
        st.write("Upload a project ZIP to inspect dependency files.")
        return

    data = uploaded.getvalue()

    with st.spinner("Inspecting project ZIP..."):
        preview = inspect_project_zip(uploaded.name, data)

    _render_detection_summary(preview)

    default_name = preview.metadata.name or Path(uploaded.name).stem
    default_version = preview.metadata.version or ""
    default_label = default_name

    st.divider()
    st.write("Project metadata")

    project_name = st.text_input("Application / product name", value=default_name, key="project_name")
    project_version = st.text_input("Version", value=default_version, key="project_version")
    output_label = st.text_input("Output label", value=default_label, key="project_output_label")

    can_generate = preview.success and bool(project_name.strip()) and bool(project_version.strip()) and bool(output_label.strip())

    if not can_generate:
        st.info("Enter required metadata after resolving input errors.")

    if st.button("Generate project SBOM", key="generate_project_sbom", disabled=not can_generate):
        with st.spinner("Generating SBOM..."):
            result = run_project_zip_job(
                original_filename=uploaded.name,
                data=data,
                project_name=project_name,
                project_version=project_version,
                output_label=output_label,
            )

        if result.success:
            st.success("SBOM generation completed.")
        else:
            st.error(f"SBOM generation failed: {result.error_summary}")

        if result.warnings:
            st.warning("Warnings")
            for warning in result.warnings:
                st.write(f"- {warning}")

        if result.artifact_zip and result.artifact_zip.exists():
            st.download_button(
                "Download result ZIP",
                data=result.artifact_zip.read_bytes(),
                file_name=result.artifact_zip.name,
                mime="application/zip",
                key=f"download_project_result_{result.job_id}",
            )


def main() -> None:
    _render_header()
    package_tab, csv_tab, project_tab = st.tabs(["Package input", "CSV/Excel input", "Project ZIP input"])

    with package_tab:
        _render_package_tab()

    with csv_tab:
        _render_csv_tab()

    with project_tab:
        _render_project_zip_tab()


if __name__ == "__main__":
    main()
