from __future__ import annotations

import io
import json
import os
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any, Optional

import pandas as pd
import streamlit as st
import yaml

from src.core.excel_normalizer import normalize_excel_first_sheet
from src.core.mapping import ColumnMapping, validate_mapping
from src.core.orchestrator import process_one
from src.models.types import InputRow
from src.utils.concurrency import FileSemaphore
from src.utils.fs import ensure_dir, rm_tree, sanitize_filename_component

DEFAULT_KEYWORDS = {
    "management_no": ["管理番号", "管理No", "No", "ID"],
    "language": ["言語", "言語名", "Language"],
    "package_name": ["パッケージ", "パッケージ名", "ライブラリ", "Library", "Package"],
    "version": ["バージョン", "バージョン名", "Version"],
    "url": ["URL", "Url", "ダウンロード", "ダウンロードURL"],
    "software_file_name": ["ソフトウェアファイル名", "ファイル名", "filename", "whl"],
    "attachment_file_name": ["添付ファイル名", "添付物ファイル名", "artifact_file_name"],
}
REQUIRED_KEYS = ["management_no", "language", "package_name", "version"]
OPTIONAL_KEYS = ["url", "software_file_name", "attachment_file_name"]
DISPLAY_NAMES = {
    "management_no": "管理番号",
    "language": "言語名",
    "package_name": "パッケージ名",
    "version": "バージョン",
    "url": "URL",
    "software_file_name": "ソフトウェアファイル名",
    "attachment_file_name": "添付ファイル名",
}
ARCHIVE_EXTS = {".zip", ".jar", ".war", ".ear"}
NO_HEADER_DEFAULT_INDEX = {
    "management_no": 0,
    "language": 1,
    "package_name": 2,
    "version": 3,
    "url": 4,
    "software_file_name": 5,
    "attachment_file_name": 6,
}
SURVEY_MODE_OPTIONS = ["precheck", "runtime"]
SURVEY_MODE_LABELS = {"precheck": "随時調査", "runtime": "定期調査"}

# PASSWORD = "sbom123"  # 任意で変更

# if "authenticated" not in st.session_state:
#     st.session_state.authenticated = False

# if not st.session_state.authenticated:
#     st.title("Login")

#     pwd = st.text_input("Password", type="password")

#     if st.button("Login"):
#         if pwd == PASSWORD:
#             st.session_state.authenticated = True
#         else:
#             st.error("Invalid password")

#     st.stop()

def load_app_config() -> dict[str, Any]:
    # アプリ設定を読み込みます。
    # - config/app.yaml があればそれを読み込み
    # - 環境変数（Cloud Run など）で上書き可能
    # Cloud Run ではファイルシステムが揮発性のため、既定の work/out は /tmp 配下を推奨します。
    cfg_path = Path(__file__).parent / 'config' / 'app.yaml'
    app_cfg: dict[str, Any]
    if cfg_path.exists():
        data = yaml.safe_load(cfg_path.read_text(encoding='utf-8')) or {}
        app_cfg = data.get('app') or {}
    else:
        app_cfg = {}

    # Cloud Run などの実行環境検出（あれば /tmp を既定に）
    on_cloud_run = bool(os.environ.get('K_SERVICE'))

    def env_get(name: str, default: Any) -> Any:
        v = os.environ.get(name)
        return default if v is None or str(v).strip() == '' else v

    def env_int(name: str, default: int) -> int:
        v = os.environ.get(name)
        if v is None or str(v).strip() == '':
            return int(default)
        try:
            return int(str(v).strip())
        except Exception:
            return int(default)

    def env_bool(name: str, default: bool) -> bool:
        v = os.environ.get(name)
        if v is None or str(v).strip() == '':
            return bool(default)
        return str(v).strip().lower() in {'1', 'true', 'yes', 'y', 'on'}

    default_work = '/tmp/work' if on_cloud_run else '../work'
    default_out = '/tmp/out' if on_cloud_run else '../out'
    default_trivy = '../bin/trivy.exe' if os.name == 'nt' else ('trivy' if on_cloud_run else '../bin/trivy')

    cfg = {
        'work_dir': env_get('SBOM_APP_WORK_DIR', app_cfg.get('work_dir', default_work)),
        'out_dir': env_get('SBOM_APP_OUT_DIR', app_cfg.get('out_dir', default_out)),
        'trivy_path': env_get('SBOM_APP_TRIVY_PATH', app_cfg.get('trivy_path', default_trivy)),
        'sbom_format': env_get('SBOM_APP_SBOM_FORMAT', app_cfg.get('sbom_format', 'spdx-json')),
        'timeout_seconds': env_int('SBOM_APP_TIMEOUT_SECONDS', int(app_cfg.get('timeout_seconds', 1800))),
        'max_upload_mb': env_int('SBOM_APP_MAX_UPLOAD_MB', int(app_cfg.get('max_upload_mb', 200))),
        'header_scan_rows': env_int('SBOM_APP_HEADER_SCAN_ROWS', int(app_cfg.get('header_scan_rows', 30))),
        'preview_rows': env_int('SBOM_APP_PREVIEW_ROWS', int(app_cfg.get('preview_rows', 20))),
        'cleanup_workdir_on_success': env_bool('SBOM_APP_CLEANUP_WORKDIR_ON_SUCCESS', bool(app_cfg.get('cleanup_workdir_on_success', True))),
        'cleanup_workdir_on_failure': env_bool('SBOM_APP_CLEANUP_WORKDIR_ON_FAILURE', bool(app_cfg.get('cleanup_workdir_on_failure', True))),
    }
    return cfg


def load_keywords() -> dict[str, list[str]]:
    kw_path = Path(__file__).parent / "config" / "keywords_ja.yaml"
    if kw_path.exists():
        data = yaml.safe_load(kw_path.read_text(encoding="utf-8")) or {}
        keywords = data.get("keywords") or {}
        result: dict[str, list[str]] = {}
        for key in set(DEFAULT_KEYWORDS.keys()) | set(keywords.keys()):
            vals = keywords.get(key) or DEFAULT_KEYWORDS.get(key) or []
            result[key] = [str(v) for v in vals]
        return result
    return DEFAULT_KEYWORDS


def app_paths(cfg: dict[str, Any]) -> tuple[Path, Path, Path, Path]:
    app_root = Path(__file__).parent.resolve()

    def _to_path(value: Any) -> Path:
        s = '' if value is None else str(value).strip()
        if not s:
            return Path('')
        p = Path(s)
        if p.is_absolute():
            return p
        return (app_root / p).resolve()

    work_dir = _to_path(cfg.get('work_dir'))
    out_dir = _to_path(cfg.get('out_dir'))

    # trivy_path は「パス」または「PATH上のコマンド名」を許容する
    import shutil
    trivy_cfg = '' if cfg.get('trivy_path') is None else str(cfg.get('trivy_path')).strip()
    if not trivy_cfg:
        found = shutil.which('trivy')
        trivy_path = Path(found) if found else (app_root / '../bin/trivy').resolve()
    else:
        looks_like_path = ('/' in trivy_cfg) or ('\\' in trivy_cfg) or trivy_cfg.startswith('.') or trivy_cfg.lower().endswith('.exe')
        if looks_like_path:
            trivy_path = _to_path(trivy_cfg)
        else:
            found = shutil.which(trivy_cfg)
            trivy_path = Path(found) if found else _to_path(trivy_cfg)

    ensure_dir(work_dir)
    ensure_dir(out_dir)
    return app_root, work_dir, out_dir, trivy_path


def new_job_id() -> str:
    return f"job__{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"


def sanitize_name(value: Any, default: str = "unknown") -> str:
    return sanitize_filename_component("" if value is None else str(value), default=default)


def file_suffix(name: str) -> str:
    return Path(name).suffix.lower()


def save_uploaded_file(uploaded_file, target_path: Path) -> Path:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_bytes(uploaded_file.getbuffer())
    return target_path


def preview_table(uploaded_file, rows: int = 20) -> pd.DataFrame:
    suffix = file_suffix(uploaded_file.name)
    raw = uploaded_file.getvalue()
    if suffix == ".csv":
        for enc in ("utf-8-sig", "cp932", "utf-8"):
            try:
                return pd.read_csv(
                    io.BytesIO(raw), header=None, dtype=str, nrows=rows, encoding=enc
                )
            except Exception:
                continue
        return pd.read_csv(io.BytesIO(raw), header=None, dtype=str, nrows=rows)
    if suffix in {".xlsx", ".xlsm"}:
        return pd.read_excel(
            io.BytesIO(raw), sheet_name=0, header=None, dtype=str, nrows=rows, engine="openpyxl"
        )
    if suffix == ".xls":
        return pd.read_excel(
            io.BytesIO(raw), sheet_name=0, header=None, dtype=str, nrows=rows, engine="xlrd"
        )
    raise ValueError("入力ファイルは CSV / Excel のみ対応です。")


def cleanup_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    work = df.copy().fillna("")
    work.columns = [str(c).strip() for c in work.columns]
    work = work.loc[
        :, [str(col).strip() != "" and not str(col).startswith("Unnamed:") for col in work.columns]
    ]
    if work.empty:
        return work
    mask = ~(work.apply(lambda row: all(str(v).strip() == "" for v in row), axis=1))
    work = work.loc[mask].copy().fillna("")
    return work.reset_index(drop=True)


def parse_csv(uploaded_file, header_row_index: int, header_present: bool) -> pd.DataFrame:
    raw = uploaded_file.getvalue()
    if header_present:
        for enc in ("utf-8-sig", "cp932", "utf-8"):
            try:
                return cleanup_dataframe(
                    pd.read_csv(io.BytesIO(raw), header=header_row_index, dtype=str, encoding=enc)
                )
            except Exception:
                continue
        return cleanup_dataframe(pd.read_csv(io.BytesIO(raw), header=header_row_index, dtype=str))
    for enc in ("utf-8-sig", "cp932", "utf-8"):
        try:
            df = pd.read_csv(
                io.BytesIO(raw), header=None, dtype=str, skiprows=header_row_index, encoding=enc
            )
            df.columns = [f"col_{i}" for i in range(1, len(df.columns) + 1)]
            return cleanup_dataframe(df)
        except Exception:
            continue
    df = pd.read_csv(io.BytesIO(raw), header=None, dtype=str, skiprows=header_row_index)
    df.columns = [f"col_{i}" for i in range(1, len(df.columns) + 1)]
    return cleanup_dataframe(df)


def parse_excel(
    uploaded_file, temp_dir: Path, header_row_index: int, scan_rows: int, header_present: bool
) -> pd.DataFrame:
    suffix = file_suffix(uploaded_file.name)
    if suffix in {".xlsx", ".xlsm"}:
        temp_path = save_uploaded_file(uploaded_file, temp_dir / f"preview{suffix}")
        normalized = normalize_excel_first_sheet(
            temp_path,
            header_row_index_1based=header_row_index + 1,
            scan_rows=scan_rows,
            header_present=header_present,
        )
        return cleanup_dataframe(pd.DataFrame(normalized.rows, columns=normalized.headers))
    if suffix == ".xls":
        if header_present:
            return cleanup_dataframe(
                pd.read_excel(
                    io.BytesIO(uploaded_file.getvalue()),
                    sheet_name=0,
                    header=header_row_index,
                    dtype=str,
                    engine="xlrd",
                )
            )
        df = pd.read_excel(
            io.BytesIO(uploaded_file.getvalue()),
            sheet_name=0,
            header=None,
            dtype=str,
            engine="xlrd",
            skiprows=header_row_index,
        )
        df.columns = [f"col_{i}" for i in range(1, len(df.columns) + 1)]
        return cleanup_dataframe(df)
    raise ValueError("Excel の拡張子が未対応です。")


def choose_default_column(
    columns: list[str], logical_key: str, keywords: dict[str, list[str]], header_present: bool
) -> int:
    if not header_present:
        return (
            min(NO_HEADER_DEFAULT_INDEX.get(logical_key, 0), max(0, len(columns) - 1))
            if columns
            else 0
        )
    aliases = [a.strip().lower() for a in keywords.get(logical_key, [])]
    normalized_columns = [str(c).strip().lower() for c in columns]
    for alias in aliases:
        if alias in normalized_columns:
            return normalized_columns.index(alias)
    for idx, col in enumerate(normalized_columns):
        if any(alias and alias in col for alias in aliases):
            return idx
    return (
        min(NO_HEADER_DEFAULT_INDEX.get(logical_key, 0), max(0, len(columns) - 1)) if columns else 0
    )


def build_mapping(
    columns: list[str], keywords: dict[str, list[str]], header_present: bool
) -> dict[str, Optional[str]]:
    c1, c2 = st.columns(2)
    mapping: dict[str, Optional[str]] = {}
    with c1:
        st.markdown("必須列")
        for key in REQUIRED_KEYS:
            mapping[key] = st.selectbox(
                DISPLAY_NAMES[key],
                options=columns,
                index=choose_default_column(columns, key, keywords, header_present),
                key=f"map_{key}",
            )
    with c2:
        st.markdown("任意列")
        none_option = "（使用しない）"
        for key in OPTIONAL_KEYS:
            options = [none_option] + columns
            default_idx = 0
            if header_present:
                guessed = choose_default_column(columns, key, keywords, header_present)
                if 0 <= guessed < len(columns):
                    default_idx = guessed + 1
            selected = st.selectbox(
                DISPLAY_NAMES[key],
                options=options,
                index=default_idx,
                key=f"map_{key}",
            )
            mapping[key] = None if selected == none_option else selected
    st.caption(
        "任意列は（使用しない）を選択できます。CSVの全列をツール側で使用する必要はありません。"
    )
    return mapping


def mapping_to_indices(mapping: dict[str, Optional[str]], columns: list[str]) -> ColumnMapping:
    cm = ColumnMapping(
        management_no=(
            columns.index(mapping["management_no"])
            if mapping.get("management_no") in columns
            else None
        ),
        language=columns.index(mapping["language"]) if mapping.get("language") in columns else None,
        package_name=(
            columns.index(mapping["package_name"])
            if mapping.get("package_name") in columns
            else None
        ),
        version=columns.index(mapping["version"]) if mapping.get("version") in columns else None,
        url=columns.index(mapping["url"]) if mapping.get("url") in columns else None,
        software_file_name=(
            columns.index(mapping["software_file_name"])
            if mapping.get("software_file_name") in columns
            else None
        ),
    )
    validate_mapping(cm)
    return cm


def dataframe_to_rows(
    df: pd.DataFrame, mapping: dict[str, Optional[str]]
) -> tuple[list[dict[str, str]], list[str]]:
    rows: list[dict[str, str]] = []
    errors: list[str] = []
    for idx, rec in df.fillna("").astype(str).iterrows():
        row = {
            logical_key: (
                "" if not mapping.get(logical_key) else str(rec[mapping[logical_key]]).strip()
            )
            for logical_key in REQUIRED_KEYS + OPTIONAL_KEYS
        }
        missing = [DISPLAY_NAMES[k] for k in REQUIRED_KEYS if not row.get(k)]
        if missing:
            errors.append(f"{idx + 1}行目: 必須値不足 ({', '.join(missing)})")
            continue
        rows.append(row)
    return rows, errors


def row_display_name(row: dict[str, str]) -> str:
    return f"{sanitize_name(row.get('management_no'))}_{sanitize_name(row.get('package_name'))}@{sanitize_name(row.get('version'))}"


def save_artifacts(files, target_dir: Path) -> list[Path]:
    saved: list[Path] = []
    ensure_dir(target_dir)
    for f in files or []:
        if file_suffix(f.name) not in ARCHIVE_EXTS:
            continue
        dst = target_dir / sanitize_name(f.name, default="artifact")
        save_uploaded_file(f, dst)
        saved.append(dst)
    return saved


def _normalize_survey_mode(survey_mode: str) -> str:
    raw = (survey_mode or "").strip().lower()
    mapping = {
        "precheck": "precheck",
        "runtime": "runtime",
        "随時調査": "precheck",
        "定期調査": "runtime",
        "事前調査": "precheck",
    }
    return mapping.get(raw, raw)


def _parse_gav_from_url(url: str) -> Optional[tuple[str, str, str]]:
    if not url:
        return None
    u = str(url).strip()
    if not u.lower().startswith("gav:"):
        return None
    parts = u[4:].split(":")
    if len(parts) < 3:
        return None
    group_id = parts[0].strip()
    artifact_id = parts[1].strip()
    version = ":".join(parts[2:]).strip()
    if not group_id or not artifact_id or not version:
        return None
    return group_id, artifact_id, version


def _build_gav_url(group_id: str, artifact_id: str, version: str) -> str:
    return f"gav:{group_id.strip()}:{artifact_id.strip()}:{version.strip()}"


def match_attachment(row: dict[str, str], attachments: list[Path]) -> Optional[Path]:
    # 『勝手に別添付を使う』の禁止: 明示指定（attachment_file_name）の完全一致のみ許可
    name = str(row.get("attachment_file_name") or "").strip()
    if not name:
        return None
    for p in attachments:
        if p.name.lower() == name.lower():
            return p
    return None


def apply_manual_java_gav_inputs(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    java_rows = [row for row in rows if str(row.get("language") or "").strip().lower() == "java"]
    if not java_rows:
        return rows
    st.subheader("Java行専用入力（GAV手入力）")
    st.caption(
        "Java 行のみ、GAV を UI から手入力できます。入力した GAV は CSV の URL 列より優先されます。"
    )
    with st.expander("Java 行ごとの GAV 手入力", expanded=False):
        updated: list[dict[str, str]] = []
        for row in rows:
            if str(row.get("language") or "").strip().lower() != "java":
                row_copy = dict(row)
                row_copy["resolved_url"] = row.get("url", "")
                row_copy["gav_source"] = ""
                updated.append(row_copy)
                continue
            existing = _parse_gav_from_url(row.get("url") or "")
            default_group = existing[0] if existing else ""
            default_artifact = existing[1] if existing else str(row.get("package_name") or "")
            default_version = existing[2] if existing else str(row.get("version") or "")
            st.markdown(f"- {row_display_name(row)}")
            c1, c2, c3 = st.columns(3)
            group_id = c1.text_input(
                "groupId",
                value=default_group,
                key=f"gav_group_{row.get('management_no','')}_{row.get('package_name','')}",
            )
            artifact_id = c2.text_input(
                "artifactId",
                value=default_artifact,
                key=f"gav_artifact_{row.get('management_no','')}_{row.get('package_name','')}",
            )
            version = c3.text_input(
                "version",
                value=default_version,
                key=f"gav_version_{row.get('management_no','')}_{row.get('package_name','')}",
            )
            row_copy = dict(row)
            if group_id.strip() and artifact_id.strip() and version.strip():
                row_copy["resolved_url"] = _build_gav_url(group_id, artifact_id, version)
                row_copy["gav_source"] = "manual_gav"
            else:
                row_copy["resolved_url"] = row.get("url", "")
                row_copy["gav_source"] = "csv_gav" if existing else ""
            updated.append(row_copy)
        return updated


def apply_attachment_assignments(
    rows: list[dict[str, str]], uploaded_attachments: list[Path]
) -> tuple[list[dict[str, str]], list[str]]:
    # Java行の添付割り当てUI。未指定行は存在してよい（Java行数 > 添付数のケース）。
    java_rows = [row for row in rows if str(row.get("language") or "").strip().lower() == "java"]
    if not java_rows:
        return rows, []
    attachment_names = [p.name for p in uploaded_attachments]
    if not attachment_names:
        return rows, []
    st.subheader("Java添付ファイルの割り当て")
    st.caption("複数ファイル添付時は、Java行ごとに使用するファイルを選択できます（未指定も可）。")
    none_label = "（未指定）"
    errors: list[str] = []
    with st.expander("Java 行ごとの添付ファイル割り当て", expanded=(len(attachment_names) > 1)):
        updated: list[dict[str, str]] = []
        chosen_by_row: dict[str, str] = {}
        for row in rows:
            if str(row.get("language") or "").strip().lower() != "java":
                updated.append(dict(row))
                continue
            label = row_display_name(row)
            default_name = str(row.get("attachment_file_name") or "").strip()
            options = [none_label] + attachment_names
            default_idx = 0
            if default_name:
                if default_name in attachment_names:
                    default_idx = attachment_names.index(default_name) + 1
                else:
                    errors.append(
                        f"{label}: 指定された添付ファイル名がアップロード一覧に存在しません -> {default_name}"
                    )
            selected = st.selectbox(
                f"{label} の添付ファイル",
                options=options,
                index=default_idx,
                key=f"attach_pick_{row.get('management_no','')}_{row.get('package_name','')}",
            )
            row_copy = dict(row)
            if selected != none_label:
                row_copy["attachment_file_name"] = selected
                row_copy["attachment_assignment_source"] = "manual"
                chosen_by_row[label] = selected
            else:
                # 未指定は許容。勝手に別添付を推測しない。
                row_copy["attachment_file_name"] = ""
                row_copy["attachment_assignment_source"] = ""
            updated.append(row_copy)
        if len(attachment_names) > 1:
            reverse: dict[str, list[str]] = {}
            for rlabel, fname in chosen_by_row.items():
                reverse.setdefault(fname, []).append(rlabel)
            duplicates = {fname: labels for fname, labels in reverse.items() if len(labels) > 1}
            if duplicates:
                st.warning(
                    "同じ添付ファイルが複数行に割り当てられています（意図していない場合は修正してください）。"
                )
                lines = [f"{fname}: {', '.join(labels)}" for fname, labels in duplicates.items()]
                st.code("\n".join(lines))
            unused = [n for n in attachment_names if n not in reverse]
            if unused:
                st.info("割り当てされていない添付ファイルがあります（未使用なら問題ありません）。")
                st.code("\n".join(unused))
        return updated, errors


def evaluate_java_input(
    row: dict[str, str], attachments: list[Path], survey_mode: str
) -> tuple[str, str, str]:
    attachment = match_attachment(row, attachments)
    has_attachment = attachment is not None
    effective_url = row.get("resolved_url") or row.get("url") or ""
    has_gav = _parse_gav_from_url(effective_url) is not None
    normalized = _normalize_survey_mode(survey_mode)
    preferred = "gav" if normalized == "precheck" else "attachment"
    fallback = "attachment" if preferred == "gav" else "gav"
    gav_source = row.get("gav_source") or (
        "csv_gav" if _parse_gav_from_url(row.get("url") or "") else ""
    )
    if preferred == "gav" and has_gav:
        return "ok", gav_source or "gav", ""
    if preferred == "attachment" and has_attachment:
        return "ok", "attachment", ""
    if fallback == "gav" and has_gav:
        # 未指定行でもGAVがあればフォールバックしてOK
        return (
            "warning",
            gav_source or "gav",
            "優先ソースが見つからないため、GAV ベースで処理します。",
        )
    if fallback == "attachment" and has_attachment:
        return (
            "warning",
            "attachment",
            "優先ソースが見つからないため、添付ファイルベースで処理します。",
        )
    if normalized == "precheck":
        return "error", "", "随時調査の Java 行は、GAV または添付ファイルのいずれかが必要です。"
    return "error", "", "定期調査の Java 行は、添付ファイルまたは GAV のいずれかが必要です。"


def build_manifest(
    job_id: str,
    input_name: str,
    survey_mode_code: str,
    survey_mode_label: str,
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "job_id": job_id,
        "input_file": input_name,
        "survey_mode_code": survey_mode_code,
        "survey_mode_label": survey_mode_label,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "results": results,
    }


def build_result_zip(job_root: Path, job_out_root: Path, manifest: dict[str, Any]) -> bytes:
    (job_root / "result_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for sub, arc in [("sbom", "sbom"), ("error", "error")]:
            d = job_out_root / sub
            if d.exists():
                for p in sorted(d.rglob("*")):
                    if p.is_file():
                        rel = p.name if sub == "sbom" else p.relative_to(d).as_posix()
                        zf.write(p, arcname=f"{arc}/{rel}")
        for p in sorted(job_root.rglob("*")):
            if p.is_file():
                zf.write(p, arcname="intermediate/" + p.relative_to(job_root).as_posix())
    buf.seek(0)
    return buf.getvalue()


def init_session_state() -> None:
    for k, v in {"result_rows": None, "result_zip": None, "result_zip_name": None}.items():
        if k not in st.session_state:
            st.session_state[k] = v


def main() -> None:
    st.set_page_config(page_title="SBOM生成ツール", layout="wide")
    init_session_state()
    cfg = load_app_config()
    keywords = load_keywords()
    _, work_dir, out_dir, trivy_path = app_paths(cfg)
    max_jobs = int(os.environ.get("SBOM_TOOL_MAX_CONCURRENT_JOBS", "1"))

    st.title("SBOM生成ツール")
    st.caption("外部提供の CSV / Excel を入力し、管理番号単位で SBOM（SPDX JSON）を生成します。")

    survey_mode_code = st.radio(
        "調査モード",
        options=SURVEY_MODE_OPTIONS,
        index=0,
        horizontal=True,
        format_func=lambda x: SURVEY_MODE_LABELS.get(x, x),
    )
    survey_mode_label = SURVEY_MODE_LABELS.get(survey_mode_code, survey_mode_code)
    st.caption("Java優先順: 随時調査は GAV 解決優先、定期調査は添付ファイル優先です。")

    input_file = st.file_uploader(
        "入力ファイル（CSV / Excel）", type=["csv", "xlsx", "xlsm", "xls"]
    )
    attachment_files = st.file_uploader(
        "Java添付ファイル（任意: ZIP / JAR / WAR / EAR）",
        type=["zip", "jar", "war", "ear"],
        accept_multiple_files=True,
    )

    if input_file is None:
        st.info("入力ファイルをアップロードしてください。")
        return

    if getattr(input_file, "size", 0) and int(input_file.size) > cfg["max_upload_mb"] * 1024 * 1024:
        st.error(f"入力ファイルサイズが上限 {cfg['max_upload_mb']} MB を超えています。")
        return

    preview_df = preview_table(input_file, rows=cfg["preview_rows"])
    st.subheader("入力プレビュー")
    st.dataframe(preview_df, use_container_width=True)

    header_present = (
        st.radio("ヘッダー行の有無", options=["あり", "なし"], index=0, horizontal=True) == "あり"
    )
    label = "ヘッダ行（0始まり）" if header_present else "データ開始行（0始まり）"
    max_header = max(0, min(len(preview_df) - 1, cfg["header_scan_rows"] - 1))
    header_row_index = int(
        st.number_input(label, min_value=0, max_value=max_header, value=0, step=1)
    )

    temp_parse_dir = work_dir / "_tmp_parse"
    ensure_dir(temp_parse_dir)
    try:
        parsed_df = (
            parse_csv(input_file, header_row_index, header_present)
            if file_suffix(input_file.name) == ".csv"
            else parse_excel(
                input_file,
                temp_parse_dir,
                header_row_index,
                cfg["header_scan_rows"],
                header_present,
            )
        )
    finally:
        if temp_parse_dir.exists():
            rm_tree(temp_parse_dir)

    if parsed_df.empty:
        st.warning("有効なデータ行が見つかりません。ヘッダ行や入力内容を確認してください。")
        return

    st.subheader("列マッピング")
    columns = [str(c) for c in parsed_df.columns]
    mapping = build_mapping(columns, keywords, header_present)
    mapping_to_indices(mapping, columns)
    chosen = [v for v in mapping.values() if v]
    if len(chosen) != len(set(chosen)):
        st.error("同じ入力列が複数項目に割り当てられています。列マッピングを見直してください。")
        return

    prepared_rows, row_errors = dataframe_to_rows(parsed_df, mapping)
    if row_errors:
        st.warning("一部行は必須値不足のため生成対象から除外します。")
        st.code(chr(10).join(row_errors))

    prepared_rows = apply_manual_java_gav_inputs(prepared_rows)

    attachment_preview_dir = work_dir / "_tmp_attachment_preview"
    ensure_dir(attachment_preview_dir)
    try:
        preview_attachments = save_artifacts(attachment_files, attachment_preview_dir)
        prepared_rows, attach_errors = apply_attachment_assignments(
            prepared_rows, preview_attachments
        )
        if attach_errors:
            st.error("添付ファイル名の指定に誤りがあります。修正してください。")
            st.code(chr(10).join(attach_errors))
            return

        java_warnings: list[str] = []
        java_errors: list[str] = []
        validated_rows: list[dict[str, str]] = []

        for row in prepared_rows:
            if str(row.get("language") or "").strip().lower() != "java":
                validated_rows.append(row)
                continue
            level, resolved_source, message = evaluate_java_input(
                row, preview_attachments, survey_mode_code
            )
            row_copy = dict(row)
            if resolved_source:
                row_copy["java_resolution_source"] = resolved_source
            validated_rows.append(row_copy)
            label2 = row_display_name(row)
            if level == "warning":
                java_warnings.append(f"{label2}: {message}")
            elif level == "error":
                java_errors.append(f"{label2}: {message}")
    finally:
        if attachment_preview_dir.exists():
            rm_tree(attachment_preview_dir)

    if java_warnings:
        st.warning("Java の入力ソース優先順により、代替ソースで処理する行があります。")
        st.code(chr(10).join(java_warnings))

    if java_errors:
        st.error("Java の入力条件を満たさない行があります。修正してください。")
        st.code(chr(10).join(java_errors))
        return

    prepared_rows = validated_rows
    if not prepared_rows:
        st.error("生成対象となる行がありません。")
        return

    st.subheader("生成対象プレビュー")
    st.dataframe(pd.DataFrame(prepared_rows), use_container_width=True)

    if st.button("生成開始", type="primary"):
        job_id = new_job_id()
        job_root = work_dir / job_id
        job_input_dir = job_root / "input"
        job_artifact_dir = job_input_dir / "artifacts"
        job_mgmt_root = job_root / "mgmt"
        job_out_root = out_dir / job_id
        job_out_sbom_dir = job_out_root / "sbom"
        job_out_err_dir = job_out_root / "error"
        for d in [
            job_input_dir,
            job_artifact_dir,
            job_mgmt_root,
            job_out_sbom_dir,
            job_out_err_dir,
        ]:
            ensure_dir(d)

        save_uploaded_file(
            input_file, job_input_dir / sanitize_name(input_file.name, default="input")
        )
        saved_attachments = save_artifacts(attachment_files, job_artifact_dir)

        progress = st.progress(0.0)
        status_box = st.empty()
        result_rows: list[dict[str, Any]] = []
        has_failure = False

        with FileSemaphore(slots_dir=work_dir / "_locks_jobs", max_concurrency=max_jobs):
            for i, row in enumerate(prepared_rows, start=1):
                status_box.info(f"処理中 ({i}/{len(prepared_rows)}): {row_display_name(row)}")
                try:
                    effective_url = (row.get("resolved_url") or row.get("url") or "").strip()
                    input_row = InputRow(
                        management_no=row["management_no"],
                        language=row["language"],
                        package_name=row["package_name"],
                        version=row["version"],
                        url=(effective_url or None),
                        software_file_name=(row.get("software_file_name") or None),
                    )
                    attachment_path = None
                    if str(row.get("language") or "").strip().lower() == "java":
                        attachment_path = match_attachment(row, saved_attachments)
                        # 行で添付が指定されているのに見つからない場合はエラー
                        if (
                            str(row.get("attachment_file_name") or "").strip()
                            and attachment_path is None
                        ):
                            raise ValueError(
                                "指定された添付ファイルがアップロード一覧に存在しません"
                            )
                    status, sbom_path, err = process_one(
                        input_row,
                        trivy_path=trivy_path,
                        work_root=job_mgmt_root,
                        out_sbom_dir=job_out_sbom_dir,
                        out_err_dir=job_out_err_dir,
                        sbom_format=cfg["sbom_format"],
                        timeout_seconds=cfg["timeout_seconds"],
                        attachment_path=attachment_path,
                        survey_mode=survey_mode_code,
                    )
                    status_str = status.value if hasattr(status, "value") else str(status)
                    result_rows.append(
                        {
                            "survey_mode_code": survey_mode_code,
                            "survey_mode_label": survey_mode_label,
                            "management_no": row["management_no"],
                            "language": row["language"],
                            "package_name": row["package_name"],
                            "version": row["version"],
                            "status": status_str,
                            "sbom_path": "" if not sbom_path else str(sbom_path),
                            "error": "" if err is None else str(err),
                            "attachment": "" if attachment_path is None else attachment_path.name,
                            "java_resolution_source": row.get("java_resolution_source", ""),
                            "gav_source": row.get("gav_source", ""),
                            "resolved_url": effective_url,
                            "attachment_assignment_source": row.get(
                                "attachment_assignment_source", ""
                            ),
                        }
                    )
                    if status_str != "SUCCESS":
                        has_failure = True
                except Exception as exc:
                    has_failure = True
                    result_rows.append(
                        {
                            "survey_mode_code": survey_mode_code,
                            "survey_mode_label": survey_mode_label,
                            "management_no": row.get("management_no", ""),
                            "language": row.get("language", ""),
                            "package_name": row.get("package_name", ""),
                            "version": row.get("version", ""),
                            "status": "FAILED_TOOL",
                            "sbom_path": "",
                            "error": str(exc),
                            "attachment": "",
                            "java_resolution_source": row.get("java_resolution_source", ""),
                            "gav_source": row.get("gav_source", ""),
                            "resolved_url": effective_url,
                            "attachment_assignment_source": row.get(
                                "attachment_assignment_source", ""
                            ),
                        }
                    )
                finally:
                    progress.progress(i / len(prepared_rows))

        st.session_state["result_rows"] = result_rows
        st.session_state["result_zip"] = build_result_zip(
            job_root,
            job_out_root,
            build_manifest(
                job_id, input_file.name, survey_mode_code, survey_mode_label, result_rows
            ),
        )
        st.session_state["result_zip_name"] = f"sbom_result_{job_id}.zip"
        status_box.success("生成処理が完了しました。")

        cleanup = (
            cfg["cleanup_workdir_on_failure"] if has_failure else cfg["cleanup_workdir_on_success"]
        )
        if cleanup:
            if job_root.exists():
                rm_tree(job_root)
            if job_out_root.exists():
                rm_tree(job_out_root)

    if st.session_state.get("result_rows"):
        st.subheader("実行結果")
        st.dataframe(pd.DataFrame(st.session_state["result_rows"]), use_container_width=True)

    if st.session_state.get("result_zip"):
        st.download_button(
            "成果物ZIPをダウンロード",
            data=st.session_state["result_zip"],
            file_name=st.session_state["result_zip_name"],
            mime="application/zip",
        )


if __name__ == "__main__":
    main()
