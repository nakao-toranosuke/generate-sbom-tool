from __future__ import annotations

import os
import re
import zipfile
from pathlib import Path
from typing import Optional, Tuple

from ..models.types import InputRow, Status
from ..utils.fs import ensure_dir, sanitize_filename_component
from .postprocess import embed_software_file_name, fill_missing_supplier_and_version_info
from .runners.java_maven import generate_spdx_from_gav
from .runners.java_resolver import download_to, is_direct_download_url
from .runners.node_npm import generate_package_lock
from .runners.python_pipenv import generate_pipenv_lock
from .runners.python_uv import generate_uv_lock
from .sbom_sanitizer import sanitize_spdx_json
from .trivy_runner import run_trivy_fs

_NL = chr(10)


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


def _map_survey_mode_label(survey_mode: str) -> str:
    normalized = _normalize_survey_mode(survey_mode)
    if normalized == "precheck":
        return "随時調査"
    if normalized == "runtime":
        return "定期調査"
    return sanitize_filename_component(survey_mode or "随時調査")


def _is_precheck_mode(survey_mode: str) -> bool:
    return _normalize_survey_mode(survey_mode) == "precheck"


def _java_source_priority(survey_mode: str) -> list[str]:
    normalized = _normalize_survey_mode(survey_mode)
    return ["gav", "attachment"] if normalized == "precheck" else ["attachment", "gav"]


def _language_labels(language: str) -> tuple[str, str]:
    lang = (language or "").strip().lower()
    if lang in {"python", "py"}:
        return "Python", "python"
    if lang in {"node", "node.js", "nodejs", "javascript", "js"}:
        return "Nodejs", "nodejs"
    if lang == "java":
        return "Java", "java"
    return (
        sanitize_filename_component(language or "Unknown"),
        sanitize_filename_component(lang or "unknown").lower(),
    )


def _format_management_no(mgmt: str) -> str:
    s = "" if mgmt is None else str(mgmt).strip()
    return s.zfill(5) if s.isdigit() else sanitize_filename_component(s)


def build_sbom_basename(survey_mode: str, language: str, mgmt: str, pkg: str, ver: str) -> str:
    survey_label = _map_survey_mode_label(survey_mode)
    language_display, language_slug = _language_labels(language)
    return f"{survey_label}__{language_display}__{_format_management_no(mgmt)}__{language_slug}_{sanitize_filename_component(pkg)}@{sanitize_filename_component(ver)}"


def build_sbom_filename(survey_mode: str, language: str, mgmt: str, pkg: str, ver: str) -> str:
    return build_sbom_basename(survey_mode, language, mgmt, pkg, ver) + ".spdx.json"


def build_err_dirname(survey_mode: str, language: str, mgmt: str, pkg: str, ver: str) -> str:
    return build_sbom_basename(survey_mode, language, mgmt, pkg, ver)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_error_bundle(
    out_err_root: Path,
    survey_mode: str,
    language: str,
    mgmt: str,
    pkg: str,
    ver: str,
    summary: str,
    step: str,
    returncode: Optional[int] = None,
    stdout: Optional[str] = None,
    stderr: Optional[str] = None,
) -> Path:
    err_dir = out_err_root / build_err_dirname(survey_mode, language, mgmt, pkg, ver)
    err_dir.mkdir(parents=True, exist_ok=True)
    _write_text(err_dir / "error.log", summary.strip() + _NL)
    meta = [f"step={step}", f"survey_mode={survey_mode}", f"language={language}"]
    if returncode is not None:
        meta.append(f"returncode={returncode}")
    _write_text(err_dir / "meta.txt", _NL.join(meta) + _NL)
    if stdout is not None:
        _write_text(err_dir / "stdout.txt", stdout)
    if stderr is not None:
        _write_text(err_dir / "stderr.txt", stderr)
    return err_dir


def _extract_zip(zip_path: Path, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(str(zip_path), "r") as zf:
        zf.extractall(str(dest_dir))


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


def _mask_env_value(value: str) -> str:
    v = "" if value is None else str(value)
    # 簡易マスク（password/secret/token が含まれる場合）
    if re.search(r"(password|secret|token)=", v, flags=re.IGNORECASE):
        return re.sub(r"(?i)(password|secret|token)=([^\s]+)", r"\1=****", v)
    return v


def _is_dangerous_java_option_value(value: str) -> bool:
    if value is None:
        return False
    raw = str(value).replace("\r", " ").replace("\n", " ")
    tokens = [t for t in raw.split() if t]
    if str(value).strip() == "-":
        return True
    return any(t == "-" for t in tokens)


def _log_and_sanitize_maven_env(log_path: Path) -> dict[str, Optional[str]]:
    keys = ["JAVA_HOME", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "MAVEN_OPTS"]
    original: dict[str, Optional[str]] = {k: os.environ.get(k) for k in keys}
    lines = []
    lines.append("=== maven env (before) ===")
    for k in keys:
        lines.append(f"{k}=" + _mask_env_value(original.get(k) or ""))
    removed = []
    for k in ["JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "MAVEN_OPTS"]:
        v = original.get(k)
        if _is_dangerous_java_option_value(v):
            removed.append(k)
            os.environ.pop(k, None)
    lines.append("=== maven env (sanitized) ===")
    for k in keys:
        lines.append(f"{k}=" + _mask_env_value(os.environ.get(k) or ""))
    if removed:
        lines.append("sanitized_keys=" + ",".join(removed))
    else:
        lines.append("sanitized_keys=")
    _write_text(log_path, _NL.join(lines) + _NL)
    return original


def _restore_env(original: dict[str, Optional[str]]) -> None:
    for k, v in original.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def process_one(
    row: InputRow,
    trivy_path: Path,
    work_root: Path,
    out_sbom_dir: Path,
    out_err_dir: Path,
    sbom_format: str,
    timeout_seconds: int,
    attachment_path: Optional[Path] = None,
    survey_mode: str = "precheck",
) -> Tuple[Status, Optional[Path], Optional[str]]:
    ensure_dir(work_root)
    mg_dir = work_root / f"mgmt_{sanitize_filename_component(row.management_no)}"
    ensure_dir(mg_dir)
    out_sbom = out_sbom_dir / build_sbom_filename(
        survey_mode, row.language, row.management_no, row.package_name, row.version
    )
    lang = (row.language or "").strip().lower()
    try:
        lock_path: Optional[Path] = None
        if lang in {"python", "py"}:
            py_dir = mg_dir / "python"
            if _is_precheck_mode(survey_mode):
                generate_uv_lock(
                    py_dir, row.package_name, row.version, timeout_seconds=timeout_seconds
                )
                target = py_dir
                lp = py_dir / "uv.lock"
            else:
                generate_pipenv_lock(
                    py_dir, row.package_name, row.version, timeout_seconds=timeout_seconds
                )
                target = py_dir
                lp = py_dir / "Pipfile.lock"
            if lp.exists():
                lock_path = lp
        elif lang in {"node", "node.js", "nodejs", "javascript", "js"}:
            node_dir = mg_dir / "node"
            generate_package_lock(
                node_dir, row.package_name, row.version, timeout_seconds=timeout_seconds
            )
            target = node_dir
        elif lang == "java":
            java_dir = mg_dir / "java"
            ensure_dir(java_dir)
            gav = _parse_gav_from_url(row.url or "")
            direct_download_path: Optional[Path] = None
            if attachment_path is None and row.url and is_direct_download_url(row.url):
                direct_download_path = download_to(row.url, java_dir / Path(row.url).name)
            last_gav_error: Optional[tuple[str, str, str, int]] = None
            selected_target: Optional[Path] = None
            for source in _java_source_priority(survey_mode):
                if source == "gav":
                    if gav is None:
                        continue
                    maven_work = java_dir / "maven"
                    ensure_dir(maven_work)
                    env_log_path = maven_work / "maven_env.txt"
                    original_env = _log_and_sanitize_maven_env(env_log_path)
                    try:
                        ok, mvn_out, mvn_err, rc = generate_spdx_from_gav(
                            mgmt=row.management_no,
                            group_id=gav[0],
                            artifact_id=gav[1],
                            version=gav[2],
                            out_path=out_sbom,
                            work_dir=maven_work,
                            timeout_seconds=timeout_seconds,
                        )
                    finally:
                        _restore_env(original_env)
                    if ok:
                        sanitize_spdx_json(
                            out_sbom,
                            survey_mode,
                            row.language,
                            row.management_no,
                            row.package_name,
                            row.version,
                        )
                        return Status.SUCCESS, out_sbom, None
                    last_gav_error = (mvn_out or "", mvn_err or "", "maven resolve", int(rc))
                    continue
                # 添付は明示指定で渡された attachment_path のみ使用（勝手に別添付は使わない）
                effective_attachment = attachment_path or direct_download_path
                if effective_attachment is None:
                    continue
                ap = Path(effective_attachment)
                if ap.suffix.lower() == ".zip":
                    extract_dir = java_dir / ("extracted_" + sanitize_filename_component(ap.stem))
                    _extract_zip(ap, extract_dir)
                    selected_target = extract_dir
                else:
                    selected_target = ap
                break
            if selected_target is None:
                if last_gav_error is not None:
                    mvn_out, mvn_err, step_name, rc = last_gav_error
                    _write_error_bundle(
                        out_err_dir,
                        survey_mode,
                        row.language,
                        row.management_no,
                        row.package_name,
                        row.version,
                        "FAILED_TOOL: maven resolve failed and no usable attachment was found",
                        step_name,
                        returncode=rc,
                        stdout=mvn_out,
                        stderr=mvn_err,
                    )
                    return Status.FAILED_TOOL, None, "gav failed and no attachment"
                _write_error_bundle(
                    out_err_dir,
                    survey_mode,
                    row.language,
                    row.management_no,
                    row.package_name,
                    row.version,
                    "SKIPPED_NO_ARTIFACT: GAV も添付ファイルも利用できません",
                    "java source resolution",
                )
                return Status.SKIPPED_NO_ARTIFACT, None, "no java source"
            target = selected_target
        else:
            raise ValueError(f"未対応の言語名です: {row.language}")

        proc = run_trivy_fs(
            trivy_path, target, out_sbom, sbom_format=sbom_format, timeout_seconds=timeout_seconds
        )
        if proc.returncode != 0:
            _write_error_bundle(
                out_err_dir,
                survey_mode,
                row.language,
                row.management_no,
                row.package_name,
                row.version,
                "FAILED_TOOL: trivy 実行失敗",
                "trivy fs",
                returncode=int(proc.returncode),
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
            )
            return Status.FAILED_TOOL, None, proc.stderr

        embed_software_file_name(out_sbom, row.package_name, row.software_file_name)
        fill_missing_supplier_and_version_info(out_sbom, lock_path=lock_path)
        sanitize_spdx_json(
            out_sbom, survey_mode, row.language, row.management_no, row.package_name, row.version
        )
        return Status.SUCCESS, out_sbom, None
    except ValueError as e:
        _write_error_bundle(
            out_err_dir,
            survey_mode,
            row.language,
            row.management_no,
            row.package_name,
            row.version,
            "FAILED_INPUT: " + str(e),
            "input validation",
            stderr=str(e) + _NL,
        )
        return Status.FAILED_INPUT, None, str(e)
    except Exception as e:
        _write_error_bundle(
            out_err_dir,
            survey_mode,
            row.language,
            row.management_no,
            row.package_name,
            row.version,
            "FAILED_TOOL: " + str(e),
            "unexpected",
            stderr=str(e) + _NL,
        )
        return Status.FAILED_TOOL, None, str(e)
