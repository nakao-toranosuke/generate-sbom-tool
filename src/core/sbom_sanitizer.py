from __future__ import annotations

import json
from pathlib import Path


def _safe_component(text: str) -> str:
    s = (text or '').strip()
    if not s:
        return 'NA'
    return ''.join(ch if ch.isalnum() or ch in {'-', '_', '.', '@'} else '_' for ch in s)


def _map_survey_mode_label(survey_mode: str) -> str:
    raw = (survey_mode or '').strip().lower()
    mapping = {
        'precheck': '随時調査',
        'runtime': '定期調査',
        '事前調査': '随時調査',
        '随時調査': '随時調査',
        '定期調査': '定期調査',
    }
    return mapping.get(raw, _safe_component(survey_mode or '随時調査'))


def _language_labels(language: str) -> tuple[str, str]:
    lang = (language or '').strip().lower()
    if lang in {'python', 'py'}:
        return 'Python', 'python'
    if lang in {'node', 'node.js', 'nodejs', 'javascript', 'js'}:
        return 'Nodejs', 'nodejs'
    if lang == 'java':
        return 'Java', 'java'
    return _safe_component(language or 'Unknown'), _safe_component(lang or 'unknown').lower()


def _format_management_no(mgmt: str) -> str:
    s = (mgmt or '').strip()
    return s.zfill(5) if s.isdigit() else _safe_component(s)


def build_public_name(survey_mode: str, language: str, mgmt: str, pkg: str, ver: str) -> str:
    survey_label = _map_survey_mode_label(survey_mode)
    language_display, language_slug = _language_labels(language)
    return f'{survey_label}__{language_display}__{_format_management_no(mgmt)}__{language_slug}_{_safe_component(pkg)}@{_safe_component(ver)}'


def sanitize_spdx_json(sbom_path: Path, survey_mode: str, language: str, mgmt: str, pkg: str, ver: str) -> None:
    p = Path(sbom_path)
    doc = json.loads(p.read_text(encoding='utf-8'))
    public_name = build_public_name(survey_mode, language, mgmt, pkg, ver)
    if isinstance(doc, dict):
        doc['name'] = public_name
        doc['documentNamespace'] = 'http://example.invalid/spdx/' + public_name
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding='utf-8')
