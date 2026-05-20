from __future__ import annotations

import re
from pathlib import Path
from typing import Optional, Dict, Set, Tuple, List, Any

from .trivy_runner import load_json, save_json

_RE_LOCK_HEADER_VERSION = re.compile(r'^version\s*=\s*(\d+)\s*$')
_RE_LOCK_PKG_NAME = re.compile(r'^name\s*=\s*"([^"]+)"\s*$')
_RE_LOCK_PKG_VER = re.compile(r'^version\s*=\s*"([^"]+)"\s*$')


def _parse_uv_lock(lock_path: Optional[Path]) -> Tuple[Optional[str], Dict[str, Set[str]]]:
    if lock_path is None or (not lock_path.exists()):
        return None, {}

    lock_format_version: Optional[str] = None
    versions_by_name: Dict[str, Set[str]] = {}

    in_pkg = False
    cur_name: Optional[str] = None
    cur_ver: Optional[str] = None

    for raw in lock_path.read_text(encoding='utf-8', errors='ignore').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue

        if lock_format_version is None:
            m = _RE_LOCK_HEADER_VERSION.match(line)
            if m:
                lock_format_version = m.group(1)
                continue

        if line == '[[package]]':
            in_pkg = True
            cur_name = None
            cur_ver = None
            continue

        if not in_pkg:
            continue

        m = _RE_LOCK_PKG_NAME.match(line)
        if m:
            cur_name = m.group(1).strip()
            continue

        m = _RE_LOCK_PKG_VER.match(line)
        if m:
            cur_ver = m.group(1).strip()
            continue

        if cur_name and cur_ver:
            s = versions_by_name.get(cur_name)
            if s is None:
                s = set()
                versions_by_name[cur_name] = s
            s.add(cur_ver)

    return lock_format_version, versions_by_name


def _ensure_annotations(pkg: Dict[str, Any]) -> List[Dict[str, Any]]:
    anns = pkg.get('annotations')
    if anns is None:
        anns = []
        pkg['annotations'] = anns
    return anns


def _purl_safe(text: str) -> str:
    s = (text or '').strip().lower()
    s = s.replace(' ', '-')
    s = re.sub(r'[^a-z0-9._-]+', '-', s)
    s = re.sub(r'-{2,}', '-', s)
    s = s.strip('-')
    return s if s else 'unknown'


def _ensure_external_refs(pkg: Dict[str, Any]) -> bool:
    # Some external importers require packages[].externalRefs with a purl, even when SPDX does not.
    ext = pkg.get('externalRefs')
    if isinstance(ext, list) and len(ext) > 0:
        return False

    name = str(pkg.get('name') or '').strip()
    ver = str(pkg.get('versionInfo') or '').strip()

    # If version is unknown, use a stable placeholder to satisfy tools that require @version.
    ver_safe = ver if (ver and ver != 'NOASSERTION') else '0'

    # Prefer pypi type only when the package is clearly a python library package and name looks sane.
    # Otherwise, fallback to generic.
    purpose = str(pkg.get('primaryPackagePurpose') or '').strip().upper()
    purl_type = 'pypi' if (purpose == 'LIBRARY' and name and name != 'uv.lock') else 'generic'

    purl = 'pkg:' + purl_type + '/' + _purl_safe(name) + '@' + _purl_safe(ver_safe)

    pkg['externalRefs'] = [
        {
            'referenceCategory': 'PACKAGE-MANAGER',
            'referenceType': 'purl',
            'referenceLocator': purl
        }
    ]
    return True


def fill_missing_supplier_and_version_info(spdx_json_path: Path, lock_path: Optional[Path] = None) -> bool:
    if spdx_json_path is None or (not spdx_json_path.exists()):
        return False

    lock_format_version, versions_by_name = _parse_uv_lock(lock_path)

    data = load_json(spdx_json_path)
    pkgs = data.get('packages')
    if not isinstance(pkgs, list):
        return False

    changed = False

    for pkg in pkgs:
        if not isinstance(pkg, dict):
            continue

        name = str(pkg.get('name') or '').strip()

        # supplier
        supplier = pkg.get('supplier')
        if supplier is None or str(supplier).strip() == '':
            pkg['supplier'] = 'NOASSERTION'
            changed = True

        # versionInfo
        version_info = pkg.get('versionInfo')
        if version_info is None or str(version_info).strip() == '':
            filled: str = 'NOASSERTION'

            if name == 'uv.lock':
                if lock_format_version:
                    filled = 'lock-format-' + str(lock_format_version)

            elif name in versions_by_name:
                cand = sorted(list(versions_by_name.get(name) or []))
                if len(cand) == 1:
                    filled = cand[0]
                elif len(cand) > 1:
                    filled = 'NOASSERTION'
                    anns = _ensure_annotations(pkg)
                    anns.append({
                        'annotator': 'Tool: sbom-tool',
                        'annotationType': 'OTHER',
                        'comment': 'candidate versions from uv.lock: ' + ','.join(cand)
                    })

            pkg['versionInfo'] = filled
            changed = True

        # externalRefs (purl)
        if _ensure_external_refs(pkg):
            changed = True

    if changed:
        save_json(spdx_json_path, data)
    return changed


def embed_software_file_name(spdx_json_path: Path, package_name: str, software_file_name: Optional[str]) -> bool:
    if not software_file_name:
        return False

    data = load_json(spdx_json_path)
    pkgs = data.get('packages') or []
    target = (package_name or '').strip().lower().replace('_', '-').replace(' ', '-')

    def _norm(s: str) -> str:
        return (s or '').strip().lower().replace('_', '-').replace(' ', '-')

    for pkg in pkgs:
        if not isinstance(pkg, dict):
            continue
        n = pkg.get('name') or pkg.get('packageName')
        if n and _norm(str(n)) == target:
            pkg['packageFileName'] = software_file_name
            save_json(spdx_json_path, data)
            return True

    anns = data.get('annotations')
    if anns is None:
        anns = []
        data['annotations'] = anns
    anns.append({
        'annotationType': 'OTHER',
        'annotator': 'Tool: sbom-tool',
        'comment': 'software_file_name=' + str(software_file_name)
    })
    save_json(spdx_json_path, data)
    return True
