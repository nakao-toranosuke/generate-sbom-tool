from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from ...utils.concurrency import FileSemaphore

_NL = chr(10)


def _pom_for_dependency(group_id: str, artifact_id: str, version: str) -> str:
    return _NL.join(
        [
            '<project xmlns="http://maven.apache.org/POM/4.0.0"',
            ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
            ' xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">',
            ' <modelVersion>4.0.0</modelVersion>',
            ' <groupId>sbom.stub</groupId>',
            ' <artifactId>standalone-pom</artifactId>',
            ' <version>0.0.0</version>',
            ' <packaging>pom</packaging>',
            ' <dependencies>',
            ' <dependency>',
            f' <groupId>{group_id}</groupId>',
            f' <artifactId>{artifact_id}</artifactId>',
            f' <version>{version}</version>',
            ' </dependency>',
            ' </dependencies>',
            '</project>',
            '',
        ]
    )


def _parse_tree_output(text: str) -> tuple[dict[str, dict], list[tuple[str, str]]]:
    nodes: dict[str, dict] = {}
    edges: list[tuple[str, str]] = []
    stack: list[tuple[int, str]] = []

    for line in (text or '').splitlines():
        s = line.rstrip()
        if not s:
            continue

        s2 = s[6:].lstrip() if s.startswith('[INFO]') else s
        parts = s2.split()
        if not parts:
            continue

        token = parts[0]
        if token in {'+-', '\\-'} and len(parts) > 1:
            token = parts[1]
        elif token.startswith('+-') or token.startswith('\\-'):
            token = token[2:]
            token = token.lstrip(' ')

        if ':' not in token and len(parts) > 1 and ':' in parts[1]:
            token = parts[1]

        if token.count(':') < 3:
            continue

        fields = token.split(':')
        group_id = fields[0]
        artifact_id = fields[1]
        version = fields[3] if len(fields) >= 4 else fields[-1]
        key = f'{group_id}:{artifact_id}:{version}'

        if key not in nodes:
            nodes[key] = {'groupId': group_id, 'artifactId': artifact_id, 'version': version}

        leading = len(s2) - len(s2.lstrip(' '))
        depth = leading // 3

        while stack and stack[-1][0] >= depth:
            stack.pop()

        if stack:
            edges.append((stack[-1][1], key))

        stack.append((depth, key))

    return nodes, edges


def _spdx_document_name(mgmt: str, pkg: str, ver: str) -> str:
    def clean(x: str) -> str:
        return ''.join(ch if ch.isalnum() or ch in {'-', '_', '.', '@'} else '_' for ch in (x or ''))

    return f'{clean(mgmt)}_{clean(pkg)}@{clean(ver)}'


def _purl_maven(group_id: str, artifact_id: str, version: str) -> str:
    return f'pkg:maven/{group_id}/{artifact_id}@{version}'


def _resolve_mvn() -> str | None:
    return shutil.which('mvn') or shutil.which('mvn.cmd') or shutil.which('mvn.bat')


def _tokenize_loose(value: str) -> list[str]:
    if value is None:
        return []
    v = str(value).replace('\r', ' ').replace('\n', ' ').replace('\t', ' ')
    v = re.sub(r'[\u00A0\u1680\u180E\u2000-\u200A\u202F\u205F\u3000]', ' ', v)
    v = re.sub(r'\s+', ' ', v).strip()
    return [t for t in v.split(' ') if t]


def _append_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open('a', encoding='utf-8') as f:
            f.write(text)
    except Exception:
        pass


def _sanitize_env_for_mvn() -> dict[str, str]:
    # Maven 実行用 env を作成。
    # B1対応: -Dmaven.repo.local が指定されていた場合は除去し、既定のローカルリポジトリ(%USERPROFILE%\.m2\repository)に戻す。
    # また、過去事象の対策として、\" が混入していた場合は正規化する。
    env = dict(os.environ)

    # Remove auto-injected JVM options (defensive)
    for key in ['_JAVA_OPTIONS', 'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS']:
        env.pop(key, None)

    mopts = str(env.get('MAVEN_OPTS', '') or '')

    # Normalize escaped quotes from bat/cmd (e.g., \"C:\path\")
    mopts = mopts.replace('\\"', '"')
    mopts = mopts.replace('\"', '"')

    # If trustStore= value is quoted, drop the surrounding quotes
    mopts = re.sub(r'-Djavax\.net\.ssl\.trustStore="([^"]+)"', r'-Djavax.net.ssl.trustStore=\1', mopts)

    # Remove stray standalone '-'
    mopts = re.sub(r'(^|\s)-(\s|$)', ' ', mopts)

    # Remove empty trustStorePassword
    mopts = re.sub(r'-Djavax\.net\.ssl\.trustStorePassword=(\s|$)', ' ', mopts)

    # Remove repo.local regardless of quoting
    mopts = re.sub(r'-Dmaven\.repo\.local="?[^\s"]+"?', ' ', mopts)

    mopts = re.sub(r'\s+', ' ', mopts).strip()
    if mopts:
        env['MAVEN_OPTS'] = mopts
    else:
        env.pop('MAVEN_OPTS', None)

    return env


def _log_runner_context(work_dir: Path, mvn_path: str, cmdline: str, env: dict[str, str]) -> None:
    log_path = work_dir / 'maven_env.txt'

    def mask(v: str) -> str:
        if v is None:
            return ''
        s = str(v)
        s = re.sub(r'(?i)(trustStorePassword=)([^\s]+)', r'\1****', s)
        return s

    keys = ['JAVA_HOME', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'MAVEN_OPTS']
    lines2: list[str] = []
    lines2.append('=== java_maven.py runner context ===')
    lines2.append('work_dir=' + str(work_dir))
    lines2.append('mvn_path=' + str(mvn_path))
    lines2.append('cmdline=' + cmdline)
    for k in keys:
        vv = env.get(k, '')
        lines2.append(f'{k}=' + mask(vv))
        lines2.append(f'{k}__repr=' + repr(vv))
        lines2.append(f'{k}__tokens=' + repr(_tokenize_loose(vv)[:200]))
    jvm_cfg = work_dir / '.mvn' / 'jvm.config'
    lines2.append('jvm.config.exists=' + ('true' if jvm_cfg.exists() else 'false'))
    lines2.append('')
    _append_text(log_path, _NL.join(lines2) + _NL)


def generate_spdx_from_gav(
    mgmt: str,
    group_id: str,
    artifact_id: str,
    version: str,
    out_path: Path,
    work_dir: Path,
    timeout_seconds: int = 1800,
) -> tuple[bool, str, str, int]:
    work_dir.mkdir(parents=True, exist_ok=True)
    mvn_path = _resolve_mvn()
    if not mvn_path:
        return False, '', 'mvn が見つかりません（StreamlitプロセスのPATHを確認してください）', 127

    (work_dir / 'pom.xml').write_text(
        _pom_for_dependency(group_id, artifact_id, version),
        encoding='utf-8',
    )

    args = [
        '-q',
        '-f',
        'pom.xml',
        'dependency:tree',
        '-DoutputType=text',
        '-DoutputFile=deps.txt',
    ]
    cmd = [mvn_path] + args
    cmdline = subprocess.list2cmdline(cmd)

    env = _sanitize_env_for_mvn()
    _log_runner_context(work_dir, mvn_path, cmdline, env)

    slots_dir = work_dir.parent / '_locks_mvn'
    max_concurrency = int(os.environ.get('SBOM_TOOL_MVN_MAX_CONCURRENCY', '1'))
    with FileSemaphore(slots_dir=slots_dir, max_concurrency=max_concurrency):
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=env,
            cwd=str(work_dir),
            shell=False,
        )

    try:
        (work_dir / 'mvn.stdout.txt').write_text(proc.stdout or '', encoding='utf-8')
        (work_dir / 'mvn.stderr.txt').write_text(proc.stderr or '', encoding='utf-8')
    except Exception:
        pass

    stdout = proc.stdout or ''
    stderr = proc.stderr or ''
    deps_txt = work_dir / 'deps.txt'
    if proc.returncode != 0 or not deps_txt.exists():
        if proc.returncode == 0 and not deps_txt.exists():
            stderr = (stderr + _NL if stderr else '') + 'deps.txt was not created'
        stderr = ('mvn_path=' + str(mvn_path)) if not stderr.strip() else ('mvn_path=' + str(mvn_path) + _NL + stderr)
        return False, stdout, stderr, int(proc.returncode)

    tree_text = deps_txt.read_text(encoding='utf-8', errors='ignore')
    nodes, edges = _parse_tree_output(tree_text)
    root_key = f'{group_id}:{artifact_id}:{version}'
    if root_key not in nodes:
        nodes[root_key] = {'groupId': group_id, 'artifactId': artifact_id, 'version': version}

    spdx_ids = {key: f'SPDXRef-Package-{i}' for i, key in enumerate(nodes.keys(), start=1)}
    packages = [
        {
            'name': val['artifactId'],
            'SPDXID': spdx_ids[key],
            'downloadLocation': 'NOASSERTION',
            'filesAnalyzed': False,
            'supplier': 'NOASSERTION',
            'versionInfo': val['version'],
            'externalRefs': [
                {
                    'referenceCategory': 'PACKAGE-MANAGER',
                    'referenceType': 'purl',
                    'referenceLocator': _purl_maven(val['groupId'], val['artifactId'], val['version']),
                }
            ],
        }
        for key, val in nodes.items()
    ]
    relationships = [
        {
            'spdxElementId': 'SPDXRef-DOCUMENT',
            'relatedSpdxElement': spdx_ids[root_key],
            'relationshipType': 'DESCRIBES',
        }
    ]
    for parent, child in edges:
        if parent in spdx_ids and child in spdx_ids:
            relationships.append(
                {
                    'spdxElementId': spdx_ids[parent],
                    'relatedSpdxElement': spdx_ids[child],
                    'relationshipType': 'DEPENDS_ON',
                }
            )

    doc_name = _spdx_document_name(mgmt, artifact_id, version)
    doc = {
        'spdxVersion': 'SPDX-2.3',
        'dataLicense': 'CC0-1.0',
        'SPDXID': 'SPDXRef-DOCUMENT',
        'name': doc_name,
        'documentNamespace': 'http://example.invalid/spdx/' + doc_name,
        'creationInfo': {
            'creators': ['Tool: sbom-tool (maven-tree)'],
            'created': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        },
        'packages': packages,
        'relationships': relationships,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding='utf-8')
    return True, stdout, stderr, 0
