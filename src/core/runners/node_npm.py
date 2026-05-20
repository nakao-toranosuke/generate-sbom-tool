from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Optional

from ...utils.concurrency import FileSemaphore

_NL = chr(10)


def _truncate(text: str, max_len: int = 8000) -> str:
    if text is None:
        return ''
    s = str(text)
    if len(s) <= max_len:
        return s
    head = s[: max_len // 2]
    tail = s[-(max_len // 2):]
    return head + _NL + '...(truncated)...' + _NL + tail


def _build_package_json(package_name: str, version: str) -> dict:
    return {
        'name': 'sbom-stub',
        'version': '0.0.0',
        'private': True,
        'dependencies': {package_name: version},
    }


def _pick_env(env: dict[str, str], key: str) -> str:
    value = env.get(key)
    return '' if value is None else str(value)


def generate_package_lock(work_dir: Path, package_name: str, version: str, timeout_seconds: int = 1800, registry: Optional[str] = None) -> Path:
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / 'package.json').write_text(
        json.dumps(_build_package_json(package_name, version), ensure_ascii=False, indent=2),
        encoding='utf-8',
    )

    cmd = ['npm', 'install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund']
    reg = registry or os.environ.get('NPM_REGISTRY')
    if reg:
        cmd += ['--registry', str(reg)]

    env = dict(os.environ)
    env['npm_config_cache'] = str((work_dir / '.npm-cache').resolve())

    slots_dir = work_dir.parent / "_locks_npm"
    max_concurrency = int(os.environ.get('SBOM_TOOL_NPM_MAX_CONCURRENCY', '1'))

    with FileSemaphore(slots_dir=slots_dir, max_concurrency=max_concurrency):
        proc = subprocess.run(
            cmd,
            cwd=str(work_dir),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=env,
        )

    (work_dir / 'npm.lock.stdout.txt').write_text(proc.stdout or '', encoding='utf-8')
    (work_dir / 'npm.lock.stderr.txt').write_text(proc.stderr or '', encoding='utf-8')
    (work_dir / 'npm.lock.command.txt').write_text(' '.join(cmd), encoding='utf-8')

    env_log_lines = [
        'NPM_CONFIG_CAFILE=' + _pick_env(env, 'NPM_CONFIG_CAFILE'),
        'npm_config_cafile=' + _pick_env(env, 'npm_config_cafile'),
        'NODE_EXTRA_CA_CERTS=' + _pick_env(env, 'NODE_EXTRA_CA_CERTS'),
        'REQUESTS_CA_BUNDLE=' + _pick_env(env, 'REQUESTS_CA_BUNDLE'),
        'SSL_CERT_FILE=' + _pick_env(env, 'SSL_CERT_FILE'),
        'CURL_CA_BUNDLE=' + _pick_env(env, 'CURL_CA_BUNDLE'),
        'HTTPS_PROXY=' + _pick_env(env, 'HTTPS_PROXY'),
        'HTTP_PROXY=' + _pick_env(env, 'HTTP_PROXY'),
        'NO_PROXY=' + _pick_env(env, 'NO_PROXY'),
    ]
    (work_dir / 'npm.lock.env.txt').write_text(_NL.join(env_log_lines) + _NL, encoding='utf-8')

    if proc.returncode != 0:
        stdout = _truncate((proc.stdout or "").strip())
        stderr = _truncate((proc.stderr or "").strip())
        parts = [
            'npm lock failed',
            'returncode=' + str(proc.returncode),
            'cwd=' + str(work_dir),
            'cmd=' + ' '.join(cmd),
            'stdout:',
            stdout if stdout else '(empty)',
            'stderr:',
            stderr if stderr else '(empty)',
        ]
        raise RuntimeError(_NL.join(parts))

    lock_path = work_dir / 'package-lock.json'
    if not lock_path.exists():
        raise RuntimeError('package-lock.json was not created')
    return lock_path
