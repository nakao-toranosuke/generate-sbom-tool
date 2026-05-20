from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Optional

from ...utils.concurrency import FileSemaphore

_NL = chr(10)


def _env_truthy(name: str) -> bool:
    v = os.environ.get(name)
    if v is None:
        return False
    s = str(v).strip().lower()
    return s in {'1', 'true', 'yes', 'y', 'on'}


def _build_pyproject(package_name: str, version: str) -> str:
    return _NL.join([
        '[project]',
        'name = "sbom-stub"',
        'version = "0.0.0"',
        'requires-python = ">=3.9"',
        'dependencies = [',
        f' "{package_name}=={version}"',
        ']',
        '',
    ])


def generate_uv_lock(work_dir: Path, package_name: str, version: str, timeout_seconds: int = 1800, system_certs: Optional[bool] = None) -> Path:
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / 'pyproject.toml').write_text(_build_pyproject(package_name, version), encoding='utf-8')
    cmd = ['uv', 'lock']
    if system_certs is True or (system_certs is None and _env_truthy('UV_SYSTEM_CERTS')):
        cmd.append('--system-certs')
    if _env_truthy('UV_VERBOSE'):
        cmd.append('--verbose')
    env = dict(os.environ)
    env['UV_CACHE_DIR'] = str((work_dir / '.uv-cache').resolve())
    slots_dir = work_dir.parent / '_locks_uv'
    max_concurrency = int(os.environ.get('SBOM_TOOL_UV_MAX_CONCURRENCY', '1'))
    with FileSemaphore(slots_dir=slots_dir, max_concurrency=max_concurrency):
        proc = subprocess.run(cmd, cwd=str(work_dir), capture_output=True, text=True, timeout=timeout_seconds, env=env)
    try:
        (work_dir / 'uv.lock.stdout.txt').write_text(proc.stdout or '', encoding='utf-8')
        (work_dir / 'uv.lock.stderr.txt').write_text(proc.stderr or '', encoding='utf-8')
    except Exception:
        pass
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or 'uv lock failed')
    lock_path = work_dir / 'uv.lock'
    if not lock_path.exists():
        raise RuntimeError('uv.lock was not created')
    return lock_path
