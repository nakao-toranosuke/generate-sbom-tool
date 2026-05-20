from __future__ import annotations

import os
import subprocess
import venv
from pathlib import Path

from ...utils.concurrency import FileSemaphore


def _python_bin(venv_dir: Path) -> Path:
    return venv_dir / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')


def generate_runtime_freeze(work_dir: Path, package_name: str, version: str, timeout_seconds: int = 1800) -> Path:
    work_dir.mkdir(parents=True, exist_ok=True)
    venv_dir = work_dir / '.venv'
    if venv_dir.exists():
        import shutil
        shutil.rmtree(venv_dir, ignore_errors=True)
    venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
    python_bin = _python_bin(venv_dir)
    env = dict(os.environ)
    env['PIP_DISABLE_PIP_VERSION_CHECK'] = '1'
    env['PIP_NO_INPUT'] = '1'
    env['PIP_CACHE_DIR'] = str((work_dir / '.pip-cache').resolve())
    with FileSemaphore(slots_dir=work_dir.parent / '_locks_pip', max_concurrency=int(os.environ.get('SBOM_TOOL_PIP_MAX_CONCURRENCY', '1'))):
        p1 = subprocess.run([str(python_bin), '-m', 'pip', 'install', f'{package_name}=={version}'], cwd=str(work_dir), capture_output=True, text=True, timeout=timeout_seconds, env=env)
        if p1.returncode != 0:
            raise RuntimeError((p1.stderr or p1.stdout or 'pip install failed').strip())
        p2 = subprocess.run([str(python_bin), '-m', 'pip', 'freeze'], cwd=str(work_dir), capture_output=True, text=True, timeout=timeout_seconds, env=env)
        if p2.returncode != 0:
            raise RuntimeError((p2.stderr or p2.stdout or 'pip freeze failed').strip())
    req = work_dir / 'requirements.txt'
    req.write_text(p2.stdout or '', encoding='utf-8')
    return req
