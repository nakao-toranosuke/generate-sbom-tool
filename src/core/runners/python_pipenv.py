from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from ...utils.concurrency import FileSemaphore


def _current_python_version() -> str:
    return f'{sys.version_info.major}.{sys.version_info.minor}'


def _build_pipfile(package_name: str, version: str) -> str:
    pyver = _current_python_version()
    pkg = str(package_name).replace(chr(34), chr(92) + chr(34))
    ver = str(version).replace(chr(34), chr(92) + chr(34))
    lines = [
        '[[source]]',
        'url = "https://pypi.org/simple"',
        'verify_ssl = true',
        'name = "pypi"',
        '',
        '[packages]',
        f'"{pkg}" = "=={ver}"',
        '',
        '[dev-packages]',
        '',
        '[requires]',
        f'python_version = "{pyver}"',
        '',
    ]
    return chr(10).join(lines)


def _pick_env(env: dict[str, str], key: str) -> str:
    value = env.get(key)
    return '' if value is None else str(value)


def generate_pipenv_lock(work_dir: Path, package_name: str, version: str, timeout_seconds: int = 1800) -> Path:
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / 'Pipfile').write_text(_build_pipfile(package_name, version), encoding='utf-8')

    env = dict(os.environ)
    env['PIPENV_VENV_IN_PROJECT'] = '1'
    env['PIPENV_IGNORE_VIRTUALENVS'] = '1'
    env['PIPENV_CACHE_DIR'] = str((work_dir / '.pipenv-cache').resolve())

    cmd = [sys.executable, "-m", "pipenv", "lock"]

    with FileSemaphore(
        slots_dir=work_dir.parent / '_locks_pipenv',
        max_concurrency=int(os.environ.get('SBOM_TOOL_PIPENV_MAX_CONCURRENCY', '1')),
    ):
        proc = subprocess.run(
            cmd,
            cwd=str(work_dir),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=env,
        )

    (work_dir / 'pipenv.lock.stdout.txt').write_text(proc.stdout or '', encoding='utf-8')
    (work_dir / 'pipenv.lock.stderr.txt').write_text(proc.stderr or '', encoding='utf-8')
    (work_dir / 'pipenv.lock.command.txt').write_text(' '.join(cmd), encoding='utf-8')

    env_log_lines = [
        'REQUESTS_CA_BUNDLE=' + _pick_env(env, 'REQUESTS_CA_BUNDLE'),
        'SSL_CERT_FILE=' + _pick_env(env, 'SSL_CERT_FILE'),
        'PIP_CERT=' + _pick_env(env, 'PIP_CERT'),
        'CURL_CA_BUNDLE=' + _pick_env(env, 'CURL_CA_BUNDLE'),
        'UV_SYSTEM_CERTS=' + _pick_env(env, 'UV_SYSTEM_CERTS'),
        'HTTPS_PROXY=' + _pick_env(env, 'HTTPS_PROXY'),
        'HTTP_PROXY=' + _pick_env(env, 'HTTP_PROXY'),
        'NO_PROXY=' + _pick_env(env, 'NO_PROXY'),
        'JAVA_TRUSTSTORE_PATH=' + _pick_env(env, 'JAVA_TRUSTSTORE_PATH'),
        'JAVA_TRUSTSTORE_PASSWORD=' + _pick_env(env, 'JAVA_TRUSTSTORE_PASSWORD'),
        'JAVA_TOOL_OPTIONS=' + _pick_env(env, 'JAVA_TOOL_OPTIONS'),
        'MAVEN_OPTS=' + _pick_env(env, 'MAVEN_OPTS'),
    ]
    (work_dir / 'pipenv.lock.env.txt').write_text(chr(10).join(env_log_lines) + chr(10), encoding='utf-8')

    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout or 'pipenv lock failed')

    lock_path = work_dir / 'Pipfile.lock'
    if not lock_path.exists():
        raise RuntimeError('Pipfile.lock was not created')

    return lock_path
