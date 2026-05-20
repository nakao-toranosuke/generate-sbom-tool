from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from ..utils.concurrency import FileSemaphore


def run_trivy_fs(trivy_path: Path, target: Path, output_path: Path, sbom_format: str = 'spdx-json', timeout_seconds: int = 1800) -> subprocess.CompletedProcess:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env['TRIVY_CACHE_DIR'] = str((output_path.parent / '.trivy-cache').resolve())
    slots_dir = output_path.parent / '_locks_trivy'
    max_concurrency = int(os.environ.get('SBOM_TOOL_TRIVY_MAX_CONCURRENCY', '1'))
    cmd = [str(trivy_path), 'fs', '--format', sbom_format, '--output', str(output_path), str(target)]
    with FileSemaphore(slots_dir=slots_dir, max_concurrency=max_concurrency):
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds, env=env)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))


def save_json(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding='utf-8')
