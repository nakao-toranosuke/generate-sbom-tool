from __future__ import annotations

import urllib.request
from pathlib import Path
from typing import Optional

from ...utils.safe_zip_extract import safe_extract_zip

SUPPORTED_ARCHIVE_EXT = {'.zip', '.jar', '.war', '.ear'}


def is_direct_download_url(url: str) -> bool:
    if not url:
        return False
    u = url.strip().lower()
    return any(u.endswith(ext) for ext in SUPPORTED_ARCHIVE_EXT)


def download_to(url: str, dest: Path, timeout_seconds: int = 60) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=timeout_seconds) as resp:
        data = resp.read()
    dest.write_bytes(data)
    return dest


def prepare_java_artifact_from_attachment(attachment_path: Path, work_dir: Path) -> tuple[Optional[Path], str]:
    work_dir.mkdir(parents=True, exist_ok=True)
    ext = attachment_path.suffix.lower()

    if ext == '.zip':
        extract_root = work_dir / 'extract'
        extract_root.mkdir(parents=True, exist_ok=True)
        safe_extract_zip(attachment_path, extract_root)
        files = [p for p in extract_root.rglob('*') if p.is_file()]

        for p in files:
            if p.name == 'pom.xml':
                return p.parent, 'ATTACH_POM'

        for p in files:
            if p.name == 'gradle.lockfile' or (p.name.endswith('.lockfile') and 'gradle' in p.name):
                return p.parent, 'ATTACH_GRADLE_LOCK'

        for p in files:
            if p.suffix.lower() in {'.jar', '.war', '.ear'}:
                return p, 'ATTACH_JAR'

        return None, 'NO_ARTIFACT'

    if ext in {'.jar', '.war', '.ear'}:
        return attachment_path, 'ATTACH_JAR'

    return None, 'UNSUPPORTED'
