from __future__ import annotations

import re
import shutil
from pathlib import Path

_LF = chr(10)
_CR = chr(13)
_TAB = chr(9)
INVALID_CHARS = re.compile('[\\/:*?"<>|' + _LF + _CR + _TAB + ']')


def sanitize_filename_component(text: str, default: str = 'unknown', max_len: int = 150) -> str:
    if text is None:
        return default
    s = str(text).strip()
    s = INVALID_CHARS.sub('_', s)
    s = re.sub(r'_+', '_', s)
    s = s.strip(' ._')
    if not s:
        s = default
    if len(s) > max_len:
        s = s[:max_len]
    return s


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def rm_tree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def bytes_to_mb(n: int) -> float:
    return float(n) / (1024 * 1024)
