from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json(path: Path, data: Any) -> None:
    ensure_dir(path.parent)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False),
        encoding="utf-8",
    )


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def safe_filename(value: str, *, max_len: int = 160, default: str = "item") -> str:
    normalized = unicodedata.normalize("NFKC", value or "").strip()
    normalized = re.sub(r"[^A-Za-z0-9._@+-]+", "_", normalized)
    normalized = normalized.strip("._-")
    if not normalized:
        normalized = default
    return normalized[:max_len]


def posix_relpath(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()
