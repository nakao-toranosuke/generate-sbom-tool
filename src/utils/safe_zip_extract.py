from __future__ import annotations

import zipfile
from pathlib import Path


def safe_extract_zip(zip_path: Path, dest_dir: Path, max_files: int = 5000, max_total_size: int = 2 * 1024 * 1024 * 1024) -> list[Path]:
    extracted: list[Path] = []
    total = 0

    with zipfile.ZipFile(zip_path, 'r') as zf:
        infos = zf.infolist()
        if len(infos) > max_files:
            raise ValueError(f'ZIP内ファイル数が上限を超えています: {len(infos)} > {max_files}')

        for info in infos:
            if info.is_dir():
                continue

            total += int(info.file_size)
            if total > max_total_size:
                raise ValueError('ZIP展開サイズが上限を超えています')

            out_path = dest_dir / info.filename
            resolved = out_path.resolve()
            if not str(resolved).startswith(str(dest_dir.resolve())):
                raise ValueError('ZIPに不正なパスが含まれています')

            out_path.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, 'r') as src, open(out_path, 'wb') as dst:
                dst.write(src.read())

            extracted.append(out_path)

    return extracted
