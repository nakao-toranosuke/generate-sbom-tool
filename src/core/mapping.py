from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class ColumnMapping:
    management_no: int
    language: int
    package_name: int
    version: int
    url: Optional[int] = None
    software_file_name: Optional[int] = None


def validate_mapping(m: ColumnMapping) -> None:
    required = [m.management_no, m.language, m.package_name, m.version]
    if any(x is None for x in required):
        raise ValueError('必須列（管理番号/言語名/パッケージ名/バージョン名）の割当が不足しています')
    if len(set(required)) != len(required):
        raise ValueError('必須列の割当が重複しています')
