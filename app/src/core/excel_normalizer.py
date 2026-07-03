from __future__ import annotations

import io
from typing import BinaryIO

import pandas as pd


def read_table(filename: str, data: bytes) -> pd.DataFrame:
    lower = filename.lower()
    if lower.endswith((".xlsx", ".xlsm")):
        return pd.read_excel(io.BytesIO(data), engine="openpyxl")

    if lower.endswith(".csv"):
        for encoding in ("utf-8-sig", "utf-8"):
            try:
                return pd.read_csv(io.BytesIO(data), encoding=encoding)
            except UnicodeDecodeError:
                continue
        raise ValueError("CSV encoding must be UTF-8 or UTF-8 BOM")

    raise ValueError("Unsupported file type. Use CSV or Excel.")
