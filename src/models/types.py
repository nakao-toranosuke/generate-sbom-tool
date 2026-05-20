from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Status(str, Enum):
    SUCCESS = 'SUCCESS'
    FAILED_INPUT = 'FAILED_INPUT'
    FAILED_TOOL = 'FAILED_TOOL'
    SKIPPED_AMBIGUOUS_GAV = 'SKIPPED_AMBIGUOUS_GAV'
    SKIPPED_NO_ARTIFACT = 'SKIPPED_NO_ARTIFACT'
    SKIPPED_UNSUPPORTED = 'SKIPPED_UNSUPPORTED'


@dataclass
class InputRow:
    management_no: str
    language: str
    package_name: str
    version: str
    url: Optional[str] = None
    software_file_name: Optional[str] = None
