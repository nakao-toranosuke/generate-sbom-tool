from __future__ import annotations

import sys
from pathlib import Path as _Path

_APP_ROOT = _Path(__file__).resolve().parents[1]
if str(_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(_APP_ROOT))

from src.core.file_orchestrator import run_file_job


def main() -> None:
    result = run_file_job(
        original_filename="requirements.txt",
        data=b"idna==3.7\n",
        output_label="file-unit",
        display_name="requirements-file",
        version="1.0.0",
    )

    print("success:", result.success)
    print("status:", result.status)
    print("job_id:", result.job_id)
    print("sbom_file:", result.sbom_file)
    print("artifact_zip:", result.artifact_zip)
    print("error_summary:", result.error_summary)

    if not result.success:
        raise SystemExit(1)

    if result.sbom_file is None or not result.sbom_file.exists():
        raise SystemExit("SBOM file was not created.")

    if result.artifact_zip is None or not result.artifact_zip.exists():
        raise SystemExit("artifact ZIP was not created.")

    print("smoke_file_unit: ok")


if __name__ == "__main__":
    main()
