from __future__ import annotations

import sys
from pathlib import Path as _Path

_APP_ROOT = _Path(__file__).resolve().parents[1]
if str(_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(_APP_ROOT))

from src.core.package_orchestrator import run_package_job


CASES = [
    {
        "ecosystem": "pypi",
        "name": "idna",
        "version": "3.7",
        "output_label": "pkg-pypi",
    },
    {
        "ecosystem": "npm",
        "name": "is-number",
        "version": "7.0.0",
        "output_label": "pkg-npm",
    },
    {
        "ecosystem": "maven",
        "name": "junit:junit",
        "version": "4.13.2",
        "output_label": "pkg-maven",
    },
]


def main() -> None:
    for case in CASES:
        print("case:", case["ecosystem"], case["name"], case["version"])
        result = run_package_job(**case)

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

    print("smoke_package_units: ok")


if __name__ == "__main__":
    main()
