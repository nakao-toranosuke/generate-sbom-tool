from __future__ import annotations

import sys
from pathlib import Path as _Path

_APP_ROOT = _Path(__file__).resolve().parents[1]
if str(_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(_APP_ROOT))

import json
import tempfile
import zipfile
from pathlib import Path

from src.core.project_orchestrator import run_project_zip_job


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "sample-node.zip"

        package_json = {
            "name": "sample-app",
            "version": "1.0.0",
            "dependencies": {
                "express": "4.18.2"
            },
        }

        package_lock = {
            "name": "sample-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {
                "": {
                    "name": "sample-app",
                    "version": "1.0.0",
                    "dependencies": {
                        "express": "4.18.2"
                    },
                },
                "node_modules/express": {
                    "version": "4.18.2",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                    "license": "MIT",
                },
            },
        }

        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("sample-app/package.json", json.dumps(package_json))
            zf.writestr("sample-app/package-lock.json", json.dumps(package_lock))

        result = run_project_zip_job(
            original_filename=zip_path.name,
            data=zip_path.read_bytes(),
            project_name="sample-app",
            project_version="1.0.0",
            output_label="sample",
        )

        print("success:", result.success)
        print("status:", result.status)
        print("job_id:", result.job_id)
        print("sbom_file:", result.sbom_file)
        print("artifact_zip:", result.artifact_zip)
        print("error_summary:", result.error_summary)
        print("warnings:", result.warnings)

        if not result.success:
            raise SystemExit(1)

        if result.artifact_zip is None or not result.artifact_zip.exists():
            raise SystemExit("artifact zip was not created")

        with zipfile.ZipFile(result.artifact_zip) as zf:
            entries = set(zf.namelist())

        required_entries = {
            "input/input_summary.json",
            "manifest/project_detection.json",
            "manifest/result_manifest.json",
            "sbom/sample__Project__sample-app@1.0.0.spdx.json",
        }

        missing = required_entries - entries
        if missing:
            raise SystemExit(f"missing artifact entries: {sorted(missing)}")

        print("smoke_project_zip: ok")


if __name__ == "__main__":
    main()
