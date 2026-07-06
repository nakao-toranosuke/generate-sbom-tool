from __future__ import annotations

import stat
import tempfile
import zipfile
from pathlib import Path

from src.core.project_orchestrator import inspect_project_zip


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "symlink-test.zip"

        info = zipfile.ZipInfo("sample-app/link-to-outside")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16

        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("sample-app/package.json", '{"name":"sample-app","version":"1.0.0"}')
            zf.writestr(info, "/etc/passwd")

        result = inspect_project_zip(zip_path.name, zip_path.read_bytes())

        print("success:", result.success)
        print("errors:", result.errors)

        if result.success:
            raise SystemExit("symlink ZIP should have been rejected")

        if not any("symlink" in error.lower() for error in result.errors):
            raise SystemExit(f"expected symlink error, got: {result.errors}")

        print("smoke_symlink_reject: ok")


if __name__ == "__main__":
    main()
