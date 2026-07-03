from __future__ import annotations

import shutil
import subprocess
import sys
from typing import Any


def _run_version(command: list[str]) -> str | None:
    if shutil.which(command[0]) is None:
        return None
    try:
        completed = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
            check=False,
        )
    except Exception as exc:
        return f"ERROR: {exc}"
    output = completed.stdout.strip()
    return output.splitlines()[0] if output else ""


def collect_runtime_versions() -> dict[str, Any]:
    return {
        "app_python_version": sys.version.split()[0],
        "streamlit_version": _run_version(["streamlit", "version"]),
        "trivy_version": _run_version(["trivy", "--version"]),
        "uv_version": _run_version(["uv", "--version"]),
        "node_version": _run_version(["node", "--version"]),
        "npm_version": _run_version(["npm", "--version"]),
        "java_version": _run_version(["java", "-version"]),
        "maven_version": _run_version(["mvn", "--version"]),
        "php_version": _run_version(["php", "--version"]),
        "composer_version": _run_version(["composer", "--version"]),
        "ruby_version": _run_version(["ruby", "--version"]),
        "bundler_version": _run_version(["bundle", "--version"]),
        "rustc_version": _run_version(["rustc", "--version"]),
        "cargo_version": _run_version(["cargo", "--version"]),
        "go_version": _run_version(["go", "version"]),
        "dotnet_version": _run_version(["dotnet", "--version"]),
    }
