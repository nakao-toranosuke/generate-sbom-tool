# SBOM Generator

SBOM Generator is a Streamlit-based tool for generating SPDX JSON SBOM artifacts from package inputs, file inputs, and project ZIP inputs.

The tool is designed for small-scale SBOM generation and local or containerized execution.

## Features

- Generate SPDX JSON SBOM files for individual package coordinates.
- Generate SPDX JSON SBOM files from CSV or Excel package input tables.
- Generate SPDX JSON SBOM files from a single selected file.
- Generate SPDX JSON SBOM files from a project ZIP archive.
- Export generation results as ZIP files.
- Reject unsafe ZIP contents such as symlinks and path traversal entries.
- Use pinned runtime and CLI versions for reproducible builds.

## Supported package ecosystems

| Ecosystem | Label | Example |
| --- | --- | --- |
| `pypi` | Python | `idna` `3.7` |
| `npm` | Node.js | `is-number` `7.0.0` |
| `maven` | Java | `junit:junit` `4.13.2` |
| `composer` | PHP | `psr/log` `3.0.2` |
| `gem` | Ruby | `rake` `13.2.1` |
| `cargo` | Rust | `itoa` `1.0.11` |
| `golang` | Go | `github.com/google/uuid` `v1.6.0` |
| `nuget` | .NET | `Newtonsoft.Json` `13.0.3` |
| `file` | File | selected file input |

`go` is accepted as an alias for `golang`.

## Supported project dependency files

Project ZIP generation detects dependency definition files such as:

- `requirements.txt`, `pyproject.toml`, `uv.lock`, `poetry.lock`, `Pipfile.lock`
- `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `npm-shrinkwrap.json`
- `pom.xml`
- `go.mod`, `go.sum`
- `composer.json`, `composer.lock`
- `Gemfile`, `Gemfile.lock`
- `Cargo.toml`, `Cargo.lock`
- `*.csproj`, `*.fsproj`, `*.vbproj`, `packages.lock.json`, `packages.config`

A project ZIP without supported dependency definition files is rejected.

## Toolchain versions

| Tool | Version |
| --- | --- |
| Python | 3.14.6 |
| Streamlit | 1.58.0 |
| uv | 0.11.26 |
| Node.js | 24.18.0 |
| npm | Node.js bundled version |
| JDK | 25 LTS |
| Maven | 3.9.16 |
| PHP | 8.5.8 |
| Composer | 2.10.2 |
| Ruby | 4.0.5 |
| Bundler | Ruby-compatible bundled version |
| Rust | 1.96.0 |
| Cargo | Rust bundled version |
| Go | 1.26.4 |
| .NET SDK | 10.0.301 |
| Trivy | 0.72.0 |

## Build

Run from the `app` directory.

```bash
cd app
docker build -t sbom-generator:v3.1 .
```

## Run

```bash
cd app
docker run --rm -p 8501:8501 sbom-generator:v3.1
```

Then open the Streamlit URL shown in the container log.

Health check:

```bash
curl -f http://127.0.0.1:8501/_stcore/health
```

Expected response:

```text
ok
```

## Input modes

### Package input

Use the `Package input` tab for one package at a time.

Required fields:

- `Ecosystem`
- `Package name`
- `Version`

Optional fields:

- `Output label`
- `Maven groupId`
- `Maven artifactId`

For Maven, specify either `groupId:artifactId` in `Package name` or fill `Maven groupId` and `Maven artifactId`.

### CSV/Excel input

Use the `CSV/Excel input` tab for multiple package rows.

Required columns:

- `ecosystem`
- `name`
- `version`

Optional columns:

- `output_label`
- `group_id`
- `artifact_id`

Example CSV:

```csv
ecosystem,name,version,output_label,group_id,artifact_id
pypi,idna,3.7,pkg-pypi,,
npm,is-number,7.0.0,pkg-npm,,
maven,junit:junit,4.13.2,pkg-maven,,
```

### File input

Use the `File input` tab for a single file.

Fields:

- selected file
- `Output label`
- `Display name`
- `Version`

### Project ZIP input

Use the `Project ZIP input` tab for a ZIP archive containing one project root.

Fields:

- selected ZIP file
- `Output label`
- `Project name`
- `Project version`

ZIP safety checks include:

- reject broken ZIP files
- reject absolute paths
- reject path traversal entries
- reject symlinks
- enforce file count and size limits
- ignore common heavy directories such as dependency caches and build output directories

## Output

Each generation result is exported as a ZIP file.

Typical output structure:

```text
sbom/
  <generated>.spdx.json
manifest/
  result_manifest.json
input/
  input_summary.json
error/
  error_summary.txt
```

`error/error_summary.txt` is included when a generation job fails.

## Smoke tests

Run from the `app` directory after building the image.

```bash
docker run --rm sbom-generator:v3.1 python /app/scripts/smoke_project_zip.py
docker run --rm sbom-generator:v3.1 python /app/scripts/smoke_symlink_reject.py
docker run --rm sbom-generator:v3.1 python /app/scripts/smoke_package_units.py
docker run --rm sbom-generator:v3.1 python /app/scripts/smoke_file_unit.py
```

Expected final markers:

```text
smoke_project_zip: ok
smoke_symlink_reject: ok
smoke_package_units: ok
smoke_file_unit: ok
```

## Version check

```bash
docker run --rm sbom-generator:v3.1 /app/scripts/check_versions.sh
```

The script prints installed tool versions and runs `pip check`.

## Development checks

Run from the repository root.

```bash
python -m compileall app/src app/streamlit_app.py app/scripts
git diff --check
```

## Notes

- The tool generates SBOM artifacts. Vulnerability, secret, and misconfiguration scanning are not part of the default workflow.
- Generation may require network access to package registries depending on the selected ecosystem.
- Browser-based file selection can fail or stall in some environments. Use the reset button next to the file selector and select the file again.
- Large inputs can take longer to process and may fail if size or count limits are exceeded.
