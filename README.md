# SBOM Generator

A web-based tool for generating SBOM files in SPDX JSON format.

## Features

- Inspect project ZIP files
- Detect dependency definition files
- Generate project SBOMs with Trivy
- Export generated results as downloadable ZIP files
- Read CSV/Excel files for package input workflows

## Output Format

- SPDX JSON

## Development

```bash
cd app
python -m pip install -r requirements.txt
streamlit run streamlit_app.py
```

## Container

```bash
cd app
docker build -t sbom-generator:v3.1 .
docker run --rm -p 8501:8501 sbom-generator:v3.1
```
