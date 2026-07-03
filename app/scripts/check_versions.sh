#!/usr/bin/env sh
set -eu

python --version
python -m pip show streamlit
streamlit version
trivy --version
python -m pip check
