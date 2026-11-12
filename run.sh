#!/usr/bin/env bash
# Starts the Web Insights Portal at http://127.0.0.1:5055 (first run installs what it needs).
set -e
cd "$(dirname "$0")"
PY=${PYTHON:-python3}
if [ ! -d .venv ]; then
  echo "First run: creating a Python environment and installing Flask, pandas, openpyxl..."
  "$PY" -m venv .venv
  .venv/bin/pip install --quiet --upgrade pip
  .venv/bin/pip install --quiet -r requirements.txt
fi
exec .venv/bin/python app.py
