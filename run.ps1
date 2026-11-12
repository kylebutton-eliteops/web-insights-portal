# Starts the ZIA Toolkit: Web Insights Portal on one port (5055) (first run installs what it needs).
Set-Location -Path $PSScriptRoot
if (-not (Test-Path .venv)) {
  Write-Host "First run: creating a Python environment and installing Flask, pandas, openpyxl..."
  python -m venv .venv
  .\.venv\Scripts\python -m pip install --quiet --upgrade pip
  .\.venv\Scripts\python -m pip install --quiet -r requirements.txt
}
.\.venv\Scripts\python app.py
