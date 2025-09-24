#!/usr/bin/env bash
set -euo pipefail

# run_full_check.sh - DECOYABLE quick full-check helper
# Usage: ./run_full_check.sh
# This script is intended for developers running on Unix-like systems (Linux, macOS).
# On Windows, run the equivalent PowerShell helper (script provided in README).

echo "[1/7] Ensure you're in repository root: $(pwd)"

# 1. Activate venv if present
if [ -f ".venv/bin/activate" ]; then
  echo "Activating virtualenv .venv"
  # shellcheck disable=SC1091
  source .venv/bin/activate
else
  echo "No .venv found - creating temporary venv"
  python -m venv .venv
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

# 2. Install dependencies
echo "[2/7] Installing dependencies"
pip install --upgrade pip
if [ -f "requirements.txt" ]; then
  pip install -r requirements.txt
fi

# 3. Lint checks (non-failing)
echo "[3/7] Running linters (non-failing)"
if command -v ruff >/dev/null 2>&1; then
  ruff check . || true
else
  echo "ruff not installed; skipping"
fi
if command -v black >/dev/null 2>&1; then
  black --check . || true
else
  echo "black not installed; skipping"
fi

# 4. Run tests (fail if tests fail)
echo "[4/7] Running tests"
pytest -q

# 5. Quick scans
echo "[5/7] Running quick scans (secrets + deps)"
python main.py scan secrets --path . || true
python main.py scan deps --path . || true

# 6. Start development server in background
echo "[6/7] Starting dev server (uvicorn)"
nohup uvicorn decoyable.api.app:app --reload --host 0.0.0.0 --port 8000 > dev-server.log 2>&1 &

# 7. Tail quick logs
echo "[7/7] Full-check complete. Server logs: dev-server.log"

echo "Tip: On Windows use the PowerShell helper in README.md or run the commands manually."
