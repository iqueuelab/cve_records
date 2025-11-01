#!/usr/bin/env bash
set -euo pipefail

# Run both Django dev server and Vite dev server concurrently.
# Usage: ./run_dev.sh
# Requirements:
# - Python dependencies (Django, etc.) installed in your active environment
# - Node dependencies installed in adminPanel/frontend (npm install)

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

cd "$ROOT_DIR"

echo "Starting Django dev server on http://127.0.0.1:8000"
python3 manage.py runserver 8000 &
PID_DJANGO=$!

cd "$ROOT_DIR/frontend"
echo "Starting Vite dev server (frontend) on http://127.0.0.1:5173"
npm run dev &
PID_VITE=$!

cleanup() {
  echo "Stopping servers..."
  kill -TERM "$PID_VITE" 2>/dev/null || true
  kill -TERM "$PID_DJANGO" 2>/dev/null || true
  wait "$PID_VITE" 2>/dev/null || true
  wait "$PID_DJANGO" 2>/dev/null || true
  exit
}

trap cleanup INT TERM

wait "$PID_DJANGO" "$PID_VITE"
