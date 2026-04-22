#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

PID_FILE="monitor.pid"
LOG_FILE="monitor.log"

# If PID file exists and process is alive, do nothing.
if [[ -f "$PID_FILE" ]]; then
  OLD_PID="$(cat "$PID_FILE" || true)"
  if [[ -n "${OLD_PID}" ]] && kill -0 "$OLD_PID" 2>/dev/null; then
    echo "Monitor already running with PID $OLD_PID"
    exit 0
  fi
  rm -f "$PID_FILE"
fi

# Optional: activate virtual environment if present.
if [[ -f ".venv/bin/activate" ]]; then
  # shellcheck source=/dev/null
  source .venv/bin/activate
fi

nohup python3 -u router_monitor.py >> "$LOG_FILE" 2>&1 &
NEW_PID=$!
echo "$NEW_PID" > "$PID_FILE"

echo "Started monitor in background. PID=$NEW_PID"
