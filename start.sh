#!/usr/bin/env bash
#
# Robust OneClick launcher for Kali/Linux.
#
# What this fixes:
#   1. Runs doctor.py first - if a REQUIRED dependency is missing, you get a
#      clear message immediately.
#   2. Logs everything to logs/oneclick_<timestamp>.log so any crash can be diagnosed.
#   3. Auto-restarts the app if it crashes unexpectedly (up to MAX_RESTARTS).
#   4. Runs in the foreground by default (Ctrl+C works normally).
#
# Usage:
#   ./start.sh                  # foreground, auto-restart on crash
#   ./start.sh --no-restart     # foreground, exit immediately on crash (for debugging)
#   ./start.sh --port 8600      # custom port
#

set -uo pipefail

PORT=8000
AUTO_RESTART=true
MAX_RESTARTS=5
RESTART_WINDOW_SECONDS=60

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-restart) AUTO_RESTART=false; shift ;;
        --port) PORT="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p logs
LOG_FILE="logs/oneclick_$(date +%Y%m%d_%H%M%S).log"

echo "=== OneClick launcher ==="
echo "Log file: $LOG_FILE"
echo

echo "--- Running dependency check (doctor.py) ---"
if ! python3 doctor.py; then
    echo
    echo "❌ Doctor check failed - fix the issues above before starting the server."
    echo "   (Full output was also written to $LOG_FILE)"
    python3 doctor.py > "$LOG_FILE" 2>&1
    exit 1
fi
echo

attempt=0
start_time=$(date +%s)

while true; do
    attempt=$((attempt + 1))
    echo "--- Starting OneClick Server (attempt $attempt) on port $PORT ---"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting attempt $attempt" >> "$LOG_FILE"

    # Run in foreground, tee output to both terminal and log file.
    uvicorn api:app --host 0.0.0.0 --port "$PORT" 2>&1 | tee -a "$LOG_FILE"
    exit_code=${PIPESTATUS[0]}

    echo "$(date '+%Y-%m-%d %H:%M:%S') - Server exited with code $exit_code" >> "$LOG_FILE"

    if [[ "$exit_code" -eq 0 ]]; then
        echo "OneClick server exited cleanly (Ctrl+C or normal shutdown). Not restarting."
        break
    fi

    if [[ "$AUTO_RESTART" != "true" ]]; then
        echo "❌ Server crashed (exit code $exit_code). --no-restart was set, so not retrying."
        echo "   Check the log for details: $LOG_FILE"
        exit "$exit_code"
    fi

    now=$(date +%s)
    elapsed=$((now - start_time))

    if [[ "$attempt" -ge "$MAX_RESTARTS" ]]; then
        echo "❌ Crashed $attempt times - giving up. Check the log:"
        echo "   $LOG_FILE"
        echo "   Also try: python3 doctor.py"
        exit "$exit_code"
    fi

    if [[ "$elapsed" -gt "$RESTART_WINDOW_SECONDS" ]]; then
        attempt=0
        start_time=$now
    fi

    echo "⚠️  Server crashed (exit code $exit_code). Restarting in 2s... (attempt $attempt/$MAX_RESTARTS)"
    sleep 2
done
