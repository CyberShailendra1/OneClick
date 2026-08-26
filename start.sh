#!/usr/bin/env bash
#
# Robust OneClick launcher for Kali/Linux.
#
# What this fixes vs plain `streamlit run app.py`:
#   1. Runs doctor.py first - if a REQUIRED dependency is missing, you get a
#      clear message immediately instead of Streamlit silently exiting.
#   2. Logs everything to logs/oneclick_<timestamp>.log so a crash can be
#      diagnosed after the fact (this is the #1 thing missing when someone
#      says "it just closes and I don't know why").
#   3. Auto-restarts the app if it crashes unexpectedly (but NOT in a tight
#      infinite loop - a genuine startup failure will still surface after
#      MAX_RESTARTS attempts instead of restart-looping forever).
#   4. Runs in the foreground by default (so Ctrl+C works normally) - use
#      `./start.sh --background` (with tmux/screen, see below) for a
#      detached long-running session.
#
# Usage:
#   ./start.sh                  # foreground, auto-restart on crash
#   ./start.sh --no-restart     # foreground, exit immediately on crash (for debugging)
#   ./start.sh --port 8600      # custom port

set -uo pipefail

PORT=8501
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
    echo "❌ Doctor check failed - fix the issues above before starting the app."
    echo "   (Full output was also written to $LOG_FILE)"
    python3 doctor.py > "$LOG_FILE" 2>&1
    exit 1
fi
echo

attempt=0
start_time=$(date +%s)

while true; do
    attempt=$((attempt + 1))
    echo "--- Starting Streamlit (attempt $attempt) on port $PORT ---"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting attempt $attempt" >> "$LOG_FILE"

    # Run in foreground, tee output to both terminal and log file.
    streamlit run app.py --server.port "$PORT" 2>&1 | tee -a "$LOG_FILE"
    exit_code=${PIPESTATUS[0]}

    echo "$(date '+%Y-%m-%d %H:%M:%S') - Streamlit exited with code $exit_code" >> "$LOG_FILE"

    if [[ "$exit_code" -eq 0 ]]; then
        echo "Streamlit exited cleanly (Ctrl+C or normal shutdown). Not restarting."
        break
    fi

    if [[ "$AUTO_RESTART" != "true" ]]; then
        echo "❌ Streamlit crashed (exit code $exit_code). --no-restart was set, so not retrying."
        echo "   Check the log for details: $LOG_FILE"
        exit "$exit_code"
    fi

    now=$(date +%s)
    elapsed=$((now - start_time))

    if [[ "$attempt" -ge "$MAX_RESTARTS" ]]; then
        echo "❌ Crashed $attempt times - giving up (not restart-looping forever)."
        echo "   This usually means a real bug, not a transient issue. Check the log:"
        echo "   $LOG_FILE"
        echo "   Also try: python3 doctor.py"
        exit "$exit_code"
    fi

    if [[ "$elapsed" -gt "$RESTART_WINDOW_SECONDS" ]]; then
        # It ran for a while before crashing - reset the attempt counter,
        # since this looks like an unrelated one-off crash, not a boot-loop.
        attempt=0
        start_time=$now
    fi

    echo "⚠️  Streamlit crashed (exit code $exit_code). Restarting in 2s... (attempt $attempt/$MAX_RESTARTS)"
    sleep 2
done
