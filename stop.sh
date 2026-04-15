#!/usr/bin/env bash
# ============================================================================
# stop.sh — Stop both FPM applications
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

stop_process() {
    local name="$1"
    local pidfile="logs/${name}.pid"

    if [ -f "$pidfile" ]; then
        local pid
        pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            echo "[*] Stopping $name (PID $pid)..."
            kill "$pid"
            sleep 1
            # Force kill if still running
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
            fi
            echo "    Stopped."
        else
            echo "[*] $name not running (stale PID file)"
        fi
        rm -f "$pidfile"
    else
        echo "[*] $name: no PID file found"
    fi
}

stop_process "mock_server"
stop_process "fpm"

echo "[OK] All processes stopped."
