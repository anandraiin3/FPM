#!/usr/bin/env bash
# ============================================================================
# start.sh — Start both FPM applications
#
# Usage:
#   ./start.sh           # Start both App 1 (Mock Server) and App 2 (FPM)
#   ./start.sh server    # Start only App 1
#   ./start.sh fpm       # Start only App 2
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check for .env
if [ ! -f .env ]; then
    echo "WARNING: .env file not found. Copy .env.example to .env and set your OPENAI_API_KEY."
    echo "  cp .env.example .env"
    exit 1
fi

# Create log directory
mkdir -p logs

start_server() {
    echo "[*] Starting Traceable Mock Server (port 8000)..."
    python -m mock_server.run > logs/mock_server.log 2>&1 &
    echo $! > logs/mock_server.pid
    echo "    PID: $(cat logs/mock_server.pid)"
    echo "    Dashboard: http://localhost:8000"
    echo "    Logs: logs/mock_server.log"
}

start_fpm() {
    echo "[*] Starting False Positive Minimizer..."
    python -m fpm.run > logs/fpm.log 2>&1 &
    echo $! > logs/fpm.pid
    echo "    PID: $(cat logs/fpm.pid)"
    echo "    Logs: logs/fpm.log"
}

case "${1:-all}" in
    server)
        start_server
        ;;
    fpm)
        start_fpm
        ;;
    all)
        start_server
        echo ""
        # Give the server a moment to start
        sleep 2
        start_fpm
        echo ""
        echo "[OK] Both applications started."
        echo "     Dashboard: http://localhost:8000"
        echo "     Stop with: ./stop.sh"
        ;;
    *)
        echo "Usage: $0 [server|fpm|all]"
        exit 1
        ;;
esac
