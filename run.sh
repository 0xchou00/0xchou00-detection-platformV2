#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend"
DASHBOARD_DIR="$PROJECT_ROOT/dashboard"
VENV_DIR="$PROJECT_ROOT/.venv"
ENV_FILE="$PROJECT_ROOT/.env"

RUN_DASHBOARD=1
RUN_AGENT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend-only)
      RUN_DASHBOARD=0
      shift
      ;;
    --with-agent)
      RUN_AGENT=1
      shift
      ;;
    *)
      printf '[run][error] Unknown argument: %s\n' "$1" >&2
      printf 'Usage: ./run.sh [--backend-only] [--with-agent]\n' >&2
      exit 1
      ;;
  esac
done

log() { printf '[run] %s\n' "$*"; }
err() { printf '[run][error] %s\n' "$*" >&2; }

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  err "Python virtual environment is missing. Run ./setup.sh first."
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  err ".env file is missing. Run ./setup.sh first."
  exit 1
fi

if [[ ! -d "$DASHBOARD_DIR/node_modules" && "$RUN_DASHBOARD" -eq 1 ]]; then
  err "Dashboard dependencies are missing. Run ./setup.sh first."
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

BACKEND_PORT="${SIEM_BACKEND_PORT:-8000}"
DASHBOARD_PORT="${SIEM_DASHBOARD_PORT:-5173}"

PIDS=()

cleanup() {
  local code=$?
  if [[ ${#PIDS[@]} -gt 0 ]]; then
    log "Stopping running services"
    kill "${PIDS[@]}" >/dev/null 2>&1 || true
  fi
  exit "$code"
}

trap cleanup INT TERM EXIT

log "Starting backend on http://0.0.0.0:${BACKEND_PORT}"
(
  cd "$BACKEND_DIR"
  exec "$VENV_DIR/bin/uvicorn" main:app --host 0.0.0.0 --port "$BACKEND_PORT"
) &
PIDS+=("$!")

if [[ "$RUN_DASHBOARD" -eq 1 ]]; then
  if ! command -v npm >/dev/null 2>&1; then
    err "npm is not installed."
    exit 1
  fi
  log "Starting dashboard on http://0.0.0.0:${DASHBOARD_PORT}"
  (
    cd "$DASHBOARD_DIR"
    exec npm run dev -- --host 0.0.0.0 --port "$DASHBOARD_PORT"
  ) &
  PIDS+=("$!")
fi

if [[ "$RUN_AGENT" -eq 1 ]]; then
  log "Starting agent"
  (
    cd "$PROJECT_ROOT"
    exec "$VENV_DIR/bin/python" "$PROJECT_ROOT/agent/agent.py" --config "$PROJECT_ROOT/agent/config.yaml"
  ) &
  PIDS+=("$!")
fi

wait -n "${PIDS[@]}"
err "A process exited unexpectedly."
exit 1
