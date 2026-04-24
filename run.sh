#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$PROJECT_ROOT/.env"
ENV_EXAMPLE="$PROJECT_ROOT/.env.example"
CHECK_SCRIPT="$PROJECT_ROOT/scripts/check.sh"

log() { printf '[run] %s\n' "$*"; }
err() { printf '[run][error] %s\n' "$*" >&2; }

if [[ ! -f "$ENV_FILE" ]]; then
  if [[ -f "$ENV_EXAMPLE" ]]; then
    log "Creating missing .env from .env.example"
    cp "$ENV_EXAMPLE" "$ENV_FILE"
  else
    err ".env is missing and .env.example is not available."
    exit 1
  fi
fi

if [[ ! -x "$CHECK_SCRIPT" ]]; then
  chmod +x "$CHECK_SCRIPT" 2>/dev/null || true
fi

bash "$CHECK_SCRIPT"

export PATH="$HOME/.local/bin:$PATH"
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    printf '%s\n' "docker compose"
    return 0
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    printf '%s\n' "$(command -v docker-compose)"
    return 0
  fi
  return 1
}

COMPOSE_BIN="$(compose_cmd)" || {
  err "No docker compose implementation available."
  exit 1
}

DOCKER_PREFIX="docker"
if docker info >/dev/null 2>&1; then
  DOCKER_ACCESS="direct"
elif command -v sudo >/dev/null 2>&1 && sudo -n docker info >/dev/null 2>&1; then
  DOCKER_PREFIX="sudo -n docker"
  DOCKER_ACCESS="sudo"
else
  err "docker is installed but not accessible for the current user. Add the user to the docker group or run with passwordless sudo."
  exit 1
fi

compose() {
  if [[ "$COMPOSE_BIN" == "docker compose" ]]; then
    $DOCKER_PREFIX compose "$@"
  else
    if [[ "$DOCKER_PREFIX" == "docker" ]]; then
      "$COMPOSE_BIN" "$@"
    else
      sudo -n "$COMPOSE_BIN" "$@"
    fi
  fi
}

wait_for_command() {
  local label="$1"
  local max_attempts="$2"
  shift 2
  local attempt=1
  until "$@"; do
    if (( attempt >= max_attempts )); then
      err "Timed out waiting for ${label}."
      return 1
    fi
    attempt=$((attempt + 1))
    sleep 2
  done
}

show_logs() {
  log "Recent service logs:"
  compose logs --no-color --tail 80 backend-api backend-worker alert-worker redis postgres || true
}

log "Starting Redis, PostgreSQL, API, workers, dashboard, lab target, and agent"
log "Docker access mode: ${DOCKER_ACCESS}"
cd "$PROJECT_ROOT"
compose up -d --build

log "Waiting for PostgreSQL"
wait_for_command "PostgreSQL" 30 compose exec -T postgres pg_isready -U siem -d siem || {
  show_logs
  exit 1
}

log "Waiting for Redis"
wait_for_command "Redis" 30 compose exec -T redis redis-cli ping || {
  show_logs
  exit 1
}

log "Waiting for API health endpoint"
wait_for_command "API health" 60 curl -fsS -H "X-API-Key: ${SIEM_VIEWER_API_KEY}" http://127.0.0.1:8000/health >/dev/null 2>&1 || {
  show_logs
  err "API did not become healthy."
  exit 1
}

log "Waiting for lab target HTTP service"
wait_for_command "lab target HTTP" 30 curl -fsS "http://127.0.0.1:${LAB_HTTP_PORT:-8081}/" >/dev/null 2>&1 || {
  show_logs
  err "Lab target HTTP service did not become ready."
  exit 1
}

log "Services are up:"
log "- API: http://localhost:8000"
log "- Dashboard: http://localhost:5173"
log "- Lab target HTTP: http://127.0.0.1:${LAB_HTTP_PORT:-8081}"
log "- Lab target SSH: ssh root@127.0.0.1 -p ${LAB_SSH_PORT:-2222}"
log "Follow logs with: ${COMPOSE_BIN} logs -f backend-api backend-worker alert-worker agent lab-target"
