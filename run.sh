#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$PROJECT_ROOT/.env"
DOCKER_BIN="docker"

log() { printf '[run] %s\n' "$*"; }
err() { printf '[run][error] %s\n' "$*" >&2; }

if ! command -v docker >/dev/null 2>&1; then
  err "docker command is required"
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  err "docker compose plugin is required"
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  err ".env is missing. Run ./setup.sh first."
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  if command -v sudo >/dev/null 2>&1; then
    DOCKER_BIN="sudo docker"
  else
    err "docker is installed but not accessible for the current user."
    exit 1
  fi
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

log "Starting Redis, PostgreSQL, API, workers, and dashboard"
cd "$PROJECT_ROOT"
${DOCKER_BIN} compose up -d --build

log "Waiting for API health endpoint"
for _ in $(seq 1 60); do
  if curl -fsS -H "X-API-Key: ${SIEM_VIEWER_API_KEY}" http://127.0.0.1:8000/health >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

log "Waiting for lab target HTTP service"
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${LAB_HTTP_PORT:-8081}/" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

log "Services are up:"
log "- API: http://localhost:8000"
log "- Dashboard: http://localhost:5173"
log "- Lab target HTTP: http://127.0.0.1:${LAB_HTTP_PORT:-8081}"
log "- Lab target SSH: ssh root@127.0.0.1 -p ${LAB_SSH_PORT:-2222}"
log "Follow logs with: ${DOCKER_BIN} compose logs -f backend-api backend-worker alert-worker agent lab-target"
