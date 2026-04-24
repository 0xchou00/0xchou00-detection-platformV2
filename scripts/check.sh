#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

log() { printf '[check] %s\n' "$*"; }
err() { printf '[check][error] %s\n' "$*" >&2; }

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

command -v docker >/dev/null 2>&1 || {
  err "docker is not installed."
  exit 1
}

if docker info >/dev/null 2>&1; then
  DOCKER_ACCESS="direct"
elif command -v sudo >/dev/null 2>&1 && sudo -n docker info >/dev/null 2>&1; then
  DOCKER_ACCESS="sudo"
else
  err "docker daemon is not running or the current user cannot access it. Add the user to the docker group or run with passwordless sudo."
  exit 1
fi

COMPOSE_BIN="$(compose_cmd)" || {
  err "docker compose is not available. Install docker-compose or the Docker Compose plugin."
  exit 1
}

AVAILABLE_KB="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || printf '0')"
MINIMUM_KB=$((4 * 1024 * 1024))
if [[ "$AVAILABLE_KB" -lt "$MINIMUM_KB" ]]; then
  err "At least 4 GiB of available RAM is required. Available: $((AVAILABLE_KB / 1024)) MiB."
  exit 1
fi

log "docker: ok"
log "access: ${DOCKER_ACCESS}"
log "compose: ok (${COMPOSE_BIN})"
log "memory: ok ($((AVAILABLE_KB / 1024)) MiB available)"
