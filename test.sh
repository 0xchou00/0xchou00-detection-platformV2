#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$PROJECT_ROOT/scripts/lab"
ENV_FILE="$PROJECT_ROOT/.env"
DOCKER_BIN="docker"

log() { printf '[test] %s\n' "$*"; }
err() { printf '[test][error] %s\n' "$*" >&2; }

if [[ ! -f "$ENV_FILE" ]]; then
  err ".env is missing. Run ./setup.sh first."
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

if ! command -v curl >/dev/null 2>&1; then
  err "curl is required."
  exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
  err "nmap is required. Run ./setup.sh first."
  exit 1
fi

if ! command -v hydra >/dev/null 2>&1; then
  err "hydra is required. Run ./setup.sh first."
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

if ! ${DOCKER_BIN} compose ps >/dev/null 2>&1; then
  err "docker compose stack is not running. Run ./run.sh first."
  exit 1
fi

for _ in $(seq 1 30); do
  if curl -fsS -H "X-API-Key: ${SIEM_VIEWER_API_KEY}" http://127.0.0.1:8000/health >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

log "Running HTTP probing against lab target"
bash "$LAB_DIR/http_probe.sh" "127.0.0.1" "${LAB_HTTP_PORT:-8081}" >/dev/null

log "Repeating HTTP probing to force a correlation candidate"
bash "$LAB_DIR/http_probe.sh" "127.0.0.1" "${LAB_HTTP_PORT:-8081}" >/dev/null

log "Running connect scan across monitored ports"
bash "$LAB_DIR/port_scan.sh" "127.0.0.1" "${LAB_FW_PORT_1:-2201},${LAB_FW_PORT_2:-2202},${LAB_FW_PORT_3:-2203},${LAB_FW_PORT_4:-2204},${LAB_FW_PORT_5:-2205},${LAB_FW_PORT_6:-2206},${LAB_FW_PORT_7:-2207},${LAB_FW_PORT_8:-2208},${LAB_SSH_PORT:-2222},${LAB_HTTP_PORT:-8081}" >/dev/null

log "Running SSH brute-force sequence with a known-success wordlist"
bash "$LAB_DIR/ssh_bruteforce.sh" "127.0.0.1" "root" "${LAB_SSH_PORT:-2222}" "$LAB_DIR/passwords.txt" >/dev/null

log "Waiting for workers to persist alerts"
sleep 8

ALERTS_JSON="$(curl -fsS -H "X-API-Key: ${SIEM_VIEWER_API_KEY}" "http://127.0.0.1:8000/alerts?limit=20&since_minutes=30")"
CORR_JSON="$(curl -fsS -H "X-API-Key: ${SIEM_VIEWER_API_KEY}" "http://127.0.0.1:8000/correlations?limit=10&since_minutes=30")"

printf '%s\n' "$ALERTS_JSON" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(f"[test] alerts_count={data.get(\"count\",0)}"); [print(f"[test] alert {i+1}: {item.get(\"severity\")} | {item.get(\"detector\")} | {item.get(\"title\")}") for i,item in enumerate((data.get(\"items\") or [])[:8])]'
printf '%s\n' "$CORR_JSON" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(f"[test] correlations_count={data.get(\"count\",0)}"); [print(f"[test] correlation {i+1}: {item.get(\"title\")} | {item.get(\"source_ip\")}") for i,item in enumerate((data.get(\"items\") or [])[:5])]'

log "Open the dashboard at http://127.0.0.1:5173 to inspect live alerts and the timeline."
log "Use docker compose logs -f backend-worker agent lab-target if you want to watch the pipeline in motion."
