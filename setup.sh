#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend"
DASHBOARD_DIR="$PROJECT_ROOT/dashboard"
VENV_DIR="$PROJECT_ROOT/.venv"
ENV_FILE="$PROJECT_ROOT/.env"

log() { printf '[setup] %s\n' "$*"; }
err() { printf '[setup][error] %s\n' "$*" >&2; }

if [[ "${EUID}" -ne 0 ]]; then
  SUDO="sudo"
else
  SUDO=""
fi

command -v apt-get >/dev/null 2>&1 || {
  err "apt-get is required. This script supports Debian-based distributions only."
  exit 1
}

log "Updating apt package index"
$SUDO apt-get update -y

log "Installing system dependencies"
$SUDO apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  git \
  nodejs \
  npm \
  python3 \
  python3-pip \
  python3-venv

command -v python3 >/dev/null 2>&1 || {
  err "python3 command not found after installation."
  exit 1
}

command -v npm >/dev/null 2>&1 || {
  err "npm command not found after installation."
  exit 1
}

log "Creating or refreshing virtual environment"
python3 -m venv "$VENV_DIR"

log "Installing Python dependencies"
"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$PROJECT_ROOT/requirements.txt"

log "Installing dashboard Node dependencies"
cd "$DASHBOARD_DIR"
npm install

log "Preparing runtime directories"
mkdir -p "$BACKEND_DIR/data"
mkdir -p "$PROJECT_ROOT/logs"

if [[ ! -f "$ENV_FILE" ]]; then
  log "Creating default .env file"
  cat >"$ENV_FILE" <<EOF
SIEM_DB_PATH=$BACKEND_DIR/data/0xchou00-tool.db
SIEM_ADMIN_API_KEY=siem-admin-dev-key
SIEM_ANALYST_API_KEY=siem-analyst-dev-key
SIEM_VIEWER_API_KEY=siem-viewer-dev-key
SIEM_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173
SIEM_GEOIP_DB_PATH=$BACKEND_DIR/data/GeoLite2-City.mmdb
ABUSEIPDB_API_KEY=
EOF
else
  log "Keeping existing .env file"
fi

log "Linux setup completed successfully"
