#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASHBOARD_DIR="$PROJECT_ROOT/dashboard"
VENV_DIR="$PROJECT_ROOT/.venv"
ENV_FILE="$PROJECT_ROOT/.env"
ENV_EXAMPLE="$PROJECT_ROOT/.env.example"
LAB_DIR="$PROJECT_ROOT/scripts/lab"

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

if [[ ! -f "$ENV_FILE" && -f "$ENV_EXAMPLE" ]]; then
  log "Creating .env from .env.example"
  cp "$ENV_EXAMPLE" "$ENV_FILE"
fi

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
fi

DISTRO_ID="${ID:-}"
DISTRO_LIKE="${ID_LIKE:-}"

case "${DISTRO_ID,,}" in
  kali|debian|ubuntu)
    log "Detected distro: ${DISTRO_ID:-unknown}"
    ;;
  *)
    if [[ "${DISTRO_LIKE,,}" != *debian* ]]; then
      err "Unsupported distribution. This script targets Kali, Debian, and Ubuntu."
      exit 1
    fi
    log "Detected Debian-like distro: ${DISTRO_ID:-unknown}"
    ;;
esac

log "Updating apt package index"
$SUDO apt-get update -y

log "Installing system dependencies"
$SUDO apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  docker.io \
  git \
  hydra \
  nodejs \
  nmap \
  npm \
  openssh-client \
  python3 \
  python3-pip \
  python3-venv

if command -v docker-compose >/dev/null 2>&1; then
  log "docker-compose is already available"
else
  if $SUDO apt-get install -y --no-install-recommends docker-compose; then
    log "Installed docker-compose from apt"
  else
    log "docker-compose package unavailable; installing Python fallback"
    python3 -m pip install --user --upgrade docker-compose
    export PATH="$HOME/.local/bin:$PATH"
  fi
fi

if command -v systemctl >/dev/null 2>&1; then
  log "Ensuring Docker service is running"
  $SUDO systemctl enable --now docker
fi

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
"$VENV_DIR/bin/pip" install --upgrade -r "$PROJECT_ROOT/requirements.txt"

log "Installing dashboard Node dependencies"
cd "$DASHBOARD_DIR"
npm install

mkdir -p "$PROJECT_ROOT/logs" "$LAB_DIR"

if [[ ! -f "$ENV_FILE" ]]; then
  log "Creating .env from .env.example"
  cp "$ENV_EXAMPLE" "$ENV_FILE"
fi

log "Setup complete. Next: ./scripts/check.sh, then ./run.sh"
