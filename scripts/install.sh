#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_NAME="0xchou00.service"
ENV_FILE="$ROOT_DIR/.env"
ENV_EXAMPLE="$ROOT_DIR/.env.example"
SYSTEMD_SOURCE_DIR="$ROOT_DIR/scripts/systemd"
SETUP_SCRIPT="$ROOT_DIR/setup.sh"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[ERROR] This installer only supports Linux."
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "[ERROR] docker is required."
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "[ERROR] systemctl is required to install systemd services."
  exit 1
fi

if [[ ! -x "$SETUP_SCRIPT" ]]; then
  echo "[ERROR] setup.sh is missing or not executable. Run: chmod +x setup.sh && ./setup.sh"
  exit 1
fi

echo "[1/5] Bootstrap environment"
"$SETUP_SCRIPT"

echo "[2/5] Preparing runtime directories"
mkdir -p "$ROOT_DIR/logs"
mkdir -p "$ROOT_DIR/agent"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "[3/5] Creating .env from .env.example"
  cp "$ENV_EXAMPLE" "$ENV_FILE"
else
  echo "[3/5] Using existing environment file at $ENV_FILE"
fi

echo "[4/5] Installing systemd units"
sudo cp "$SYSTEMD_SOURCE_DIR/$SERVICE_NAME" "$SYSTEMD_DIR/$SERVICE_NAME"
sudo sed -i "s|__PROJECT_ROOT__|$ROOT_DIR|g" "$SYSTEMD_DIR/$SERVICE_NAME"
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"

echo "[5/5] Validating generated units"
sudo systemctl status "$SERVICE_NAME" --no-pager >/dev/null 2>&1 || true

echo "Setup complete"
echo
echo "Next steps:"
echo "  1. Review $ENV_FILE"
echo "  2. Start the stack:    sudo systemctl start $SERVICE_NAME"
echo "  3. Check stack status: sudo systemctl status $SERVICE_NAME"
