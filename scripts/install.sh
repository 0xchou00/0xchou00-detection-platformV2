#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
VENV_DIR="$ROOT_DIR/.venv"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_NAME="0xchou00.service"
AGENT_SERVICE_NAME="0xchou00-agent.service"
ENV_FILE="$ROOT_DIR/.env"
AGENT_CONFIG_FILE="$ROOT_DIR/agent/config.yaml"
SYSTEMD_SOURCE_DIR="$ROOT_DIR/scripts/systemd"
SETUP_SCRIPT="$ROOT_DIR/setup.sh"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[ERROR] This installer only supports Linux."
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 is required but was not found."
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

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  echo "[1/7] Bootstrap environment"
  "$SETUP_SCRIPT"
else
  echo "[1/7] Reusing existing virtual environment"
fi

echo "[2/7] Ensuring Python dependencies are up to date"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$ROOT_DIR/requirements.txt"

echo "[3/7] Preparing runtime directories"
mkdir -p "$ROOT_DIR/logs"
mkdir -p "$BACKEND_DIR/data"
mkdir -p "$ROOT_DIR/agent"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "[4/7] Creating default environment file"
  cat > "$ENV_FILE" <<EOF
SIEM_DB_PATH=$BACKEND_DIR/data/0xchou00-tool.db
SIEM_ADMIN_API_KEY=siem-admin-dev-key
SIEM_ANALYST_API_KEY=siem-analyst-dev-key
SIEM_VIEWER_API_KEY=siem-viewer-dev-key
SIEM_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173
SIEM_GEOIP_DB_PATH=$BACKEND_DIR/data/GeoLite2-City.mmdb
ABUSEIPDB_API_KEY=
EOF
else
  echo "[4/7] Using existing environment file at $ENV_FILE"
fi

echo "[5/7] Installing systemd units"
sudo cp "$SYSTEMD_SOURCE_DIR/$SERVICE_NAME" "$SYSTEMD_DIR/$SERVICE_NAME"
sudo cp "$SYSTEMD_SOURCE_DIR/$AGENT_SERVICE_NAME" "$SYSTEMD_DIR/$AGENT_SERVICE_NAME"
sudo sed -i "s|__PROJECT_ROOT__|$ROOT_DIR|g" "$SYSTEMD_DIR/$SERVICE_NAME"
sudo sed -i "s|__BACKEND_DIR__|$BACKEND_DIR|g" "$SYSTEMD_DIR/$SERVICE_NAME"
sudo sed -i "s|__PROJECT_ROOT__|$ROOT_DIR|g" "$SYSTEMD_DIR/$AGENT_SERVICE_NAME"
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl enable "$AGENT_SERVICE_NAME"

echo "[6/7] Validating generated units"
sudo systemctl status "$SERVICE_NAME" --no-pager >/dev/null 2>&1 || true
sudo systemctl status "$AGENT_SERVICE_NAME" --no-pager >/dev/null 2>&1 || true

echo "[7/7] Setup complete"
echo
echo "Next steps:"
echo "  1. Review $ENV_FILE"
echo "  2. Start the tool:     sudo systemctl start $SERVICE_NAME"
echo "  3. Start the agent:    sudo systemctl start $AGENT_SERVICE_NAME"
echo "  4. Check tool status:  sudo systemctl status $SERVICE_NAME"
echo "  5. Check agent status: sudo systemctl status $AGENT_SERVICE_NAME"
