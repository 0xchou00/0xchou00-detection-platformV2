#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-127.0.0.1}"
PORT="${2:-8081}"

paths=(
  "/"
  "/admin"
  "/.env"
  "/phpmyadmin"
  "/wp-login.php"
  "/.git/config"
  "/admin"
  "/.env"
  "/wp-login.php"
)

for path in "${paths[@]}"; do
  curl -k -A "sqlmap/1.8" -s -o /dev/null -w "%{http_code}\n" "http://${TARGET}:${PORT}${path}" || true
  sleep 0.3
done
