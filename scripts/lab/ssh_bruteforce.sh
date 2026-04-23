#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-127.0.0.1}"
USER="${2:-root}"
PORT="${3:-2222}"
WORDLIST="${4:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/passwords.txt}"

hydra -s "${PORT}" -l "${USER}" -P "${WORDLIST}" -t 4 -f -V "ssh://${TARGET}" || true
