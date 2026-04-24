#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-127.0.0.1}"
PORTS="${2:-2201,2202,2203,2204,2205,2206,2207,2208,2222,8081}"

nmap -Pn -sT -p "${PORTS}" "${TARGET}"
