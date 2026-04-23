#!/usr/bin/env bash
set -euo pipefail

mkdir -p /var/log/nginx /run/sshd /var/run/sshd
touch /var/log/auth.log /var/log/firewall.log /var/log/nginx/access.log /var/log/nginx/error.log

echo "root:${LAB_TARGET_PASSWORD:-labpass123}" | chpasswd

exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
