#!/usr/bin/env bash
set -euo pipefail
systemctl disable --now shielddome-api shielddome-worker || true
rm -f /etc/systemd/system/shielddome-api.service /etc/systemd/system/shielddome-worker.service
rm -f /etc/nginx/sites-enabled/shielddome /etc/nginx/sites-available/shielddome
systemctl daemon-reload
echo "Application services removed. Data and /etc/shielddome were intentionally preserved."
