#!/usr/bin/env bash
set -euo pipefail
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

restart_services() {
  systemctl start shielddome-api shielddome-worker
}

trap restart_services EXIT
systemctl stop shielddome-api shielddome-worker
rsync -a --delete --exclude data --exclude .git --exclude node_modules "${SOURCE_DIR}/" /opt/shielddome/
/opt/shielddome/.venv/bin/pip install -r /opt/shielddome/requirements.txt
cd /opt/shielddome/frontend && npm ci && npm run build
cd /opt/shielddome && PYTHONPATH=/opt/shielddome /opt/shielddome/.venv/bin/python scripts/initialize.py
chown -R shielddome:shielddome /opt/shielddome
trap - EXIT
restart_services
echo "Upgrade completed."
