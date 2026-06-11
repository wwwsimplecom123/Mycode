#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/install-linux.sh"
  exit 1
fi

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
apt-get update
apt-get install -y nginx postgresql postgresql-contrib python3 python3-venv python3-pip nodejs npm rsync

id shielddome >/dev/null 2>&1 || useradd --system --home /opt/shielddome --shell /usr/sbin/nologin shielddome
mkdir -p /opt/shielddome /etc/shielddome/tls /var/lib/shielddome/raw /var/log/shielddome
rsync -a --delete --exclude data --exclude .git --exclude node_modules "${SOURCE_DIR}/" /opt/shielddome/

python3 -m venv /opt/shielddome/.venv
/opt/shielddome/.venv/bin/pip install --upgrade pip
/opt/shielddome/.venv/bin/pip install -r /opt/shielddome/requirements.txt

cd /opt/shielddome/frontend
npm ci || npm install
npm run build

install -m 0600 /opt/shielddome/deploy/shielddome.env.example /etc/shielddome/shielddome.env
install -m 0644 /opt/shielddome/deploy/shielddome-api.service /etc/systemd/system/shielddome-api.service
install -m 0644 /opt/shielddome/deploy/shielddome-worker.service /etc/systemd/system/shielddome-worker.service
install -m 0644 /opt/shielddome/deploy/nginx-shielddome.conf /etc/nginx/sites-available/shielddome
ln -sf /etc/nginx/sites-available/shielddome /etc/nginx/sites-enabled/shielddome
install -m 0644 /opt/shielddome/deploy/shielddome.logrotate /etc/logrotate.d/shielddome

chown -R shielddome:shielddome /opt/shielddome /var/lib/shielddome /var/log/shielddome
systemctl daemon-reload
echo "Edit /etc/shielddome/shielddome.env and TLS files, initialize PostgreSQL, then enable services."
