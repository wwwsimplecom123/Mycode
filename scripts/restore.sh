#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -ne 1 ]]; then echo "Usage: $0 backup.dump"; exit 2; fi
source /etc/shielddome/shielddome.env
systemctl stop shielddome-api shielddome-worker
pg_restore --clean --if-exists --dbname="${SHIELDDOME_DATABASE_URL}" "$1"
systemctl start shielddome-api shielddome-worker
