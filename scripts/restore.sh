#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -lt 1 || "$#" -gt 2 ]]; then echo "Usage: $0 backup.dump [raw.tar.gz]"; exit 2; fi
source /etc/shielddome/shielddome.env
systemctl stop shielddome-api shielddome-worker
pg_restore --clean --if-exists --dbname="${SHIELDDOME_DATABASE_URL}" "$1"
if [[ "${2:-}" ]]; then
  mkdir -p /var/lib/shielddome
  tar -C /var/lib/shielddome -xzf "$2"
  chown -R shielddome:shielddome /var/lib/shielddome
fi
systemctl start shielddome-api shielddome-worker
echo "Restore completed. Verify with: curl http://127.0.0.1/api/v1/health"
