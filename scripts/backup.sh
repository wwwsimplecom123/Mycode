#!/usr/bin/env bash
set -euo pipefail
DEST="${1:-/var/backups/shielddome}"
STAMP="$(date +%Y%m%d-%H%M%S)"
mkdir -p "${DEST}"
source /etc/shielddome/shielddome.env
pg_dump "${SHIELDDOME_DATABASE_URL}" --format=custom --file="${DEST}/shielddome-${STAMP}.dump"
tar -C /var/lib/shielddome -czf "${DEST}/raw-${STAMP}.tar.gz" raw
find "${DEST}" -type f -mtime +30 -delete
echo "Backup completed: ${STAMP}"
