#!/usr/bin/env bash
set -euo pipefail
DEST="${1:-/var/backups/shielddome}"
RETENTION_DAYS="${SHIELDDOME_BACKUP_RETENTION_DAYS:-30}"
STAMP="$(date +%Y%m%d-%H%M%S)"
mkdir -p "${DEST}"
source /etc/shielddome/shielddome.env
pg_dump "${SHIELDDOME_DATABASE_URL}" --format=custom --file="${DEST}/shielddome-${STAMP}.dump"
tar -C /var/lib/shielddome -czf "${DEST}/raw-${STAMP}.tar.gz" raw
find "${DEST}" -type f \( -name 'shielddome-*.dump' -o -name 'raw-*.tar.gz' \) -mtime +"${RETENTION_DAYS}" -delete
echo "Backup completed: ${STAMP}"
echo "Retention: ${RETENTION_DAYS} days"
echo "Restore drill: restore the .dump with scripts/restore.sh, then extract the matching raw-*.tar.gz into /var/lib/shielddome/raw."
