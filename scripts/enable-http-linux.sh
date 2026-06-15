#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/enable-http-linux.sh"
  exit 1
fi

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET=/etc/nginx/sites-available/shielddome
BACKUP="${TARGET}.before-http"
DEFAULT_SITE=/etc/nginx/sites-enabled/default
DEFAULT_TARGET=""

cp -a "${TARGET}" "${BACKUP}"
if [[ -L "${DEFAULT_SITE}" ]]; then
  DEFAULT_TARGET="$(readlink -f "${DEFAULT_SITE}")"
  rm -f "${DEFAULT_SITE}"
fi
install -m 0644 "${SOURCE_DIR}/deploy/nginx-shielddome-http.conf" "${TARGET}"

if ! nginx -t; then
  cp -a "${BACKUP}" "${TARGET}"
  if [[ -n "${DEFAULT_TARGET}" ]]; then
    ln -s "${DEFAULT_TARGET}" "${DEFAULT_SITE}"
  fi
  nginx -t
  echo "Nginx validation failed; previous configuration restored."
  exit 1
fi

systemctl reload nginx
echo "ShieldDome HTTP-only test access enabled on port 80."
