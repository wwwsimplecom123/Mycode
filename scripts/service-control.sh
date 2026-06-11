#!/usr/bin/env bash
set -euo pipefail
ACTION="${1:-status}"
case "${ACTION}" in
  start|stop|restart|status)
    systemctl "${ACTION}" shielddome-api shielddome-worker
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status}"
    exit 2
    ;;
esac
