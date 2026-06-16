#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1}"
ENV_FILE="${SHIELDDOME_ENV_FILE:-/etc/shielddome/shielddome.env}"

ok() { echo "[OK] $*"; }
warn() { echo "[WARN] $*"; }
fail() { echo "[FAIL] $*"; exit 1; }

[[ -r "${ENV_FILE}" ]] || fail "Cannot read ${ENV_FILE}"
set -a
source "${ENV_FILE}"
set +a
ok "Environment file readable"

for name in SHIELDDOME_DATABASE_URL SHIELDDOME_DATA_ENCRYPTION_KEY SHIELDDOME_ADMIN_TOKEN SHIELDDOME_INGEST_TOKEN; do
  [[ -n "${!name:-}" ]] && ok "${name} configured" || warn "${name} is empty"
done

systemctl is-active --quiet shielddome-api && ok "shielddome-api active" || warn "shielddome-api is not active"
systemctl is-active --quiet shielddome-worker && ok "shielddome-worker active" || warn "shielddome-worker is not active"
nginx -t >/dev/null && ok "Nginx configuration valid" || warn "Nginx configuration test failed"

if command -v ss >/dev/null 2>&1; then
  ss -lnt | grep -q ':80 ' && ok "Port 80 is listening" || warn "Port 80 is not listening"
  ss -lnt | grep -q ':9090 ' && warn "Port 9090 is listening; close it if not needed" || ok "Port 9090 not listening"
  ss -lnt | grep -q ':7890 ' && warn "Port 7890 is listening; close it if not needed" || ok "Port 7890 not listening"
fi

if command -v psql >/dev/null 2>&1; then
  psql "${SHIELDDOME_DATABASE_URL}" -Atc "select 1" >/dev/null && ok "PostgreSQL reachable" || warn "PostgreSQL check failed"
  psql "${SHIELDDOME_DATABASE_URL}" -Atc "select extname from pg_extension where extname='vector'" | grep -q '^vector$' && ok "pgvector enabled" || warn "pgvector extension missing"
fi

curl -fsS "${BASE_URL}/api/v1/health" >/dev/null && ok "HTTP health endpoint reachable" || warn "HTTP health endpoint failed"
curl -fsS -H "X-API-Key: ${SHIELDDOME_ADMIN_TOKEN}" "${BASE_URL}/api/v1/system/status" >/dev/null && ok "System status endpoint reachable" || warn "System status endpoint failed"

echo "[INFO] Model connectivity is tested from the console: 模型 API 设置 -> 测试连接"
echo "[INFO] Self-check completed for ${BASE_URL}"
