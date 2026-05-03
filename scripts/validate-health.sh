#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-http://localhost:8000/api}"
FRONTEND_URL="${FRONTEND_URL:-}"

echo "Validating API health at ${API_BASE}/health"
curl -fsS "${API_BASE}/health" | node -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{const j=JSON.parse(s); if(j.status!=="ok") throw new Error("health status is not ok"); console.log(JSON.stringify(j,null,2));})'

if [ -n "${FRONTEND_URL}" ]; then
  echo "Validating frontend at ${FRONTEND_URL}"
  curl -fsSI "${FRONTEND_URL}" | head -10
fi

echo "Health validation passed."
