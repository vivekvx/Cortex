#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export PYTHONPATH="${PYTHONPATH:-backend}"
export CORTEX_TRACE_DB="${CORTEX_TRACE_DB:-$ROOT_DIR/cortex_traces.sqlite3}"
export CORTEX_GATEWAY_WORKSPACE="${CORTEX_GATEWAY_WORKSPACE:-$ROOT_DIR/.cortex-workspace}"
export CORTEX_SANDBOX_IMAGE="${CORTEX_SANDBOX_IMAGE:-alpine:3.20}"

mkdir -p "$CORTEX_GATEWAY_WORKSPACE"

if [[ "${RELOAD:-0}" == "1" ]]; then
  exec python3 -m uvicorn cortex_shield.api:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}" --reload
fi

exec python3 -m uvicorn cortex_shield.api:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}"
