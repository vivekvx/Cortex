#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export PYTHONPATH="${PYTHONPATH:-backend}"

python3 -m unittest discover -s backend/tests -v
node --test integrations/openclaw/openclaw-adapter.test.mjs integrations/openclaw/patch-openclaw.test.mjs
frontend/node_modules/.bin/tsc --noEmit --target es2022 --lib es2022,dom --module nodenext --moduleResolution nodenext --types node --typeRoots frontend/node_modules/@types integrations/openclaw/cortex-shield-openclaw-wrapper.ts
npm --prefix frontend run build
