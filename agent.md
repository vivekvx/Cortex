# Cortex Agent Guide

## Mission

Cortex Shield protects agent tool execution before damage happens.

Core loop:

1. Agent asks to use tool.
2. Cortex scores risk.
3. Policy allows, blocks, or asks human approval.
4. Approved risky shell commands can run in Docker sandbox.
5. Browser/file outputs can become tainted sources.
6. Later risky chains from tainted sources are blocked.
7. Trace saved for review.

## Current System

- Backend: FastAPI runtime in `backend/cortex_shield`.
- Frontend: Next.js dashboard in `frontend`.
- OpenClaw integration: `integrations/openclaw`.
- Policy config: `config/policy.example.json`.
- Traces: SQLite.

## Main Safety Features

- API bearer token support through `CORTEX_API_TOKEN`.
- Configurable policy through `CORTEX_POLICY_PATH`.
- Prompt-injection and credential-access hard blocks.
- Human approval queue for high-risk actions.
- Optional Docker shell sandbox through `CORTEX_SANDBOX_SHELL=1`.
- Taint tracking for browser/file-read output.

## Run Backend

```bash
PYTHONPATH=backend python3 -m uvicorn cortex_shield.api:app --port 8000
```

With auth, policy, and sandbox:

```bash
CORTEX_API_TOKEN=dev-secret \
CORTEX_POLICY_PATH=/Users/vivek/cortex/config/policy.example.json \
CORTEX_SANDBOX_SHELL=1 \
PYTHONPATH=backend python3 -m uvicorn cortex_shield.api:app --port 8000
```

## Run Frontend

```bash
npm --prefix frontend run dev
```

## Test

```bash
PYTHONPATH=backend python3 -m unittest discover -s backend/tests -v
node --test integrations/openclaw/openclaw-adapter.test.mjs integrations/openclaw/patch-openclaw.test.mjs
npm --prefix frontend run build
```

## Next Best Work

Improve dashboard review flow.

Goal: show clearer approval reasons, command blast radius, taint source, and sandbox result.
