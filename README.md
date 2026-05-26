# Cortex Shield

Runtime security and observability layer for autonomous AI agents.

## MVP

- Intercept tool calls before execution.
- Score risk for shell, browser, filesystem, network, and memory actions.
- Block credential exfiltration and prompt-injection chains.
- Pause high-risk actions for human approval.
- Persist execution traces in SQLite.
- Mark browser/file-read output as tainted and block dangerous follow-up chains.
- Show runs, events, and approvals in a thin Next.js dashboard.

## Local Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn cortex_shield.api:app --reload
```

Optional local API auth and policy config:

```bash
CORTEX_API_TOKEN=dev-secret \
CORTEX_POLICY_PATH=/Users/vivek/cortex/config/policy.example.json \
PYTHONPATH=backend python3 -m uvicorn cortex_shield.api:app --port 8000
```

Optional Docker shell sandbox:

```bash
CORTEX_SANDBOX_SHELL=1 \
PYTHONPATH=backend python3 -m uvicorn cortex_shield.api:app --port 8000
```

When enabled in the OpenClaw adapter, approved high-risk shell commands run through
`/sandbox/shell` inside a Docker container with no network, read-only filesystem,
PID/memory/CPU limits, and timeout. If Docker is missing, sandbox execution fails closed.

## Local Frontend

```bash
cd frontend
npm install
npm run dev
```

Set `NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8000` when backend runs elsewhere.
Set `NEXT_PUBLIC_CORTEX_API_TOKEN=dev-secret` when `CORTEX_API_TOKEN` is enabled.

## Tests

```bash
PYTHONPATH=backend python3 -m unittest discover -s backend/tests -v
node --test integrations/openclaw/openclaw-adapter.test.mjs
npm --prefix frontend run build
```

## OpenClaw Adapter

The OpenClaw adapter wraps OpenClaw-compatible tools at the `execute` boundary.

```js
import { OpenClawAdapter } from "./integrations/openclaw/openclaw-adapter.mjs";

const adapter = new OpenClawAdapter({
  runId,
  apiBaseUrl: "http://127.0.0.1:8000",
});

const guardedTools = adapter.wrapTools(openClawTools);
```

Gateway mode makes Cortex execute tools server-side instead of trusting the agent
process to run them locally:

```bash
CORTEX_GATEWAY_TOOLS=1 openclaw
```

Gateway endpoints:

- `POST /gateway/tools/shell`
- `POST /gateway/tools/filesystem`
- `POST /gateway/tools/browser`
- `GET /events/{event_id}/taint-graph`

Patch a local OpenClaw checkout so real sessions use Cortex:

```bash
node integrations/openclaw/patch-openclaw.mjs /path/to/openclaw
cd /path/to/openclaw
CORTEX_SHIELD_ENABLED=1 CORTEX_API_BASE_URL=http://127.0.0.1:8000 pnpm test
```

When backend auth is enabled, pass the same token to OpenClaw:

```bash
CORTEX_SHIELD_ENABLED=1 \
CORTEX_API_BASE_URL=http://127.0.0.1:8000 \
CORTEX_API_TOKEN=dev-secret \
CORTEX_SANDBOX_SHELL=1 \
openclaw
```

Run the malicious-site demo after starting the backend:

```bash
PYTHONPATH=backend python3 -m uvicorn cortex_shield.api:app --port 8000
node integrations/openclaw/malicious-site-demo.mjs
```
