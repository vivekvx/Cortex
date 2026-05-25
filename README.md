# Cortex Shield

Runtime security and observability layer for autonomous AI agents.

## MVP

- Intercept tool calls before execution.
- Score risk for shell, browser, filesystem, network, and memory actions.
- Block credential exfiltration and prompt-injection chains.
- Pause high-risk actions for human approval.
- Persist execution traces in SQLite.
- Show runs, events, and approvals in a thin Next.js dashboard.

## Local Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn cortex_shield.api:app --reload
```

## Local Frontend

```bash
cd frontend
npm install
npm run dev
```

Set `NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8000` when backend runs elsewhere.

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

Patch a local OpenClaw checkout so real sessions use Cortex:

```bash
node integrations/openclaw/patch-openclaw.mjs /path/to/openclaw
cd /path/to/openclaw
CORTEX_SHIELD_ENABLED=1 CORTEX_API_BASE_URL=http://127.0.0.1:8000 pnpm test
```

Run the malicious-site demo after starting the backend:

```bash
PYTHONPATH=backend python3 -m uvicorn cortex_shield.api:app --port 8000
node integrations/openclaw/malicious-site-demo.mjs
```
