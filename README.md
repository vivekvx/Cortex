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
```
