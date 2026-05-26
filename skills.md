# Cortex Skills

## Security Runtime

- Inspect tool calls before execution.
- Score risk by tool, action, payload, and known attack patterns.
- Enforce allow, block, or approval policy.
- Preserve hard blocks for credentials and prompt injection.

## Sandbox Execution

- Run approved high-risk shell commands in Docker.
- Disable network.
- Use read-only filesystem.
- Add PID, memory, CPU, and timeout limits.
- Fail closed when Docker is unavailable.

## OpenClaw Integration

- Wrap OpenClaw shell, browser, and file tools.
- Send tool calls to `/guard/check`.
- Resume after human approval.
- Route approved shell calls to `/sandbox/shell` when enabled.
- Record tool output or error back to Cortex.

## Dashboard

- Show runs.
- Show tool events.
- Show risk decisions.
- Show pending approvals.
- Let human approve or reject actions.

## Policy Work

- Use `CORTEX_POLICY_PATH` for config.
- Support reason-based policy overrides.
- Never allow policy config to downgrade hard safety blocks.

## Testing Discipline

- Add tests before new behavior.
- Backend tests use `unittest`.
- Integration tests use Node test runner.
- Frontend verification uses `npm --prefix frontend run build`.

## Next Skill To Add

Taint tracking:

- Label browser and file output as untrusted.
- Track source event ID.
- Detect later shell/file/network use of untrusted content.
- Block critical chains.
- Show taint reason in dashboard.
