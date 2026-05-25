# OpenClaw Tool Execution Path Study

Source studied: <https://github.com/openclaw/openclaw>

## Current Entry Points

- OpenClaw agent tools share an `AnyAgentTool` shape with `name`, `parameters`, and `execute(toolCallId, params, signal, onUpdate)`.
- Core shell execution is exposed as the `exec` tool from `src/agents/bash-tools.exec.ts`.
- Filesystem tools are built from `read`, `write`, and `edit` wrappers in `src/agents/pi-tools.read.ts`.
- Browser control is a bundled plugin tool named `browser` from `extensions/browser/src/browser-tool.ts`.
- Plugin tools can also be materialized from cached descriptors in `src/plugins/tools.ts`, then resolved back to runtime tools before `execute`.

## Existing Policy Hooks

- OpenClaw already has native pre-tool and post-tool hook relays in `src/agents/harness/native-hook-relay.ts`.
- `pre_tool_use` calls `runBeforeToolCallHook` with normalized `toolName`, params, run/session metadata, and can block before execution.
- `post_tool_use` calls `runAgentHarnessAfterToolCallHook` with original args and tool result.
- Native hook relay normalizes Codex-style `exec` input by converting `cmd` into `command`.

## Cortex Integration Choice

For this repo, Cortex adds a standalone `OpenClawAdapter` instead of patching OpenClaw internals. It wraps OpenClaw-compatible tools at the `AnyAgentTool.execute` boundary:

```js
const adapter = new OpenClawAdapter({ runId, apiBaseUrl: "http://127.0.0.1:8000" });
const guardedTools = adapter.wrapTools(openClawTools);
```

This matches OpenClaw's tool contract and keeps integration small:

- `exec`, `bash`, and `process` map to Cortex `shell`.
- `read`, `write`, and `edit` map to Cortex `filesystem`.
- `browser` maps to Cortex `browser`.
- High-risk decisions wait for `/approvals/{event_id}` to become approved.
- Browser outputs are inspected before returning page content to the agent, so hidden prompt injection is blocked before the agent can act on it.
