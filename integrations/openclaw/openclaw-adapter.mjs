const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";
const DEFAULT_APPROVAL_POLL_MS = 1000;
const DEFAULT_APPROVAL_TIMEOUT_MS = 5 * 60 * 1000;

const SHELL_TOOLS = new Set(["exec", "bash", "process"]);
const FILE_TOOLS = new Set(["read", "write", "edit"]);
const WATCHED_TOOLS = new Set([...SHELL_TOOLS, ...FILE_TOOLS, "browser"]);

export class CortexShieldBlockedError extends Error {
  constructor(message, event) {
    super(message);
    this.name = "CortexShieldBlockedError";
    this.event = event;
  }
}

export class CortexShieldApprovalError extends Error {
  constructor(message, event) {
    super(message);
    this.name = "CortexShieldApprovalError";
    this.event = event;
  }
}

export class OpenClawAdapter {
  constructor(options) {
    if (!options?.runId) {
      throw new Error("runId required");
    }
    this.runId = options.runId;
    this.apiBaseUrl = trimTrailingSlash(options.apiBaseUrl ?? DEFAULT_API_BASE_URL);
    this.apiToken = options.apiToken ?? process.env.CORTEX_API_TOKEN;
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    this.approvalPollMs = options.approvalPollMs ?? DEFAULT_APPROVAL_POLL_MS;
    this.approvalTimeoutMs = options.approvalTimeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS;

    if (typeof this.fetchImpl !== "function") {
      throw new Error("fetch implementation required");
    }
  }

  wrapTools(tools) {
    return tools.map((tool) => this.wrapTool(tool));
  }

  wrapTool(tool) {
    if (!tool || typeof tool.execute !== "function" || !WATCHED_TOOLS.has(tool.name)) {
      return tool;
    }

    const adapter = this;
    return {
      ...tool,
      async execute(toolCallId, params, signal, onUpdate) {
        const mappedCall = mapOpenClawToolCall(tool.name, params);
        const check = await adapter.check(mappedCall);
        const decision = check.decision?.action;
        const event = check.event;

        if (decision === "block") {
          throw new CortexShieldBlockedError(check.decision.reason, event);
        }

        if (decision === "require_approval") {
          const approvedEvent = await adapter.waitForApproval(event.id, signal);
          if (approvedEvent.approval_status !== "approved") {
            throw new CortexShieldApprovalError("tool call rejected by Cortex Shield", approvedEvent);
          }
        }

        try {
          const output = await tool.execute.call(this, toolCallId, params, signal, onUpdate);
          if (tool.name === "browser") {
            const outputCheck = await adapter.check({
              tool: "browser",
              action: "result",
              payload: {
                source_event_id: event.id,
                output,
              },
            });
            if (outputCheck.decision?.action === "block") {
              await adapter.recordResult(event.id, { error: outputCheck.decision.reason });
              throw new CortexShieldBlockedError(outputCheck.decision.reason, outputCheck.event);
            }
          }
          await adapter.recordResult(event.id, { output });
          return output;
        } catch (error) {
          await adapter.recordResult(event.id, { error: error instanceof Error ? error.message : String(error) });
          throw error;
        }
      },
    };
  }

  async check(toolCall) {
    return await this.postJson("/guard/check", { run_id: this.runId, ...toolCall });
  }

  async recordResult(eventId, result) {
    return await this.postJson(`/events/${encodeURIComponent(eventId)}/result`, result);
  }

  async waitForApproval(eventId, signal) {
    const started = Date.now();
    while (Date.now() - started <= this.approvalTimeoutMs) {
      if (signal?.aborted) {
        throw new CortexShieldApprovalError("tool call aborted while waiting for approval", { id: eventId });
      }

      const event = await this.getJson(`/events/${encodeURIComponent(eventId)}`);
      if (event.approval_status === "approved" || event.approval_status === "rejected") {
        return event;
      }

      await sleep(this.approvalPollMs);
    }

    throw new CortexShieldApprovalError("tool call approval timed out", { id: eventId });
  }

  async postJson(path, body) {
    const response = await this.fetchImpl(`${this.apiBaseUrl}${path}`, {
      method: "POST",
      headers: this.headers({ "content-type": "application/json" }),
      body: JSON.stringify(body),
    });
    return await readJsonResponse(response);
  }

  async getJson(path) {
    const response = await this.fetchImpl(`${this.apiBaseUrl}${path}`, {
      method: "GET",
      headers: this.headers({ accept: "application/json" }),
    });
    return await readJsonResponse(response);
  }

  headers(base) {
    if (!this.apiToken) {
      return base;
    }
    return { ...base, authorization: `Bearer ${this.apiToken}` };
  }
}

export function mapOpenClawToolCall(toolName, params = {}) {
  const payload = normalizeParams(params);
  if (SHELL_TOOLS.has(toolName)) {
    return {
      tool: "shell",
      action: "run",
      payload: {
        ...payload,
        command: readCommand(payload),
      },
    };
  }

  if (toolName === "browser") {
    return {
      tool: "browser",
      action: String(payload.action ?? payload.operation ?? "navigate"),
      payload,
    };
  }

  if (FILE_TOOLS.has(toolName)) {
    return {
      tool: "filesystem",
      action: toolName,
      payload,
    };
  }

  return {
    tool: "network",
    action: toolName,
    payload,
  };
}

function readCommand(payload) {
  if (typeof payload.command === "string") return payload.command;
  if (typeof payload.cmd === "string") return payload.cmd;
  if (typeof payload.script === "string") return payload.script;
  return "";
}

function normalizeParams(params) {
  if (!params || typeof params !== "object" || Array.isArray(params)) {
    return {};
  }
  return params;
}

async function readJsonResponse(response) {
  const body = await response.json();
  if (!response.ok) {
    throw new Error(body?.detail ?? `Cortex Shield request failed: ${response.status}`);
  }
  return body;
}

function trimTrailingSlash(value) {
  return value.replace(/\/+$/, "");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
