type CortexTool = {
  name: string;
  execute(
    toolCallId: string,
    params: unknown,
    signal?: AbortSignal,
    onUpdate?: (update: unknown) => void,
  ): Promise<unknown>;
  [key: string]: unknown;
};

type CortexOptions = {
  runId?: string;
  apiBaseUrl?: string;
  apiToken?: string;
  enabled?: boolean;
  approvalPollMs?: number;
  approvalTimeoutMs?: number;
  sandboxShell?: boolean;
};

type TaintSource = {
  eventId: string;
  text: string;
};

const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";
const DEFAULT_APPROVAL_POLL_MS = 1000;
const DEFAULT_APPROVAL_TIMEOUT_MS = 5 * 60 * 1000;
const SHELL_TOOLS = new Set(["exec", "bash", "process"]);
const FILE_TOOLS = new Set(["read", "write", "edit"]);
const WATCHED_TOOLS = new Set([...SHELL_TOOLS, ...FILE_TOOLS, "browser"]);

export function wrapToolsWithCortexShield<T extends CortexTool>(
  tools: T[],
  options: CortexOptions = {},
): T[] {
  if (!isCortexShieldEnabled(options)) {
    return tools;
  }

  const runId = options.runId?.trim();
  if (!runId) {
    return tools;
  }

  const taintSources: TaintSource[] = [];
  return tools.map((tool) => wrapTool(tool, runId, options, taintSources));
}

function isCortexShieldEnabled(options: CortexOptions): boolean {
  if (options.enabled !== undefined) {
    return options.enabled;
  }
  const value = process.env.CORTEX_SHIELD_ENABLED?.trim().toLowerCase();
  return value === "1" || value === "true" || value === "yes";
}

function wrapTool<T extends CortexTool>(
  tool: T,
  runId: string,
  options: CortexOptions,
  taintSources: TaintSource[],
): T {
  if (!WATCHED_TOOLS.has(tool.name) || typeof tool.execute !== "function") {
    return tool;
  }

  const apiBaseUrl = trimTrailingSlash(
    options.apiBaseUrl ?? process.env.CORTEX_API_BASE_URL ?? DEFAULT_API_BASE_URL,
  );
  const apiToken = options.apiToken ?? process.env.CORTEX_API_TOKEN;
  const approvalPollMs = options.approvalPollMs ?? DEFAULT_APPROVAL_POLL_MS;
  const approvalTimeoutMs = options.approvalTimeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS;
  const sandboxShell = options.sandboxShell ?? process.env.CORTEX_SANDBOX_SHELL === "1";

  return {
    ...tool,
    async execute(toolCallId, params, signal, onUpdate) {
      const mappedCall = attachTaintSource(mapOpenClawToolCall(tool.name, params), taintSources);
      const check = await postJson(apiBaseUrl, apiToken, "/guard/check", {
        run_id: runId,
        ...mappedCall,
      });
      const decision = readDecisionAction(check);
      const eventId = readEventId(check);

      if (decision === "block") {
        throw new Error(readDecisionReason(check) ?? "blocked by Cortex Shield");
      }

      let approved = false;
      if (decision === "require_approval") {
        await waitForApproval(apiBaseUrl, apiToken, eventId, approvalPollMs, approvalTimeoutMs, signal);
        approved = true;
      }

      try {
        const output =
          sandboxShell && approved && SHELL_TOOLS.has(tool.name)
            ? await postJson(apiBaseUrl, apiToken, "/sandbox/shell", {
                run_id: runId,
                command: readCommand(mappedCall.payload),
              })
            : await tool.execute(toolCallId, params, signal, onUpdate);
        if (tool.name === "browser") {
          const outputCheck = await postJson(apiBaseUrl, apiToken, "/guard/check", {
            run_id: runId,
            tool: "browser",
            action: "result",
            payload: { source_event_id: eventId, output },
          });
          if (readDecisionAction(outputCheck) === "block") {
            const reason = readDecisionReason(outputCheck) ?? "browser output blocked by Cortex Shield";
            await postJson(apiBaseUrl, apiToken, `/events/${encodeURIComponent(eventId)}/result`, {
              error: reason,
            });
            throw new Error(reason);
          }
        }

        rememberTaintSource(tool.name, mappedCall.action, output, eventId, taintSources);
        await postJson(apiBaseUrl, apiToken, `/events/${encodeURIComponent(eventId)}/result`, { output });
        return output;
      } catch (error) {
        await postJson(apiBaseUrl, apiToken, `/events/${encodeURIComponent(eventId)}/result`, {
          error: error instanceof Error ? error.message : String(error),
        });
        throw error;
      }
    },
  };
}

function attachTaintSource(
  toolCall: ReturnType<typeof mapOpenClawToolCall>,
  taintSources: TaintSource[],
): ReturnType<typeof mapOpenClawToolCall> {
  if (typeof toolCall.payload.source_event_id === "string" || toolCall.tool === "browser") {
    return toolCall;
  }

  const sourceEventId = findTaintSource(toolCall.payload, taintSources);
  if (!sourceEventId) {
    return toolCall;
  }

  return {
    ...toolCall,
    payload: {
      ...toolCall.payload,
      source_event_id: sourceEventId,
    },
  };
}

function rememberTaintSource(
  toolName: string,
  action: string,
  output: unknown,
  eventId: string,
  taintSources: TaintSource[],
): void {
  if (toolName !== "browser" && !(toolName === "read" && action === "read")) {
    return;
  }

  for (const text of flattenText(output)) {
    const normalized = text.trim();
    if (normalized.length >= 8) {
      taintSources.push({ eventId, text: normalized });
    }
  }
}

function findTaintSource(payload: unknown, taintSources: TaintSource[]): string | undefined {
  const payloadText = flattenText(payload).join("\n");
  if (!payloadText) {
    return undefined;
  }

  for (const source of taintSources) {
    if (payloadText.includes(source.text) || source.text.includes(payloadText)) {
      return source.eventId;
    }
  }
  return undefined;
}

function mapOpenClawToolCall(toolName: string, params: unknown) {
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

  return { tool: "network", action: toolName, payload };
}

function normalizeParams(params: unknown): Record<string, unknown> {
  return params && typeof params === "object" && !Array.isArray(params)
    ? (params as Record<string, unknown>)
    : {};
}

function readCommand(payload: Record<string, unknown>): string {
  if (typeof payload.command === "string") return payload.command;
  if (typeof payload.cmd === "string") return payload.cmd;
  if (typeof payload.script === "string") return payload.script;
  return "";
}

function flattenText(value: unknown): string[] {
  if (typeof value === "string") {
    return [value];
  }
  if (Array.isArray(value)) {
    return value.flatMap((item) => flattenText(item));
  }
  if (value && typeof value === "object") {
    return Object.values(value as Record<string, unknown>).flatMap((item) => flattenText(item));
  }
  return [];
}

async function waitForApproval(
  apiBaseUrl: string,
  apiToken: string | undefined,
  eventId: string,
  pollMs: number,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<void> {
  const started = Date.now();
  while (Date.now() - started <= timeoutMs) {
    if (signal?.aborted) {
      throw new Error("Cortex Shield approval wait aborted");
    }
    const event = await getJson(apiBaseUrl, apiToken, `/events/${encodeURIComponent(eventId)}`);
    const status = readStringField(event, "approval_status");
    if (status === "approved") return;
    if (status === "rejected") throw new Error("tool call rejected by Cortex Shield");
    await sleep(pollMs);
  }
  throw new Error("Cortex Shield approval timed out");
}

async function postJson(
  apiBaseUrl: string,
  apiToken: string | undefined,
  path: string,
  body: unknown,
): Promise<unknown> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    method: "POST",
    headers: authHeaders(apiToken, { "content-type": "application/json" }),
    body: JSON.stringify(body),
  });
  return readResponse(response);
}

async function getJson(
  apiBaseUrl: string,
  apiToken: string | undefined,
  path: string,
): Promise<unknown> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    method: "GET",
    headers: authHeaders(apiToken, { accept: "application/json" }),
  });
  return readResponse(response);
}

function authHeaders(apiToken: string | undefined, base: Record<string, string>): Record<string, string> {
  return apiToken ? { ...base, authorization: `Bearer ${apiToken}` } : base;
}

async function readResponse(response: Response): Promise<unknown> {
  const body = await response.json();
  if (!response.ok) {
    throw new Error(readStringField(body, "detail") ?? `Cortex Shield request failed: ${response.status}`);
  }
  return body;
}

function readDecisionAction(value: unknown): string | undefined {
  return readNestedString(value, "decision", "action");
}

function readDecisionReason(value: unknown): string | undefined {
  return readNestedString(value, "decision", "reason");
}

function readEventId(value: unknown): string {
  const eventId = readNestedString(value, "event", "id");
  if (!eventId) {
    throw new Error("Cortex Shield response missing event id");
  }
  return eventId;
}

function readNestedString(value: unknown, objectKey: string, fieldKey: string): string | undefined {
  if (!value || typeof value !== "object") return undefined;
  const nested = (value as Record<string, unknown>)[objectKey];
  return readStringField(nested, fieldKey);
}

function readStringField(value: unknown, key: string): string | undefined {
  if (!value || typeof value !== "object") return undefined;
  const field = (value as Record<string, unknown>)[key];
  return typeof field === "string" ? field : undefined;
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
