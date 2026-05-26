export type OpenClawTool = {
  name: string;
  execute(
    toolCallId: string,
    params: unknown,
    signal?: AbortSignal,
    onUpdate?: (update: unknown) => void,
  ): Promise<unknown>;
  [key: string]: unknown;
};

export type OpenClawAdapterOptions = {
  runId: string;
  apiBaseUrl?: string;
  apiToken?: string;
  fetch?: typeof fetch;
  approvalPollMs?: number;
  approvalTimeoutMs?: number;
  sandboxShell?: boolean;
};

export class CortexShieldBlockedError extends Error {
  event: unknown;
}

export class CortexShieldApprovalError extends Error {
  event: unknown;
}

export class OpenClawAdapter {
  constructor(options: OpenClawAdapterOptions);
  wrapTool<T extends OpenClawTool>(tool: T): T;
  wrapTools<T extends OpenClawTool>(tools: T[]): T[];
}

export function mapOpenClawToolCall(
  toolName: string,
  params?: unknown,
): {
  tool: string;
  action: string;
  payload: Record<string, unknown>;
};
