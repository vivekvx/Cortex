import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { describe, it } from "node:test";

const repoRoot = path.resolve(new URL("../..", import.meta.url).pathname);
const patchScript = path.join(repoRoot, "integrations/openclaw/patch-openclaw.mjs");

describe("patch-openclaw", () => {
  it("patches OpenClaw tool factories and copies wrapper", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cortex-openclaw-patch-"));
    const agentsDir = path.join(tmp, "src/agents");
    fs.mkdirSync(agentsDir, { recursive: true });
    fs.writeFileSync(
      path.join(agentsDir, "pi-tools.ts"),
      [
        'import { resolveWorkspaceRoot } from "./workspace-dir.js";',
        "export function createOpenClawCodingTools(options?: { runId?: string }) {",
        "  const withDeferredFollowupDescriptions = [];",
        "  return withDeferredFollowupDescriptions;",
        "}",
      ].join("\n"),
    );
    fs.writeFileSync(
      path.join(agentsDir, "openclaw-tools.ts"),
      [
        'import { resolveWorkspaceRoot } from "./workspace-dir.js";',
        "export function createOpenClawTools(options?: { runId?: string; wrapBeforeToolCallHook?: boolean }) {",
        "  const allTools = [];",
        "  if (options?.wrapBeforeToolCallHook === false) {",
        "    return allTools;",
        "  }",
        "  return allTools.map((tool) =>",
        "    isToolWrappedWithBeforeToolCallHook(tool)",
        "      ? tool",
        "      : wrapToolWithBeforeToolCallHook(tool, hookContext),",
        "  );",
        "}",
      ].join("\n"),
    );

    execFileSync("node", [patchScript, tmp], { cwd: repoRoot });

    const piTools = fs.readFileSync(path.join(agentsDir, "pi-tools.ts"), "utf8");
    const openClawTools = fs.readFileSync(path.join(agentsDir, "openclaw-tools.ts"), "utf8");

    assert.match(piTools, /wrapToolsWithCortexShield\(withDeferredFollowupDescriptions/);
    assert.match(openClawTools, /wrapToolsWithCortexShield\(allTools/);
    assert.match(openClawTools, /wrapToolsWithCortexShield\(hookedTools/);
    assert.equal(fs.existsSync(path.join(agentsDir, "cortex-shield-openclaw-wrapper.ts")), true);
  });
});
