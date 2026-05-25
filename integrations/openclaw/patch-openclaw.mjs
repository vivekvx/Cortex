#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(process.argv[2] ?? process.env.OPENCLAW_REPO ?? ".");

const wrapperSource = path.join(here, "cortex-shield-openclaw-wrapper.ts");
const wrapperTarget = path.join(repoRoot, "src/agents/cortex-shield-openclaw-wrapper.ts");
const piToolsPath = path.join(repoRoot, "src/agents/pi-tools.ts");
const openClawToolsPath = path.join(repoRoot, "src/agents/openclaw-tools.ts");

assertFile(wrapperSource);
assertFile(piToolsPath);
assertFile(openClawToolsPath);

fs.copyFileSync(wrapperSource, wrapperTarget);
patchPiTools(piToolsPath);
patchOpenClawTools(openClawToolsPath);

console.log(`Cortex Shield OpenClaw patch applied to ${repoRoot}`);

function patchPiTools(filePath) {
  let text = fs.readFileSync(filePath, "utf8");
  text = ensureImport(
    text,
    'import { wrapToolsWithCortexShield } from "./cortex-shield-openclaw-wrapper.js";',
    'import { resolveWorkspaceRoot } from "./workspace-dir.js";',
  );
  text = replaceOnce(
    text,
    "  return withDeferredFollowupDescriptions;\n}",
    [
      "  return wrapToolsWithCortexShield(withDeferredFollowupDescriptions, {",
      "    runId: options?.runId,",
      "  });",
      "}",
    ].join("\n"),
  );
  fs.writeFileSync(filePath, text);
}

function patchOpenClawTools(filePath) {
  let text = fs.readFileSync(filePath, "utf8");
  text = ensureImport(
    text,
    'import { wrapToolsWithCortexShield } from "./cortex-shield-openclaw-wrapper.js";',
    'import { resolveWorkspaceRoot } from "./workspace-dir.js";',
  );
  text = replaceOnce(
    text,
    "    return allTools;\n  }",
    [
      "    return wrapToolsWithCortexShield(allTools, {",
      "      runId: options?.runId,",
      "    });",
      "  }",
    ].join("\n"),
  );
  text = replaceOnce(
    text,
    [
      "  return allTools.map((tool) =>",
      "    isToolWrappedWithBeforeToolCallHook(tool)",
      "      ? tool",
      "      : wrapToolWithBeforeToolCallHook(tool, hookContext),",
      "  );",
    ].join("\n"),
    [
      "  const hookedTools = allTools.map((tool) =>",
      "    isToolWrappedWithBeforeToolCallHook(tool)",
      "      ? tool",
      "      : wrapToolWithBeforeToolCallHook(tool, hookContext),",
      "  );",
      "  return wrapToolsWithCortexShield(hookedTools, {",
      "    runId: options?.runId,",
      "  });",
    ].join("\n"),
  );
  fs.writeFileSync(filePath, text);
}

function ensureImport(text, importLine, anchorLine) {
  if (text.includes(importLine)) return text;
  if (!text.includes(anchorLine)) {
    throw new Error(`import anchor not found: ${anchorLine}`);
  }
  return text.replace(anchorLine, `${importLine}\n${anchorLine}`);
}

function replaceOnce(text, from, to) {
  const count = text.split(from).length - 1;
  if (count !== 1) {
    throw new Error(`expected one match, found ${count}: ${from.slice(0, 80)}`);
  }
  return text.replace(from, to);
}

function assertFile(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`file not found: ${filePath}`);
  }
}
