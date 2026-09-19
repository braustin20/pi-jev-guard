import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { blockedUserBash, registerJevGuard } from "../src/index.js";
import type { GuardConfig, JevAssessment, NormalizedCall } from "../src/types.js";
import type { JevClassifier } from "../src/jev.js";

class FakeClassifier implements JevClassifier {
  public calls = 0;
  public available(): boolean { return true; }
  public async classify(_call: NormalizedCall, config: GuardConfig): Promise<JevAssessment> {
    this.calls++;
    return {
      probabilities: Object.fromEntries(Object.keys(config.hazards).map((name) => [name, 0.01])),
      model: config.model,
      usage: { input_tokens: 1, output_tokens: 1 },
    };
  }
}

interface FakePi {
  handlers: Map<string, (event: any, ctx: ExtensionContext) => Promise<any>>;
  entries: Array<{ type: string; data: unknown }>;
  api: ExtensionAPI;
}

function fakePi(options: { appendThrows?: boolean } = {}): FakePi {
  const handlers = new Map<string, (event: any, ctx: ExtensionContext) => Promise<any>>();
  const entries: Array<{ type: string; data: unknown }> = [];
  const api = {
    on(name: string, handler: (event: any, ctx: ExtensionContext) => Promise<any>) { handlers.set(name, handler); },
    registerCommand() {},
    getAllTools() { return []; },
    appendEntry(type: string, data: unknown) {
      if (options.appendThrows) throw new Error("audit unavailable");
      entries.push({ type, data });
    },
  } as unknown as ExtensionAPI;
  return { handlers, entries, api };
}

function context(cwd: string, options: { hasUI: boolean; select?: () => Promise<string | undefined> }): ExtensionContext {
  return {
    cwd,
    hasUI: options.hasUI,
    mode: options.hasUI ? "tui" : "json",
    signal: undefined,
    isProjectTrusted: () => true,
    ui: {
      select: options.select ?? (async () => undefined),
      notify() {},
    },
  } as unknown as ExtensionContext;
}

async function isolatedAgentDir<T>(run: (cwd: string, agentDir: string) => Promise<T>): Promise<T> {
  const root = await mkdtemp(path.join(tmpdir(), "jev-guard-index-"));
  const cwd = path.join(root, "project");
  const agentDir = path.join(root, "agent");
  await mkdir(cwd);
  await mkdir(agentDir);
  const previous = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  try {
    return await run(cwd, agentDir);
  } finally {
    if (previous === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previous;
  }
}

test("blocked user shell result uses exit code 126", () => {
  assert.equal(blockedUserBash("denied").result.exitCode, 126);
});

test("tool prompt blocks when no UI is available and audit omits raw arguments", async () => isolatedAgentDir(async (cwd) => {
  const pi = fakePi();
  registerJevGuard(pi.api, new FakeClassifier());
  const result = await pi.handlers.get("tool_call")?.(
    { type: "tool_call", toolName: "bash", toolCallId: "1", input: { command: "rm -rf /tmp/private-name" } },
    context(cwd, { hasUI: false }),
  );
  assert.equal(result?.block, true);
  assert.match(result?.reason, /Approval required/);
  assert.equal(pi.entries.length, 1);
  assert.doesNotMatch(JSON.stringify(pi.entries), /rm -rf|private-name/);
}));

test("user shell fails closed when approval or auditing throws", async () => isolatedAgentDir(async (cwd) => {
  const approvalPi = fakePi();
  registerJevGuard(approvalPi.api, new FakeClassifier());
  const approvalResult = await approvalPi.handlers.get("user_bash")?.(
    { type: "user_bash", command: "rm -rf /tmp/x", cwd, excludeFromContext: false },
    context(cwd, { hasUI: true, select: async () => { throw new Error("dialog unavailable"); } }),
  );
  assert.equal(approvalResult?.result.exitCode, 126);

  const auditPi = fakePi({ appendThrows: true });
  registerJevGuard(auditPi.api, new FakeClassifier());
  const auditResult = await auditPi.handlers.get("user_bash")?.(
    { type: "user_bash", command: "git status", cwd, excludeFromContext: false },
    context(cwd, { hasUI: true }),
  );
  assert.equal(auditResult?.result.exitCode, 126);
}));

test("exact session approval bypasses repeat classification only for the same call", async () => isolatedAgentDir(async (cwd) => {
  const pi = fakePi();
  const classifier = new FakeClassifier();
  let prompts = 0;
  registerJevGuard(pi.api, classifier);
  const ctx = context(cwd, {
    hasUI: true,
    select: async () => {
      prompts++;
      return "Allow this exact call for the session";
    },
  });
  const event = { type: "user_bash", command: "rm -rf /tmp/cache-test", cwd, excludeFromContext: false };
  assert.equal(await pi.handlers.get("user_bash")?.(event, ctx), undefined);
  assert.equal(await pi.handlers.get("user_bash")?.(event, ctx), undefined);
  assert.equal(classifier.calls, 1);
  assert.equal(prompts, 1);
}));

test("excluded tools bypass classification", async () => isolatedAgentDir(async (cwd, agentDir) => {
  await writeFile(path.join(agentDir, "jev-guard.json"), JSON.stringify({
    version: 1,
    excludedTools: ["write"],
  }));
  const pi = fakePi();
  const classifier = new FakeClassifier();
  registerJevGuard(pi.api, classifier);
  const result = await pi.handlers.get("tool_call")?.(
    { type: "tool_call", toolName: "write", toolCallId: "1", input: { path: "x", content: "secret" } },
    context(cwd, { hasUI: false }),
  );
  assert.equal(result, undefined);
  assert.equal(classifier.calls, 0);
}));
