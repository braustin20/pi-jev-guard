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
  commands: Map<string, { handler: (args: string, ctx: ExtensionContext) => Promise<void> }>;
  entries: Array<{ type: string; data: unknown }>;
  api: ExtensionAPI;
}

function fakePi(options: { appendThrows?: boolean } = {}): FakePi {
  const handlers = new Map<string, (event: any, ctx: ExtensionContext) => Promise<any>>();
  const commands = new Map<string, { handler: (args: string, ctx: ExtensionContext) => Promise<void> }>();
  const entries: Array<{ type: string; data: unknown }> = [];
  const api = {
    on(name: string, handler: (event: any, ctx: ExtensionContext) => Promise<any>) { handlers.set(name, handler); },
    registerCommand(name: string, command: { handler: (args: string, ctx: ExtensionContext) => Promise<void> }) {
      commands.set(name, command);
    },
    getAllTools() { return []; },
    appendEntry(type: string, data: unknown) {
      if (options.appendThrows) throw new Error("audit unavailable");
      entries.push({ type, data });
    },
  } as unknown as ExtensionAPI;
  return { handlers, commands, entries, api };
}

function context(cwd: string, options: {
  hasUI: boolean;
  select?: (title: string, choices: string[]) => Promise<string | undefined>;
  notify?: (message: string) => void;
}): ExtensionContext {
  return {
    cwd,
    hasUI: options.hasUI,
    mode: options.hasUI ? "tui" : "json",
    signal: undefined,
    isProjectTrusted: () => true,
    ui: {
      select: options.select ?? (async () => undefined),
      notify: options.notify ?? (() => {}),
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

  const toolAuditResult = await auditPi.handlers.get("tool_call")?.(
    { type: "tool_call", toolName: "bash", toolCallId: "audit", input: { command: "git status" } },
    context(cwd, { hasUI: true }),
  );
  assert.equal(toolAuditResult?.block, true);
  assert.match(toolAuditResult?.reason, /audit unavailable/);
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

test("allow all bypasses the guard until it is manually enabled", async () => isolatedAgentDir(async (cwd) => {
  const pi = fakePi();
  const classifier = new FakeClassifier();
  const selections = ["Allow all for current session", "Deny"];
  registerJevGuard(pi.api, classifier);
  const ctx = context(cwd, {
    hasUI: true,
    select: async () => selections.shift(),
  });

  const first = await pi.handlers.get("user_bash")?.(
    { type: "user_bash", command: "rm -rf /tmp/session-bypass-first", cwd, excludeFromContext: false },
    ctx,
  );
  assert.equal(first, undefined);
  assert.equal(classifier.calls, 1);
  assert.equal(pi.entries.length, 1);

  const bypassed = await pi.handlers.get("tool_call")?.(
    { type: "tool_call", toolName: "bash", toolCallId: "2", input: { command: "rm -rf /tmp/session-bypass-second" } },
    ctx,
  );
  assert.equal(bypassed, undefined);
  assert.equal(classifier.calls, 1);
  assert.equal(pi.entries.length, 2);
  assert.equal((pi.entries[1]?.data as { sessionBypass?: boolean }).sessionBypass, true);
  assert.doesNotMatch(JSON.stringify(pi.entries[1]), /session-bypass-second/);

  await pi.commands.get("jev-guard")?.handler("enable", ctx);
  const afterEnable = await pi.handlers.get("user_bash")?.(
    { type: "user_bash", command: "rm -rf /tmp/session-bypass-third", cwd, excludeFromContext: false },
    ctx,
  );
  assert.equal(afterEnable?.result.exitCode, 126);
  assert.equal(classifier.calls, 2);
  assert.equal(pi.entries.length, 3);
}));

test("test command still reports its assessment while the guard is bypassed", async () => isolatedAgentDir(async (cwd) => {
  const pi = fakePi();
  const classifier = new FakeClassifier();
  let notification = "";
  registerJevGuard(pi.api, classifier);
  const ctx = context(cwd, {
    hasUI: true,
    select: async () => "Allow all for current session",
    notify: (message) => { notification = message; },
  });
  await pi.handlers.get("user_bash")?.(
    { type: "user_bash", command: "rm -rf /tmp/test-command-bypass", cwd, excludeFromContext: false },
    ctx,
  );
  await pi.commands.get("jev-guard")?.handler("test git status", ctx);
  assert.match(notification, /Tool: bash/);
  assert.doesNotMatch(notification, /is bypassed for the current session/);
  assert.equal(classifier.calls, 2);
}));

test("starting a new session clears the guard bypass", async () => isolatedAgentDir(async (cwd) => {
  const pi = fakePi();
  const classifier = new FakeClassifier();
  const selections = ["Allow all for current session", "Deny"];
  registerJevGuard(pi.api, classifier);
  const ctx = context(cwd, {
    hasUI: true,
    select: async () => selections.shift(),
  });

  await pi.handlers.get("user_bash")?.(
    { type: "user_bash", command: "rm -rf /tmp/session-reset-first", cwd, excludeFromContext: false },
    ctx,
  );
  await pi.handlers.get("session_start")?.({ type: "session_start", reason: "new" }, ctx);
  const afterSessionStart = await pi.handlers.get("user_bash")?.(
    { type: "user_bash", command: "rm -rf /tmp/session-reset-second", cwd, excludeFromContext: false },
    ctx,
  );
  assert.equal(afterSessionStart?.result.exitCode, 126);
  assert.equal(classifier.calls, 2);
}));

test("concurrent prompts stop after session bypass is selected", async () => isolatedAgentDir(async (cwd) => {
  const pi = fakePi();
  const classifier = new FakeClassifier();
  let prompts = 0;
  registerJevGuard(pi.api, classifier);
  const ctx = context(cwd, {
    hasUI: true,
    select: async () => {
      prompts++;
      return "Allow all for current session";
    },
  });

  const calls = await Promise.all([
    pi.handlers.get("user_bash")?.(
      { type: "user_bash", command: "rm -rf /tmp/concurrent-bypass-one", cwd, excludeFromContext: false },
      ctx,
    ),
    pi.handlers.get("user_bash")?.(
      { type: "user_bash", command: "rm -rf /tmp/concurrent-bypass-two", cwd, excludeFromContext: false },
      ctx,
    ),
  ]);
  assert.deepEqual(calls, [undefined, undefined]);
  assert.equal(prompts, 1);
  assert.equal(pi.entries.length, 2);
}));

test("session bypass choice is hidden when session approvals are disabled", async () => isolatedAgentDir(async (cwd, agentDir) => {
  await writeFile(path.join(agentDir, "jev-guard.json"), JSON.stringify({
    version: 1,
    sessionApprovals: { enabled: false },
  }));
  const pi = fakePi();
  let offeredChoices: string[] = [];
  registerJevGuard(pi.api, new FakeClassifier());
  const result = await pi.handlers.get("user_bash")?.(
    { type: "user_bash", command: "rm -rf /tmp/no-session-bypass", cwd, excludeFromContext: false },
    context(cwd, {
      hasUI: true,
      select: async (_title, choices) => {
        offeredChoices = choices;
        return "Deny";
      },
    }),
  );
  assert.equal(result?.result.exitCode, 126);
  assert.doesNotMatch(offeredChoices.join(" "), /Allow all for current session/);
}));

test("session bypass choice is hidden when session approval capacity is zero", async () => isolatedAgentDir(async (cwd, agentDir) => {
  await writeFile(path.join(agentDir, "jev-guard.json"), JSON.stringify({
    version: 1,
    sessionApprovals: { maxEntries: 0 },
  }));
  const pi = fakePi();
  let offeredChoices: string[] = [];
  registerJevGuard(pi.api, new FakeClassifier());
  await pi.handlers.get("user_bash")?.(
    { type: "user_bash", command: "rm -rf /tmp/no-capacity-bypass", cwd, excludeFromContext: false },
    context(cwd, {
      hasUI: true,
      select: async (_title, choices) => {
        offeredChoices = choices;
        return "Deny";
      },
    }),
  );
  assert.doesNotMatch(offeredChoices.join(" "), /Allow all for current session/);
}));

test("context policy change reconciles and clears the session bypass", async () => isolatedAgentDir(async (cwd) => {
  const pi = fakePi();
  const classifier = new FakeClassifier();
  registerJevGuard(pi.api, classifier);
  const firstContext = context(cwd, {
    hasUI: true,
    select: async () => "Allow all for current session",
  });
  await pi.handlers.get("user_bash")?.(
    { type: "user_bash", command: "rm -rf /tmp/context-bypass-first", cwd, excludeFromContext: false },
    firstContext,
  );

  const secondCwd = path.join(path.dirname(cwd), "second-project");
  const projectConfigDirectory = path.join(secondCwd, ".pi");
  await mkdir(projectConfigDirectory, { recursive: true });
  await writeFile(path.join(projectConfigDirectory, "jev-guard.json"), JSON.stringify({
    version: 1,
    sessionApprovals: { enabled: false },
  }));
  const secondContext = context(secondCwd, {
    hasUI: true,
    select: async () => "Deny",
  });
  const result = await pi.handlers.get("user_bash")?.(
    { type: "user_bash", command: "rm -rf /tmp/context-bypass-second", cwd: secondCwd, excludeFromContext: false },
    secondContext,
  );
  assert.equal(result?.result.exitCode, 126);
  assert.equal(classifier.calls, 2);
}));

test("policy reload clears the session bypass and invalid policy still blocks", async () => isolatedAgentDir(async (cwd, agentDir) => {
  const pi = fakePi();
  const classifier = new FakeClassifier();
  registerJevGuard(pi.api, classifier);
  const ctx = context(cwd, {
    hasUI: true,
    select: async () => "Allow all for current session",
  });
  await pi.handlers.get("user_bash")?.(
    { type: "user_bash", command: "rm -rf /tmp/reload-bypass", cwd, excludeFromContext: false },
    ctx,
  );
  await writeFile(path.join(agentDir, "jev-guard.json"), JSON.stringify({ version: 1, unexpected: true }));
  await pi.commands.get("jev-guard")?.handler("reload", ctx);
  const result = await pi.handlers.get("user_bash")?.(
    { type: "user_bash", command: "git status", cwd, excludeFromContext: false },
    ctx,
  );
  assert.equal(result?.result.exitCode, 126);
  assert.match(result?.result.output, /configuration is invalid/);
  assert.equal(classifier.calls, 1);
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
