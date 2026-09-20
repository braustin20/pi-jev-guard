import assert from "node:assert/strict";
import { chmod, mkdtemp, mkdir, readFile, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { ensureGlobalConfig, loadConfig, mergeConfigForTest } from "../src/config.js";
import { DEFAULT_CONFIG } from "../src/defaults.js";
import type { GuardConfig } from "../src/types.js";

const unixOnly = { skip: process.platform === "win32" };

async function secureGlobalPath(root: string): Promise<string> {
  const agentDir = path.join(root, "agent");
  await mkdir(agentDir, { recursive: true, mode: 0o700 });
  return path.join(agentDir, "jev-guard.json");
}

test("global config can disable a built-in hazard and add a custom hazard", () => {
  const merged = mergeConfigForTest(structuredClone(DEFAULT_CONFIG), {
    hazards: {
      destructive_filesystem: { enabled: false, decision: "prompt", promptAt: 0.4 },
      production_deployment: { enabled: true, decision: "prompt", promptAt: 0.3 },
    },
  }, false);
  assert.equal(merged.hazards.destructive_filesystem?.enabled, false);
  assert.equal(merged.hazards.production_deployment?.promptAt, 0.3);
});

test("global protected paths and redaction keys extend secure defaults", () => {
  const merged = mergeConfigForTest(structuredClone(DEFAULT_CONFIG), {
    protectedPaths: ["/opt/company/**"],
    privacy: { redactKeys: ["companyCredential"] } as typeof DEFAULT_CONFIG.privacy,
  }, false);
  assert.ok(merged.protectedPaths.includes("/etc/**"));
  assert.ok(merged.protectedPaths.includes("/opt/company/**"));
  assert.ok(merged.privacy.redactKeys.includes("token"));
  assert.ok(merged.privacy.redactKeys.includes("companyCredential"));
});

test("project merge is tighten-only by default", () => {
  const merged = mergeConfigForTest(structuredClone(DEFAULT_CONFIG), {
    protectUserBash: false,
    sessionApprovals: { enabled: false, maxEntries: 0 },
    excludedTools: ["bash"],
    trustedDestinations: ["evil.example"],
    hazards: {
      destructive_filesystem: { enabled: false, decision: "allow", promptAt: 0.99 },
      production_deployment: { enabled: true, decision: "block", promptAt: 0.2 },
    },
    protectedPaths: ["/opt/protected/**"],
    rules: [
      { id: "allow-rm", decision: "allow", tool: "bash" },
      { id: "block-prune", decision: "block", commandRegex: "docker\\s+system\\s+prune" },
    ],
  }, true);
  assert.equal(merged.protectUserBash, true);
  assert.equal(merged.sessionApprovals.enabled, false);
  assert.equal(merged.sessionApprovals.maxEntries, 0);
  assert.deepEqual(merged.excludedTools, []);
  assert.deepEqual(merged.trustedDestinations, []);
  assert.equal(merged.hazards.destructive_filesystem?.enabled, true);
  assert.equal(merged.hazards.destructive_filesystem?.decision, "prompt");
  assert.equal(merged.hazards.destructive_filesystem?.promptAt, 0.4);
  assert.equal(merged.hazards.production_deployment?.decision, "block");
  assert.ok(merged.protectedPaths.includes("/opt/protected/**"));
  assert.equal(merged.rules.some((rule) => rule.id === "allow-rm"), false);
  assert.equal(merged.rules.some((rule) => rule.id === "block-prune"), true);
});

test("global config accepts but does not expose the TypeSafe credential", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "jev-guard-global-credential-"));
  const globalPath = await secureGlobalPath(root);
  const projectPath = path.join(root, "project.json");
  await writeFile(globalPath, JSON.stringify({ version: 1, typesafeApiKey: "test-only-key" }), { mode: 0o600 });
  const result = await loadConfig({ globalPath, projectPath, projectRoot: root, projectTrusted: false });
  assert.ok(result.config);
  assert.equal((result.config as GuardConfig & { typesafeApiKey?: string }).typesafeApiKey, undefined);
});

test("project config rejects TypeSafe credentials", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "jev-guard-project-credential-"));
  const globalPath = path.join(root, "global.json");
  const projectPath = path.join(root, "project.json");
  await writeFile(projectPath, JSON.stringify({ version: 1, typesafeApiKey: "test-only-key" }));
  const result = await loadConfig({ globalPath, projectPath, projectRoot: root, projectTrusted: true });
  assert.equal(result.config, undefined);
  assert.ok(result.errors.some((error) => error.includes("allowed only in the global configuration")));
});

test("creates a minimal global config once with private permissions", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "jev-guard-default-config-"));
  const globalPath = path.join(root, "agent", "jev-guard.json");
  assert.equal(await ensureGlobalConfig(globalPath), true);
  assert.deepEqual(JSON.parse(await readFile(globalPath, "utf8")), { version: 1, typesafeApiKey: "" });
  if (process.platform !== "win32") {
    assert.equal((await stat(path.dirname(globalPath))).mode & 0o777, 0o700);
    assert.equal((await stat(globalPath)).mode & 0o777, 0o600);
  }
  assert.equal(await ensureGlobalConfig(globalPath), false);
});

test("malformed global config errors never include credential content", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "jev-guard-malformed-global-"));
  const globalPath = await secureGlobalPath(root);
  const projectPath = path.join(root, "project.json");
  await writeFile(
    globalPath,
    '{"version":1,"typesafeApiKey":"never-echo-this",}',
    { mode: 0o600 },
  );
  const result = await loadConfig({ globalPath, projectPath, projectRoot: root, projectTrusted: false });
  assert.equal(result.config, undefined);
  assert.match(result.errors.join(" "), /invalid JSON/);
  assert.doesNotMatch(result.errors.join(" "), /never-echo-this/);
});

test("global config rejects malformed credential types without echoing values", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "jev-guard-malformed-credential-"));
  const globalPath = await secureGlobalPath(root);
  const projectPath = path.join(root, "project.json");
  await writeFile(
    globalPath,
    JSON.stringify({ version: 1, typesafeApiKey: { secret: "never-echo-this" } }),
    { mode: 0o600 },
  );
  const result = await loadConfig({ globalPath, projectPath, projectRoot: root, projectTrusted: false });
  assert.equal(result.config, undefined);
  assert.doesNotMatch(result.errors.join(" "), /never-echo-this/);
});

test("global policy loading rejects insecure permissions", unixOnly, async () => {
  const root = await mkdtemp(path.join(tmpdir(), "jev-guard-insecure-global-"));
  const globalPath = await secureGlobalPath(root);
  const projectPath = path.join(root, "project.json");
  await writeFile(globalPath, JSON.stringify({ version: 1 }), { mode: 0o600 });
  await chmod(globalPath, 0o644);
  const result = await loadConfig({ globalPath, projectPath, projectRoot: root, projectTrusted: false });
  assert.equal(result.config, undefined);
  assert.match(result.errors.join(" "), /permissions are too broad/);
});

test("global policy loading rejects symlinks and oversized files", unixOnly, async () => {
  const root = await mkdtemp(path.join(tmpdir(), "jev-guard-secure-global-"));
  const globalPath = await secureGlobalPath(root);
  const projectPath = path.join(root, "project.json");
  const targetPath = path.join(root, "target.json");
  await writeFile(targetPath, JSON.stringify({ version: 1 }), { mode: 0o600 });
  await symlink(targetPath, globalPath);
  const linked = await loadConfig({ globalPath, projectPath, projectRoot: root, projectTrusted: false });
  assert.equal(linked.config, undefined);
  assert.match(linked.errors.join(" "), /symbolic link/);

  await unlink(globalPath);
  await writeFile(globalPath, JSON.stringify({ padding: "x".repeat(257 * 1024) }), { mode: 0o600 });
  const oversized = await loadConfig({ globalPath, projectPath, projectRoot: root, projectTrusted: false });
  assert.equal(oversized.config, undefined);
  assert.match(oversized.errors.join(" "), /exceeds/);
});

test("untrusted project configuration is ignored", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "jev-guard-config-"));
  const globalPath = path.join(root, "global.json");
  const projectPath = path.join(root, ".pi", "jev-guard.json");
  await mkdir(path.dirname(projectPath));
  await writeFile(projectPath, JSON.stringify({ version: 1, model: "untrusted-model" }));
  const result = await loadConfig({ globalPath, projectPath, projectRoot: root, projectTrusted: false });
  assert.equal(result.config?.model, DEFAULT_CONFIG.model);
  assert.equal(result.projectConfigLoaded, false);
});

test("rejects unknown fields and invalid regular expressions", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "jev-guard-invalid-"));
  const globalPath = await secureGlobalPath(root);
  const projectPath = path.join(root, "project.json");
  await writeFile(globalPath, JSON.stringify({ version: 1, unexpected: true }), { mode: 0o600 });
  const unknown = await loadConfig({ globalPath, projectPath, projectRoot: root, projectTrusted: false });
  assert.equal(unknown.config, undefined);
  assert.ok(unknown.errors.some((error) => error.includes("additional properties")));

  await writeFile(globalPath, JSON.stringify({
    version: 1,
    rules: [{ id: "bad", decision: "block", commandRegex: "[" }],
  }));
  const regex = await loadConfig({ globalPath, projectPath, projectRoot: root, projectTrusted: false });
  assert.equal(regex.config, undefined);
  assert.ok(regex.errors.some((error) => error.includes("invalid commandRegex")));

  await writeFile(globalPath, JSON.stringify({
    version: 1,
    rules: [{ id: "redos", decision: "block", commandRegex: "^(a+)+$" }],
  }));
  const unsafe = await loadConfig({ globalPath, projectPath, projectRoot: root, projectTrusted: false });
  assert.equal(unsafe.config, undefined);
  assert.ok(unsafe.errors.some((error) => error.includes("unsafe commandRegex")));

  await writeFile(
    globalPath,
    '{"version":1,"hazards":{"__proto__":{"decision":"allow"}}}',
  );
  const reservedHazard = await loadConfig({ globalPath, projectPath, projectRoot: root, projectTrusted: false });
  assert.equal(reservedHazard.config, undefined);
  assert.ok(reservedHazard.errors.some((error) => error.includes("must NOT be valid")));
});
