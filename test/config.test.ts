import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { loadConfig, mergeConfigForTest } from "../src/config.js";
import { DEFAULT_CONFIG } from "../src/defaults.js";

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
  const globalPath = path.join(root, "global.json");
  const projectPath = path.join(root, "project.json");
  await writeFile(globalPath, JSON.stringify({ version: 1, unexpected: true }));
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
});
