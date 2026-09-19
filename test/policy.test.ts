import assert from "node:assert/strict";
import test from "node:test";
import { DEFAULT_CONFIG } from "../src/defaults.js";
import { composeDecision, composeFailureDecision } from "../src/policy.js";
import type { Finding, JevAssessment, NormalizedCall } from "../src/types.js";

function call(findings: Finding[] = []): NormalizedCall {
  return {
    toolName: "bash",
    cwd: "/work",
    projectRoot: "/work",
    arguments: { command: "git status" },
    paths: [],
    shell: {
      command: "git status",
      tokens: ["git", "status"],
      operators: [],
      commands: ["git"],
      destinations: [],
      complex: false,
      mutating: false,
      networked: false,
      unknown: false,
    },
    deterministicFindings: findings,
    mutating: false,
    networked: false,
    unknown: false,
    redacted: false,
    stateTruncated: false,
    callHash: "hash",
  };
}

const clear: JevAssessment = {
  probabilities: Object.fromEntries(Object.keys(DEFAULT_CONFIG.hazards).map((name) => [name, 0.01])),
  model: "jev-1.13.0",
  usage: { input_tokens: 1, output_tokens: 1 },
};

test("explicit block rule has highest precedence", () => {
  const config = structuredClone(DEFAULT_CONFIG);
  config.rules = [{ id: "block-git", decision: "block", commandRegex: "^git status" }];
  assert.equal(composeDecision(call(), config, clear).decision, "block");
});

test("Jev hazard at threshold prompts", () => {
  const jev = structuredClone(clear);
  jev.probabilities.destructive_filesystem = 0.8;
  const result = composeDecision(call(), structuredClone(DEFAULT_CONFIG), jev);
  assert.equal(result.decision, "prompt");
  assert.ok(result.findings.some((finding) => finding.id === "jev:destructive_filesystem"));
});

test("deterministic prompt beats explicit allow", () => {
  const config = structuredClone(DEFAULT_CONFIG);
  config.rules = [{ id: "allow-git", decision: "allow", commandRegex: "^git status" }];
  const finding: Finding = {
    id: "outside-project",
    category: "outside_project_or_system_change",
    message: "outside",
    decision: "prompt",
    source: "deterministic",
  };
  assert.equal(composeDecision(call([finding]), config, clear).decision, "prompt");
});

test("truncated classifier state requires approval", () => {
  const truncated = call();
  truncated.stateTruncated = true;
  const result = composeDecision(truncated, structuredClone(DEFAULT_CONFIG), clear);
  assert.equal(result.decision, "prompt");
  assert.ok(result.findings.some((finding) => finding.id === "classifier-state-truncated"));
});

test("headless classification failure blocks by default", () => {
  assert.equal(composeFailureDecision(call(), structuredClone(DEFAULT_CONFIG), false, "timeout").decision, "block");
});

test("headless allow-read-only only permits known local reads", () => {
  const config = structuredClone(DEFAULT_CONFIG);
  config.failureMode.headless = "allow-read-only";
  assert.equal(composeFailureDecision(call(), config, false, "timeout").decision, "allow");
  const networked = call();
  networked.networked = true;
  assert.equal(composeFailureDecision(networked, config, false, "timeout").decision, "block");
});
