import safeRegex from "safe-regex2";
import { matchesGlob } from "./paths.js";
import type {
  Assessment,
  Decision,
  Finding,
  GuardConfig,
  JevAssessment,
  NormalizedCall,
  RuleConfig,
} from "./types.js";

function commandOf(call: NormalizedCall): string | undefined {
  return call.shell?.command;
}

function destinationsOf(call: NormalizedCall): string[] {
  const output = new Set(call.shell?.destinations ?? []);
  let serialized = "";
  try {
    serialized = JSON.stringify(call.arguments);
  } catch {
    return [...output];
  }
  for (const match of serialized.matchAll(/\b(?:https?|ssh|ftp):\/\/[^\s'"`<>\\]+/gi)) {
    try {
      output.add(new URL(match[0]).hostname.toLowerCase());
    } catch {
      // Invalid destinations do not match destination allow rules.
    }
  }
  return [...output];
}

export function ruleMatches(rule: RuleConfig, call: NormalizedCall): boolean {
  if (rule.tool !== undefined && rule.tool !== call.toolName) return false;
  const command = commandOf(call);
  if (rule.command !== undefined && rule.command !== command) return false;
  if (rule.commandRegex !== undefined) {
    if (command === undefined || !safeRegex(rule.commandRegex)) return false;
    if (!new RegExp(rule.commandRegex).test(command)) return false; // nosemgrep -- length-bounded and checked by safe-regex2.
  }
  const pathGlob = rule.pathGlob;
  if (
    pathGlob !== undefined &&
    !call.paths.some((fact) => fact.canonical !== null && matchesGlob(fact.canonical, pathGlob))
  ) return false;
  if (rule.destination !== undefined && !destinationsOf(call).includes(rule.destination.toLowerCase())) return false;
  return true;
}

function matchedRule(call: NormalizedCall, config: GuardConfig, decision: Decision): RuleConfig | undefined {
  return config.rules.find((rule) => rule.decision === decision && ruleMatches(rule, call));
}

function assessment(
  call: NormalizedCall,
  decision: Decision,
  reason: string,
  findings: Finding[],
  jev?: JevAssessment,
  rule?: RuleConfig,
): Assessment {
  return {
    decision,
    reason,
    call,
    findings,
    probabilities: jev?.probabilities ?? {},
    ...(jev ? { model: jev.model, usage: jev.usage } : {}),
    ...(rule ? { matchedRule: rule.id } : {}),
    timestamp: new Date().toISOString(),
  };
}

export function composeDecision(call: NormalizedCall, config: GuardConfig, jev: JevAssessment): Assessment {
  const blockRule = matchedRule(call, config, "block");
  if (blockRule) {
    const finding: Finding = {
      id: `rule:${blockRule.id}`,
      category: "explicit_rule",
      message: `Blocked by rule ${blockRule.id}`,
      decision: "block",
      source: "rule",
    };
    return assessment(call, "block", finding.message, [finding, ...call.deterministicFindings], jev, blockRule);
  }

  const deterministicBlock = call.deterministicFindings.find((finding) => finding.decision === "block");
  if (deterministicBlock) return assessment(call, "block", deterministicBlock.message, call.deterministicFindings, jev);

  const promptRule = matchedRule(call, config, "prompt");
  if (promptRule) {
    const finding: Finding = {
      id: `rule:${promptRule.id}`,
      category: "explicit_rule",
      message: `Approval required by rule ${promptRule.id}`,
      decision: "prompt",
      source: "rule",
    };
    return assessment(call, "prompt", finding.message, [finding, ...call.deterministicFindings], jev, promptRule);
  }

  const findings = [...call.deterministicFindings];
  if (call.stateTruncated) {
    findings.push({
      id: "classifier-state-truncated",
      category: "classification_completeness",
      message: "Classifier state exceeded the configured byte limit and was truncated",
      decision: "prompt",
      source: "deterministic",
    });
  }
  for (const [name, probability] of Object.entries(jev.probabilities)) {
    const policy = config.hazards[name];
    if (!policy?.enabled || probability < policy.promptAt) continue;
    findings.push({
      id: `jev:${name}`,
      category: name,
      message: `Jev detected ${name} (${Math.round(probability * 100)}%)`,
      decision: policy.decision,
      source: "jev",
      probability,
    });
  }

  const modelBlock = findings.find((finding) => finding.source === "jev" && finding.decision === "block");
  if (modelBlock) return assessment(call, "block", modelBlock.message, findings, jev);
  const modelPrompt = findings.find((finding) => finding.source === "jev" && finding.decision === "prompt");
  if (modelPrompt) return assessment(call, "prompt", modelPrompt.message, findings, jev);
  const deterministicPrompt = findings.find(
    (finding) => finding.source === "deterministic" && finding.decision === "prompt",
  );
  if (deterministicPrompt) return assessment(call, "prompt", deterministicPrompt.message, findings, jev);

  const allowRule = matchedRule(call, config, "allow");
  if (allowRule) return assessment(call, "allow", `Allowed by rule ${allowRule.id}`, findings, jev, allowRule);
  return assessment(call, "allow", "No enabled hazard crossed its threshold", findings, jev);
}

export function composeFailureDecision(
  call: NormalizedCall,
  config: GuardConfig,
  hasUI: boolean,
  error: string,
  cancelled = false,
): Assessment {
  const blockRule = matchedRule(call, config, "block");
  const promptRule = matchedRule(call, config, "prompt");
  const deterministicBlock = call.deterministicFindings.some((finding) => finding.decision === "block");
  const deterministicPrompt = call.deterministicFindings.some((finding) => finding.decision === "prompt");
  let decision: Decision;
  if (cancelled || blockRule || deterministicBlock) {
    decision = "block";
  } else if (promptRule || deterministicPrompt) {
    decision = hasUI ? "prompt" : "block";
  } else if (hasUI) {
    decision = config.failureMode.interactive;
  } else if (config.failureMode.headless === "allow") {
    decision = "allow";
  } else if (
    config.failureMode.headless === "allow-read-only" &&
    !call.mutating &&
    !call.networked &&
    !call.unknown
  ) {
    decision = "allow";
  } else {
    decision = "block";
  }
  const finding: Finding = {
    id: "classification-failure",
    category: "classification_failure",
    message: `Jev classification unavailable: ${error}`,
    decision,
    source: "failure",
  };
  return {
    decision,
    reason: finding.message,
    call,
    findings: [...call.deterministicFindings, finding],
    probabilities: {},
    classificationError: error,
    timestamp: new Date().toISOString(),
  };
}
