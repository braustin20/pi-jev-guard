import type { Assessment } from "./types.js";

export const AUDIT_ENTRY_TYPE = "jev-guard-assessment";

export interface AuditEntry {
  callHash: string;
  toolName: string;
  decision: Assessment["decision"];
  findingIds: string[];
  categories: string[];
  probabilities: Record<string, number>;
  intentAlignment?: number;
  model?: string;
  usage?: Assessment["usage"];
  classificationError?: string;
  matchedRule?: string;
  timestamp: string;
}

export interface SessionBypassAuditEntry {
  toolName: string;
  decision: "allow";
  sessionBypass: true;
  timestamp: string;
}

export function createSessionBypassAuditEntry(toolName: string): SessionBypassAuditEntry {
  return {
    toolName,
    decision: "allow",
    sessionBypass: true,
    timestamp: new Date().toISOString(),
  };
}

export function createAuditEntry(assessment: Assessment): AuditEntry {
  return {
    callHash: assessment.call.callHash,
    toolName: assessment.call.toolName,
    decision: assessment.decision,
    findingIds: assessment.findings.map((finding) => finding.id),
    categories: [...new Set(assessment.findings.map((finding) => finding.category))],
    probabilities: assessment.probabilities,
    ...(assessment.intentAlignment === undefined ? {} : { intentAlignment: assessment.intentAlignment }),
    ...(assessment.model ? { model: assessment.model } : {}),
    ...(assessment.usage ? { usage: assessment.usage } : {}),
    ...(assessment.classificationError ? { classificationError: assessment.classificationError } : {}),
    ...(assessment.matchedRule ? { matchedRule: assessment.matchedRule } : {}),
    timestamp: assessment.timestamp,
  };
}
