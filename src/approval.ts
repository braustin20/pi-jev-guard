import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { Assessment } from "./types.js";

export type ApprovalChoice = "once" | "session" | "deny";

function detail(assessment: Assessment): string {
  let target = assessment.call.shell?.command;
  if (!target) target = assessment.call.paths.map((path) => path.canonical ?? path.input).join(", ");
  if (!target) target = "(no path or command)";
  let findings = "- Classification was unavailable; policy requires approval";
  if (assessment.findings.length > 0) {
    findings = assessment.findings.map((finding) => {
      let probability = "";
      if (finding.probability !== undefined) probability = ` (${Math.round(finding.probability * 100)}%)`;
      return `- ${finding.message}${probability}`;
    }).join("\n");
  }
  const model = assessment.model ? `\nModel: ${assessment.model}` : "";
  const privacy = assessment.call.redacted
    ? "Arguments were redacted before classification."
    : "No secret-looking argument values required redaction.";
  const truncation = assessment.call.stateTruncated ? " State was truncated to the configured byte limit." : "";
  return [
    `Tool: ${assessment.call.toolName}`,
    `Target: ${target}`,
    `Project: ${assessment.call.projectRoot}`,
    "",
    "Findings:",
    findings,
    model,
    "",
    `${privacy}${truncation}`,
  ].join("\n");
}

export class ApprovalPrompter {
  private tail: Promise<void> = Promise.resolve();

  public async prompt(assessment: Assessment, ctx: ExtensionContext, sessionCacheEnabled: boolean): Promise<ApprovalChoice> {
    let release: (() => void) | undefined;
    const previous = this.tail;
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      const options = sessionCacheEnabled
        ? ["Allow once", "Allow this exact call for the session", "Deny"]
        : ["Allow once", "Deny"];
      const selected = await ctx.ui.select(`Jev Guard approval required\n\n${detail(assessment)}`, options);
      if (selected === "Allow once") return "once";
      if (selected === "Allow this exact call for the session") return "session";
      return "deny";
    } finally {
      release?.();
    }
  }
}
