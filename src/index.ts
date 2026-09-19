import path from "node:path";
import {
  CONFIG_DIR_NAME,
  getAgentDir,
  type ExtensionAPI,
  type ExtensionContext,
  type ToolCallEvent,
} from "@earendil-works/pi-coding-agent";
import { ApprovalPrompter } from "./approval.js";
import { AUDIT_ENTRY_TYPE, createAuditEntry } from "./audit.js";
import { loadConfig } from "./config.js";
import { DEFAULT_CONFIG } from "./defaults.js";
import { TypeSafeJevClassifier, safeClassificationError, type JevClassifier } from "./jev.js";
import { findGitRoot, normalizeCall } from "./normalize.js";
import { composeDecision, composeFailureDecision } from "./policy.js";
import type { Assessment, ConfigLoadResult, GuardConfig, ToolMetadata } from "./types.js";

export class GuardRuntime {
  private configState: ConfigLoadResult | undefined;
  private configKey = "";
  private configPromise: Promise<ConfigLoadResult> | undefined;
  private configPromiseKey = "";
  private configGeneration = 0;
  private readonly approvals = new Set<string>();
  private readonly prompter = new ApprovalPrompter();
  private lastAssessment: Assessment | undefined;

  public constructor(
    private readonly pi: ExtensionAPI,
    private readonly classifier: JevClassifier = new TypeSafeJevClassifier(),
  ) {}

  public clearSessionState(): void {
    this.approvals.clear();
    this.lastAssessment = undefined;
  }

  public invalidateConfig(): void {
    this.configState = undefined;
    this.configKey = "";
    this.configPromise = undefined;
    this.configPromiseKey = "";
    this.configGeneration++;
    this.approvals.clear();
  }

  private async loadForContext(ctx: ExtensionContext): Promise<ConfigLoadResult> {
    const trusted = ctx.isProjectTrusted();
    const key = `${ctx.cwd}\0${trusted}`;
    if (this.configState && this.configKey === key) return this.configState;
    if (this.configPromise && this.configPromiseKey === key) return this.configPromise;
    const generation = ++this.configGeneration;
    const promise = (async () => {
      const globalPath = path.join(getAgentDir(), "jev-guard.json");
      const preliminary = await loadConfig({
        globalPath,
        projectPath: path.join(ctx.cwd, CONFIG_DIR_NAME, "jev-guard.json"),
        projectRoot: ctx.cwd,
        projectTrusted: false,
      });
      const boundary = preliminary.config?.projectBoundary ?? DEFAULT_CONFIG.projectBoundary;
      const gitRoot = boundary === "git-root" ? await findGitRoot(ctx.cwd) : null;
      const projectRoot = gitRoot ?? ctx.cwd;
      return loadConfig({
        globalPath,
        projectPath: path.join(projectRoot, CONFIG_DIR_NAME, "jev-guard.json"),
        projectRoot,
        projectTrusted: trusted,
      });
    })();
    this.configPromise = promise;
    this.configPromiseKey = key;
    try {
      const result = await promise;
      if (generation === this.configGeneration) {
        this.configState = result;
        this.configKey = key;
      }
      return result;
    } finally {
      if (this.configPromise === promise) {
        this.configPromise = undefined;
        this.configPromiseKey = "";
      }
    }
  }

  private metadata(toolName: string): ToolMetadata | undefined {
    const tool = this.pi.getAllTools().find((candidate) => candidate.name === toolName);
    if (!tool) return undefined;
    return {
      name: tool.name,
      description: tool.description,
      source: tool.sourceInfo.source,
    };
  }

  public async assess(
    toolName: string,
    argumentsValue: unknown,
    cwd: string,
    ctx: ExtensionContext,
  ): Promise<Assessment> {
    const loaded = await this.loadForContext(ctx);
    if (!loaded.config) throw new Error(`Invalid Jev Guard configuration: ${loaded.errors.join("; ")}`);
    const config = loaded.config;
    const metadata = this.metadata(toolName);
    const call = await normalizeCall({
      toolName,
      arguments: argumentsValue,
      cwd,
      projectRoot: loaded.projectRoot,
      config,
      ...(metadata ? { metadata } : {}),
    });

    if (config.sessionApprovals.enabled && this.approvals.has(call.callHash)) {
      const cached: Assessment = {
        decision: "allow",
        reason: "Allowed by exact-call session approval",
        call,
        findings: call.deterministicFindings,
        probabilities: {},
        timestamp: new Date().toISOString(),
      };
      this.lastAssessment = cached;
      return cached;
    }

    try {
      const jev = await this.classifier.classify(call, config, ctx.signal);
      const result = composeDecision(call, config, jev);
      this.lastAssessment = result;
      return result;
    } catch (error) {
      const result = composeFailureDecision(
        call,
        config,
        ctx.hasUI,
        safeClassificationError(error),
        ctx.signal?.aborted ?? false,
      );
      this.lastAssessment = result;
      return result;
    }
  }

  private cacheApproval(hash: string, config: GuardConfig): void {
    if (!config.sessionApprovals.enabled || config.sessionApprovals.maxEntries === 0) return;
    this.approvals.add(hash);
    while (this.approvals.size > config.sessionApprovals.maxEntries) {
      const oldest = this.approvals.values().next().value as string | undefined;
      if (oldest === undefined) break;
      this.approvals.delete(oldest);
    }
  }

  public async decide(assessment: Assessment, ctx: ExtensionContext): Promise<Assessment> {
    const loaded = await this.loadForContext(ctx);
    if (assessment.decision !== "prompt") return assessment;
    if (!loaded.config) {
      return { ...assessment, decision: "block", reason: "Configuration became invalid before approval" };
    }
    if (!ctx.hasUI) {
      return { ...assessment, decision: "block", reason: "Approval required but no UI is available" };
    }
    const choice = await this.prompter.prompt(
      assessment,
      ctx,
      loaded.config.sessionApprovals.enabled && loaded.config.sessionApprovals.maxEntries > 0,
    );
    if (choice === "deny") return { ...assessment, decision: "block", reason: "Blocked by user" };
    if (choice === "session") this.cacheApproval(assessment.call.callHash, loaded.config);
    return {
      ...assessment,
      decision: "allow",
      reason: choice === "session" ? "Approved for this exact call for the session" : "Approved once",
    };
  }

  public audit(assessment: Assessment): void {
    this.lastAssessment = assessment;
    this.pi.appendEntry(AUDIT_ENTRY_TYPE, createAuditEntry(assessment));
  }

  public async status(ctx: ExtensionContext): Promise<string> {
    const loaded = await this.loadForContext(ctx);
    if (!loaded.config) {
      return `Jev Guard disabled: invalid configuration\n${loaded.errors.map((error) => `- ${error}`).join("\n")}`;
    }
    let projectPolicy = "ignored (project untrusted)";
    if (loaded.projectConfigLoaded) projectPolicy = "loaded";
    else if (ctx.isProjectTrusted()) projectPolicy = "not present";
    return [
      "Jev Guard enabled",
      `Model: ${loaded.config.model}`,
      `Project root: ${loaded.projectRoot}`,
      `Project policy: ${projectPolicy}`,
      `TypeSafe API: ${this.classifier.available() ? "available" : "unavailable (environment and config-file credentials not found or invalid)"}`,
      `Protected user shell: ${loaded.config.protectUserBash ? "yes" : "no"}`,
      `Session approvals: ${this.approvals.size}`,
    ].join("\n");
  }

  public explain(): string {
    if (!this.lastAssessment) return "No Jev Guard assessment has been made in this session.";
    const assessment = this.lastAssessment;
    return [
      `${assessment.decision.toUpperCase()}: ${assessment.reason}`,
      `Tool: ${assessment.call.toolName}`,
      `Call hash: ${assessment.call.callHash}`,
      `Findings: ${assessment.findings.length === 0 ? "none" : assessment.findings.map((finding) => finding.id).join(", ")}`,
      `Probabilities: ${Object.keys(assessment.probabilities).length === 0 ? "none" : JSON.stringify(assessment.probabilities)}`,
      `Model: ${assessment.model ?? "unavailable"}`,
      `Arguments redacted: ${assessment.call.redacted ? "yes" : "no"}`,
    ].join("\n");
  }

  public async config(ctx: ExtensionContext): Promise<GuardConfig | undefined> {
    return (await this.loadForContext(ctx)).config;
  }
}

export function blockedUserBash(reason: string) {
  return {
    result: {
      output: `jev-guard: ${reason}`,
      exitCode: 126,
      cancelled: false,
      truncated: false,
    },
  };
}

export function registerJevGuard(
  pi: ExtensionAPI,
  classifier: JevClassifier = new TypeSafeJevClassifier(),
): void {
  const guard = new GuardRuntime(pi, classifier);

  pi.on("session_start", async (_event, ctx) => {
    guard.clearSessionState();
    guard.invalidateConfig();
    const status = await guard.status(ctx);
    if (status.startsWith("Jev Guard disabled") && ctx.hasUI) ctx.ui.notify(status, "error");
  });

  pi.on("tool_call", async (event: ToolCallEvent, ctx) => {
    let config: GuardConfig | undefined;
    try {
      config = await guard.config(ctx);
    } catch (error) {
      return { block: true, reason: error instanceof Error ? error.message : String(error) };
    }
    if (!config) return { block: true, reason: "Jev Guard configuration is invalid; execution is disabled" };
    if (config.excludedTools.includes(event.toolName)) return undefined;

    let assessment: Assessment;
    try {
      assessment = await guard.assess(event.toolName, event.input, ctx.cwd, ctx);
    } catch (error) {
      return { block: true, reason: error instanceof Error ? error.message : String(error) };
    }
    const final = await guard.decide(assessment, ctx);
    guard.audit(final);
    if (final.decision === "block") return { block: true, reason: final.reason };
    return undefined;
  });

  pi.on("user_bash", async (event, ctx) => {
    let config: GuardConfig | undefined;
    try {
      config = await guard.config(ctx);
    } catch (error) {
      return blockedUserBash(error instanceof Error ? error.message : String(error));
    }
    if (!config) return blockedUserBash("configuration is invalid; execution is disabled");
    if (!config.protectUserBash) return undefined;

    let assessment: Assessment;
    try {
      assessment = await guard.assess("user_bash", { command: event.command }, event.cwd, ctx);
    } catch (error) {
      return blockedUserBash(error instanceof Error ? error.message : String(error));
    }
    try {
      const final = await guard.decide(assessment, ctx);
      guard.audit(final);
      return final.decision === "block" ? blockedUserBash(final.reason) : undefined;
    } catch (error) {
      return blockedUserBash(error instanceof Error ? error.message : String(error));
    }
  });

  pi.registerCommand("jev-guard", {
    description: "Show status, explain the last decision, reload policy, or test a command",
    handler: async (args, ctx) => {
      const input = args.trim();
      const subcommand = input.split(/\s+/, 1)[0] || "status";
      if (subcommand === "status") {
        ctx.ui.notify(await guard.status(ctx), "info");
        return;
      }
      if (subcommand === "explain") {
        ctx.ui.notify(guard.explain(), "info");
        return;
      }
      if (subcommand === "reload") {
        guard.invalidateConfig();
        const status = await guard.status(ctx);
        ctx.ui.notify(status, status.startsWith("Jev Guard disabled") ? "error" : "info");
        return;
      }
      if (subcommand === "test") {
        const command = input.slice("test".length).trim();
        if (!command) {
          ctx.ui.notify("Usage: /jev-guard test <command>", "warning");
          return;
        }
        try {
          const assessment = await guard.assess("bash", { command }, ctx.cwd, ctx);
          guard.audit(assessment);
          ctx.ui.notify(guard.explain(), assessment.decision === "block" ? "error" : "info");
        } catch (error) {
          ctx.ui.notify(error instanceof Error ? error.message : String(error), "error");
        }
        return;
      }
      ctx.ui.notify("Usage: /jev-guard [status|explain|reload|test <command>]", "warning");
    },
  });
}

export default function jevGuard(pi: ExtensionAPI): void {
  registerJevGuard(pi);
}
