import path from "node:path";
import {
  CONFIG_DIR_NAME,
  getAgentDir,
  type ExtensionAPI,
  type ExtensionContext,
  type ToolCallEvent,
} from "@earendil-works/pi-coding-agent";
import { ApprovalPrompter } from "./approval.js";
import { AUDIT_ENTRY_TYPE, createAuditEntry, createSessionBypassAuditEntry } from "./audit.js";
import { ensureGlobalConfig, loadConfig } from "./config.js";
import { defaultCredentialPath } from "./credentials.js";
import { DEFAULT_CONFIG } from "./defaults.js";
import { TypeSafeJevClassifier, safeClassificationError, type JevClassifier } from "./jev.js";
import { findGitRoot, normalizeCall } from "./normalize.js";
import { composeDecision, composeFailureDecision } from "./policy.js";
import type { Assessment, ConfigLoadResult, GuardConfig, ToolMetadata } from "./types.js";

const INTERACTION_ONLY_TOOLS = new Set(["ask_user"]);

export class GuardRuntime {
  private configState: ConfigLoadResult | undefined;
  private configKey = "";
  private configPromise: Promise<ConfigLoadResult> | undefined;
  private configPromiseKey = "";
  private configGeneration = 0;
  private readonly approvals = new Set<string>();
  private readonly prompter = new ApprovalPrompter();
  private sessionBypassed = false;
  private lastAssessment: Assessment | undefined;

  public constructor(
    private readonly pi: ExtensionAPI,
    private readonly classifier: JevClassifier = new TypeSafeJevClassifier(),
  ) {}

  public clearSessionState(): void {
    this.approvals.clear();
    this.sessionBypassed = false;
    this.lastAssessment = undefined;
  }

  public isSessionBypassed(): boolean {
    return this.sessionBypassed;
  }

  public enableSessionGuard(): void {
    this.sessionBypassed = false;
  }

  private sessionControlsEnabled(config: GuardConfig): boolean {
    return config.sessionApprovals.enabled && config.sessionApprovals.maxEntries > 0;
  }

  private reconcileSessionBypass(config: GuardConfig | undefined): void {
    if (this.sessionBypassed && (!config || !this.sessionControlsEnabled(config))) {
      this.sessionBypassed = false;
    }
  }

  public invalidateConfig(): void {
    this.configState = undefined;
    this.configKey = "";
    this.configPromise = undefined;
    this.configPromiseKey = "";
    this.configGeneration++;
    this.approvals.clear();
    this.sessionBypassed = false;
  }

  private async loadForContext(ctx: ExtensionContext): Promise<ConfigLoadResult> {
    const trusted = ctx.isProjectTrusted();
    const key = `${ctx.cwd}\0${trusted}`;
    if (this.configKey && this.configKey !== key) this.approvals.clear();
    if (this.configState && this.configKey === key) return this.configState;
    if (this.configPromise && this.configPromiseKey === key) return this.configPromise;
    const generation = ++this.configGeneration;
    const promise = (async () => {
      const globalPath = defaultCredentialPath(getAgentDir());
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
        globalBase: {
          errors: preliminary.errors,
          ...(preliminary.config ? { config: preliminary.config } : {}),
        },
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

    if (this.sessionControlsEnabled(config) && this.approvals.has(call.callHash)) {
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
    if (this.sessionBypassed) {
      return { ...assessment, decision: "allow", reason: "Guard bypassed for current session by user" };
    }
    const loaded = await this.loadForContext(ctx);
    if (assessment.decision !== "prompt") return assessment;
    if (!loaded.config) {
      return { ...assessment, decision: "block", reason: "Configuration became invalid before approval" };
    }
    if (!ctx.hasUI) {
      return { ...assessment, decision: "block", reason: "Approval required but no UI is available" };
    }
    const sessionControlsEnabled = this.sessionControlsEnabled(loaded.config);
    const approvalGeneration = this.configGeneration;
    const choice = await this.prompter.prompt(
      assessment,
      ctx,
      sessionControlsEnabled,
      () => this.sessionBypassed,
      () => {
        if (approvalGeneration === this.configGeneration) this.sessionBypassed = true;
      },
    );
    if (approvalGeneration !== this.configGeneration) {
      return { ...assessment, decision: "block", reason: "Policy changed during approval" };
    }
    if (choice === "deny") return { ...assessment, decision: "block", reason: "Blocked by user" };
    if (choice === "session") this.cacheApproval(assessment.call.callHash, loaded.config);
    let reason = "Approved once";
    if (choice === "session") reason = "Approved for this exact call for the session";
    if (choice === "all-session" || choice === "bypassed") {
      reason = "Guard bypassed for current session by user";
    }
    return { ...assessment, decision: "allow", reason };
  }

  public audit(assessment: Assessment): void {
    this.lastAssessment = assessment;
    this.pi.appendEntry(AUDIT_ENTRY_TYPE, createAuditEntry(assessment));
  }

  public auditSessionBypass(toolName: string): void {
    this.pi.appendEntry(AUDIT_ENTRY_TYPE, createSessionBypassAuditEntry(toolName));
  }

  public async status(ctx: ExtensionContext): Promise<string> {
    const loaded = await this.loadForContext(ctx);
    this.reconcileSessionBypass(loaded.config);
    if (this.sessionBypassed) {
      const policy = loaded.config
        ? "Policy configuration: valid"
        : `Policy configuration: invalid\n${loaded.errors.map((error) => `- ${error}`).join("\n")}`;
      return [
        "Jev Guard bypassed for current session",
        "All tool and protected shell calls are allowed without assessment.",
        "Run /jev-guard enable to turn the guard back on.",
        policy,
        `Session approvals: ${this.approvals.size}`,
      ].join("\n");
    }
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

  public async explain(ctx: ExtensionContext): Promise<string> {
    const loaded = await this.loadForContext(ctx);
    this.reconcileSessionBypass(loaded.config);
    if (this.sessionBypassed) {
      return "Jev Guard is bypassed for the current session. Run /jev-guard enable to turn it back on.";
    }
    return this.explainLastAssessment();
  }

  public explainLastAssessment(): string {
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
    const config = (await this.loadForContext(ctx)).config;
    this.reconcileSessionBypass(config);
    return config;
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
    const globalConfigPath = defaultCredentialPath(getAgentDir());
    try {
      const created = await ensureGlobalConfig(globalConfigPath);
      if (created && ctx.hasUI) {
        ctx.ui.notify(`Created Jev Guard configuration at ${globalConfigPath}`, "info");
      }
    } catch (error) {
      if (ctx.hasUI) {
        const message = error instanceof Error ? error.message : String(error);
        ctx.ui.notify(`Could not create Jev Guard configuration: ${message}`, "warning");
      }
    }
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
    if (INTERACTION_ONLY_TOOLS.has(event.toolName) || config.excludedTools.includes(event.toolName)) return undefined;
    if (guard.isSessionBypassed()) {
      try {
        guard.auditSessionBypass(event.toolName);
        return undefined;
      } catch (error) {
        return { block: true, reason: error instanceof Error ? error.message : String(error) };
      }
    }

    let assessment: Assessment;
    try {
      assessment = await guard.assess(event.toolName, event.input, ctx.cwd, ctx);
    } catch (error) {
      return { block: true, reason: error instanceof Error ? error.message : String(error) };
    }
    try {
      const final = await guard.decide(assessment, ctx);
      guard.audit(final);
      if (final.decision === "block") return { block: true, reason: final.reason };
      return undefined;
    } catch (error) {
      return { block: true, reason: error instanceof Error ? error.message : String(error) };
    }
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
    if (guard.isSessionBypassed()) {
      try {
        guard.auditSessionBypass("user_bash");
        return undefined;
      } catch (error) {
        return blockedUserBash(error instanceof Error ? error.message : String(error));
      }
    }

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
    description: "Show status, enable the guard, explain the last decision, reload policy, or test a command",
    handler: async (args, ctx) => {
      const input = args.trim();
      const subcommand = input.split(/\s+/, 1)[0] || "status";
      if (subcommand === "status") {
        ctx.ui.notify(await guard.status(ctx), "info");
        return;
      }
      if (subcommand === "enable") {
        guard.enableSessionGuard();
        const status = await guard.status(ctx);
        ctx.ui.notify(status, status.startsWith("Jev Guard disabled") ? "error" : "info");
        return;
      }
      if (subcommand === "explain") {
        ctx.ui.notify(await guard.explain(ctx), "info");
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
          ctx.ui.notify(guard.explainLastAssessment(), assessment.decision === "block" ? "error" : "info");
        } catch (error) {
          ctx.ui.notify(error instanceof Error ? error.message : String(error), "error");
        }
        return;
      }
      ctx.ui.notify("Usage: /jev-guard [status|enable|explain|reload|test <command>]", "warning");
    },
  });
}

export default function jevGuard(pi: ExtensionAPI): void {
  registerJevGuard(pi);
}
