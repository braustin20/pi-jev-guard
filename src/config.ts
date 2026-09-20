import { readFile } from "node:fs/promises";
import path from "node:path";
import { Ajv2020, type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";
import safeRegex from "safe-regex2";
import { DEFAULT_CONFIG } from "./defaults.js";
import type { ConfigLoadResult, Decision, GuardConfig, HazardConfig, RuleConfig } from "./types.js";

let validatorPromise: Promise<ValidateFunction> | undefined;

function cloneDefault(): GuardConfig {
  return structuredClone(DEFAULT_CONFIG);
}

async function getValidator(): Promise<ValidateFunction> {
  validatorPromise ??= readFile(new URL("../config.schema.json", import.meta.url), "utf8").then((source) => {
    try {
      const schema = JSON.parse(source) as object;
      const ajv = new Ajv2020({ allErrors: true, strict: true });
      return ajv.compile(schema);
    } catch (error) {
      throw new Error(`Bundled configuration schema is invalid: ${error instanceof Error ? error.message : String(error)}`);
    }
  });
  return validatorPromise;
}

function formatErrors(errors: ErrorObject[] | null | undefined, source: string): string[] {
  return (errors ?? []).map((error) => `${source}${error.instancePath || "/"}: ${error.message ?? "invalid value"}`);
}

async function readConfigFile(filePath: string): Promise<{ value?: Partial<GuardConfig>; errors: string[] }> {
  try {
    const source = await readFile(filePath, "utf8");
    const value: unknown = JSON.parse(source);
    const validator = await getValidator();
    if (!validator(value)) return { errors: formatErrors(validator.errors, filePath) };
    const config = value as Partial<GuardConfig>;
    const errors: string[] = [];
    for (const rule of config.rules ?? []) {
      if (rule.commandRegex) {
        try {
          // nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp -- policy regex is length-bounded and checked by safe-regex2 before use.
          new RegExp(rule.commandRegex);
          if (!safeRegex(rule.commandRegex)) {
            errors.push(`${filePath}: rule ${rule.id} has an unsafe commandRegex`);
          }
        } catch (error) {
          errors.push(`${filePath}: rule ${rule.id} has invalid commandRegex: ${String(error)}`);
        }
      }
    }
    return errors.length > 0 ? { errors } : { value: config, errors: [] };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { errors: [] };
    return { errors: [`${filePath}: ${error instanceof Error ? error.message : String(error)}`] };
  }
}

function mergeHazard(base: HazardConfig | undefined, patch: Partial<HazardConfig>): HazardConfig {
  let instructions: HazardConfig["instructions"];
  if (patch.instructions !== undefined) instructions = { ...base?.instructions, ...patch.instructions };
  else if (base?.instructions !== undefined) instructions = base.instructions;
  return {
    enabled: patch.enabled ?? base?.enabled ?? true,
    decision: patch.decision ?? base?.decision ?? "prompt",
    promptAt: patch.promptAt ?? base?.promptAt ?? 0.5,
    ...(instructions === undefined ? {} : { instructions }),
  };
}

function mergeConfig(base: GuardConfig, patch: Partial<GuardConfig>): GuardConfig {
  const hazards = { ...base.hazards };
  for (const [name, value] of Object.entries(patch.hazards ?? {})) hazards[name] = mergeHazard(hazards[name], value);
  return {
    ...base,
    ...patch,
    failureMode: { ...base.failureMode, ...patch.failureMode },
    api: { ...base.api, ...patch.api },
    privacy: {
      ...base.privacy,
      ...patch.privacy,
      redactKeys: [...new Set([...base.privacy.redactKeys, ...(patch.privacy?.redactKeys ?? [])])],
    },
    sessionApprovals: { ...base.sessionApprovals, ...patch.sessionApprovals },
    hazards,
    protectedPaths: [...new Set([...base.protectedPaths, ...(patch.protectedPaths ?? [])])],
    trustedDestinations: patch.trustedDestinations ?? base.trustedDestinations,
    excludedTools: patch.excludedTools ?? base.excludedTools,
    rules: patch.rules ?? base.rules,
  };
}

const DECISION_RANK: Record<Decision, number> = { allow: 0, prompt: 1, block: 2 };
const INTERACTIVE_RANK = { allow: 0, prompt: 1, block: 2 } as const;
const HEADLESS_RANK = { allow: 0, "allow-read-only": 1, block: 2 } as const;

function strongerDecision(left: Decision, right: Decision): Decision {
  return DECISION_RANK[right] > DECISION_RANK[left] ? right : left;
}

function mergeTightenOnly(global: GuardConfig, project: Partial<GuardConfig>): GuardConfig {
  if (global.allowProjectRelaxation) return mergeConfig(global, project);

  const result = structuredClone(global);
  result.protectUserBash ||= project.protectUserBash ?? false;
  const projectInteractive = project.failureMode?.interactive;
  if (projectInteractive && INTERACTIVE_RANK[projectInteractive] > INTERACTIVE_RANK[result.failureMode.interactive]) {
    result.failureMode.interactive = projectInteractive;
  }
  const projectHeadless = project.failureMode?.headless;
  if (projectHeadless && HEADLESS_RANK[projectHeadless] > HEADLESS_RANK[result.failureMode.headless]) {
    result.failureMode.headless = projectHeadless;
  }
  result.privacy.includeFileContents &&= project.privacy?.includeFileContents ?? true;
  result.privacy.maxStateBytes = Math.min(result.privacy.maxStateBytes, project.privacy?.maxStateBytes ?? Infinity);
  result.privacy.redactKeys = [...new Set([...result.privacy.redactKeys, ...(project.privacy?.redactKeys ?? [])])];
  result.sessionApprovals.enabled &&= project.sessionApprovals?.enabled ?? true;
  result.sessionApprovals.maxEntries = Math.min(
    result.sessionApprovals.maxEntries,
    project.sessionApprovals?.maxEntries ?? Infinity,
  );
  result.protectedPaths = [...new Set([...result.protectedPaths, ...(project.protectedPaths ?? [])])];
  result.rules = [
    ...result.rules,
    ...(project.rules ?? []).filter((rule: RuleConfig) => rule.decision !== "allow"),
  ];

  for (const [name, patch] of Object.entries(project.hazards ?? {})) {
    const current = result.hazards[name];
    if (!current) {
      if (patch.enabled !== false && patch.decision !== "allow") result.hazards[name] = mergeHazard(undefined, patch);
      continue;
    }
    current.enabled ||= patch.enabled ?? false;
    current.decision = strongerDecision(current.decision, patch.decision ?? current.decision);
    current.promptAt = Math.min(current.promptAt, patch.promptAt ?? current.promptAt);
  }
  return result;
}

export async function loadConfig(options: {
  globalPath: string;
  projectPath: string;
  projectRoot: string;
  projectTrusted: boolean;
}): Promise<ConfigLoadResult> {
  const globalResult = await readConfigFile(options.globalPath);
  const errors = [...globalResult.errors];
  let config = globalResult.value ? mergeConfig(cloneDefault(), globalResult.value) : cloneDefault();
  let projectConfigLoaded = false;

  if (options.projectTrusted) {
    const projectResult = await readConfigFile(options.projectPath);
    errors.push(...projectResult.errors);
    if (projectResult.value) {
      config = mergeTightenOnly(config, projectResult.value);
      projectConfigLoaded = true;
    }
  }

  if (config.api.totalTimeoutMs < config.api.timeoutMs) {
    errors.push("api.totalTimeoutMs must be greater than or equal to api.timeoutMs");
  }
  return {
    ...(errors.length === 0 ? { config } : {}),
    projectRoot: path.resolve(options.projectRoot),
    globalPath: options.globalPath,
    projectPath: options.projectPath,
    projectConfigLoaded,
    errors,
  };
}

export function mergeConfigForTest(base: GuardConfig, patch: Partial<GuardConfig>, tightenOnly: boolean): GuardConfig {
  return tightenOnly ? mergeTightenOnly(base, patch) : mergeConfig(base, patch);
}
