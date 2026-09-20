import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import path from "node:path";
import { promisify } from "node:util";
import { READ_ONLY_TOOLS } from "./defaults.js";
import { detectDeterministic } from "./deterministic.js";
import { extractPathInputs, inspectPath, isWithin } from "./paths.js";
import { redactString, redactValue, truncateString } from "./redaction.js";
import { analyzeShell, extractShellPathCandidates } from "./shell.js";
import type {
  GuardConfig,
  NormalizedCall,
  RecoverabilityFacts,
  ToolMetadata,
} from "./types.js";

const execFile = promisify(execFileCallback);
const GIT_ENV = { ...process.env, GIT_OPTIONAL_LOCKS: "0" };

type StableValue = string | number | boolean | null | StableValue[] | { [key: string]: StableValue } | undefined;

function stableValue(value: unknown, seen = new WeakSet<object>()): StableValue {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean" || value === undefined) {
    return value;
  }
  if (typeof value === "bigint") return value.toString();
  if (typeof value !== "object") return String(value);
  if (seen.has(value)) return "[CIRCULAR]";
  seen.add(value);
  if (Array.isArray(value)) return value.map((item) => stableValue(item, seen));
  return Object.fromEntries(
    Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => [key, stableValue(child, seen)]),
  );
}

export function callHash(toolName: string, cwd: string, args: unknown): string {
  return createHash("sha256")
    .update(JSON.stringify(stableValue({ toolName, cwd, args })))
    .digest("hex");
}

export async function findGitRoot(cwd: string): Promise<string | null> {
  try {
    const result = await execFile("git", ["-c", "core.fsmonitor=false", "-C", cwd, "rev-parse", "--show-toplevel"], {
      encoding: "utf8",
      timeout: 2_000,
      env: GIT_ENV,
    });
    return result.stdout.trim() || null;
  } catch {
    return null;
  }
}

async function recoverability(
  toolName: string,
  paths: NormalizedCall["paths"],
  projectRoot: string,
): Promise<RecoverabilityFacts | undefined> {
  if (toolName !== "write" && toolName !== "edit") return undefined;
  const gitRoot = await findGitRoot(projectRoot);
  const result: RecoverabilityFacts = { gitRepository: gitRoot !== null, overwrittenPaths: [] };

  for (const fact of paths) {
    if (!fact.absolute || !fact.canonical || !isWithin(projectRoot, fact.canonical)) continue;
    let tracked = false;
    let dirty = false;
    let untracked = false;
    if (gitRoot) {
      const relative = path.relative(gitRoot, fact.canonical);
      try {
        await execFile("git", ["-c", "core.fsmonitor=false", "-C", gitRoot, "ls-files", "--error-unmatch", "--", relative], {
          encoding: "utf8",
          timeout: 2_000,
          env: GIT_ENV,
        });
        tracked = true;
      } catch {
        tracked = false;
      }
      try {
        const status = await execFile("git", ["-c", "core.fsmonitor=false", "-C", gitRoot, "status", "--porcelain=v1", "--", relative], {
          encoding: "utf8",
          timeout: 2_000,
          env: GIT_ENV,
        });
        const line = status.stdout.trim();
        untracked = line.startsWith("??");
        dirty = line.length > 0 && !untracked;
      } catch {
        dirty = fact.exists;
      }
    }
    result.overwrittenPaths.push({
      path: fact.canonical,
      exists: fact.exists,
      tracked,
      dirty,
      untracked: fact.exists && (!gitRoot || untracked || !tracked),
    });
  }
  return result;
}

function shellCommand(toolName: string, args: unknown): string | undefined {
  if (toolName !== "bash" && toolName !== "powershell" && toolName !== "user_bash") return undefined;
  if (!args || typeof args !== "object") return undefined;
  const command = (args as Record<string, unknown>).command;
  return typeof command === "string" ? command : undefined;
}

function likelyNetworked(toolName: string, args: unknown): boolean {
  if (/\b(?:web|fetch|http|request|download|upload|mcp)\b/i.test(toolName)) return true;
  try {
    return /\b(?:https?|ssh|ftp):\/\//i.test(JSON.stringify(args));
  } catch {
    return false;
  }
}

export async function normalizeCall(options: {
  toolName: string;
  arguments: unknown;
  cwd: string;
  projectRoot: string;
  config: GuardConfig;
  metadata?: ToolMetadata;
  userRequest?: string;
}): Promise<NormalizedCall> {
  const command = shellCommand(options.toolName, options.arguments);
  const shell = command === undefined ? undefined : analyzeShell(command);
  const rawPaths = new Set(extractPathInputs(options.toolName, options.arguments));
  if (shell) for (const candidate of extractShellPathCandidates(shell)) rawPaths.add(candidate);
  const paths = await Promise.all(
    [...rawPaths].map((candidate) => inspectPath(candidate, options.cwd, options.projectRoot, options.config.protectedPaths)),
  );
  const recoverabilityFacts = await recoverability(options.toolName, paths, options.projectRoot);
  const omitFileContents =
    !options.config.privacy.includeFileContents && ["read", "write", "edit"].includes(options.toolName);
  const redacted = redactValue(options.arguments, {
    redactKeys: options.config.privacy.redactKeys,
    omitFileContents,
  });
  const inputUserRequest = options.config.intentAwareness.enabled ? options.userRequest : undefined;
  const sanitizedUserRequest = inputUserRequest === undefined
    ? undefined
    : redactString(inputUserRequest, options.config.privacy.redactKeys);
  const boundedUserRequest = sanitizedUserRequest === undefined
    ? undefined
    : truncateString(sanitizedUserRequest, options.config.intentAwareness.maxRequestBytes);
  const mutating = shell?.mutating ?? !READ_ONLY_TOOLS.has(options.toolName);
  const networked = shell?.networked ?? likelyNetworked(options.toolName, options.arguments);
  const unknown = shell?.unknown ?? (!READ_ONLY_TOOLS.has(options.toolName) && !["write", "edit"].includes(options.toolName));

  const base: Omit<NormalizedCall, "deterministicFindings"> = {
    toolName: options.toolName,
    ...(options.metadata?.description ? { toolDescription: options.metadata.description } : {}),
    ...(options.metadata?.source ? { toolSource: options.metadata.source } : {}),
    cwd: options.cwd,
    projectRoot: options.projectRoot,
    arguments: redacted.value,
    paths,
    ...(shell ? { shell } : {}),
    ...(recoverabilityFacts ? { recoverability: recoverabilityFacts } : {}),
    ...(boundedUserRequest?.value ? { userRequest: boundedUserRequest.value } : {}),
    ...(boundedUserRequest?.truncated ? { userRequestTruncated: true } : {}),
    mutating,
    networked,
    unknown,
    redacted: redacted.redacted || sanitizedUserRequest !== inputUserRequest,
    stateTruncated: false,
    callHash: callHash(options.toolName, options.cwd, options.arguments),
  };
  return { ...base, deterministicFindings: detectDeterministic(base, options.config) };
}
