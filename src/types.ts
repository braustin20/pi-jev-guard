export type Decision = "allow" | "prompt" | "block";
export type FindingSource = "deterministic" | "rule" | "jev" | "failure";

export interface Finding {
  id: string;
  category: string;
  message: string;
  decision: Decision;
  source: FindingSource;
  probability?: number;
}

export interface PathFact {
  input: string;
  absolute: string | null;
  canonical: string | null;
  exists: boolean;
  dynamic: boolean;
  withinProject: boolean | null;
  protected: boolean;
  sensitive: boolean;
  matchedPattern?: string;
}

export interface ShellFacts {
  command: string;
  tokens: string[];
  operators: string[];
  commands: string[];
  destinations: string[];
  complex: boolean;
  mutating: boolean;
  networked: boolean;
  unknown: boolean;
}

export interface RecoverabilityFacts {
  gitRepository: boolean;
  overwrittenPaths: Array<{
    path: string;
    exists: boolean;
    tracked: boolean;
    dirty: boolean;
    untracked: boolean;
  }>;
}

export interface NormalizedCall {
  toolName: string;
  toolDescription?: string;
  toolSource?: string;
  cwd: string;
  projectRoot: string;
  arguments: unknown;
  paths: PathFact[];
  shell?: ShellFacts;
  recoverability?: RecoverabilityFacts;
  userRequest?: string;
  userRequestTruncated?: boolean;
  deterministicFindings: Finding[];
  mutating: boolean;
  networked: boolean;
  unknown: boolean;
  redacted: boolean;
  stateTruncated: boolean;
  callHash: string;
}

export interface HazardInstructions {
  question: string;
  focus?: string;
  true?: string;
  false?: string;
}

export interface HazardConfig {
  enabled: boolean;
  decision: Decision;
  promptAt: number;
  instructions?: HazardInstructions;
}

export interface RuleConfig {
  id: string;
  decision: Decision;
  tool?: string;
  command?: string;
  commandRegex?: string;
  pathGlob?: string;
  destination?: string;
}

export interface GuardConfig {
  version: 1;
  model: string;
  protectUserBash: boolean;
  allowProjectRelaxation: boolean;
  projectBoundary: "cwd" | "git-root";
  failureMode: {
    interactive: "prompt" | "block" | "allow";
    headless: "block" | "allow-read-only" | "allow";
  };
  api: {
    timeoutMs: number;
    totalTimeoutMs: number;
    maxRetries: number;
    logLevel: "warn" | "error" | "off";
  };
  privacy: {
    includeFileContents: boolean;
    maxStateBytes: number;
    redactKeys: string[];
  };
  hazards: Record<string, HazardConfig>;
  protectedPaths: string[];
  trustedDestinations: string[];
  excludedTools: string[];
  intentAwareness: {
    enabled: boolean;
    alignmentAt: number;
    maxRequestBytes: number;
  };
  sessionApprovals: {
    enabled: boolean;
    maxEntries: number;
  };
  rules: RuleConfig[];
}

export interface JevAssessment {
  probabilities: Record<string, number>;
  intentAlignment?: number;
  model: string;
  usage: { input_tokens: number; output_tokens: number };
}

export interface Assessment {
  decision: Decision;
  reason: string;
  call: NormalizedCall;
  findings: Finding[];
  probabilities: Record<string, number>;
  intentAlignment?: number;
  model?: string;
  usage?: { input_tokens: number; output_tokens: number };
  classificationError?: string;
  matchedRule?: string;
  timestamp: string;
}

export interface ConfigLoadResult {
  config?: GuardConfig;
  projectRoot: string;
  globalPath: string;
  projectPath?: string;
  projectConfigLoaded: boolean;
  errors: string[];
}

export interface ToolMetadata {
  name: string;
  description?: string;
  source?: string;
}
