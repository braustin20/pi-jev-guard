import type { GuardConfig, HazardConfig } from "./types.js";

const hazard = (promptAt: number): HazardConfig => ({
  enabled: true,
  decision: "prompt",
  promptAt,
});

export const DEFAULT_HAZARDS: Record<string, HazardConfig> = {
  destructive_filesystem: hazard(0.4),
  outside_project_or_system_change: hazard(0.4),
  sensitive_data_exfiltration: hazard(0.35),
  download_and_execute: hazard(0.35),
  permissions_or_iam_change: hazard(0.4),
  destructive_version_control: hazard(0.4),
  irreversible_edit: hazard(0.45),
  complex_shell_composition: hazard(0.55),
  sensitive_information_access: hazard(0.4),
};

export const DEFAULT_CONFIG: GuardConfig = {
  version: 1,
  model: "jev-1.13.0",
  protectUserBash: true,
  allowProjectRelaxation: false,
  projectBoundary: "git-root",
  failureMode: {
    interactive: "prompt",
    headless: "block",
  },
  api: {
    timeoutMs: 4_000,
    totalTimeoutMs: 6_000,
    maxRetries: 0,
    logLevel: "off",
  },
  privacy: {
    includeFileContents: false,
    maxStateBytes: 12_000,
    redactKeys: [
      "apiKey",
      "authorization",
      "cookie",
      "credential",
      "password",
      "privateKey",
      "secret",
      "token",
    ],
  },
  hazards: DEFAULT_HAZARDS,
  protectedPaths: [
    "/etc/**",
    "/usr/**",
    "/bin/**",
    "/sbin/**",
    "/boot/**",
    "~/.ssh/**",
    "~/.aws/**",
    "~/.azure/**",
    "~/.config/gcloud/**",
    "~/.kube/**",
    "~/.gnupg/**",
    "~/.docker/config.json",
    "~/.git-credentials",
    "~/.npmrc",
    "~/.pypirc",
    "~/.bashrc",
    "~/.bash_profile",
    "~/.profile",
    "~/.zshrc",
    "~/.config/fish/config.fish",
    "~/.pi/**",
  ],
  trustedDestinations: [],
  excludedTools: [],
  sessionApprovals: {
    enabled: true,
    maxEntries: 256,
  },
  rules: [],
};

export const CONTENT_KEYS = new Set([
  "content",
  "data",
  "newText",
  "oldText",
  "patch",
  "replacement",
  "text",
]);

export const READ_ONLY_TOOLS = new Set([
  "read",
  "grep",
  "find",
  "ls",
  "glob",
  "search",
  "web_search",
  "fetch_content",
  "get_search_content",
  "source_check",
  "symbol_search",
  "project_report",
  "module_report",
  "read_symbol",
  "read_enclosing",
  "lens_diagnostics",
]);
