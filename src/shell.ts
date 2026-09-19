import type { ShellFacts } from "./types.js";

const MUTATING_COMMANDS = new Set([
  "aws",
  "az",
  "chmod",
  "chown",
  "cp",
  "dd",
  "docker",
  "gcloud",
  "git",
  "helm",
  "install",
  "kubectl",
  "ln",
  "mkdir",
  "mv",
  "npm",
  "pnpm",
  "rm",
  "rmdir",
  "rsync",
  "scp",
  "sed",
  "systemctl",
  "terraform",
  "truncate",
  "unlink",
  "yarn",
]);

const READ_ONLY_COMMANDS = new Set([
  "awk",
  "cargo",
  "cat",
  "cmake",
  "cut",
  "diff",
  "du",
  "echo",
  "env",
  "fd",
  "find",
  "git",
  "go",
  "grep",
  "head",
  "jest",
  "jq",
  "ls",
  "make",
  "ninja",
  "node",
  "npm",
  "npx",
  "pnpm",
  "printf",
  "pytest",
  "pwd",
  "rg",
  "sort",
  "tail",
  "test",
  "tsc",
  "uniq",
  "vitest",
  "wc",
  "which",
]);

const NETWORK_COMMANDS = new Set([
  "curl",
  "ftp",
  "gh",
  "nc",
  "netcat",
  "rsync",
  "scp",
  "ssh",
  "wget",
]);

const COMPOUND_OPERATORS = new Set(["|", "||", "&&", ";", "\n", "$(", "`", "<(", ">("]);
const SENSITIVE_PATH_OPERAND = /(?:^|\/)(?:\.env(?:\.|$)|\.git-credentials$|\.npmrc$|\.pypirc$|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$|credentials?$|secrets?\.(?:json|ya?ml|toml)$|shadow$|passwd$|private[_-]?key)/i;

function scan(command: string): { tokens: string[]; operators: string[]; unclosedQuote: boolean } {
  const tokens: string[] = [];
  const operators: string[] = [];
  let token = "";
  let quote: "'" | '"' | null = null;
  let escaped = false;
  const flush = (): void => {
    if (token.length > 0) tokens.push(token);
    token = "";
  };

  for (let index = 0; index < command.length; index++) {
    const character = command.charAt(index);
    const next = command[index + 1] ?? "";
    if (escaped) {
      token += character;
      escaped = false;
      continue;
    }
    if (character === "\\" && quote !== "'") {
      escaped = true;
      token += character;
      continue;
    }
    if (quote) {
      token += character;
      if (character === quote) quote = null;
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      token += character;
      continue;
    }
    if (/\s/.test(character)) {
      flush();
      if (character === "\n") operators.push("\n");
      continue;
    }

    const pair = character + next;
    if (["&&", "||", ">>", "<<", "$(", "<(", ">("].includes(pair)) {
      flush();
      operators.push(pair);
      index++;
      continue;
    }
    if (["|", ";", ">", "<", "`"].includes(character)) {
      flush();
      operators.push(character);
      continue;
    }
    token += character;
  }
  flush();
  return { tokens, operators, unclosedQuote: quote !== null || escaped };
}

function baseCommand(value: string): string {
  const withoutQuotes = value.replace(/^['"]|['"]$/g, "");
  const pieces = withoutQuotes.split("/");
  return pieces.at(-1)?.toLowerCase() ?? withoutQuotes.toLowerCase();
}

function commandHeads(command: string): string[] {
  return command
    .split(/(?:&&|\|\||[;|\n])/)
    .map((part) => part.trim().split(/\s+/)[0] ?? "")
    .map(baseCommand)
    .filter(Boolean);
}

function destinations(command: string): string[] {
  const found = new Set<string>();
  for (const match of command.matchAll(/\b(?:https?|ssh|ftp):\/\/[^\s'"`<>|]+/gi)) {
    try {
      const url = new URL(match[0]);
      if (url.hostname) found.add(url.hostname.toLowerCase());
    } catch {
      // The unknown URL remains visible in command text and is handled as complex input.
    }
  }
  for (const match of command.matchAll(/\b(?:scp|ssh|rsync)\b[^\n]*?\b(?:[\w.-]+@)?([\w.-]+):/gi)) {
    if (match[1]) found.add(match[1].toLowerCase());
  }
  return [...found];
}

export function analyzeShell(command: string): ShellFacts {
  const scanned = scan(command);
  const commands = commandHeads(command);
  const lower = command.toLowerCase();
  const compound = scanned.operators.some((operator) => COMPOUND_OPERATORS.has(operator));
  const nestedShell = /\b(?:eval|xargs)\b|\b(?:ba|z|fi)?sh\s+-c\b/.test(lower);
  const mutatingGit = /\bgit\s+(?:add|am|apply|branch\s+-[dD]|checkout|cherry-pick|clean|commit|config|merge|mv|pull|push|rebase|remote|reset|restore|revert|rm|stash\s+(?:clear|drop|pop)|switch|tag\s+-d)\b/i.test(command);
  const mutatingPackage = /\b(?:npm|pnpm|yarn)\s+(?:install|add|remove|uninstall|publish|update|audit\s+fix)\b/i.test(command);
  const opaqueCode = /\b(?:node|python3?|ruby|perl)\b[^\n;&|]*\s(?:-e|-c)\b/i.test(command);
  const packageScript = command.match(/\b(?:npm|pnpm|yarn)\s+(?:run\s+)?([\w:-]+)/i)?.[1]?.toLowerCase();
  const understoodPackageScript = packageScript === undefined || /^(?:test|build|check|lint|typecheck|format(?::check)?)$/.test(packageScript);
  const mutating =
    scanned.operators.some((operator) => operator === ">" || operator === ">>" || operator === "<<") ||
    commands.some((name) => MUTATING_COMMANDS.has(name) && name !== "git" && name !== "npm" && name !== "pnpm" && name !== "yarn") ||
    mutatingGit ||
    mutatingPackage;
  const networked = commands.some((name) => NETWORK_COMMANDS.has(name)) || /\b(?:https?|ssh|ftp):\/\//i.test(command);
  const unknown =
    scanned.unclosedQuote ||
    opaqueCode ||
    !understoodPackageScript ||
    commands.length === 0 ||
    commands.some((name) => !READ_ONLY_COMMANDS.has(name) && !MUTATING_COMMANDS.has(name) && !NETWORK_COMMANDS.has(name));

  return {
    command,
    tokens: scanned.tokens,
    operators: scanned.operators,
    commands,
    destinations: destinations(command),
    complex: compound || nestedShell || scanned.unclosedQuote,
    mutating,
    networked,
    unknown,
  };
}

export function extractShellPathCandidates(facts: ShellFacts): string[] {
  const candidates = new Set<string>();
  for (const token of facts.tokens) {
    const clean = token.replace(/^['"]|['"]$/g, "");
    if (
      clean.startsWith("/") ||
      clean.startsWith("~/") ||
      clean.startsWith("./") ||
      clean.startsWith("../") ||
      SENSITIVE_PATH_OPERAND.test(clean)
    ) {
      candidates.add(clean.replace(/[,:]$/, ""));
    }
  }
  return [...candidates];
}
