import { constants } from "node:fs";
import { access, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import type { PathFact } from "./types.js";

const PATH_KEYS = /^(?:path|paths|file|files|filePath|filename|directory|dir|cwd|root|target|destination)$/i;
const DYNAMIC_PATH = /(?:\$\{|\$[A-Za-z_]|%[A-Za-z_][A-Za-z0-9_]*%|[`*?[])/;
const SENSITIVE_PATH = /(?:^|\/)(?:\.env(?:\.|$)|\.git-credentials$|\.npmrc$|\.pypirc$|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$|credentials?$|secrets?\.(?:json|ya?ml|toml)$|shadow$|passwd$|private[_-]?key)/i;

export function expandHome(value: string): string {
  if (value === "~") return homedir();
  if (value.startsWith("~/")) return path.join(homedir(), value.slice(2));
  return value;
}

export function normalizeSlashes(value: string): string {
  return value.replaceAll(path.sep, "/");
}

export function isWithin(parent: string, child: string): boolean {
  const relative = path.relative(parent, child);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

export function globToRegExp(glob: string): RegExp {
  const normalized = normalizeSlashes(expandHome(glob));
  let source = "^";
  for (let index = 0; index < normalized.length; index++) {
    const character = normalized.charAt(index);
    const next = normalized[index + 1];
    if (character === "*" && next === "*") {
      source += ".*";
      index++;
    } else if (character === "*") {
      source += "[^/]*";
    } else if (character === "?") {
      source += "[^/]";
    } else {
      source += character.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
    }
  }
  // nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp -- all regex metacharacters are escaped and glob wildcards expand to bounded fragments.
  return new RegExp(`${source}$`);
}

export function matchesGlob(value: string, glob: string): boolean {
  return globToRegExp(glob).test(normalizeSlashes(value));
}

async function exists(value: string): Promise<boolean> {
  try {
    await access(value, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

async function canonicalize(value: string): Promise<{ canonical: string; exists: boolean }> {
  if (await exists(value)) {
    return { canonical: await realpath(value), exists: true };
  }

  const missing: string[] = [];
  let current = value;
  while (!(await exists(current))) {
    const parent = path.dirname(current);
    if (parent === current) return { canonical: value, exists: false };
    missing.unshift(path.basename(current));
    current = parent;
  }
  return { canonical: path.join(await realpath(current), ...missing), exists: false };
}

export async function inspectPath(
  input: string,
  cwd: string,
  projectRoot: string,
  protectedPaths: string[],
): Promise<PathFact> {
  const expanded = expandHome(input.replace(/^@/, ""));
  const dynamic = DYNAMIC_PATH.test(expanded);
  if (dynamic || expanded.includes("\0")) {
    return {
      input,
      absolute: null,
      canonical: null,
      exists: false,
      dynamic: true,
      withinProject: null,
      protected: false,
      sensitive: SENSITIVE_PATH.test(normalizeSlashes(expanded)),
    };
  }

  const absolute = path.resolve(cwd, expanded);
  try {
    const result = await canonicalize(absolute);
    const matchedPattern = protectedPaths.find((pattern) => matchesGlob(result.canonical, pattern));
    return {
      input,
      absolute,
      canonical: result.canonical,
      exists: result.exists,
      dynamic: false,
      withinProject: isWithin(projectRoot, result.canonical),
      protected: matchedPattern !== undefined,
      sensitive: SENSITIVE_PATH.test(normalizeSlashes(result.canonical)),
      ...(matchedPattern === undefined ? {} : { matchedPattern }),
    };
  } catch {
    return {
      input,
      absolute,
      canonical: null,
      exists: false,
      dynamic: true,
      withinProject: null,
      protected: false,
      sensitive: SENSITIVE_PATH.test(normalizeSlashes(absolute)),
    };
  }
}

export function extractPathInputs(toolName: string, args: unknown): string[] {
  if (!args || typeof args !== "object") return [];
  const output = new Set<string>();

  const visit = (value: unknown, key = "", depth = 0): void => {
    if (depth > 5) return;
    if (typeof value === "string" && (PATH_KEYS.test(key) || (toolName === "write" || toolName === "edit") && key === "path")) {
      output.add(value);
      return;
    }
    if (Array.isArray(value)) {
      if (PATH_KEYS.test(key)) {
        for (const item of value) if (typeof item === "string") output.add(item);
      } else {
        for (const item of value) visit(item, key, depth + 1);
      }
      return;
    }
    if (value && typeof value === "object") {
      for (const [childKey, child] of Object.entries(value)) visit(child, childKey, depth + 1);
    }
  };

  visit(args);
  return [...output];
}
