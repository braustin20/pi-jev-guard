import { CONTENT_KEYS } from "./defaults.js";

const ENV_ASSIGNMENT = /\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s;&|]+)/g;
const LONG_FLAG_ARGUMENT = /(--[A-Za-z][A-Za-z0-9_-]*)(=|\s+)("[^"]*"|'[^']*'|[^\s;&|]+)/g;
const HEADER_ARGUMENT = /(-H|--header)\s+(?:(['"])([^'"]+)\2|([^\s;&|]+))/gi;
const BASIC_AUTH_ARGUMENT = /(-u|--user)\s+("[^"]*"|'[^']*'|[^\s;&|]+)/gi;
const BEARER = /\b(Bearer\s+)[A-Za-z0-9._~+\/-]+=*/gi;
const URL_PATTERN = /\bhttps?:\/\/[^\s'"`<>]+/gi;

function keyIsSensitive(key: string, redactKeys: string[]): boolean {
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
  return redactKeys.some((candidate) => normalized.includes(candidate.toLowerCase().replace(/[^a-z0-9]/g, "")));
}

function sanitizeUrl(raw: string, redactKeys: string[]): string {
  try {
    const url = new URL(raw);
    if (url.username) url.username = "[REDACTED]";
    if (url.password) url.password = "[REDACTED]";
    for (const key of [...url.searchParams.keys()]) {
      if (keyIsSensitive(key, redactKeys)) url.searchParams.set(key, "[REDACTED]");
    }
    return url.toString();
  } catch {
    return raw;
  }
}

export function redactString(value: string, redactKeys: string[]): string {
  return value
    .replace(URL_PATTERN, (match) => sanitizeUrl(match, redactKeys))
    .replace(ENV_ASSIGNMENT, (match, name: string) => {
      if (keyIsSensitive(name, redactKeys)) return `${name}=[REDACTED]`;
      return match;
    })
    .replace(LONG_FLAG_ARGUMENT, (match, flag: string, separator: string, argument: string) => {
      if (!keyIsSensitive(flag.slice(2), redactKeys)) return match;
      const quote = argument.startsWith("\"") || argument.startsWith("'") ? argument.charAt(0) : "";
      return `${flag}${separator}${quote}[REDACTED]${quote}`;
    })
    .replace(HEADER_ARGUMENT, (match, option: string, quote: string | undefined, quoted: string | undefined, plain: string | undefined) => {
      const header = quoted ?? plain ?? "";
      const separator = header.indexOf(":");
      if (separator < 0 || !keyIsSensitive(header.slice(0, separator), redactKeys)) return match;
      const marker = quote ?? "";
      return `${option} ${marker}${header.slice(0, separator)}: [REDACTED]${marker}`;
    })
    .replace(BASIC_AUTH_ARGUMENT, "$1 [REDACTED]")
    .replace(BEARER, "$1[REDACTED]");
}

export function redactValue(
  value: unknown,
  options: { redactKeys: string[]; omitFileContents: boolean },
  key = "",
  seen = new WeakSet<object>(),
): { value: unknown; redacted: boolean } {
  if (options.omitFileContents && CONTENT_KEYS.has(key)) {
    return { value: "[OMITTED]", redacted: true };
  }
  if (key && keyIsSensitive(key, options.redactKeys)) {
    return { value: "[REDACTED]", redacted: true };
  }
  if (typeof value === "string") {
    const sanitized = redactString(value, options.redactKeys);
    return { value: sanitized, redacted: sanitized !== value };
  }
  if (value === null || typeof value !== "object") return { value, redacted: false };
  if (seen.has(value)) return { value: "[CIRCULAR]", redacted: true };
  seen.add(value);

  let redacted = false;
  if (Array.isArray(value)) {
    const output = value.map((item) => {
      const result = redactValue(item, options, key, seen);
      redacted ||= result.redacted;
      return result.value;
    });
    return { value: output, redacted };
  }

  const output: Record<string, unknown> = {};
  for (const [childKey, childValue] of Object.entries(value)) {
    const result = redactValue(childValue, options, childKey, seen);
    output[childKey] = result.value;
    redacted ||= result.redacted;
  }
  return { value: output, redacted };
}

export function truncateString(value: string, maxBytes: number): { value: string; truncated: boolean } {
  if (Buffer.byteLength(value, "utf8") <= maxBytes) return { value, truncated: false };
  const suffix = "...[TRUNCATED]";
  const budget = Math.max(0, maxBytes - Buffer.byteLength(suffix, "utf8"));
  let prefix = Buffer.from(value, "utf8").subarray(0, budget).toString("utf8");
  if (prefix.endsWith("�")) prefix = prefix.slice(0, -1);
  return { value: prefix + suffix, truncated: true };
}

export function serializeState(value: unknown, maxBytes: number): { state: string; truncated: boolean } {
  const serialized = JSON.stringify(value);
  if (Buffer.byteLength(serialized, "utf8") <= maxBytes) return { state: serialized, truncated: false };
  const suffix = "\n...[TRUNCATED]";
  const budget = Math.max(0, maxBytes - Buffer.byteLength(suffix, "utf8"));
  let prefix = Buffer.from(serialized, "utf8").subarray(0, budget).toString("utf8");
  if (prefix.endsWith("�")) prefix = prefix.slice(0, -1);
  return { state: prefix + suffix, truncated: true };
}
