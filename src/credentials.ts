import { constants, closeSync, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import path from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";

const MAX_CONFIG_FILE_BYTES = 256 * 1024;
const CONFIG_FILE_NAME = "jev-guard.json";

export interface TypeSafeCredential {
  apiKey: string;
  source: "environment" | "config-file";
}

export interface CredentialLookupOptions {
  environment?: NodeJS.ProcessEnv;
  agentDir?: string;
}

export class CredentialError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "CredentialError";
  }
}

export class CredentialFileError extends CredentialError {
  public constructor(message: string) {
    super(message);
    this.name = "CredentialFileError";
  }
}

export function defaultCredentialPath(agentDir: string = getAgentDir()): string {
  return path.join(agentDir, CONFIG_FILE_NAME);
}

function parseCredentialFile(source: string, filePath: string): string | undefined {
  if (source.includes("\0")) throw new CredentialFileError(`${filePath} contains a NUL byte`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw new CredentialFileError(`${filePath} is not valid JSON`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new CredentialFileError(`${filePath} must contain a JSON object`);
  }
  const apiKey = (parsed as { typesafeApiKey?: unknown }).typesafeApiKey;
  if (apiKey === undefined || apiKey === "") return undefined;
  if (typeof apiKey !== "string" || apiKey.trim().length === 0) {
    throw new CredentialFileError(`${filePath} must define typesafeApiKey as a non-empty string or omit it`);
  }
  return apiKey.trim();
}

function assertSecureDirectory(directoryPath: string): void {
  let stats;
  try {
    stats = lstatSync(directoryPath);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    throw new CredentialFileError(`Unable to inspect ${directoryPath}: ${code ?? "unknown error"}`);
  }
  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw new CredentialFileError(`${directoryPath} must be a real directory, not a link`);
  }
  if ((stats.mode & 0o022) !== 0) {
    throw new CredentialFileError(`${directoryPath} must not be writable by group or other users`);
  }
  const currentUser = process.getuid?.();
  if (currentUser !== undefined && stats.uid !== currentUser) {
    throw new CredentialFileError(`${directoryPath} is not owned by the current user`);
  }
}

function readBoundedFile(descriptor: number, filePath: string): string {
  const stats = fstatSync(descriptor);
  if (!stats.isFile()) throw new CredentialFileError(`${filePath} is not a regular file`);
  if (stats.size > MAX_CONFIG_FILE_BYTES) {
    throw new CredentialFileError(`${filePath} exceeds ${MAX_CONFIG_FILE_BYTES} bytes`);
  }
  const buffer = Buffer.alloc(MAX_CONFIG_FILE_BYTES + 1);
  let offset = 0;
  for (;;) {
    if (offset >= buffer.length) break;
    const bytesRead = readSync(descriptor, buffer, offset, buffer.length - offset, null);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  if (offset > MAX_CONFIG_FILE_BYTES) {
    throw new CredentialFileError(`${filePath} exceeds ${MAX_CONFIG_FILE_BYTES} bytes`);
  }
  return buffer.subarray(0, offset).toString("utf8");
}

export function readSecureGlobalConfigSource(
  filePath: string,
  purpose: "credential" | "policy" = "credential",
): string | undefined {
  if (process.platform === "win32") {
    let stats;
    try {
      stats = lstatSync(filePath);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT") return undefined;
      throw new CredentialFileError(`Unable to inspect the Jev Guard configuration: ${code ?? "unknown error"}`);
    }
    if (purpose === "credential") {
      throw new CredentialError("Config-file credential loading is unsupported on Windows; use TYPESAFE_API_KEY instead");
    }
    if (stats.isSymbolicLink() || !stats.isFile()) {
      throw new CredentialFileError(`${filePath} must be a regular file, not a link`);
    }
    let descriptor: number;
    try {
      descriptor = openSync(filePath, constants.O_RDONLY);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      throw new CredentialFileError(`Unable to open ${filePath}: ${code ?? "unknown error"}`);
    }
    try {
      return readBoundedFile(descriptor, filePath);
    } finally {
      closeSync(descriptor);
    }
  }

  let descriptor: number;
  try {
    descriptor = openSync(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return undefined;
    if (code === "ELOOP" || code === "EMLINK") {
      throw new CredentialFileError(`${filePath} must not be a symbolic link`);
    }
    throw new CredentialFileError(`Unable to open ${filePath}: ${code ?? "unknown error"}`);
  }

  try {
    const agentDirectory = path.dirname(filePath);
    assertSecureDirectory(path.dirname(agentDirectory));
    assertSecureDirectory(agentDirectory);
    const stats = fstatSync(descriptor);
    if ((stats.mode & 0o077) !== 0) {
      throw new CredentialFileError(`${filePath} permissions are too broad; run chmod 600 ${filePath}`);
    }
    const currentUser = process.getuid?.();
    if (currentUser !== undefined && stats.uid !== currentUser) {
      throw new CredentialFileError(`${filePath} is not owned by the current user`);
    }
    return readBoundedFile(descriptor, filePath);
  } finally {
    closeSync(descriptor);
  }
}

export function resolveTypeSafeCredential(options: CredentialLookupOptions = {}): TypeSafeCredential | undefined {
  const environment = options.environment ?? process.env;
  const environmentKey = environment.TYPESAFE_API_KEY?.trim();
  if (environmentKey) return { apiKey: environmentKey, source: "environment" };

  const filePath = defaultCredentialPath(options.agentDir);
  const source = readSecureGlobalConfigSource(filePath, "credential");
  const fileKey = source === undefined ? undefined : parseCredentialFile(source, filePath);
  return fileKey ? { apiKey: fileKey, source: "config-file" } : undefined;
}
