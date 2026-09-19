import { constants, closeSync, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

const MAX_CREDENTIAL_FILE_BYTES = 16 * 1024;
const CREDENTIAL_FILE_NAME = "settings.json";
const SETTINGS_KEYS = new Set(["typesafeApiKey"]);

export interface TypeSafeCredential {
  apiKey: string;
  source: "environment" | "config-file";
}

export interface CredentialLookupOptions {
  environment?: NodeJS.ProcessEnv;
  configHome?: string;
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

function defaultConfigHome(environment: NodeJS.ProcessEnv): string {
  const configuredHome = environment.XDG_CONFIG_HOME;
  return configuredHome && path.isAbsolute(configuredHome)
    ? configuredHome
    : path.join(homedir(), ".config");
}

export function defaultCredentialPath(environment: NodeJS.ProcessEnv = process.env): string {
  return path.join(defaultConfigHome(environment), "pi-jev-guard", CREDENTIAL_FILE_NAME);
}

function parseCredentialFile(source: string, filePath: string): string {
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
  const settings = parsed as Record<string, unknown>;
  const unknownKeys = Object.keys(settings).filter((key) => !SETTINGS_KEYS.has(key));
  if (unknownKeys.length > 0) {
    throw new CredentialFileError(`${filePath} contains unknown settings: ${unknownKeys.join(", ")}`);
  }
  if (typeof settings.typesafeApiKey !== "string" || settings.typesafeApiKey.trim().length === 0) {
    throw new CredentialFileError(`${filePath} must define a non-empty typesafeApiKey string`);
  }
  return settings.typesafeApiKey.trim();
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

function readCredentialFile(filePath: string): string | undefined {
  if (process.platform === "win32") {
    try {
      lstatSync(filePath);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT") return undefined;
      throw new CredentialFileError(`Unable to inspect the TypeSafe credential file: ${code ?? "unknown error"}`);
    }
    throw new CredentialError("Credential-file loading is unsupported on Windows; use TYPESAFE_API_KEY instead");
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
    const credentialDirectory = path.dirname(filePath);
    assertSecureDirectory(path.dirname(credentialDirectory));
    assertSecureDirectory(credentialDirectory);
    const stats = fstatSync(descriptor);
    if (!stats.isFile()) throw new CredentialFileError(`${filePath} is not a regular file`);
    if (stats.size > MAX_CREDENTIAL_FILE_BYTES) {
      throw new CredentialFileError(`${filePath} exceeds ${MAX_CREDENTIAL_FILE_BYTES} bytes`);
    }
    if ((stats.mode & 0o077) !== 0) {
      throw new CredentialFileError(`${filePath} permissions are too broad; run chmod 600 ${filePath}`);
    }
    const currentUser = process.getuid?.();
    if (currentUser !== undefined && stats.uid !== currentUser) {
      throw new CredentialFileError(`${filePath} is not owned by the current user`);
    }
    const buffer = Buffer.alloc(MAX_CREDENTIAL_FILE_BYTES + 1);
    let offset = 0;
    for (;;) {
      if (offset >= buffer.length) break;
      const bytesRead = readSync(descriptor, buffer, offset, buffer.length - offset, null);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > MAX_CREDENTIAL_FILE_BYTES) {
      throw new CredentialFileError(`${filePath} exceeds ${MAX_CREDENTIAL_FILE_BYTES} bytes`);
    }
    return parseCredentialFile(buffer.subarray(0, offset).toString("utf8"), filePath);
  } finally {
    closeSync(descriptor);
  }
}

export function resolveTypeSafeCredential(options: CredentialLookupOptions = {}): TypeSafeCredential | undefined {
  const environment = options.environment ?? process.env;
  const environmentKey = environment.TYPESAFE_API_KEY?.trim();
  if (environmentKey) return { apiKey: environmentKey, source: "environment" };

  const configHome = options.configHome ?? defaultConfigHome(environment);
  const filePath = path.join(configHome, "pi-jev-guard", CREDENTIAL_FILE_NAME);
  const fileKey = readCredentialFile(filePath);
  return fileKey ? { apiKey: fileKey, source: "config-file" } : undefined;
}
