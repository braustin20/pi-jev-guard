import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  CredentialFileError,
  defaultCredentialPath,
  resolveTypeSafeCredential,
} from "../src/credentials.js";

const unixOnly = { skip: process.platform === "win32" };

async function credentialDirectory(): Promise<{ configHome: string; filePath: string }> {
  const configHome = await mkdtemp(path.join(tmpdir(), "jev-guard-credentials-"));
  const directory = path.join(configHome, "pi-jev-guard");
  await mkdir(directory);
  return { configHome, filePath: path.join(directory, "env") };
}

test("environment credential takes precedence over the config file", async () => {
  const { configHome, filePath } = await credentialDirectory();
  await writeFile(filePath, "TYPESAFE_API_KEY=file-value\n", { mode: 0o600 });
  const result = resolveTypeSafeCredential({
    environment: { TYPESAFE_API_KEY: "environment-value" },
    configHome,
  });
  assert.deepEqual(result, { apiKey: "environment-value", source: "environment" });
});

test("reads TYPESAFE_API_KEY from the config directory without sourcing shell code", unixOnly, async () => {
  const { configHome, filePath } = await credentialDirectory();
  await writeFile(filePath, [
    "# Only this assignment is parsed.",
    "UNRELATED_COMMAND=$(touch /tmp/should-not-run)",
    "export TYPESAFE_API_KEY='config-file-value'",
    "",
  ].join("\n"), { mode: 0o600 });
  const result = resolveTypeSafeCredential({ environment: {}, configHome });
  assert.deepEqual(result, { apiKey: "config-file-value", source: "config-file" });
});

test("rejects credential files readable by group or other users", unixOnly, async () => {
  const { configHome, filePath } = await credentialDirectory();
  await writeFile(filePath, "TYPESAFE_API_KEY=insecure\n", { mode: 0o644 });
  await chmod(filePath, 0o644);
  await assert.rejects(
    async () => resolveTypeSafeCredential({ environment: {}, configHome }),
    (error: unknown) => error instanceof CredentialFileError && /chmod 600/.test(error.message),
  );
});

test("rejects credential directories writable by group or other users", unixOnly, async () => {
  const { configHome, filePath } = await credentialDirectory();
  await writeFile(filePath, "TYPESAFE_API_KEY=insecure-directory\n", { mode: 0o600 });
  await chmod(path.dirname(filePath), 0o777);
  await assert.rejects(
    async () => resolveTypeSafeCredential({ environment: {}, configHome }),
    (error: unknown) => error instanceof CredentialFileError && /must not be writable/.test(error.message),
  );
});

test("supports a quoted key followed by an inline comment", unixOnly, async () => {
  const { configHome, filePath } = await credentialDirectory();
  await writeFile(filePath, "TYPESAFE_API_KEY=\"quoted-value\" # local note\n", { mode: 0o600 });
  assert.deepEqual(
    resolveTypeSafeCredential({ environment: {}, configHome }),
    { apiKey: "quoted-value", source: "config-file" },
  );
});

test("rejects oversized credential files", unixOnly, async () => {
  const { configHome, filePath } = await credentialDirectory();
  await writeFile(filePath, `TYPESAFE_API_KEY=${"x".repeat(17 * 1024)}\n`, { mode: 0o600 });
  await assert.rejects(
    async () => resolveTypeSafeCredential({ environment: {}, configHome }),
    (error: unknown) => error instanceof CredentialFileError && /exceeds/.test(error.message),
  );
});

test("rejects a symlink credential file", unixOnly, async () => {
  const { configHome, filePath } = await credentialDirectory();
  const target = path.join(configHome, "target");
  await writeFile(target, "TYPESAFE_API_KEY=linked\n", { mode: 0o600 });
  await symlink(target, filePath);
  await assert.rejects(
    async () => resolveTypeSafeCredential({ environment: {}, configHome }),
    (error: unknown) => error instanceof CredentialFileError && /symbolic link/.test(error.message),
  );
});

test("returns undefined when neither credential source exists", unixOnly, async () => {
  const configHome = await mkdtemp(path.join(tmpdir(), "jev-guard-no-credentials-"));
  assert.equal(resolveTypeSafeCredential({ environment: {}, configHome }), undefined);
});

test("uses XDG_CONFIG_HOME for the default credential path", () => {
  const configHome = path.resolve(tmpdir(), "custom-config");
  assert.equal(
    defaultCredentialPath({ XDG_CONFIG_HOME: configHome }),
    path.join(configHome, "pi-jev-guard", "env"),
  );
});
