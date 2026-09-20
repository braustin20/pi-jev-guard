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

async function credentialDirectory(): Promise<{ agentDir: string; filePath: string }> {
  const root = await mkdtemp(path.join(tmpdir(), "jev-guard-credentials-"));
  const agentDir = path.join(root, "agent");
  await mkdir(agentDir, { mode: 0o700 });
  return { agentDir, filePath: path.join(agentDir, "jev-guard.json") };
}

test("environment credential takes precedence over the global config", async () => {
  const { agentDir, filePath } = await credentialDirectory();
  await writeFile(filePath, JSON.stringify({ version: 1, typesafeApiKey: "file-value" }), { mode: 0o600 });
  const result = resolveTypeSafeCredential({
    environment: { TYPESAFE_API_KEY: "environment-value" },
    agentDir,
  });
  assert.deepEqual(result, { apiKey: "environment-value", source: "environment" });
});

test("reads typesafeApiKey alongside global policy settings", unixOnly, async () => {
  const { agentDir, filePath } = await credentialDirectory();
  await writeFile(filePath, JSON.stringify({
    version: 1,
    typesafeApiKey: "config-file-value",
    protectUserBash: true,
    hazards: { complex_shell_composition: { decision: "allow" } },
  }), { mode: 0o600 });
  const result = resolveTypeSafeCredential({ environment: {}, agentDir });
  assert.deepEqual(result, { apiKey: "config-file-value", source: "config-file" });
});

test("treats an omitted or empty config credential as unavailable", unixOnly, async () => {
  const { agentDir, filePath } = await credentialDirectory();
  await writeFile(filePath, JSON.stringify({ version: 1 }), { mode: 0o600 });
  assert.equal(resolveTypeSafeCredential({ environment: {}, agentDir }), undefined);
  await writeFile(filePath, JSON.stringify({ version: 1, typesafeApiKey: "" }), { mode: 0o600 });
  assert.equal(resolveTypeSafeCredential({ environment: {}, agentDir }), undefined);
});

test("rejects malformed JSON config", unixOnly, async () => {
  const { agentDir, filePath } = await credentialDirectory();
  await writeFile(filePath, "{not-json}", { mode: 0o600 });
  assert.throws(
    () => resolveTypeSafeCredential({ environment: {}, agentDir }),
    (error: unknown) => error instanceof CredentialFileError && /valid JSON/.test(error.message),
  );
});

test("rejects global config readable by group or other users", unixOnly, async () => {
  const { agentDir, filePath } = await credentialDirectory();
  await writeFile(filePath, JSON.stringify({ typesafeApiKey: "insecure" }), { mode: 0o644 });
  await chmod(filePath, 0o644);
  assert.throws(
    () => resolveTypeSafeCredential({ environment: {}, agentDir }),
    (error: unknown) => error instanceof CredentialFileError && /chmod 600/.test(error.message),
  );
});

test("rejects agent directories writable by group or other users", unixOnly, async () => {
  const { agentDir, filePath } = await credentialDirectory();
  await writeFile(filePath, JSON.stringify({ typesafeApiKey: "insecure-directory" }), { mode: 0o600 });
  await chmod(agentDir, 0o777);
  assert.throws(
    () => resolveTypeSafeCredential({ environment: {}, agentDir }),
    (error: unknown) => error instanceof CredentialFileError && /must not be writable/.test(error.message),
  );
});

test("rejects oversized global config files", unixOnly, async () => {
  const { agentDir, filePath } = await credentialDirectory();
  await writeFile(filePath, JSON.stringify({ typesafeApiKey: "x".repeat(257 * 1024) }), { mode: 0o600 });
  assert.throws(
    () => resolveTypeSafeCredential({ environment: {}, agentDir }),
    (error: unknown) => error instanceof CredentialFileError && /exceeds/.test(error.message),
  );
});

test("rejects a symlink global config", unixOnly, async () => {
  const { agentDir, filePath } = await credentialDirectory();
  const target = path.join(path.dirname(agentDir), "target");
  await writeFile(target, JSON.stringify({ typesafeApiKey: "linked" }), { mode: 0o600 });
  await symlink(target, filePath);
  assert.throws(
    () => resolveTypeSafeCredential({ environment: {}, agentDir }),
    (error: unknown) => error instanceof CredentialFileError && /symbolic link/.test(error.message),
  );
});

test("returns undefined when neither credential source exists", unixOnly, async () => {
  const root = await mkdtemp(path.join(tmpdir(), "jev-guard-no-credentials-"));
  const agentDir = path.join(root, "agent");
  assert.equal(resolveTypeSafeCredential({ environment: {}, agentDir }), undefined);
});

test("uses the Pi agent directory for the credential path", () => {
  const agentDir = path.resolve(tmpdir(), "custom-agent");
  assert.equal(defaultCredentialPath(agentDir), path.join(agentDir, "jev-guard.json"));
});
