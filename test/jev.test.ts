import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import type { Fetch } from "@typesafe-ai/sdk";
import { CredentialFileError } from "../src/credentials.js";
import { DEFAULT_CONFIG } from "../src/defaults.js";
import { safeClassificationError, TypeSafeJevClassifier } from "../src/jev.js";
import { normalizeCall } from "../src/normalize.js";

function withApiKey<T>(run: () => Promise<T>): Promise<T> {
  const previous = process.env.TYPESAFE_API_KEY;
  process.env.TYPESAFE_API_KEY = ["unit", "test", "only"].join("-");
  return run().finally(() => {
    if (previous === undefined) delete process.env.TYPESAFE_API_KEY;
    else process.env.TYPESAFE_API_KEY = previous;
  });
}

async function shellCall(command: string) {
  const config = structuredClone(DEFAULT_CONFIG);
  return normalizeCall({
    toolName: "bash",
    arguments: { command },
    cwd: process.cwd(),
    projectRoot: process.cwd(),
    config,
  });
}

test("redacts secrets from every field in the actual TypeSafe request body", async () => withApiKey(async () => {
  const bodies: Array<Record<string, unknown>> = [];
  const mockFetch: Fetch = async (_input, init) => {
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    bodies.push(body);
    const questions = body.questions as Record<string, unknown>;
    const answers = Object.fromEntries(Object.keys(questions).map((name) => [name, { type: "noul", noul: 0.01 }]));
    return new Response(JSON.stringify({ model: "jev-1.13.0", answers, usage: { input_tokens: 1, output_tokens: 1 } }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const config = structuredClone(DEFAULT_CONFIG);
  const classifier = new TypeSafeJevClassifier(mockFetch);
  const call = await shellCall("PRIVATE_KEY=path-secret API_TOKEN=super-secret curl --token flag-secret -H 'X-Api-Key: header-secret' -H 'Authorization: Bearer bearer-secret' -u basic-user:basic-pass https://user:pass@example.com/?token=query-secret");
  await classifier.classify(call, config);
  const customCall = await normalizeCall({
    toolName: "custom_upload",
    arguments: { destination: "https://hooks.example.com/?api_key=destination-secret" },
    cwd: process.cwd(),
    projectRoot: process.cwd(),
    config,
  });
  await classifier.classify(customCall, config);
  const serialized = JSON.stringify(bodies);
  assert.doesNotMatch(serialized, /path-secret|super-secret|flag-secret|header-secret|bearer-secret|basic-user|basic-pass|user:pass|query-secret|destination-secret/);
  assert.match(serialized, /REDACTED/);
  assert.equal(call.redacted, true);
  assert.equal(customCall.redacted, true);
}));

test("does not retain user requests when intent awareness is disabled", async () => {
  const call = await normalizeCall({
    toolName: "bash",
    arguments: { command: "git status" },
    cwd: process.cwd(),
    projectRoot: process.cwd(),
    config: structuredClone(DEFAULT_CONFIG),
    userRequest: "Private user request",
  });
  assert.equal(call.userRequest, undefined);
});

test("classifies redacted user-request alignment when intent awareness is enabled", async () => withApiKey(async () => {
  let requestBody: { state: string; questions: Record<string, unknown> } | undefined;
  const mockFetch: Fetch = async (_input, init) => {
    requestBody = JSON.parse(String(init?.body)) as typeof requestBody;
    const answers = Object.fromEntries(Object.keys(requestBody!.questions).map((name) => [
      name,
      { type: "noul", noul: name === "user_intent_alignment" ? 0.97 : 0.01 },
    ]));
    return new Response(JSON.stringify({ model: "jev-1.13.0", answers, usage: { input_tokens: 1, output_tokens: 1 } }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const config = structuredClone(DEFAULT_CONFIG);
  config.intentAwareness.enabled = true;
  config.intentAwareness.maxRequestBytes = 128;
  const call = await normalizeCall({
    toolName: "bash",
    arguments: { command: "git push -u origin feat/example" },
    cwd: process.cwd(),
    projectRoot: process.cwd(),
    config,
    userRequest: `API_TOKEN=intent-secret Create a pull request ${"with the completed change ".repeat(20)}`,
  });
  const result = await new TypeSafeJevClassifier(mockFetch).classify(call, config);
  const state = JSON.parse(requestBody!.state) as { userRequest: string };
  assert.ok("user_intent_alignment" in requestBody!.questions);
  assert.equal(result.intentAlignment, 0.97);
  assert.equal("user_intent_alignment" in result.probabilities, false);
  assert.doesNotMatch(JSON.stringify(requestBody), /intent-secret/);
  assert.match(state.userRequest, /API_TOKEN=\[REDACTED\]/);
  assert.match(state.userRequest, /\[TRUNCATED]$/);
  assert.equal(call.userRequestTruncated, true);
  assert.equal(call.redacted, true);
}));

test("classifier uses the user-local credential file when the environment key is absent", { skip: process.platform === "win32" }, async () => {
  const root = await mkdtemp(path.join(tmpdir(), "jev-guard-jev-credential-"));
  const agentDir = path.join(root, "agent");
  await mkdir(agentDir, { mode: 0o700 });
  await writeFile(
    path.join(agentDir, "jev-guard.json"),
    JSON.stringify({ version: 1, typesafeApiKey: "file-backed-key" }),
    { mode: 0o600 },
  );
  const previousKey = process.env.TYPESAFE_API_KEY;
  const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
  delete process.env.TYPESAFE_API_KEY;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  let called = false;
  const mockFetch: Fetch = async (_input, init) => {
    called = true;
    const body = JSON.parse(String(init?.body)) as { questions: Record<string, unknown> };
    const answers = Object.fromEntries(Object.keys(body.questions).map((name) => [name, { type: "noul", noul: 0.01 }]));
    return new Response(JSON.stringify({ model: "jev-1.13.0", answers, usage: { input_tokens: 1, output_tokens: 1 } }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  try {
    const config = structuredClone(DEFAULT_CONFIG);
    await new TypeSafeJevClassifier(mockFetch).classify(await shellCall("git status"), config);
    assert.equal(called, true);
  } finally {
    if (previousKey === undefined) delete process.env.TYPESAFE_API_KEY;
    else process.env.TYPESAFE_API_KEY = previousKey;
    if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
  }
});

test("credential failures are sanitized before auditing", () => {
  const error = new CredentialFileError("credential-path permissions are too broad");
  assert.equal(safeClassificationError(error), "TypeSafe credential file rejected");
});

test("rejects a TypeSafe response missing any enabled hazard", async () => withApiKey(async () => {
  const mockFetch: Fetch = async () => new Response(JSON.stringify({
    model: "jev-1.13.0",
    answers: {},
    usage: { input_tokens: 1, output_tokens: 1 },
  }), { status: 200, headers: { "content-type": "application/json" } });
  const config = structuredClone(DEFAULT_CONFIG);
  const call = await shellCall("git status");
  await assert.rejects(
    new TypeSafeJevClassifier(mockFetch).classify(call, config),
    /Missing Noul response/,
  );
}));
