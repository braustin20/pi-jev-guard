import assert from "node:assert/strict";
import test from "node:test";
import type { Fetch } from "@typesafe-ai/sdk";
import { DEFAULT_CONFIG } from "../src/defaults.js";
import { TypeSafeJevClassifier } from "../src/jev.js";
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
