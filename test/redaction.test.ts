import assert from "node:assert/strict";
import test from "node:test";
import { redactString, redactValue, serializeState, truncateString } from "../src/redaction.js";

const keys = ["token", "password", "apiKey", "authorization", "secret"];

test("redacts secret-looking keys recursively", () => {
  const result = redactValue(
    { apiKey: "abc", nested: { password: "hunter2", safe: "visible" } },
    { redactKeys: keys, omitFileContents: false },
  );
  assert.equal(result.redacted, true);
  assert.deepEqual(result.value, {
    apiKey: "[REDACTED]",
    nested: { password: "[REDACTED]", safe: "visible" },
  });
});

test("redacts environment, flag, header, basic-auth, bearer, and URL secrets", () => {
  const input = [
    "API_TOKEN=abc",
    "curl --api-key flag-secret",
    "-H 'X-Api-Key: header-secret'",
    "-H 'Authorization: Bearer bearer-secret'",
    "-u basic-user:basic-pass",
    "https://url-user:url-pass@example.com/x?token=query-secret&ok=yes",
  ].join(" ");
  const output = redactString(input, keys);
  assert.doesNotMatch(output, /abc|flag-secret|header-secret|bearer-secret|basic-user|basic-pass|url-user|url-pass|query-secret/);
  assert.match(output, /ok=yes/);
});

test("omits file content fields when configured", () => {
  const result = redactValue(
    { path: "safe.txt", content: "private", edits: [{ oldText: "old", newText: "new" }] },
    { redactKeys: keys, omitFileContents: true },
  );
  assert.deepEqual(result.value, {
    path: "safe.txt",
    content: "[OMITTED]",
    edits: [{ oldText: "[OMITTED]", newText: "[OMITTED]" }],
  });
});

test("caps user requests by UTF-8 bytes without splitting characters", () => {
  const result = truncateString("Create 🔒".repeat(100), 80);
  assert.equal(result.truncated, true);
  assert.ok(Buffer.byteLength(result.value, "utf8") <= 80);
  assert.doesNotMatch(result.value, /�/);
  assert.match(result.value, /\[TRUNCATED]$/);
});

test("caps classifier state by UTF-8 bytes", () => {
  const result = serializeState({ value: "🔒".repeat(1000) }, 200);
  assert.equal(result.truncated, true);
  assert.ok(Buffer.byteLength(result.state, "utf8") <= 200);
  assert.match(result.state, /\[TRUNCATED]$/);
});
