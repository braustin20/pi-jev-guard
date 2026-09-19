import assert from "node:assert/strict";
import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { inspectPath, isWithin, matchesGlob } from "../src/paths.js";

test("containment uses path boundaries rather than prefixes", () => {
  assert.equal(isWithin("/project/foo", "/project/foo/src"), true);
  assert.equal(isWithin("/project/foo", "/project/foobar"), false);
});

test("glob matching supports protected path trees", () => {
  assert.equal(matchesGlob("/etc/ssh/sshd_config", "/etc/**"), true);
  assert.equal(matchesGlob("/workspace/etc/file", "/etc/**"), false);
});

test("resolves existing symlinks outside the project", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "jev-guard-paths-"));
  const project = path.join(root, "project");
  const outside = path.join(root, "outside");
  await mkdir(project);
  await mkdir(outside);
  await writeFile(path.join(outside, "secret"), "x");
  await symlink(path.join(outside, "secret"), path.join(project, "link"));
  const fact = await inspectPath("link", project, project, []);
  assert.equal(fact.withinProject, false);
  assert.equal(fact.canonical, path.join(outside, "secret"));
});

test("canonicalizes nearest existing parent for new paths", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "jev-guard-new-path-"));
  const fact = await inspectPath("new/deep/file.txt", root, root, []);
  assert.equal(fact.exists, false);
  assert.equal(fact.withinProject, true);
  assert.equal(fact.canonical, path.join(root, "new/deep/file.txt"));
});

test("marks variable paths unknown", async () => {
  const fact = await inspectPath("$TARGET/file", "/tmp", "/tmp", []);
  assert.equal(fact.dynamic, true);
  assert.equal(fact.withinProject, null);
});
