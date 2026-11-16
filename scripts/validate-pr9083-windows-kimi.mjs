import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";

assert.equal(process.platform, "win32", "This proof must execute on Windows.");
const oldHead = "5b4f67417e786074ab81c2bdcf02f5d5f8395020";
const candidate = "e60a04fc10bd24b3027e6c73a07c412ffdd478a9";
const testPath =
  "tests/boundary/filesystem/clientConfigurationEnvironment.test.ts";
const sourcePath = "src/application/SetupClientConfiguration.ts";
const prefix = "preserves a lowercase explicit Kimi schema profile";
const reportDirectory = "pr9083-windows-kimi-evidence";
await mkdir(reportDirectory, { recursive: true });
const fixedTest = await readFile(testPath, "utf8");
const cleanSource = await readFile(sourcePath, "utf8");
const original = spawnSync("git", ["show", oldHead + ":" + testPath], {
  encoding: "utf8",
});
assert.equal(original.status, 0, original.stderr);
const baselineTest = original.stdout;
const receipt = {
  platform: process.platform,
  node: process.version,
  oldHead,
  candidate,
  nativeArtifactRun: 43786166227,
  testPath,
  sourcePath,
  checks: [],
};
const hash = (text) => createHash("sha256").update(text).digest("hex");
const run = (label, args, expectedExit = 0) => {
  const result = spawnSync(process.execPath, args, {
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });
  process.stdout.write(result.stdout ?? "");
  process.stderr.write(result.stderr ?? "");
  assert.equal(result.error, undefined, label + ": subprocess error");
  assert.equal(result.status, expectedExit, label + ": unexpected exit");
  receipt.checks.push({ label, command: [process.execPath, ...args], exit: result.status });
  return result;
};
const targeted = async (label, expectedExit, expectedStatus) => {
  const report = reportDirectory + "/" + label + ".json";
  const result = run(label, [
    "node_modules/vitest/vitest.mjs",
    "run",
    "--coverage.enabled=false",
    "--reporter=default",
    "--reporter=json",
    "--outputFile=" + report,
    testPath,
    "-t",
    prefix,
  ], expectedExit);
  const data = JSON.parse(await readFile(report, "utf8"));
  const selected = data.testResults.flatMap((file) => file.assertionResults)
    .filter((test) => test.fullName.includes(prefix));
  assert.equal(selected.length, 1, label + ": expected one selected regression");
  assert.equal(selected[0].status, expectedStatus, label + ": selected result");
  assert.equal(data.numFailedTests, expectedExit === 0 ? 0 : 1);
  assert.equal(data.numPassedTests, expectedExit === 0 ? 1 : 0);
  receipt.checks.at(-1).selected = selected;
  return {
    ...selected[0],
    diagnosticOutput: (result.stdout + result.stderr).replace(/\u001b\[[0-9;]*m/g, ""),
  };
};
try {
  const { parseMcpInputSchemaProfile } = await import("../dist/config/mcpInputSchemaProfile.js");
  const removed = parseMcpInputSchemaProfile("full");
  assert.equal(removed.ok, false);
  assert.match(removed.error.message, /full.*removed/);
  assert.deepEqual(parseMcpInputSchemaProfile("compact"), { ok: true, value: "compact" });
  receipt.profilePolicy = { full: removed.error.message, compact: "accepted" };

  receipt.priorWindowsEvidence = {
    run: 43794117585,
    originalFixture: "1 failed, 74 filtered out",
    correctedEnvironmentFile: "75 passed",
    expandedKimiFile: "28 passed, 1 existing POSIX-path expectation failed on Windows",
  };
  const profileReport = reportDirectory + "/kimi-input-profiles.json";
  run("kimi-input-profiles", [
    "node_modules/vitest/vitest.mjs",
    "run",
    "--coverage.enabled=false",
    "--reporter=default",
    "--reporter=json",
    "--outputFile=" + profileReport,
    "tests/boundary/filesystem/kimiClientConfiguration.test.ts",
    "-t",
    "Kimi Code input-schema profile selection",
  ]);
  const profiles = JSON.parse(await readFile(profileReport, "utf8"));
  assert.equal(profiles.numPassedTests, 4);
  assert.equal(profiles.numFailedTests, 0);
  run("format", ["node_modules/oxfmt/bin/oxfmt", "--check", testPath]);
  run("lint", ["node_modules/oxlint/bin/oxlint", testPath]);

  const anchor = [
    "    launcher,",
    "    environment.value,",
    "    parsed === undefined",
  ].join("\n");
  assert.equal(cleanSource.split(anchor).length, 2, "one registration seam");
  const mutation = [
    "    launcher,",
    '    client.name === "kimi"',
    '      ? { ...environment.value, REA_MCP_INPUT_SCHEMA_PROFILE: "compact" }',
    "      : environment.value,",
    "    parsed === undefined",
  ].join("\n");
  await writeFile(sourcePath, cleanSource.replace(anchor, mutation));
  const mutationFailure = await targeted("duplicate-key-mutation", 1, "failed");
  assert.match(mutationFailure.diagnosticOutput, /REA_MCP_INPUT_SCHEMA_PROFILE/);

  await writeFile(sourcePath, cleanSource);
  await targeted("restored-candidate", 0, "passed");
} finally {
  await writeFile(testPath, fixedTest);
  await writeFile(sourcePath, cleanSource);
  assert.equal(hash(await readFile(testPath, "utf8")), hash(fixedTest));
  assert.equal(hash(await readFile(sourcePath, "utf8")), hash(cleanSource));
  receipt.restoredHashes = { test: hash(fixedTest), source: hash(cleanSource) };
  await writeFile(reportDirectory + "/receipt.json", JSON.stringify(receipt, null, 2) + "\n");
}
console.log("PR9083_WINDOWS_KIMI_PROOF_COMPLETE");
