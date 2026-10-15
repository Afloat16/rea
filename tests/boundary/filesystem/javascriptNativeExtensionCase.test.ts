import { execFile } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { expect, it } from "vitest";

import { createJavaScriptArtifactReader } from "../../../src/artifacts/javascript/JavaScriptArtifactReader.js";
import { analyzeJavaScriptArtifactFiles } from "../../../src/application/javascript/JavaScriptArtifactAnalysis.js";
import { buildJavaScriptArtifactGraph } from "../../../src/application/javascript/JavaScriptArtifactGraphBuilder.js";
import { scanCanonicalArtifactInventory } from "../../fixtures/artifactInventory.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { readJavaScriptArtifactFiles } from "../../support/javascriptApplicationScope.js";

it("keeps broad addon inventory hints separate from Node's native loader extension", async () => {
  const root = await createTestTempDirectory("rea-native-extension-case-");
  await Promise.all([
    writeFile(join(root, "addon.NODE"), "module.exports = { value: 42 };"),
    writeFile(join(root, "exact.node"), "self-authored invalid native fixture"),
    writeFile(
      join(root, "main.cjs"),
      'const ordinary = require("./addon.NODE"); const native = require("./exact.node");',
    ),
  ]);
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      "-e",
      `const upper = require(process.argv[1]);
       let exactCode;
       try { require(process.argv[2]); } catch (error) { exactCode = error.code; }
       process.stdout.write(JSON.stringify({ upper, exactCode }));`,
      join(root, "addon.NODE"),
      join(root, "exact.node"),
    ],
    { timeout: 10_000, maxBuffer: 4_096 },
  );
  expect(JSON.parse(stdout)).toEqual({
    upper: { value: 42 },
    exactCode: "ERR_DLOPEN_FAILED",
  });

  const snapshot = await scanCanonicalArtifactInventory(root, {});
  const reader = createJavaScriptArtifactReader(root, "directory");
  try {
    const files = await readJavaScriptArtifactFiles(reader, snapshot);
    expect(
      files.files
        .filter(({ kind }) => kind === "native-addon")
        .map(({ path }) => path)
        .sort(),
    ).toEqual(["addon.NODE", "exact.node"]);
    const analysis = analyzeJavaScriptArtifactFiles(files);
    const graph = buildJavaScriptArtifactGraph(snapshot, files, analysis);
    const requested = graph.nodes
      .filter(({ kind }) => kind === "native-export")
      .flatMap(({ observations }) => observations)
      .map(({ properties }) => properties.specifier);
    expect(requested).toEqual(["./exact.node"]);
    expect(graph.edges).toContainEqual(
      expect.objectContaining({
        properties: expect.objectContaining({
          specifier: "./addon.NODE",
          resolved_path: "addon.NODE",
        }),
      }),
    );
  } finally {
    await reader.close();
  }
});
