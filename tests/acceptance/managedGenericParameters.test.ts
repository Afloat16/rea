import { createHash } from "node:crypto";
import { unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { expect } from "vitest";

import { artifactMcpCall } from "../../scripts/lib/artifact-e2e.mjs";
import { parseEvidence } from "../../src/domain/evidence.js";
import { managedMemberInspectionSchema } from "../../src/domain/managed/managedArtifact.js";
import { analysisViewResultSchema } from "../../src/domain/analysisView/analysisViewResult.js";
import { buildManagedPeFixture } from "../../src/dotnet/ManagedPe.fixture.js";
import { fileIdentity } from "../fixtures/evidenceSubject.js";
import { createMcpSchemaValidation } from "../fixtures/mcpSchemaValidation.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

const genericFixture = () =>
  buildManagedPeFixture({
    methodSignature: Buffer.from([0x10, 0x01, 0x00, 0x01]),
    genericParameters: [
      { number: 0, flags: 1, owner: 2, name: "TValue" },
      { number: 0, flags: 20, owner: 3, name: "TResult" },
    ],
    genericConstraints: [
      { owner: 1, constraint: 9 },
      { owner: 2, constraint: 9 },
    ],
    typeReferences: [{ namespace: "System", name: "IDisposable" }],
  });

const createTransport = () =>
  new StdioClientTransport({
    command: process.execPath,
    args: [resolve("scripts/rea.mjs"), "mcp"],
    cwd: process.cwd(),
    env: {
      PATH: process.env.PATH ?? "",
      REA_LOG_LEVEL: "silent",
      ...(process.platform === "win32"
        ? {
            SystemRoot: process.env.SystemRoot ?? "",
            TEMP: tmpdir(),
            TMP: tmpdir(),
          }
        : {}),
    },
    stderr: "pipe",
  });

cliTest(
  "CLI and stdio MCP retain generic owner and constraint facts after source removal",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-managed-generics-");
    const path = join(root, "generics.dll");
    const bytes = genericFixture();
    await writeFile(path, bytes);
    const output = await cli.run({
      arguments: [
        "inspect-managed-members",
        path,
        "--detail",
        "complete",
        "--json",
      ],
    });
    expect(output.exitCode, output.stderr).toBe(0);
    const cliEvidence = parseEvidence(output.json);
    const report = managedMemberInspectionSchema.parse(
      cliEvidence.normalized_result,
    );
    expect(report.generic_parameters).toMatchObject({
      state: "complete",
      rows: [
        {
          token: "0x2a000001",
          owner_token: "0x02000001",
          owner_kind: "type",
          name: "TValue",
        },
        {
          token: "0x2a000002",
          owner_token: "0x06000001",
          owner_kind: "method",
          name: "TResult",
        },
      ],
      constraints: [
        {
          parameter_token: "0x2a000001",
          constraint_token: "0x01000002",
          constraint_name: "System.IDisposable",
        },
        {
          parameter_token: "0x2a000002",
          constraint_token: "0x01000002",
          constraint_name: "System.IDisposable",
        },
      ],
    });
    const transport = createTransport();
    transport.stderr?.on("data", () => undefined);
    const client = new Client(
      { name: "managed-generic-declarations", version: "1" },
      { jsonSchemaValidator: createMcpSchemaValidation() },
    );
    try {
      await client.connect(transport);
      const response = await artifactMcpCall(client, {
        name: "inspect_managed_members",
        arguments: { path, detail: "complete" },
      });
      expect(response.isError, JSON.stringify(response)).not.toBe(true);
      const parent = parseEvidence(response.structuredContent);
      expect(parent.normalized_result).toEqual(cliEvidence.normalized_result);
      const sha256 = createHash("sha256").update(bytes).digest("hex");
      expect(fileIdentity(parent.subject).sha256).toBe(sha256);
      expect(fileIdentity(cliEvidence.subject).sha256).toBe(sha256);
      await unlink(path);

      const source = {
        kind: "retained-evidence",
        evidence_id: parent.evidence_id,
      };
      for (const view of [
        {
          kind: "managed-members",
          collection: "generic_parameters",
          names: ["TResult"],
          fields: ["name", "flags"],
          offset: 0,
          limit: 1,
        },
        {
          kind: "managed-members",
          collection: "generic_constraints",
          names: ["System.IDisposable"],
          fields: ["constraint_name"],
          offset: 1,
          limit: 1,
        },
      ]) {
        const reply = await artifactMcpCall(client, {
          name: "inspect_analysis_view",
          arguments: { source, view },
        });
        expect(reply.isError, JSON.stringify(reply)).not.toBe(true);
        const evidence = parseEvidence(reply.structuredContent);
        expect(evidence.evidence_links).toEqual([parent.evidence_id]);
        const page = analysisViewResultSchema.parse(evidence.normalized_result);
        expect(page).toMatchObject({
          source_coverage: { state: "complete", issues: [] },
          page: {
            rows: [
              view.collection === "generic_parameters"
                ? {
                    source_index: 1,
                    token: "0x2a000002",
                    owner_coded_index: 3,
                    owner_token: "0x06000001",
                    name: "TResult",
                    flags: 20,
                  }
                : {
                    source_index: 1,
                    token: "0x2c000002",
                    parameter_row: 2,
                    parameter_token: "0x2a000002",
                    owner_token: "0x06000001",
                    constraint_coded_index: 9,
                    constraint_token: "0x01000002",
                    constraint_name: "System.IDisposable",
                  },
            ],
          },
        });
      }
      const summaryReply = await artifactMcpCall(client, {
        name: "inspect_analysis_view",
        arguments: { source, view: { kind: "summary" } },
      });
      expect(summaryReply.isError, JSON.stringify(summaryReply)).not.toBe(true);
      const summary = analysisViewResultSchema.parse(
        parseEvidence(summaryReply.structuredContent).normalized_result,
      );
      expect(summary).toMatchObject({
        summary: {
          generic_parameters: { state: "complete", issues: [] },
          reported_counts: { generic_parameters: 2, generic_constraints: 2 },
        },
      });
      expect(summary).not.toHaveProperty("summary.generic_parameters.rows");
      expect(summary).not.toHaveProperty(
        "summary.generic_parameters.constraints",
      );
    } finally {
      try {
        await client.close();
      } finally {
        await transport.close();
      }
    }
  },
);
