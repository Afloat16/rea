import { unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";

import { parseEvidence } from "../../src/domain/evidence.js";
import {
  analysisViewResultSchema,
  managedMemberSummaryViewResultSchema,
} from "../../src/domain/analysisView/analysisViewResult.js";
import { buildManagedMarshallingFixture } from "../../src/dotnet/ManagedPe.fixture.js";
import { connectLocalToolsMcp } from "../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

cliTest(
  "CLI and stdio MCP retain marshalling declarations after the assembly disappears",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-managed-marshalling-");
    const path = join(root, "marshalling.dll");
    const bundlePath = join(root, "evidence.json");
    await writeFile(path, buildManagedMarshallingFixture());
    const initial = await cli.run({
      arguments: [
        "inspect-managed-members",
        path,
        "--detail",
        "summary",
        "--evidence_output",
        bundlePath,
        "--json",
      ],
    });
    expect(initial.exitCode, initial.stderr + initial.stdout).toBe(0);
    const delivered = initial.json as { summary: unknown };
    const cliSummary = managedMemberSummaryViewResultSchema.parse(
      parseEvidence(delivered.summary).normalized_result,
    );
    const { call } = await connectLocalToolsMcp();
    const response = await call("inspect_managed_members", {
      path,
      detail: "summary",
    });
    expect(response.isError, JSON.stringify(response)).not.toBe(true);
    const mcpSummary = managedMemberSummaryViewResultSchema.parse(
      parseEvidence(response.structuredContent).normalized_result,
    );
    for (const summary of [cliSummary, mcpSummary]) {
      expect(summary.summary.reported_counts.marshalling).toBe(5);
      expect(summary.summary.marshalling).toEqual({
        state: "complete",
        issues: [],
      });
      expect(summary.summary).not.toHaveProperty("declarations");
    }
    await unlink(path);
    const request = (evidenceId: string) => ({
      source: { kind: "retained-evidence", evidence_id: evidenceId },
      view: {
        kind: "managed-members",
        collection: "marshalling",
        names: ["Text", "value"],
        declaring_types: ["Example.Native"],
        fields: ["native_type", "parameter_sequence", "method_token"],
        offset: 1,
        limit: 1,
      },
    });
    const cliPage = await cli.run({
      arguments: [
        "inspect-analysis-view",
        JSON.stringify(request(cliSummary.parent_evidence_id)),
        "--evidence-bundle",
        bundlePath,
        "--json",
      ],
    });
    expect(cliPage.exitCode, cliPage.stderr).toBe(0);
    const mcpPage = await call(
      "inspect_analysis_view",
      request(mcpSummary.parent_evidence_id),
    );
    expect(mcpPage.isError, JSON.stringify(mcpPage)).not.toBe(true);
    for (const [raw, parent] of [
      [cliPage.json, cliSummary.parent_evidence_id],
      [mcpPage.structuredContent, mcpSummary.parent_evidence_id],
    ] as const) {
      const evidence = parseEvidence(raw);
      expect(evidence.evidence_links).toEqual([parent]);
      const page = analysisViewResultSchema.parse(evidence.normalized_result);
      expect(page).toMatchObject({
        parent_evidence_id: parent,
        source_coverage: { state: "complete", issues: [] },
        coverage: { total: 2, examined: 1, next_offset: null },
        page: {
          collection: "marshalling",
          source_count: 5,
          rows: [
            {
              token: "0x0d000003",
              parent_raw: 5,
              parent_token: "0x08000002",
              method_token: "0x06000001",
              parameter_sequence: 1,
              native_type: { raw_hex: "2a04000401", root_name: "LPArray" },
              source_index: 2,
            },
          ],
        },
      });
      if (page.kind !== "managed-members") throw new Error("Wrong page kind");
      expect(page.page.rows[0]).not.toHaveProperty("parent_name");
      expect(page.page.rows[0]).toHaveProperty("row_offset");
    }
  },
);
