import { createHash } from "node:crypto";
import { writeFile, unlink, readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { buildManagedPeFixture } from "../../src/dotnet/ManagedPe.fixture.js";
import { managedMemberInspectionSchema } from "../../src/domain/managed/managedArtifact.js";
import { parseEvidence } from "../../src/domain/evidence.js";
import {
  analysisViewResultSchema,
  managedMemberSummaryViewResultSchema,
} from "../../src/domain/analysisView/analysisViewResult.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

cliTest(
  "retains security declarations from public CLI and stdio MCP through summary, filtering and paging after source removal",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-managed-security-");
    const path = join(root, "declarations.dll");
    const permissionSet = Buffer.from([
      0x2e, 1, 4, 0x54, 0x65, 0x73, 0x74, 1, 0,
    ]);
    const bytes = buildManagedPeFixture({
      securityDeclarations: [
        { parent: 6, action: 8, permissionSet },
        { parent: 4, action: 6, permissionSet },
        { parent: 5, action: 2, permissionSet },
        { parent: 7, action: 2, permissionSet },
      ],
    });
    await writeFile(path, bytes);
    const output = await cli.run({
      arguments: ["inspect-managed-members", path, "--json"],
    });
    expect(output.exitCode, output.stderr).toBe(0);
    const cliEvidence = parseEvidence(output.json);
    const report = managedMemberInspectionSchema.parse(
      cliEvidence.normalized_result,
    );
    expect(report.artifact.sha256).toBe(
      createHash("sha256").update(bytes).digest("hex"),
    );
    expect(report.security_declarations).toMatchObject({
      state: "partial",
      declarations: [
        { parent_kind: "Assembly" },
        { parent_kind: "TypeDef" },
        { parent_kind: "MethodDef" },
        { parent_kind: "unknown" },
      ],
    });
    const call = await cli.sharedMcpCall!();
    const complete = await call("inspect_managed_members", { path });
    expect(complete.isError, JSON.stringify(complete)).not.toBe(true);
    const parent = parseEvidence(complete.structuredContent);
    expect(parent.normalized_result).toEqual(report);
    const summaryReply = await call("inspect_managed_members", {
      path,
      detail: "summary",
    });
    expect(summaryReply.isError, JSON.stringify(summaryReply)).not.toBe(true);
    const summary = managedMemberSummaryViewResultSchema.parse(
      parseEvidence(summaryReply.structuredContent).normalized_result,
    );
    expect(summary.parent_evidence_id).toBe(parent.evidence_id);
    expect(summary.summary.reported_counts.security_declarations).toBe(4);
    expect(summary.summary.security_declarations).toEqual({
      state: "partial",
      issues: report.security_declarations!.issues,
    });
    expect(summary.summary.security_declarations).not.toHaveProperty(
      "declarations",
    );
    expect(Buffer.compare(await readFile(path), bytes)).toBe(0);
    await unlink(path);
    const projectedReply = await call("inspect_analysis_view", {
      source: { kind: "retained-evidence", evidence_id: parent.evidence_id },
      view: {
        kind: "managed-members",
        collection: "security_declarations",
        names: ["Main"],
        fields: ["parent_name", "action_name"],
        offset: 0,
        limit: 1,
      },
    });
    expect(projectedReply.isError, JSON.stringify(projectedReply)).not.toBe(
      true,
    );
    const evidence = parseEvidence(projectedReply.structuredContent);
    expect(evidence.evidence_links).toEqual([parent.evidence_id]);
    const projected = analysisViewResultSchema.parse(
      evidence.normalized_result,
    );
    expect(projected).toMatchObject({
      kind: "managed-members",
      source_coverage: {
        state: "partial",
        issues: report.security_declarations!.issues,
      },
      identity_scope: report.identity_scope,
      page: {
        collection: "security_declarations",
        source_count: 4,
        unresolved_filter_rows: 1,
        rows: [
          {
            source_index: 2,
            token: "0x0e000003",
            parent_token: "0x06000001",
            parent_raw: 5,
            parent_name: "Main",
            action_name: "Demand",
          },
        ],
      },
    });
  },
);
