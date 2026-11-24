import { expect, it } from "vitest";
import { MANAGED_RECONSTRUCTION_IMPORT_EXAMPLE } from "../../contracts/managed/managedWorkflowExamples.js";
import { managedMemberInspectionSchema } from "../managed/managedArtifact.js";
import {
  managedMembersViewRequestSchema,
  managedMembersViewPageSchema,
  managedMemberSummarySchema,
} from "./managedMemberViewSchemas.js";
import { projectManagedMemberView } from "./managedMemberView.js";
import type { AnalysisViewParent } from "./analysisViewParent.js";

const source = () =>
  managedMemberInspectionSchema.parse(
    MANAGED_RECONSTRUCTION_IMPORT_EXAMPLE.static_members.normalized_result,
  );
const parent = (normalizedResult: unknown): AnalysisViewParent => ({
  predicateType: "rea.analysis",
  evidenceId: `ev_${"a".repeat(64)}`,
  operation: "inspect_managed_members",
  normalizedResult,
  sealedResult: true,
  limitations: [],
});
const request = (extra: object = {}) =>
  managedMembersViewRequestSchema.parse({
    kind: "managed-members",
    collection: "security_declarations",
    offset: 0,
    limit: 1,
    ...extra,
  });

it("preserves historical omission and explicit unexamined security without asserting absence", () => {
  for (const facet of [undefined, null]) {
    const report = source();
    if (facet === null) report.security_declarations = null;
    const summary = projectManagedMemberView(parent(report), {
      kind: "summary",
    });
    if (!summary.ok || !("summary" in summary.value))
      throw new Error("Missing summary");
    expect(managedMemberSummarySchema.parse(summary.value.summary)).toEqual(
      summary.value.summary,
    );
    if (facet === null)
      expect(
        summary.value.summary.reported_counts.security_declarations,
      ).toBeNull();
    else
      expect(summary.value.summary.reported_counts).not.toHaveProperty(
        "security_declarations",
      );
    expect(projectManagedMemberView(parent(report), request())).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  }
});

it("counts examined declarations and preserves scope and own coverage when filtering projected rows", () => {
  const report = source();
  const row = {
    token: "0x0e000001",
    row_offset: 300,
    parent_raw: 6,
    parent_token: "0x20000001",
    parent_kind: "Assembly" as const,
    parent_name: "Example",
    parent_flags: 0,
    declaring_type_token: null,
    declaring_type: null,
    action: 8,
    action_name: "RequestMinimum",
    permission_set: null,
  };
  report.security_declarations = {
    state: "partial",
    declarations: [
      row,
      { ...row, token: "0x0e000002", row_offset: 306, parent_name: null },
      { ...row, token: "0x0e000003", row_offset: 312 },
    ],
    issues: [
      {
        code: "invalid-blob",
        scope: "metadata.DeclSecurity",
        offset: 400,
        detail: "fixture",
      },
    ],
  };
  const summary = projectManagedMemberView(parent(report), { kind: "summary" });
  expect(summary).toMatchObject({
    ok: true,
    value: {
      summary: {
        reported_counts: { security_declarations: 3 },
        security_declarations: {
          state: "partial",
          issues: report.security_declarations.issues,
        },
      },
    },
  });
  const result = projectManagedMemberView(
    parent(report),
    request({ names: ["Example"], fields: ["action_name"], offset: 1 }),
  );
  if (!result.ok || !("page" in result.value)) throw new Error("Missing page");
  expect(managedMembersViewPageSchema.parse(result.value.page)).toEqual(
    result.value.page,
  );
  expect(result.value).toMatchObject({
    source_coverage: {
      state: "partial",
      issues: report.security_declarations.issues,
    },
    coverage: { total: 2, examined: 1 },
    page: {
      source_count: 3,
      unresolved_filter_rows: 1,
      rows: [
        {
          token: "0x0e000003",
          row_offset: 312,
          parent_token: "0x20000001",
          parent_raw: 6,
          source_index: 2,
          action_name: "RequestMinimum",
        },
      ],
    },
  });
  expect(result.value.page.rows[0]).not.toHaveProperty("permission_set");
});
