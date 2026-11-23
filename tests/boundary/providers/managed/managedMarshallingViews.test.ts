import { expect, it } from "vitest";
import { inspectManagedMembersBytes } from "../../../../src/dotnet/ManagedMemberInspector.js";
import {
  buildManagedMarshallingFixture,
  managedPeFixtureTarget,
} from "../../../../src/dotnet/ManagedPe.fixture.js";
import { managedMembersViewRequestSchema } from "../../../../src/domain/analysisView/managedMemberViewSchemas.js";
import { projectManagedMemberView } from "../../../../src/domain/analysisView/managedMemberView.js";
import type { AnalysisViewParent } from "../../../../src/domain/analysisView/analysisViewParent.js";
const parent = (normalizedResult: unknown): AnalysisViewParent => ({
  predicateType: "rea.analysis",
  evidenceId: `ev_${"a".repeat(64)}`,
  operation: "inspect_managed_members",
  normalizedResult,
  sealedResult: true,
  limitations: [],
});

it("keeps marshalling coverage separate from members and preserves historical unknowns", () => {
  const bytes = buildManagedMarshallingFixture({
    declarations: [{ parent: 0 }, { parent: 2 }],
  });
  const report = inspectManagedMembersBytes(
    bytes,
    managedPeFixtureTarget(bytes),
  );
  const request = managedMembersViewRequestSchema.parse({
    kind: "managed-members",
    collection: "marshalling",
    fields: ["native_type"],
    names: ["Text"],
    declaring_types: ["Example.Native"],
  });
  const result = projectManagedMemberView(parent(report), request);
  expect(result).toMatchObject({
    ok: true,
    value: {
      source_coverage: { state: "partial" },
      coverage: { total: 1 },
      page: {
        source_count: 2,
        unresolved_filter_rows: 1,
        rows: [{ token: "0x0d000002", native_type: { raw_hex: "14" } }],
      },
    },
  });
  expect(report.coverage.state).toBe("complete");
  const { marshalling, ...historical } = report;
  expect(marshalling).not.toBeNull();
  expect(projectManagedMemberView(parent(historical), request)).toMatchObject({
    ok: false,
  });
  expect(
    projectManagedMemberView(
      parent({ ...historical, marshalling: null }),
      request,
    ),
  ).toMatchObject({ ok: false });
  const summary = projectManagedMemberView(parent(historical), {
    kind: "summary",
  });
  expect(summary).toMatchObject({ ok: true });
  if (summary.ok && "summary" in summary.value) {
    expect(summary.value.summary).not.toHaveProperty("marshalling");
    expect(summary.value.summary.reported_counts).not.toHaveProperty(
      "marshalling",
    );
  }
});
