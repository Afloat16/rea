import { expect, it } from "vitest";
import { managedMemberInspectionSchema } from "../domain/managed/managedArtifact.js";
import { inspectManagedMembersBytes } from "./ManagedMemberInspector.js";
import {
  buildManagedMethodImplFixture,
  managedPeFixtureTarget,
} from "./ManagedPe.fixture.js";

const inspect = (
  bytes: Buffer,
  options: Parameters<typeof inspectManagedMembersBytes>[2] = {},
) => inspectManagedMembersBytes(bytes, managedPeFixtureTarget(bytes), options);

it("retains explicit implementation links to both MemberRef and MethodDef declarations", () => {
  const result = inspect(buildManagedMethodImplFixture());
  expect(result.method_implementations).toMatchObject({
    state: "complete",
    issues: [],
    declarations: [
      {
        token: "0x19000001",
        class_raw: 2,
        class_token: "0x02000002",
        class_name: "Example.Implementation",
        body: {
          raw: 2,
          token: "0x06000001",
          kind: "method-def",
          name: "Execute",
          declaring_type: "Example.Implementation",
          member_kind: "method",
        },
        declaration: {
          raw: 3,
          token: "0x0a000001",
          kind: "member-ref",
          name: "Run",
          declaring_type: "Example.IRemote",
          member_kind: "method",
        },
      },
      {
        token: "0x19000002",
        class_raw: 4,
        class_name: "Example.Unrelated",
        body: { token: "0x06000003", name: "Elsewhere" },
        declaration: {
          raw: 4,
          token: "0x06000002",
          name: "Required",
          declaring_type: "Example.Contract",
        },
      },
    ],
  });
  const row = result.method_implementations!.declarations[0]!;
  expect(row.row_offset).toBeGreaterThan(0);
  expect(row.body.row_offset).toBe(result.methods[0]!.row_offset);
  expect(row.declaration.row_offset).toBe(result.member_refs[0]!.row_offset);
});

it("scopes by returned types and names targets outside the returned method page", () => {
  const result = inspect(buildManagedMethodImplFixture(), {
    typeNames: ["Example.Implementation"],
    methodLimit: 0,
  });
  expect(result.methods).toEqual([]);
  expect(result.method_implementations).toMatchObject({
    state: "complete",
    declarations: [
      {
        class_name: "Example.Implementation",
        body: { name: "Execute" },
        declaration: { name: "Run" },
      },
    ],
  });
  expect(
    inspect(buildManagedMethodImplFixture(), { typeNames: ["Missing.Type"] })
      .method_implementations,
  ).toEqual({ state: "complete", declarations: [], issues: [] });
});

it("preserves physical MethodDef identities when MethodPtr changes the owning type", () => {
  const result = inspect(
    buildManagedMethodImplFixture({ methodPointers: [3, 2, 1] }),
    { typeNames: ["Example.Implementation"] },
  );
  expect(result.methods.map(({ token }) => token)).toEqual(["0x06000003"]);
  expect(result.method_implementations?.declarations[0]).toMatchObject({
    class_name: "Example.Implementation",
    body: {
      token: "0x06000001",
      name: "Execute",
      declaring_type: "Example.Unrelated",
    },
  });
});

it("retains a MemberRef body without mistaking it for a physical MethodDef", () => {
  const result = inspect(
    buildManagedMethodImplFixture({ declarations: [[2, 3, 4]] }),
  );
  expect(result.method_implementations?.declarations[0]).toMatchObject({
    body: { raw: 3, token: "0x0a000001", kind: "member-ref", name: "Run" },
    declaration: {
      raw: 4,
      token: "0x06000002",
      kind: "method-def",
      name: "Required",
    },
  });
});

it.each([0, 8, 5])(
  "keeps invalid MethodBody coordinate %i with a readable declaration",
  (raw) => {
    const result = inspect(
      buildManagedMethodImplFixture({ declarations: [[2, raw, 3]] }),
    );
    expect(result.method_implementations).toMatchObject({
      state: "partial",
      declarations: [
        {
          body: { raw, token: null, kind: "unknown", name: null },
          declaration: { name: "Run" },
        },
      ],
    });
    expect(result.coverage.state).toBe("complete");
  },
);

it.each([0, 8, 5])(
  "keeps invalid MethodDeclaration coordinate %i with a readable body",
  (raw) => {
    const result = inspect(
      buildManagedMethodImplFixture({ declarations: [[2, 2, raw]] }),
    );
    expect(result.method_implementations).toMatchObject({
      state: "partial",
      declarations: [
        {
          body: { name: "Execute" },
          declaration: { raw, token: null, kind: "unknown", name: null },
        },
      ],
    });
  },
);

it.each([0, 5])(
  "retains unknown membership for invalid Class row %i",
  (owner) => {
    const result = inspect(
      buildManagedMethodImplFixture({
        declarations: [
          [owner, 2, 3],
          [4, 6, 4],
        ],
      }),
      { typeNames: ["Example.Unrelated"] },
    );
    expect(result.method_implementations).toMatchObject({
      state: "partial",
      declarations: [
        {
          class_raw: owner,
          class_token: null,
          class_name: null,
          body: { name: "Execute" },
        },
        { class_token: "0x02000004", class_name: "Example.Unrelated" },
      ],
    });
  },
);

it("retains duplicate class/declaration pairs without silently choosing a body", () => {
  const result = inspect(
    buildManagedMethodImplFixture({
      declarations: [
        [2, 2, 3],
        [2, 6, 3],
      ],
    }),
  );
  expect(result.method_implementations?.state).toBe("partial");
  expect(
    result.method_implementations?.declarations.map(({ body }) => body.token),
  ).toEqual(["0x06000001", "0x06000003"]);
  expect(
    result.method_implementations?.issues.some(({ detail }) =>
      detail.includes("Duplicate Class"),
    ),
  ).toBe(true);
});

it("keeps a field MemberRef coordinate while refusing to label its kind as a method", () => {
  const result = inspect(
    buildManagedMethodImplFixture({
      memberRefSignature: Buffer.from([0x06, 0x08]),
    }),
  );
  expect(result.method_implementations?.state).toBe("partial");
  expect(
    result.method_implementations?.declarations[0]?.declaration,
  ).toMatchObject({
    raw: 3,
    token: "0x0a000001",
    name: "Run",
    member_kind: "field",
  });
  expect(result.coverage.state).toBe("complete");
});

it("preserves an unreadable body name beside the original token and readable declaration", () => {
  const result = inspect(buildManagedMethodImplFixture({ methodName: "" }));
  expect(result.method_implementations?.state).toBe("partial");
  expect(result.method_implementations?.declarations[0]).toMatchObject({
    body: { raw: 2, token: "0x06000001", name: null },
    declaration: { name: "Run" },
  });
});

it("distinguishes an examined empty table from historical omission", () => {
  const result = inspect(buildManagedMethodImplFixture({ declarations: [] }));
  expect(result.method_implementations).toEqual({
    state: "complete",
    declarations: [],
    issues: [],
  });
  const { method_implementations: _facet, ...historical } = result;
  expect(managedMemberInspectionSchema.parse(historical)).not.toHaveProperty(
    "method_implementations",
  );
});

it("keeps previously admitted member facts when the implementation facet exceeds capacity", () => {
  const bytes = buildManagedMethodImplFixture({
    declarations: Array.from({ length: 1200 }, () => [2, 2, 3] as const),
  });
  const result = inspect(bytes, { maxRepresentationBytes: 48_000 });
  expect(result.methods).toHaveLength(3);
  expect(result.coverage.state).toBe("complete");
  expect(result.method_implementations).toMatchObject({
    state: "partial",
    declarations: [],
    issues: [{ code: "resource-limit" }],
  });
});

it("skips unselected rows before spending decoded-row capacity or resolving their malformed targets", () => {
  const bytes = buildManagedMethodImplFixture({
    declarations: [
      ...Array.from({ length: 1200 }, () => [4, 0xffff, 0xffff] as const),
      [2, 2, 3],
    ],
  });
  const result = inspect(bytes, {
    typeNames: ["Example.Implementation"],
    maxRepresentationBytes: 48_000,
  });
  expect(result.method_implementations).toMatchObject({
    state: "complete",
    issues: [],
    declarations: [{ body: { name: "Execute" } }],
  });
});

it("reads wide MethodDefOrRef coordinates without decoding an unselected method inventory", () => {
  const result = inspect(
    buildManagedMethodImplFixture({
      methodCount: 32768,
      declarations: [[2, 65536, 3]],
    }),
    { typeNames: ["Example.Implementation"] },
  );
  expect(result.methods).toHaveLength(1);
  expect(result.method_implementations).toMatchObject({
    state: "complete",
    declarations: [
      {
        body: {
          raw: 65536,
          token: "0x06008000",
          name: "Extra",
          declaring_type: "Example.Unrelated",
        },
        declaration: { name: "Run" },
      },
    ],
  });
});
