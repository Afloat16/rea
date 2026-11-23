import { expect, it } from "vitest";
import { managedMemberInspectionSchema } from "../domain/managed/managedArtifact.js";
import { inspectManagedMembersBytes } from "./ManagedMemberInspector.js";
import {
  buildManagedPeFixture,
  fixtureUserStringHeap,
  managedPeFixtureTarget,
} from "./ManagedPe.fixture.js";

const parameters = [
  { number: 0, flags: 0x0001, owner: 2, name: "TValue" },
  { number: 0, flags: 0x0014, owner: 3, name: "TResult" },
] as const;

const fixture = (overrides: Parameters<typeof buildManagedPeFixture>[0] = {}) =>
  buildManagedPeFixture({
    methodSignature: Buffer.from([0x10, 0x01, 0x00, 0x01]),
    genericParameters: parameters,
    genericConstraints: [
      { owner: 1, constraint: 9 },
      { owner: 2, constraint: 4 },
    ],
    typeReferences: [{ namespace: "System", name: "IDisposable" }],
    ...overrides,
  });

const inspect = (
  bytes: Buffer,
  options: Parameters<typeof inspectManagedMembersBytes>[2] = {},
) => inspectManagedMembersBytes(bytes, managedPeFixtureTarget(bytes), options);

it("retains physical generic declarations, owner coordinates, flags and constraint types", () => {
  const report = inspect(fixture());
  expect(report.metadata.table_row_counts).toMatchObject({
    GenericParam: 2,
    GenericParamConstraint: 2,
  });
  expect(report.generic_parameters).toMatchObject({
    state: "complete",
    issues: [],
    rows: [
      {
        token: "0x2a000001",
        number: 0,
        flags: 1,
        owner_coded_index: 2,
        owner_token: "0x02000001",
        owner_kind: "type",
        name: "TValue",
      },
      {
        token: "0x2a000002",
        number: 0,
        flags: 20,
        owner_coded_index: 3,
        owner_token: "0x06000001",
        owner_kind: "method",
        name: "TResult",
      },
    ],
    constraints: [
      {
        token: "0x2c000001",
        parameter_row: 1,
        parameter_token: "0x2a000001",
        owner_token: "0x02000001",
        constraint_coded_index: 9,
        constraint_token: "0x01000002",
        constraint_name: "System.IDisposable",
      },
      {
        token: "0x2c000002",
        parameter_row: 2,
        parameter_token: "0x2a000002",
        owner_token: "0x06000001",
        constraint_coded_index: 4,
        constraint_token: "0x02000001",
        constraint_name: "Fixture.Program",
      },
    ],
  });
});

it("records an empty examined inventory separately from historical omission", () => {
  const report = inspect(buildManagedPeFixture());
  expect(report.generic_parameters).toEqual({
    state: "complete",
    rows: [],
    constraints: [],
    issues: [],
  });
  const { generic_parameters: _omitted, ...historical } = report;
  expect(managedMemberInspectionSchema.parse(historical)).not.toHaveProperty(
    "generic_parameters",
  );
});

it("follows the returned MethodDef interval while retaining selected type parameters", () => {
  const report = inspect(
    fixture({
      methodRowCount: 2,
      genericParameters: [
        ...parameters,
        { number: 0, flags: 8, owner: 5, name: "TSecond" },
      ],
      genericConstraints: [
        { owner: 1, constraint: 9 },
        { owner: 2, constraint: 9 },
        { owner: 3, constraint: 9 },
      ],
    }),
    { methodOffset: 1, methodLimit: 1 },
  );
  expect(report.methods.map(({ token }) => token)).toEqual(["0x06000002"]);
  expect(report.generic_parameters?.rows.map(({ token }) => token)).toEqual([
    "0x2a000001",
    "0x2a000003",
  ]);
  expect(
    report.generic_parameters?.constraints.map(({ token }) => token),
  ).toEqual(["0x2c000001", "0x2c000003"]);
});

it("keeps exact owner type selection and does not infer owners from names", () => {
  const report = inspect(
    fixture({
      additionalEmptyTypes: 1,
      genericParameters: [parameters[0], { ...parameters[0], owner: 4 }],
      genericConstraints: [
        { owner: 1, constraint: 9 },
        { owner: 2, constraint: 9 },
      ],
    }),
    { typeNames: ["Fixture.Program"] },
  );
  expect(
    report.generic_parameters?.rows.map(({ owner_token }) => owner_token),
  ).toEqual(["0x02000002"]);
  expect(
    report.generic_parameters?.constraints.map(
      ({ parameter_token }) => parameter_token,
    ),
  ).toEqual(["0x2a000002"]);
});

it.each([0, 200, 201])(
  "retains a malformed owner %i instead of inventing an attribution",
  (owner) => {
    const report = inspect(
      fixture({
        genericParameters: [{ ...parameters[0], owner }],
        genericConstraints: [],
      }),
    );
    expect(report.generic_parameters).toMatchObject({
      state: "partial",
      rows: [
        { owner_coded_index: owner, owner_token: null, owner_kind: "unknown" },
      ],
    });
    expect(report.generic_parameters?.issues[0]?.scope).toContain(
      "GenericParam",
    );
    expect(report.coverage.state).toBe("complete");
  },
);

it("keeps an unreadable parameter name's row and its otherwise readable constraints", () => {
  const report = inspect(
    fixture({
      genericParameters: [{ ...parameters[0], nameIndex: 0xffff }],
      genericConstraints: [{ owner: 1, constraint: 9 }],
    }),
  );
  expect(report.generic_parameters).toMatchObject({
    state: "partial",
    rows: [{ token: "0x2a000001", name: null, name_index: 0xffff }],
    constraints: [
      { parameter_token: "0x2a000001", constraint_name: "System.IDisposable" },
    ],
  });
});

it("retains duplicate declarations and constraints with explicit uncertainty", () => {
  const report = inspect(
    fixture({
      genericParameters: [parameters[0], parameters[0]],
      genericConstraints: [
        { owner: 1, constraint: 9 },
        { owner: 1, constraint: 9 },
      ],
    }),
  );
  expect(report.generic_parameters).toMatchObject({ state: "partial" });
  expect(report.generic_parameters?.rows).toHaveLength(2);
  expect(report.generic_parameters?.constraints).toHaveLength(2);
  expect(
    report.generic_parameters?.issues.map(({ detail }) => detail).join(" "),
  ).toContain("Duplicate");
});

it.each([0, 3, 400])(
  "retains an unresolved constraint code %i and its physical association",
  (constraint) => {
    const report = inspect(
      fixture({ genericConstraints: [{ owner: 1, constraint }] }),
    );
    expect(report.generic_parameters).toMatchObject({
      state: "partial",
      constraints: [
        {
          parameter_token: "0x2a000001",
          constraint_coded_index: constraint,
          constraint_token: null,
          constraint_name: null,
        },
      ],
    });
  },
);

it("retains orphan constraint coordinates without treating them as a selected parameter", () => {
  const report = inspect(
    fixture({ genericConstraints: [{ owner: 99, constraint: 9 }] }),
  );
  expect(report.generic_parameters).toMatchObject({
    state: "partial",
    constraints: [
      {
        parameter_row: 99,
        parameter_token: null,
        owner_token: null,
        constraint_name: "System.IDisposable",
      },
    ],
  });
});

it("retains distinct constructed constraint tokens when nominal names agree", () => {
  const report = inspect(
    fixture({
      typeReferences: [{ namespace: "Contracts", name: "IContainer`1" }],
      typeSpecSignatures: [
        Buffer.from([0x15, 0x12, 9, 1, 0x08]),
        Buffer.from([0x15, 0x12, 9, 1, 0x0e]),
      ],
      genericConstraints: [
        { owner: 1, constraint: 6 },
        { owner: 1, constraint: 10 },
      ],
    }),
  );
  expect(report.generic_parameters).toMatchObject({
    state: "complete",
    constraints: [
      {
        constraint_token: "0x1b000001",
        constraint_name: "Contracts.IContainer`1",
      },
      {
        constraint_token: "0x1b000002",
        constraint_name: "Contracts.IContainer`1",
      },
    ],
  });
});

it("confines malformed constraint signature failures to the generic inventory", () => {
  const report = inspect(
    fixture({
      typeSpecSignatures: [Buffer.from([0x15])],
      genericConstraints: [{ owner: 1, constraint: 6 }],
    }),
  );
  expect(report.generic_parameters).toMatchObject({
    state: "partial",
    constraints: [{ constraint_token: "0x1b000001", constraint_name: null }],
    issues: [
      expect.objectContaining({
        code: "invalid-blob",
        scope: "metadata.TypeSpec:0x1b000001",
      }),
    ],
  });
  expect(report.coverage).toEqual({ state: "complete", issues: [] });
});

it("reads four-byte TypeDefOrRef and string indexes without losing the constraint row", () => {
  const typeReferences = Array.from({ length: 16_383 }, (_, index) => ({
    namespace: "Contracts",
    name: `I${index}`,
  }));
  const report = inspect(
    fixture({
      typeReferences,
      genericConstraints: [{ owner: 1, constraint: 65_537 }],
    }),
  );
  expect(report.generic_parameters).toMatchObject({
    state: "complete",
    rows: [{ name: "TValue" }, { name: "TResult" }],
    constraints: [
      {
        constraint_coded_index: 65_537,
        constraint_token: "0x01004000",
        constraint_name: "Contracts.I16382",
      },
    ],
  });
});

it("reads four-byte TypeOrMethodDef indexes for the selected physical method", () => {
  const report = inspect(
    fixture({
      methodRowCount: 32_768,
      genericParameters: [{ ...parameters[1], owner: 65_537 }],
      genericConstraints: [{ owner: 1, constraint: 9 }],
    }),
    { methodOffset: 32_767, methodLimit: 1 },
  );
  expect(report.generic_parameters).toMatchObject({
    state: "complete",
    rows: [
      { owner_coded_index: 65_537, owner_token: "0x06008000", name: "TResult" },
    ],
    constraints: [{ owner_token: "0x06008000" }],
  });
});

it("reads a four-byte GenericParam owner index after excluded declarations", () => {
  const report = inspect(
    fixture({
      additionalEmptyTypes: 1,
      genericParameters: [
        ...Array.from({ length: 65_535 }, () => parameters[0]),
        { ...parameters[0], owner: 4 },
      ],
      genericConstraints: [{ owner: 65_536, constraint: 9 }],
    }),
    { typeNames: ["Fixture.Program"] },
  );
  expect(report.generic_parameters).toMatchObject({
    state: "complete",
    rows: [{ token: "0x2a010000", owner_token: "0x02000002" }],
    constraints: [
      {
        parameter_row: 65_536,
        parameter_token: "0x2a010000",
        owner_token: "0x02000002",
      },
    ],
  });
});

it("preserves members and requested literals when only generic names exceed capacity", () => {
  const { heap, tokens } = fixtureUserStringHeap(["retained literal"]);
  const token = tokens[0];
  if (token === undefined) throw new Error("Missing literal token");
  const ilBody = Buffer.from([0x1e, 0x72, 0, 0, 0, 0, 0x26, 0x2a]);
  ilBody.writeUInt32LE(Number.parseInt(token, 16), 2);
  const bytes = fixture({
    targetFramework: null,
    userStringHeap: heap,
    ilBody,
    genericParameters: [{ ...parameters[0], name: `T${"x".repeat(8_000)}` }],
    genericConstraints: [{ owner: 1, constraint: 9 }],
  });
  const complete = inspect(bytes);
  const limited = inspect(bytes, { maxRepresentationBytes: 40_000 });
  expect(complete.generic_parameters?.state).toBe("complete");
  expect(limited).toMatchObject({
    methods: complete.methods,
    fields: complete.fields,
    coverage: complete.coverage,
    user_strings: complete.user_strings,
    generic_parameters: {
      state: "partial",
      rows: [],
      constraints: [],
      issues: [{ code: "resource-limit", scope: "metadata.GenericParam" }],
    },
  });
  expect(limited.methods).toHaveLength(1);
  expect(limited.user_strings?.literals.map(({ value }) => value)).toEqual([
    "retained literal",
  ]);
});

it("filters unrelated parameter and constraint rows before reserving decoded capacity", () => {
  const report = inspect(
    fixture({
      additionalEmptyTypes: 1,
      genericParameters: [
        ...Array.from({ length: 1_200 }, (_, number) => ({
          ...parameters[0],
          number,
        })),
        { ...parameters[0], owner: 4, name: "TSelected" },
      ],
      genericConstraints: Array.from({ length: 1_201 }, (_, index) => ({
        owner: index + 1,
        constraint: 9,
      })),
    }),
    { typeNames: ["Fixture.Program"], maxRepresentationBytes: 40_000 },
  );
  expect(report.generic_parameters).toMatchObject({
    state: "complete",
    issues: [],
    rows: [
      { token: "0x2a0004b1", owner_token: "0x02000002", name: "TSelected" },
    ],
    constraints: [
      {
        token: "0x2c0004b1",
        parameter_token: "0x2a0004b1",
        constraint_name: "System.IDisposable",
      },
    ],
  });
});

it("keeps the facet unexamined when even its bounded recovery cannot be admitted", () => {
  const bytes = buildManagedPeFixture({
    genericParameters: [{ number: 0, flags: 0, owner: 2, name: "T" }],
  });
  const complete = inspect(bytes);
  const limited = inspect(bytes, { maxRepresentationBytes: 20_000 });
  expect(complete.generic_parameters).toMatchObject({
    state: "complete",
    rows: [{ name: "T" }],
  });
  expect(limited).toMatchObject({
    methods: complete.methods,
    fields: complete.fields,
    coverage: complete.coverage,
    user_strings: complete.user_strings,
    generic_parameters: null,
  });
  expect(limited.methods).toHaveLength(1);
});

it("keeps live generic owner bookkeeping charged across nested TypeSpec decoding", () => {
  const bytes = buildManagedPeFixture({
    genericParameters: Array.from({ length: 500 }, (_, number) => ({
      number,
      flags: 0,
      owner: 2,
      name: "T",
    })),
    genericConstraints: Array.from({ length: 500 }, (_, index) => ({
      owner: index + 1,
      constraint: index === 0 ? 6 : 9,
    })),
    typeReferences: [{ namespace: "Contracts", name: "I`1" }],
    typeSpecSignatures: [Buffer.from([0x15, 0x12, 9, 1, 0x08])],
  });
  const complete = inspect(bytes, { maxRepresentationBytes: 900_000 });
  const limited = inspect(bytes, { maxRepresentationBytes: 600_000 });
  expect(complete.generic_parameters).toMatchObject({
    state: "complete",
    issues: [],
  });
  expect(complete.generic_parameters?.constraints).toHaveLength(500);
  expect(limited).toMatchObject({
    methods: complete.methods,
    coverage: complete.coverage,
    generic_parameters: {
      state: "partial",
      rows: [],
      constraints: [],
      issues: [{ code: "resource-limit" }],
    },
  });
});
