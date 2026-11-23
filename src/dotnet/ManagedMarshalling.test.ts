import { expect, it } from "vitest";
import { inspectManagedMembersBytes } from "./ManagedMemberInspector.js";
import {
  buildManagedMarshallingFixture,
  managedPeFixtureTarget,
} from "./ManagedPe.fixture.js";
import { managedMemberInspectionSchema } from "../domain/managed/managedArtifact.js";

const inspect = (
  bytes: Buffer,
  options: Parameters<typeof inspectManagedMembersBytes>[2] = {},
) => inspectManagedMembersBytes(bytes, managedPeFixtureTarget(bytes), options);

it("retains exact native descriptors for fields, parameters and return values", () => {
  const bytes = buildManagedMarshallingFixture();
  const report = inspect(bytes);
  expect(report.marshalling).toMatchObject({
    state: "complete",
    issues: [],
    declarations: [
      {
        token: "0x0d000001",
        parent_raw: 2,
        parent_kind: "field",
        parent_token: "0x04000001",
        parent_name: "Text",
        parent_flags: 0x1001,
        parameter_sequence: null,
        method_token: null,
        declaring_type: "Example.Native",
        native_type: {
          raw_hex: "14",
          byte_length: 1,
          root_code: 0x14,
          root_name: "LPStr",
        },
      },
      {
        token: "0x0d000002",
        parent_kind: "parameter",
        parent_token: "0x08000001",
        parent_name: "",
        parent_flags: 0x2000,
        parameter_sequence: 0,
        method_token: "0x06000001",
        method_name: "Invoke",
        declaring_type: "Example.Native",
        native_type: { raw_hex: "15", root_name: "LPWStr" },
      },
      {
        token: "0x0d000003",
        parent_token: "0x08000002",
        parent_name: "value",
        parameter_sequence: 1,
        method_name: "Invoke",
        native_type: { raw_hex: "2a04000401", root_name: "LPArray" },
      },
      {
        token: "0x0d000004",
        parent_token: "0x08000003",
        method_name: "Elsewhere",
        declaring_type: "Example.Other",
        native_type: { root_name: "Bool" },
      },
      {
        token: "0x0d000005",
        parent_token: "0x04000002",
        parent_name: "OtherText",
        native_type: { root_name: "SysInt" },
      },
    ],
  });
  for (const declaration of report.marshalling!.declarations) {
    const descriptor = declaration.native_type;
    expect(
      bytes
        .subarray(
          descriptor.data_offset!,
          descriptor.data_offset! + descriptor.byte_length!,
        )
        .toString("hex"),
    ).toBe(descriptor.raw_hex);
    expect(descriptor.blob_offset).toBeLessThan(descriptor.data_offset!);
    expect(declaration.row_offset).toBeGreaterThan(0);
  }
  expect(report.marshalling!.declarations[0]!.parent_row_offset).toBe(
    report.fields[0]!.row_offset,
  );
});

it("honors declaring-type selection and the examined MethodDef page independently", () => {
  const bytes = buildManagedMarshallingFixture();
  const selected = inspect(bytes, { typeNames: ["Example.Native"] });
  expect(selected.marshalling?.declarations.map(({ token }) => token)).toEqual([
    "0x0d000001",
    "0x0d000002",
    "0x0d000003",
  ]);
  expect(
    inspect(bytes, { typeNames: ["Example.Native"], methodLimit: 0 })
      .marshalling?.declarations,
  ).toMatchObject([{ parent_kind: "field", parent_name: "Text" }]);
  expect(
    inspect(bytes, {
      methodOffset: 1,
      methodLimit: 1,
    }).marshalling?.declarations.map(({ token }) => token),
  ).toEqual(["0x0d000001", "0x0d000004", "0x0d000005"]);
  expect(inspect(bytes, { typeNames: ["Missing"] }).marshalling).toEqual({
    state: "complete",
    declarations: [],
    issues: [],
  });
});

it("resolves physical ParamPtr and MethodPtr identities before filtering", () => {
  const report = inspect(
    buildManagedMarshallingFixture({
      parameterPointers: [3, 1, 2],
      methodPointers: [2, 1],
    }),
    { typeNames: ["Example.Native"] },
  );
  expect(report.methods[0]?.token).toBe("0x06000002");
  expect(report.marshalling).toMatchObject({
    state: "complete",
    declarations: [
      { parent_token: "0x04000001" },
      {
        parent_token: "0x08000002",
        method_token: "0x06000002",
        method_name: "Elsewhere",
        declaring_type: "Example.Native",
      },
    ],
  });
});

it("distinguishes empty parameter lists from parameters before the first owner", () => {
  const empty = inspect(
    buildManagedMarshallingFixture({
      parameterStarts: [1, 1],
      declarations: [{ parent: 3 }],
    }),
  );
  expect(empty.marshalling).toMatchObject({
    state: "complete",
    declarations: [
      {
        parent_token: "0x08000001",
        method_name: "Elsewhere",
        parameter_sequence: 0,
      },
    ],
  });
  const gap = inspect(
    buildManagedMarshallingFixture({
      parameterStarts: [2, 3],
      declarations: [{ parent: 3 }, { parent: 5 }],
    }),
  );
  expect(gap.marshalling).toMatchObject({
    state: "partial",
    declarations: [
      { parent_token: "0x08000001", method_token: null },
      { parent_token: "0x08000002", method_name: "Invoke" },
    ],
  });
});

it("does not need parameter ownership to inspect field-only declarations", () => {
  const result = inspect(
    buildManagedMarshallingFixture({
      parameterStarts: [0, 0],
      parameterPointers: [1, 1, 1],
      declarations: [{ parent: 2 }],
    }),
  );
  expect(result.marshalling).toMatchObject({
    state: "complete",
    issues: [],
    declarations: [
      {
        parent_token: "0x04000001",
        native_type: { raw_hex: "14" },
      },
    ],
  });
});

it("handles wide HasFieldMarshal and MethodDef.ParamList columns", () => {
  const result = inspect(
    buildManagedMarshallingFixture({
      parameterCount: 65536,
      declarations: [
        { parent: 65536 * 2 + 1, descriptor: Buffer.from([0x20]) },
      ],
    }),
  );
  expect(result.marshalling).toMatchObject({
    state: "complete",
    declarations: [
      {
        parent_raw: 131073,
        parent_token: "0x08010000",
        method_token: "0x06000002",
        native_type: { root_name: "SysUInt" },
      },
    ],
  });
});

it.each([0, 6, 9])(
  "retains invalid parent %i with exact descriptor and unknown membership",
  (parent) => {
    const result = inspect(
      buildManagedMarshallingFixture({ declarations: [{ parent }] }),
      { typeNames: ["Missing"] },
    );
    expect(result.marshalling).toMatchObject({
      state: "partial",
      declarations: [
        {
          parent_raw: parent,
          parent_kind: "unknown",
          parent_token: null,
          parent_name: null,
          declaring_type: null,
          native_type: { raw_hex: "14" },
        },
      ],
    });
    expect(result.coverage.state).toBe("complete");
  },
);

it.each([
  [0, 3],
  [3, 1],
  [1, 5],
])(
  "keeps parameters when ParamList ownership is malformed: %j",
  (...parameterStarts) => {
    const result = inspect(
      buildManagedMarshallingFixture({
        parameterStarts,
        declarations: [{ parent: 5 }],
      }),
      { typeNames: ["Missing"] },
    );
    expect(result.marshalling).toMatchObject({
      state: "partial",
      declarations: [
        {
          parent_token: "0x08000002",
          parent_name: "value",
          method_token: null,
          declaring_type: null,
        },
      ],
    });
    expect(result.marshalling?.issues).toHaveLength(1);
  },
);

it.each([
  [1, 1, 3],
  [1, 4, 3],
  [1, 3],
])(
  "retains ambiguous or missing ParamPtr ownership: %j",
  (...parameterPointers) => {
    const result = inspect(
      buildManagedMarshallingFixture({
        parameterPointers,
        declarations: [{ parent: 5 }],
      }),
    );
    expect(result.marshalling).toMatchObject({
      state: "partial",
      declarations: [
        {
          parent_token: "0x08000002",
          method_token: null,
          native_type: { raw_hex: "14" },
        },
      ],
    });
  },
);

it("preserves empty parameter names separately from malformed heap coordinates", () => {
  expect(
    inspect(buildManagedMarshallingFixture({ parameterName: "" })).marshalling,
  ).toMatchObject({
    state: "complete",
    declarations: [{}, {}, { parent_name: "" }, {}, {}],
  });
  const result = inspect(
    buildManagedMarshallingFixture({
      parameterNameIndex: 0xffff,
      declarations: [{ parent: 5 }],
    }),
  );
  expect(result.marshalling).toMatchObject({
    state: "partial",
    declarations: [
      {
        parent_name: null,
        method_name: "Invoke",
        parameter_sequence: 1,
        native_type: { raw_hex: "14" },
      },
    ],
  });
});

it("retains duplicate parents and unrecognized native-type bytes without normalizing them", () => {
  const result = inspect(
    buildManagedMarshallingFixture({
      declarations: [
        { parent: 2, descriptor: Buffer.from([0xfe, 0, 0xff]) },
        { parent: 2, descriptor: Buffer.from([0x02]) },
      ],
    }),
  );
  expect(result.marshalling).toMatchObject({
    state: "partial",
    declarations: [
      { native_type: { raw_hex: "fe00ff", root_code: 0xfe, root_name: null } },
      { native_type: { raw_hex: "02", root_name: "Bool" } },
    ],
  });
  expect(result.marshalling?.issues.map(({ code }) => code)).toEqual([
    "unsupported-metadata",
    "invalid-row",
  ]);
});

it.each([0, 0xffff])(
  "keeps parent facts when native descriptor index %i is empty or invalid",
  (blobIndex) => {
    const result = inspect(
      buildManagedMarshallingFixture({
        declarations: [{ parent: 2, blobIndex }],
      }),
    );
    expect(result.marshalling).toMatchObject({
      state: "partial",
      declarations: [
        {
          parent_token: "0x04000001",
          parent_name: "Text",
          native_type: {
            blob_index: blobIndex,
            raw_hex: blobIndex === 0 ? "" : null,
            root_code: null,
          },
        },
      ],
    });
    expect(result.coverage.state).toBe("complete");
  },
);

it("does not decode excluded owners or spend a row reservation for each excluded declaration", () => {
  const bytes = buildManagedMarshallingFixture({
    declarations: [
      ...Array.from({ length: 1500 }, () => ({ parent: 7, blobIndex: 0xffff })),
      { parent: 2 },
    ],
  });
  const result = inspect(bytes, {
    typeNames: ["Example.Native"],
    maxRepresentationBytes: 40000,
  });
  expect(result.marshalling).toMatchObject({
    state: "complete",
    declarations: [{ token: "0x0d0005dd", parent_name: "Text" }],
  });
});

it("preserves admitted members when descriptor expansion exceeds remaining capacity", () => {
  const bytes = buildManagedMarshallingFixture({
    declarations: [{ parent: 2, descriptor: Buffer.alloc(120000, 0x14) }],
  });
  const result = inspect(bytes, { maxRepresentationBytes: 60000 });
  expect(result.fields).toHaveLength(2);
  expect(result.methods).toHaveLength(2);
  expect(result.coverage.state).toBe("complete");
  expect(result.marshalling).toMatchObject({
    state: "partial",
    declarations: [],
    issues: [
      {
        code: "resource-limit",
        scope: "metadata.FieldMarshal",
        limit: { parameter: "max_metadata_representation_bytes" },
      },
    ],
  });
});

it("distinguishes examined empty metadata from historical omission and null", () => {
  const report = inspect(buildManagedMarshallingFixture({ declarations: [] }), {
    userStrings: false,
  });
  expect(report.marshalling).toEqual({
    state: "complete",
    declarations: [],
    issues: [],
  });
  const { marshalling, ...historical } = report;
  expect(marshalling).not.toBeNull();
  expect(managedMemberInspectionSchema.parse(historical)).not.toHaveProperty(
    "marshalling",
  );
  expect(
    managedMemberInspectionSchema.parse({ ...historical, marshalling: null })
      .marshalling,
  ).toBeNull();
});
