import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import {
  buildManagedPeFixture,
  buildManagedMemberPointerFixture,
  managedPeFixtureTarget,
} from "./ManagedPe.fixture.js";
import { inspectManagedMembersBytes } from "./ManagedMemberInspector.js";
import { readManagedPeLayout } from "../domain/managed/managedPeReader.js";
import {
  readManagedMetadataLayout,
  metadataRowOffset,
} from "../domain/managed/managedMetadataLayout.js";
import {
  metadataRowCursor,
  readMetadataBlob,
} from "../domain/managed/managedMetadataHeaps.js";

const permission = Buffer.from([0x2e, 1, 4, 0x54, 0x65, 0x73, 0x74, 1, 0]);
const declaration = (parent = 6, action = 8, permissionSet = permission) => ({
  parent,
  action,
  permissionSet,
});
const inspect = (
  bytes: Buffer,
  options: Parameters<typeof inspectManagedMembersBytes>[2] = {},
) => inspectManagedMembersBytes(bytes, managedPeFixtureTarget(bytes), options);
const layoutOf = (bytes: Buffer) => {
  const pe = readManagedPeLayout(bytes);
  return readManagedMetadataLayout(
    bytes,
    pe.rvaToOffset(pe.cli!.metadata.rva, pe.cli!.metadata.size, "fixture"),
    pe.cli!.metadata.size,
  );
};

it("reports all three parent kinds with original row/blob coordinates and exact bytes", () => {
  const bytes = buildManagedPeFixture({
    securityDeclarations: [declaration(), declaration(4, 6), declaration(5, 2)],
  });
  const report = inspect(bytes);
  expect(report.security_declarations).toMatchObject({
    state: "complete",
    issues: [],
    declarations: [
      {
        token: "0x0e000001",
        parent_kind: "Assembly",
        parent_token: "0x20000001",
        parent_raw: 6,
        parent_name: "Fixture.Managed",
        action: 8,
        action_name: "RequestMinimum",
      },
      {
        token: "0x0e000002",
        parent_kind: "TypeDef",
        parent_token: "0x02000001",
        parent_name: "Fixture.Program",
        action_name: "LinkDemand",
      },
      {
        token: "0x0e000003",
        parent_kind: "MethodDef",
        parent_token: "0x06000001",
        parent_name: "Main",
        declaring_type: "Fixture.Program",
        action_name: "Demand",
      },
    ],
  });
  const layout = layoutOf(bytes);
  for (const [
    index,
    row,
  ] of report.security_declarations!.declarations.entries()) {
    const cursor = metadataRowCursor(bytes, layout, 14, index + 1);
    cursor.u16();
    cursor.readIndex(layout.codedIndexSize("HasDeclSecurity"));
    const blobIndex = cursor.readIndex(layout.blobIndexSize);
    const raw = readMetadataBlob(bytes, layout, blobIndex);
    expect(row.row_offset).toBe(metadataRowOffset(layout, 14, index + 1));
    expect(row.permission_set).toMatchObject({
      blob_index: blobIndex,
      data_offset: raw.byteOffset - bytes.byteOffset,
      byte_length: permission.length,
      sha256: createHash("sha256").update(permission).digest("hex"),
      raw_hex: permission.toString("hex"),
      format: "binary",
      attribute_count: 1,
      attributes: [
        { type_name: "Test", named_argument_count: 0, arguments_hex: "00" },
      ],
    });
  }
});

it("distinguishes an examined empty table from a historical missing facet", () => {
  expect(inspect(buildManagedPeFixture()).security_declarations).toEqual({
    state: "complete",
    declarations: [],
    issues: [],
  });
});

it("keeps assembly declarations beside selected types and physical method pages", () => {
  const bytes = buildManagedPeFixture({
    additionalEmptyTypes: 1,
    methodRowCount: 2,
    firstTypeMethodRowCount: 1,
    securityDeclarations: [
      declaration(),
      declaration(4, 6),
      declaration(8, 6),
      declaration(5, 2),
      declaration(9, 2),
    ],
  });
  expect(
    inspect(bytes, {
      typeNames: ["Fixture.Program"],
    }).security_declarations?.declarations.map((row) => row.parent_token),
  ).toEqual(["0x20000001", "0x02000002", "0x06000002"]);
  expect(
    inspect(bytes, {
      methodOffset: 1,
      methodLimit: 1,
    }).security_declarations?.declarations.map((row) => row.parent_token),
  ).toEqual(["0x20000001", "0x02000001", "0x02000002", "0x06000002"]);
});

it.each([0, 7, 0xfffc])(
  "preserves invalid parent %i as unknown without erasing a later valid row",
  (parent) => {
    const report = inspect(
      buildManagedPeFixture({
        securityDeclarations: [declaration(parent), declaration()],
      }),
    );
    expect(report.security_declarations).toMatchObject({
      state: "partial",
      declarations: [
        { parent_raw: parent, parent_kind: "unknown", parent_token: null },
        { parent_kind: "Assembly" },
      ],
    });
    expect(report.security_declarations!.issues.length).toBeGreaterThan(0);
    expect(report.methods).toHaveLength(1);
  },
);

it("keeps a valid binary attribute before a truncated later attribute", () => {
  const malformed = Buffer.from([...permission]);
  malformed[1] = 2;
  const report = inspect(
    buildManagedPeFixture({
      securityDeclarations: [declaration(6, 8, malformed)],
    }),
  );
  expect(report.security_declarations).toMatchObject({
    state: "partial",
    declarations: [
      {
        permission_set: {
          raw_hex: malformed.toString("hex"),
          attribute_count: 2,
          attributes: [{ type_name: "Test" }],
        },
      },
    ],
  });
});

it("retains legacy permission bytes as opaque and leaves members complete", () => {
  const xml = Buffer.from(
    '<PermissionSet class="System.Security.PermissionSet"/>',
    "utf16le",
  );
  const report = inspect(
    buildManagedPeFixture({ securityDeclarations: [declaration(6, 8, xml)] }),
  );
  expect(report.security_declarations).toMatchObject({
    state: "partial",
    declarations: [
      {
        permission_set: {
          format: "legacy-or-unknown",
          raw_hex: xml.toString("hex"),
          attributes: [],
          attribute_count: null,
        },
      },
    ],
  });
  expect(report.coverage.state).toBe("complete");
});

it.each([
  ["empty", Buffer.alloc(0)],
  ["missing count", Buffer.from([0x2e])],
  ["reserved count", Buffer.from([0x2e, 0xff])],
  ["truncated type name", Buffer.from([0x2e, 1, 12, 0x54])],
  ["payload leaves blob", Buffer.from([0x2e, 1, 1, 0x54, 8, 0])],
  [
    "named count crosses its block",
    Buffer.from([0x2e, 1, 1, 0x54, 1, 0x80, 0]),
  ],
  ["trailing bytes", Buffer.from([0x2e, 0, 0])],
] as const)("reports %s without hiding byte provenance", (_name, value) => {
  const report = inspect(
    buildManagedPeFixture({
      securityDeclarations: [declaration(6, 8, value)],
    }),
  );
  expect(report.security_declarations?.state).toBe("partial");
  expect(
    report.security_declarations?.declarations[0]?.permission_set?.raw_hex,
  ).toBe(value.toString("hex"));
});

it("retains an invalid UTF8 attribute name's bytes and continues at the next framed attribute", () => {
  const value = Buffer.from([0x2e, 2, 1, 0xff, 1, 0, 1, 0x54, 1, 0]);
  const report = inspect(
    buildManagedPeFixture({
      securityDeclarations: [declaration(6, 8, value)],
    }),
  );
  expect(report.security_declarations).toMatchObject({
    state: "partial",
    declarations: [
      {
        permission_set: {
          attributes: [
            { type_name: null, type_name_hex: "ff" },
            { type_name: "T" },
          ],
        },
      },
    ],
  });
});

it("reports nonminimal compressed values while keeping readable attributes", () => {
  const value = Buffer.from([0x2e, 0x80, 1, ...permission.subarray(2)]);
  const report = inspect(
    buildManagedPeFixture({
      securityDeclarations: [declaration(6, 8, value)],
    }),
  );
  expect(report.security_declarations).toMatchObject({
    state: "partial",
    declarations: [{ permission_set: { attributes: [{ type_name: "Test" }] } }],
  });
});

it("preserves duplicate declarations and unknown action codes with diagnostics", () => {
  const report = inspect(
    buildManagedPeFixture({
      securityDeclarations: [
        declaration(),
        declaration(),
        declaration(6, 0xffff),
      ],
    }),
  );
  expect(report.security_declarations).toMatchObject({
    state: "partial",
    declarations: [
      { action: 8 },
      { action: 8 },
      { action: 0xffff, action_name: null },
    ],
  });
  expect(
    report.security_declarations!.issues.some((issue) =>
      issue.detail.includes("Duplicate"),
    ),
  ).toBe(true);
});

it("preserves a checked row when its permission blob index is invalid", () => {
  const report = inspect(
    buildManagedPeFixture({
      securityDeclarations: [
        { ...declaration(), blobIndex: 0xffff },
        declaration(4, 6),
      ],
    }),
  );
  expect(report.security_declarations).toMatchObject({
    state: "partial",
    declarations: [
      { parent_kind: "Assembly", permission_set: null },
      { parent_kind: "TypeDef", permission_set: { format: "binary" } },
    ],
  });
});

it("keeps admitted members and earlier declarations when a later blob exceeds capacity", () => {
  const large = Buffer.concat([Buffer.from([0x2e, 0]), Buffer.alloc(80_000)]);
  const bytes = buildManagedPeFixture({
    securityDeclarations: [declaration(), declaration(4, 6, large)],
  });
  const report = inspect(bytes, { maxRepresentationBytes: 40_000 });
  expect(report.coverage.state).toBe("complete");
  expect(report.methods).toHaveLength(1);
  expect(report.security_declarations).toMatchObject({
    state: "partial",
    declarations: [{ parent_kind: "Assembly" }],
    issues: [
      expect.objectContaining({
        code: "resource-limit",
        scope: "metadata.DeclSecurity",
      }),
    ],
  });
  expect(report.security_declarations?.issues[0]?.limit).toBeDefined();
});

it("excludes unselected type blobs before allocating their expanded representation", () => {
  const large = Buffer.concat([Buffer.from([0x2e, 0]), Buffer.alloc(80_000)]);
  const bytes = buildManagedPeFixture({
    additionalEmptyTypes: 1,
    securityDeclarations: [
      declaration(4, 6, large),
      declaration(8, 6),
      declaration(),
    ],
  });
  const report = inspect(bytes, {
    typeNames: ["Fixture.Program"],
    maxRepresentationBytes: 40_000,
  });
  expect(report.security_declarations).toMatchObject({
    state: "complete",
    issues: [],
    declarations: [{ parent_token: "0x02000002" }, { parent_kind: "Assembly" }],
  });
});

it("keeps a declaration on an unreadable TypeDef inside a selected inspection", () => {
  const bytes = buildManagedPeFixture({
    additionalEmptyTypes: 1,
    securityDeclarations: [declaration(4, 6)],
  });
  const layout = layoutOf(bytes);
  bytes.writeUInt16LE(0, metadataRowOffset(layout, 2, 1) + 4);
  const report = inspect(bytes, { typeNames: ["Fixture.Program"] });
  expect(report.security_declarations).toMatchObject({
    state: "partial",
    declarations: [
      {
        parent_token: "0x02000001",
        parent_kind: "TypeDef",
        parent_name: null,
      },
    ],
  });
});

it("reports an action/parent mismatch and missing HasSecurity without dropping facts", () => {
  const bytes = buildManagedPeFixture({
    methodFlags: 0x0016,
    securityDeclarations: [declaration(5, 8)],
  });
  const report = inspect(bytes);
  expect(report.security_declarations).toMatchObject({
    state: "partial",
    declarations: [{ action: 8, parent_kind: "MethodDef" }],
  });
  expect(
    report.security_declarations?.issues.map((issue) => issue.detail).join(" "),
  ).toContain("HasSecurity");
  expect(
    report.security_declarations?.issues.map((issue) => issue.detail).join(" "),
  ).toContain("incompatible");
});

it("rejects a declared named-argument count with no argument bytes", () => {
  const value = Buffer.from([0x2e, 1, 1, 0x54, 1, 2]);
  const report = inspect(
    buildManagedPeFixture({
      securityDeclarations: [declaration(6, 8, value)],
    }),
  );
  expect(report.security_declarations).toMatchObject({
    state: "partial",
    declarations: [
      {
        permission_set: {
          attributes: [{ named_argument_count: 2, arguments_hex: "02" }],
        },
      },
    ],
  });
});

it("uses physical MethodDef parents when MethodPtr reverses declaring ownership", () => {
  const bytes = buildManagedMemberPointerFixture({
    securityDeclarations: [declaration(5, 2), declaration(9, 2)],
  });
  for (const [name, token] of [
    ["Fixture.A", "0x06000002"],
    ["Fixture.B", "0x06000001"],
  ] as const) {
    expect(
      inspect(bytes, { typeNames: [name] }).security_declarations?.declarations,
    ).toMatchObject([
      { parent_token: token, declaring_type: name, parent_name: ".ctor" },
    ]);
  }
});

it("retains a selected method's declaration when an unreadable signature omits its member projection", () => {
  const bytes = buildManagedPeFixture({
    securityDeclarations: [declaration(5, 2)],
  });
  const layout = layoutOf(bytes);
  const signatureOffset =
    metadataRowOffset(layout, 6, 1) + 8 + layout.stringIndexSize;
  bytes.writeUInt16LE(0xffff, signatureOffset);
  const report = inspect(bytes, { typeNames: ["Fixture.Program"] });
  expect(report.methods).toHaveLength(0);
  expect(report.security_declarations).toMatchObject({
    state: "partial",
    declarations: [
      {
        parent_token: "0x06000001",
        parent_kind: "MethodDef",
        parent_name: null,
        declaring_type_token: "0x02000001",
        declaring_type: "Fixture.Program",
        permission_set: { format: "binary" },
      },
    ],
  });
});

it("keeps a method declaration when malformed list coordinates leave selection membership unknown", () => {
  const bytes = buildManagedPeFixture({
    securityDeclarations: [declaration(5, 2)],
  });
  const layout = layoutOf(bytes);
  bytes.writeUInt16LE(
    0,
    metadataRowOffset(layout, 2, 1) +
      4 +
      2 * layout.stringIndexSize +
      layout.codedIndexSize("TypeDefOrRef") +
      layout.tableIndexSize(4),
  );
  const report = inspect(bytes, { typeNames: ["Fixture.Program"] });
  expect(report.security_declarations).toMatchObject({
    state: "partial",
    declarations: [
      {
        parent_token: "0x06000001",
        parent_kind: "MethodDef",
        declaring_type_token: null,
      },
    ],
  });
});

it("reads four-byte HasDeclSecurity indices without truncating the parent row", () => {
  const bytes = buildManagedPeFixture({
    additionalEmptyTypes: 16_383,
    securityDeclarations: [declaration(16_384 * 4, 6)],
  });
  expect(layoutOf(bytes).codedIndexSize("HasDeclSecurity")).toBe(4);
  const report = inspect(bytes, {
    typeNames: ["Fixture.Program"],
    maxRepresentationBytes: 64 * 1024 * 1024,
  });
  expect(report.security_declarations).toMatchObject({
    state: "complete",
    declarations: [
      {
        parent_raw: 65_536,
        parent_token: "0x02004000",
        parent_name: "Fixture.Program",
      },
    ],
  });
});
