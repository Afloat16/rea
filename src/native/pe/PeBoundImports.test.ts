import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { peBoundImportsFixture } from "../../../tests/fixtures/binaryDiagnostics/peBoundImports.js";
import {
  inspectPeImportsInputSchema,
  peImportsSchema,
} from "../../domain/native/peImports.js";
import { parsePeImports, parsePeImportsFromHandle } from "./PeImportParser.js";

const path = "/artifacts/bound.exe";
const parse = async (bytes: Buffer, extra: Record<string, unknown> = {}) => {
  const artifact = {
    path,
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
  const input = inspectPeImportsInputSchema.parse({ path, ...extra });
  const buffer = peImportsSchema.parse(
    await parsePeImports(bytes, artifact, input),
  );
  const positional = peImportsSchema.parse(
    await parsePeImportsFromHandle(
      {
        size: bytes.length,
        prefix: bytes.subarray(0, 256),
        readRange: async (offset, length) =>
          bytes.subarray(offset, offset + length),
      },
      artifact,
      input,
    ),
  );
  expect(positional).toEqual(buffer);
  return buffer;
};

it.each([32, 64] as const)(
  "reads PE%s bound DLLs and interleaved forwarder references",
  async (bits) => {
    const { bytes, rva, tableBytes, at } = peBoundImportsFixture({ bits });
    const report = await parse(bytes);
    expect(report.bound_import_directory).toEqual({
      rva,
      size: tableBytes,
      locations: [{ offset: at(rva), bytes: 32 }],
    });
    expect(report.bound_imports).toMatchObject([
      {
        index: 0,
        name: "KERNEL32.dll",
        name_offset: 32,
        time_date_stamp: 0x12345678,
        number_of_forwarder_refs: 1,
        location: { offset: at(rva), bytes: 8 },
        forwarders: [
          {
            index: 0,
            name: "NTDLL.dll",
            time_date_stamp: 0x23456789,
            reserved: 0,
            location: { offset: at(rva + 8), bytes: 8 },
          },
        ],
      },
      {
        index: 1,
        name: "USER32.dll",
        time_date_stamp: 0x3456789a,
        number_of_forwarder_refs: 0,
        location: { offset: at(rva + 16), bytes: 8 },
        forwarders: [],
      },
    ]);
    expect(report.coverage).toMatchObject({
      status: "complete",
      examined_bound_records: 3,
    });
    expect(report.imphash.md5).toBe("92cef6cc91a85825f3c8a0516517c66f");
  },
);

it.each([{ headers: true }, { splitAt: 0x608 }])(
  "retains correct physical locations across alternate directory mappings %j",
  async (options) => {
    const { bytes, at, rva } = peBoundImportsFixture(options);
    const report = await parse(bytes);
    expect(report.bound_imports?.[0]?.name).toBe("KERNEL32.dll");
    expect(report.bound_imports?.[0]?.forwarders[0]?.location).toEqual({
      offset: at(rva + 8),
      bytes: 8,
    });
    expect(report.bound_import_directory?.locations.length).toBe(
      "splitAt" in options ? 2 : 1,
    );
    expect(report.coverage.status).toBe("complete");
  },
);

it.each([0, 7, 8])(
  "does not consume a bound descriptor beyond declared directory size %i",
  async (declaredSize) => {
    const { bytes } = peBoundImportsFixture({
      declaredSize,
      rows: [{ name: "ONE.dll" }, { name: "TWO.dll" }],
    });
    const report = await parse(bytes);
    expect(report.bound_imports).toHaveLength(declaredSize < 8 ? 0 : 1);
    expect(report.bound_import_directory?.locations).toHaveLength(
      declaredSize < 8 ? 0 : 1,
    );
    expect(report.coverage.status).toBe("partial");
    expect(report.issues).toContainEqual(
      expect.objectContaining({
        code: "malformed_entry",
        message: expect.stringMatching(/bound.*directory.*size/iu),
      }),
    );
  },
);

it("preserves the owning DLL and readable forwarder prefix when a declared group is truncated", async () => {
  const { bytes } = peBoundImportsFixture({
    rows: [
      {
        name: "OWNER.dll",
        declaredForwarders: 2,
        forwarders: [{ name: "FIRST.dll" }, { name: "SECOND.dll" }],
      },
    ],
    declaredSize: 16,
  });
  const report = await parse(bytes);
  expect(report.bound_imports).toMatchObject([
    {
      number_of_forwarder_refs: 2,
      forwarders: [{ index: 0, time_date_stamp: 0x23456789 }],
    },
  ]);
  expect(report.bound_imports?.[0]?.forwarders).toHaveLength(1);
  expect(report.coverage).toMatchObject({
    status: "partial",
    examined_bound_records: 2,
  });
});

it("keeps unreadable directory-relative names and nonzero reserved fields without invalidating standard imphash", async () => {
  const { bytes } = peBoundImportsFixture({
    rows: [
      {
        name: "OWNER.dll",
        nameOffset: 0xffff,
        forwarders: [{ name: "FORWARD.dll", reserved: 9 }],
      },
      { name: "LATER.dll" },
    ],
  });
  const report = await parse(bytes);
  expect(report.bound_imports).toMatchObject([
    {
      name: null,
      name_offset: 0xffff,
      forwarders: [{ name: "FORWARD.dll", reserved: 9 }],
    },
    { name: "LATER.dll" },
  ]);
  expect(report.coverage.status).toBe("partial");
  expect(report.imphash.md5).toBe("92cef6cc91a85825f3c8a0516517c66f");
});

it("requires a name terminator inside the bound directory while accepting its final byte", async () => {
  const fixture = peBoundImportsFixture({ rows: [{ name: "LAST.dll" }] });
  expect((await parse(fixture.bytes)).bound_imports?.[0]?.name).toBe(
    "LAST.dll",
  );
  fixture.bytes.writeUInt32LE(
    fixture.tableBytes - 1,
    fixture.directoryOffset + 4,
  );
  const truncated = await parse(fixture.bytes);
  expect(truncated.bound_imports?.[0]?.name).toBeNull();
  expect(truncated.coverage.status).toBe("partial");
});

it("charges DLLs and forwarder references to a dedicated caller budget", async () => {
  const { bytes } = peBoundImportsFixture();
  await expect(parse(bytes, { max_bound_records: 2 })).rejects.toThrow(
    /bound.*3.*2/iu,
  );
  expect(
    (await parse(bytes, { max_bound_records: 3, max_dlls: 1 })).bound_imports,
  ).toHaveLength(2);
});

it("keeps old retained reports unobserved and newly absent directories explicitly empty", async () => {
  const { bytes, directoryOffset } = peBoundImportsFixture();
  bytes.writeUInt32LE(0, directoryOffset);
  const report = await parse(bytes);
  expect(report.bound_import_directory).toBeNull();
  expect(report.bound_imports).toEqual([]);
  expect(report.coverage.examined_bound_records).toBe(0);
  const historical = structuredClone(report);
  delete historical.bound_import_directory;
  delete historical.bound_imports;
  delete historical.coverage.examined_bound_records;
  expect(peImportsSchema.parse(historical)).not.toHaveProperty("bound_imports");
});
