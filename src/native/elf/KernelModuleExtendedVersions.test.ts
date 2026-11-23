import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import {
  inspectKernelModuleInputSchema,
  kernelModuleSchema,
} from "../../domain/native/kernelModule.js";
import {
  kernelModuleFixture,
  modversionEntry,
} from "./KernelModule.fixture.js";
import { parseKernelModuleFromHandle } from "./KernelModuleParser.js";

const path = "/artifacts/extended.ko";
const sha256 = (bytes: Buffer) =>
  createHash("sha256").update(bytes).digest("hex");
const crcs = (little = true, values = [0x12345678, 0x90abcdef]): Buffer => {
  const bytes = Buffer.alloc(values.length * 4);
  for (const [index, value] of values.entries()) {
    if (little) bytes.writeUInt32LE(value, index * 4);
    else bytes.writeUInt32BE(value, index * 4);
  }
  return bytes;
};
const fixture = (
  extra: Parameters<typeof kernelModuleFixture>[0] = {},
): Buffer =>
  kernelModuleFixture({
    modinfo: null,
    versions: null,
    thisModule: null,
    ksymtab: null,
    initText: null,
    exitText: null,
    signature: null,
    extendedNames: Buffer.from("printk\0module_layout\0\0", "latin1"),
    extendedCrcs: crcs(),
    ...extra,
  });
const inspect = async (bytes: Buffer, extra: Record<string, number> = {}) =>
  kernelModuleSchema.parse(
    await parseKernelModuleFromHandle(
      {
        size: bytes.length,
        prefix: bytes.subarray(0, 64),
        readRange: async (offset, length) =>
          bytes.subarray(offset, offset + length),
      },
      { path, sha256: sha256(bytes), bytes: bytes.length },
      inspectKernelModuleInputSchema.parse({ path, ...extra }),
    ),
  );

it.each([
  [32, true],
  [32, false],
  [64, true],
  [64, false],
] as const)(
  "joins extended u32 CRCs and names in ELF%i little=%s",
  async (bits, little) => {
    const bytes = fixture({ bits, little, extendedCrcs: crcs(little) });
    const report = await inspect(bytes);
    expect(report).toMatchObject({
      versions: { status: "absent", entries: [] },
      extended_versions: {
        status: "present",
        reason: null,
        entries: [
          {
            index: 0,
            crc_hex: "12345678",
            name: "printk",
            status: "observed",
            reason: null,
          },
          {
            index: 1,
            crc_hex: "90abcdef",
            name: "module_layout",
            status: "observed",
            reason: null,
          },
        ],
      },
      coverage: { status: "complete", examined_entries: 2 },
    });
  },
);

it("preserves long, duplicate and byte-valued symbol names in source order", async () => {
  const name = "_R" + "kernel_long_symbol_".repeat(16) + "\u00ff";
  const report = await inspect(
    fixture({
      extendedNames: Buffer.from(name + "\0" + name + "\0\0", "latin1"),
    }),
  );
  expect(report).toMatchObject({
    extended_versions: {
      status: "present",
      entries: [
        {
          name,
          crc_hex: "12345678",
          name_sha256: sha256(Buffer.from(name + "\0", "latin1")),
        },
        { name, crc_hex: "90abcdef" },
      ],
    },
  });
});

it("distinguishes absent, empty and unexamined extended tables", async () => {
  expect(
    await inspect(fixture({ extendedNames: null, extendedCrcs: null })),
  ).toMatchObject({ extended_versions: { status: "absent", entries: [] } });
  expect(
    await inspect(
      fixture({
        extendedNames: Buffer.from([0]),
        extendedCrcs: Buffer.alloc(0),
      }),
    ),
  ).toMatchObject({ extended_versions: { status: "present", entries: [] } });
  expect(await inspect(fixture({ type: 2 }))).toMatchObject({
    applicability: "not_applicable",
    extended_versions: null,
  });
});

it.each(["names", "crcs"] as const)(
  "reports a missing %s half while retaining other metadata",
  async (missing) => {
    expect(
      await inspect(
        fixture({
          ...(missing === "names"
            ? { extendedNames: null }
            : { extendedCrcs: null }),
          modinfo: Buffer.from("license=GPL\0"),
        }),
      ),
    ).toMatchObject({
      extended_versions: {
        status: "malformed",
        reason: `missing_${missing}`,
        entries: [],
      },
      modinfo: {
        status: "present",
        entries: [{ key: "license", value: "GPL" }],
      },
      coverage: { status: "partial", examined_entries: 1 },
    });
  },
);

it("keeps missing section names unknown rather than reporting absent extended versions", async () => {
  const bytes = fixture();
  bytes.writeUInt16LE(0, 62);
  expect(await inspect(bytes)).toMatchObject({
    extended_versions: { status: "unknown", entries: [] },
  });
});

it("refuses a partial CRC word without assigning the trailing bytes to a symbol", async () => {
  expect(
    await inspect(
      fixture({ extendedCrcs: Buffer.concat([crcs(), Buffer.from([1])]) }),
    ),
  ).toMatchObject({
    extended_versions: {
      status: "malformed",
      reason: "crcs_size_not_multiple",
      entries: [],
    },
    coverage: { status: "partial" },
  });
});

it("keeps already joined rows and unresolved CRCs after the name list ends", async () => {
  expect(
    await inspect(fixture({ extendedNames: Buffer.from("printk\0") })),
  ).toMatchObject({
    extended_versions: {
      status: "present",
      entries: [
        { index: 0, name: "printk", status: "observed" },
        {
          index: 1,
          name: null,
          crc_hex: "90abcdef",
          status: "malformed",
          reason: "name_missing",
        },
      ],
    },
    coverage: { status: "partial", examined_entries: 2 },
  });
});

it("preserves an unterminated name's bytes and never shifts later CRC ownership", async () => {
  expect(
    await inspect(
      fixture({ extendedNames: Buffer.from("printk\0unterminated") }),
    ),
  ).toMatchObject({
    extended_versions: {
      entries: [
        { name: "printk", status: "observed" },
        {
          name: null,
          crc_hex: "90abcdef",
          status: "malformed",
          reason: "name_unterminated",
          name_sha256: sha256(Buffer.from("unterminated")),
        },
      ],
    },
    coverage: { status: "partial" },
  });
});

it("records unmatched nonzero name bytes separately from the compiler's trailing NUL", async () => {
  expect(
    await inspect(
      fixture({ extendedNames: Buffer.from("printk\0module_layout\0extra\0") }),
    ),
  ).toMatchObject({
    extended_versions: {
      status: "present",
      trailing_names: { zero_padding: false },
    },
    coverage: { status: "partial" },
  });
});

it("shares the entry budget with existing metadata before allocating extended rows", async () => {
  await expect(
    inspect(fixture({ modinfo: Buffer.from("license=GPL\0") }), {
      max_entries: 2,
    }),
  ).rejects.toMatchObject({ reason: "limit", boundary: "capacity" });
  expect(
    await inspect(fixture({ modinfo: Buffer.from("license=GPL\0") }), {
      max_entries: 3,
    }),
  ).toMatchObject({ coverage: { examined_entries: 3 } });
});

it("omits oversized names independently of structure and restores them with the selected budget", async () => {
  const name = "x".repeat(4097);
  const bytes = fixture({
    extendedNames: Buffer.from(name + "\0module_layout\0\0"),
  });
  expect(await inspect(bytes)).toMatchObject({
    extended_versions: {
      entries: [
        {
          name: null,
          status: "observed",
          reason: null,
          omitted_fields: ["name"],
        },
        { name: "module_layout" },
      ],
      omission_limits: [
        { parameter: "max_version_name_bytes", effective_value: 4096 },
      ],
    },
    coverage: { status: "partial" },
  });
  expect(await inspect(bytes, { max_version_name_bytes: 4097 })).toMatchObject({
    extended_versions: {
      entries: [{ name, omitted_fields: [] }, { name: "module_layout" }],
    },
    coverage: { status: "complete" },
  });
});

it("streams a name across windows without shifting the next name or CRC", async () => {
  const name = "x".repeat(65536);
  const bytes = fixture({
    extendedNames: Buffer.from(name + "\0module_layout\0\0"),
  });
  const reads: number[] = [];
  const report = await parseKernelModuleFromHandle(
    {
      size: bytes.length,
      prefix: bytes.subarray(0, 64),
      readRange: async (offset, length) => {
        reads.push(length);
        return bytes.subarray(offset, offset + length);
      },
    },
    { path, sha256: sha256(bytes), bytes: bytes.length },
    inspectKernelModuleInputSchema.parse({
      path,
      max_version_name_bytes: 65536,
    }),
  );
  expect(Math.max(...reads)).toBeLessThanOrEqual(65536);
  expect(report).toMatchObject({
    extended_versions: {
      entries: [
        {
          name,
          crc_hex: "12345678",
          name_sha256: sha256(Buffer.from(name + "\0")),
        },
        { name: "module_layout", crc_hex: "90abcdef" },
      ],
    },
    coverage: { status: "complete" },
  });
});

it("observes cancellation between name windows", async () => {
  const bytes = fixture({
    extendedNames: Buffer.from("x".repeat(140000) + "\0module_layout\0\0"),
  });
  const controller = new AbortController();
  await expect(
    parseKernelModuleFromHandle(
      {
        size: bytes.length,
        prefix: bytes.subarray(0, 64),
        readRange: async (offset, length) => {
          if (length === 65536) controller.abort();
          return bytes.subarray(offset, offset + length);
        },
      },
      { path, sha256: sha256(bytes), bytes: bytes.length },
      inspectKernelModuleInputSchema.parse({ path }),
      controller.signal,
    ),
  ).rejects.toMatchObject({ reason: "cancelled" });
});

it.each([
  ["names", 1],
  ["crcs", 2],
] as const)(
  "preserves stored hashes while refusing compressed %s payloads",
  async (kind, index) => {
    const bytes = fixture();
    bytes.writeBigUInt64LE(0x800n, 64 + index * 64 + 8);
    expect(await inspect(bytes)).toMatchObject({
      extended_versions: {
        status: "unsupported",
        reason: `${kind}_compressed`,
        entries: [],
        [kind]: { sha256: expect.any(String) },
      },
      coverage: { status: "partial" },
    });
  },
);

it.each([
  ["names", 1],
  ["crcs", 2],
] as const)(
  "never decodes NOBITS %s as stored metadata",
  async (kind, index) => {
    const bytes = fixture();
    bytes.writeUInt32LE(8, 64 + index * 64 + 4);
    expect(await inspect(bytes)).toMatchObject({
      extended_versions: {
        status: "malformed",
        reason: `${kind}_not_file_backed`,
        entries: [],
        [kind]: null,
      },
      coverage: { status: "partial" },
    });
  },
);

it("keeps classic and extended inventories independent when both are declared", async () => {
  expect(
    await inspect(
      fixture({ versions: modversionEntry(1, "classic", 64, true) }),
    ),
  ).toMatchObject({
    versions: { entries: [{ name: "classic", crc_hex: "0000000000000001" }] },
    extended_versions: {
      entries: [
        { name: "printk", crc_hex: "12345678" },
        { name: "module_layout" },
      ],
    },
    coverage: { status: "complete", examined_entries: 3 },
  });
});

it("reports duplicate named sections while preserving the first physical pair", async () => {
  expect(
    await inspect(
      fixture({
        sharedNameSections: {
          name: "__version_ext_names",
          count: 1,
          body: Buffer.from("different\0"),
        },
      }),
    ),
  ).toMatchObject({
    extended_versions: {
      entries: [{ name: "printk" }, { name: "module_layout" }],
    },
    coverage: { status: "partial" },
    limitations: expect.arrayContaining([
      expect.stringContaining("Multiple __version_ext_names"),
    ]),
  });
});

it("retains an empty name's ordinal instead of associating its CRC with the next name", async () => {
  expect(
    await inspect(
      fixture({ extendedNames: Buffer.from("\0module_layout\0\0") }),
    ),
  ).toMatchObject({
    extended_versions: {
      entries: [
        {
          index: 0,
          name: null,
          crc_hex: "12345678",
          status: "malformed",
          reason: "name_empty",
        },
        {
          index: 1,
          name: "module_layout",
          crc_hex: "90abcdef",
          status: "observed",
        },
      ],
    },
    coverage: { status: "partial" },
  });
});
