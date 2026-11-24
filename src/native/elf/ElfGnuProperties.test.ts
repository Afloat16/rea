import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { bufferByteSource } from "../../domain/byteSource.js";
import {
  elfNotesSchema,
  inspectElfNotesInputSchema,
} from "../../domain/native/elfNotes.js";
import { parseElfNotesFromHandle } from "./ElfNoteParser.js";
import {
  elfNote,
  elfNoteFixture,
  gnuBuildIdNote,
  gnuPropertyNote,
} from "./ElfNotes.fixture.js";

const property = (
  type: number,
  value: Buffer,
  bits: 32 | 64 = 64,
  little = true,
): Buffer => {
  const alignment = bits / 8;
  const bytes = Buffer.alloc(
    Math.ceil((8 + value.length) / alignment) * alignment,
  );
  if (little) {
    bytes.writeUInt32LE(type, 0);
    bytes.writeUInt32LE(value.length, 4);
  } else {
    bytes.writeUInt32BE(type, 0);
    bytes.writeUInt32BE(value.length, 4);
  }
  value.copy(bytes, 8);
  return bytes;
};
const word = (value: number, little = true): Buffer => {
  const bytes = Buffer.alloc(4);
  if (little) bytes.writeUInt32LE(value);
  else bytes.writeUInt32BE(value);
  return bytes;
};
const image = (
  descriptor: Buffer,
  options: {
    bits?: 32 | 64;
    little?: boolean;
    machine?: number;
    ownership?: "program" | "section" | "both";
    owner?: string;
  } = {},
) =>
  elfNoteFixture({
    ...options,
    alignment: (options.bits ?? 64) / 8,
    sectionName: ".note.gnu.property",
    notes: elfNote(
      options.owner ?? "GNU",
      5,
      descriptor,
      options.little ?? true,
      (options.bits ?? 64) / 8,
    ),
  });
const parse = async (bytes: Buffer) => {
  const input = inspectElfNotesInputSchema.parse({
    path: "/artifacts/program",
  });
  return parseElfNotesFromHandle(
    bufferByteSource(bytes, 32),
    {
      path: input.path,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      bytes: bytes.length,
    },
    input,
    async () => {},
  );
};

it("decodes GNU x86 feature and ISA declarations with physical payload provenance", async () => {
  const bytes = elfNoteFixture({
    notes: gnuPropertyNote(),
    alignment: 8,
    ownership: "program",
  });
  const report = await parse(bytes);
  const properties = report.entries[0]?.gnu?.properties;
  expect(properties).toMatchObject({
    issue: null,
    entries: [
      {
        type: 0xc0000002,
        type_name: "GNU_PROPERTY_X86_FEATURE_1_AND",
        value_hex: "0x3",
        flags: ["IBT", "SHSTK"],
        unknown_bits_hex: "0x0",
        issue: null,
      },
      {
        type: 0xc0008002,
        type_name: "GNU_PROPERTY_X86_ISA_1_NEEDED",
        value_hex: "0x1",
        flags: ["x86-64-baseline"],
        unknown_bits_hex: "0x0",
        issue: null,
      },
    ],
  });
  for (const entry of properties?.entries ?? []) {
    const payload = bytes.subarray(
      entry.data_location.offset,
      entry.data_location.offset + entry.data_location.bytes,
    );
    expect(entry.data_sha256).toBe(
      createHash("sha256").update(payload).digest("hex"),
    );
    expect(entry.data_hex).toBe(payload.toString("hex"));
  }
  expect(elfNotesSchema.parse(report)).toEqual(report);
});

it("reads ELF32 big-endian words and retains unrecognized ISA bits", async () => {
  const descriptor = property(0xc0008002, word(0x80000005, false), 32, false);
  const report = await parse(
    image(descriptor, {
      bits: 32,
      little: false,
      machine: 3,
      ownership: "section",
    }),
  );
  expect(report.entries[0]?.gnu?.properties).toMatchObject({
    issue: null,
    entries: [
      {
        value_hex: "0x80000005",
        flags: ["x86-64-baseline", "x86-64-v3"],
        unknown_bits_hex: "0x80000000",
      },
    ],
  });
});

it("interprets AArch64 features only under their machine namespace", async () => {
  const descriptor = property(0xc0000000, word(7));
  const report = await parse(
    image(descriptor, { machine: 183, ownership: "program" }),
  );
  expect(report.entries[0]?.gnu?.properties).toMatchObject({
    issue: null,
    entries: [
      {
        type_name: "GNU_PROPERTY_AARCH64_FEATURE_1_AND",
        value_hex: "0x7",
        flags: ["BTI", "PAC", "GCS"],
        unknown_bits_hex: "0x0",
      },
    ],
  });
  const foreign = await parse(
    image(descriptor, { machine: 62, ownership: "program" }),
  );
  expect(foreign.entries[0]?.gnu?.properties?.entries?.[0]).toMatchObject({
    type: 0xc0000000,
    type_name: null,
    value_hex: null,
    flags: null,
    unknown_bits_hex: null,
    data_hex: "07000000",
    issue: null,
  });
});

it("keeps exact class-sized stack declarations above the safe integer range", async () => {
  const value = Buffer.alloc(8);
  value.writeBigUInt64LE(0x20000000000001n);
  const report = await parse(
    image(Buffer.concat([property(1, value), property(2, Buffer.alloc(0))]), {
      ownership: "program",
    }),
  );
  expect(report.entries[0]?.gnu?.properties).toMatchObject({
    issue: null,
    entries: [
      {
        type_name: "GNU_PROPERTY_STACK_SIZE",
        value_hex: "0x20000000000001",
        flags: null,
        issue: null,
      },
      {
        type_name: "GNU_PROPERTY_NO_COPY_ON_PROTECTED",
        value_hex: null,
        flags: null,
        issue: null,
      },
    ],
  });
});

it("retains unknown property data without inventing machine semantics", async () => {
  const data = Buffer.alloc(80, 0xab);
  const report = await parse(
    image(property(0xfeed1234, data), { machine: 243, ownership: "program" }),
  );
  expect(report.entries[0]?.gnu?.properties).toMatchObject({
    issue: null,
    entries: [
      {
        type: 0xfeed1234,
        type_name: null,
        data_hex: null,
        data_sha256: createHash("sha256").update(data).digest("hex"),
        value_hex: null,
        flags: null,
        unknown_bits_hex: null,
        issue: null,
      },
    ],
  });
});

it("preserves duplicate records in order instead of reporting an effective feature policy", async () => {
  const report = await parse(
    image(
      Buffer.concat([
        property(0xc0000002, word(1)),
        property(0xc0000002, word(2)),
      ]),
      { ownership: "program" },
    ),
  );
  expect(
    report.entries[0]?.gnu?.properties?.entries?.map(
      (entry) => entry.value_hex,
    ),
  ).toEqual(["0x1", "0x2"]);
  expect(report.entries[0]?.gnu?.properties?.issue).toBeNull();
});

it("retains malformed known values while decoding a following well-framed record", async () => {
  const report = await parse(
    image(
      Buffer.concat([
        property(0xc0000002, Buffer.from([1, 2])),
        property(0xc0008002, word(1)),
      ]),
      { ownership: "program" },
    ),
  );
  expect(report.entries[0]?.gnu?.properties).toMatchObject({
    issue: null,
    entries: [
      {
        type_name: "GNU_PROPERTY_X86_FEATURE_1_AND",
        value_hex: null,
        issue: expect.stringMatching(/4-byte/u),
      },
      {
        type_name: "GNU_PROPERTY_X86_ISA_1_NEEDED",
        value_hex: "0x1",
        issue: null,
      },
    ],
  });
});

it("keeps raw note evidence and a decoded prefix when later property framing is truncated", async () => {
  const descriptor = Buffer.concat([
    property(0xc0008002, word(1)),
    Buffer.from([1, 2, 3]),
  ]);
  const report = await parse(image(descriptor, { ownership: "program" }));
  expect(report.entries[0]?.gnu?.properties).toMatchObject({
    entries: [{ value_hex: "0x1" }],
    issue: expect.stringMatching(/truncated/u),
  });
  expect(report.entries[0]?.descriptor.sha256).toBe(
    createHash("sha256").update(descriptor).digest("hex"),
  );
  expect(report.coverage.status).toBe("complete");
});

it("reports property payloads extending beyond their descriptor without losing raw evidence", async () => {
  const descriptor = property(0xc0008002, word(1));
  descriptor.writeUInt32LE(30, 4);
  const report = await parse(image(descriptor, { ownership: "program" }));
  expect(report.entries[0]?.gnu?.properties).toMatchObject({
    entries: [],
    issue: expect.stringMatching(/outside/u),
  });
  expect(report.entries[0]?.descriptor.bytes).toBe(descriptor.length);
});

it("does not decode foreign note owners even when their type and bytes match GNU", async () => {
  const report = await parse(
    image(property(0xc0008002, word(1)), {
      owner: "OTHER",
      ownership: "program",
    }),
  );
  expect(report.entries[0]?.gnu).toBeNull();
  expect(report.entries[0]?.type_name).toBe("unknown");
});

it("preserves existing build-ID reports", async () => {
  const report = await parse(
    elfNoteFixture({ notes: gnuBuildIdNote(), ownership: "program" }),
  );
  expect(report.entries[0]?.gnu?.build_id_hex).toBe(
    "0123456789abcdef0123456789abcdef01234567",
  );
});

it("retains aliased note declarations and identical physical property offsets", async () => {
  const report = await parse(
    image(property(0xc0008002, word(1)), { ownership: "both" }),
  );
  expect(report.entries).toHaveLength(2);
  expect(report.entries[0]?.gnu?.properties?.entries).toHaveLength(1);
  expect(report.entries[1]?.gnu?.properties).toEqual(
    report.entries[0]?.gnu?.properties,
  );
});

it("bounds descriptor decoding while keeping the original note range and digest", async () => {
  const descriptor = property(0xfeed1234, Buffer.alloc(65536));
  const report = await parse(image(descriptor, { ownership: "program" }));
  expect(report.entries[0]?.gnu?.properties).toMatchObject({
    entries: null,
    issue: expect.stringMatching(/descriptor decode allowance/u),
  });
  expect(report.entries[0]?.descriptor.sha256).toBe(
    createHash("sha256").update(descriptor).digest("hex"),
  );
});

it("bounds projected property records before allocating an expanded report", async () => {
  const descriptor = Buffer.concat(
    Array.from({ length: 1500 }, () => property(0xfeed1234, Buffer.alloc(0))),
  );
  const report = await parse(image(descriptor, { ownership: "program" }));
  expect(report.entries[0]?.gnu?.properties).toMatchObject({
    entries: null,
    issue: expect.stringMatching(/projected JSON allowance/u),
  });
  expect(report.entries[0]?.descriptor.bytes).toBe(descriptor.length);
});
