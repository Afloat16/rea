import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { inspectDwarfUnitsInputSchema } from "../../domain/native/dwarfUnits.js";
import { DwarfUnitsProvider } from "./DwarfUnitsProvider.js";
import {
  elfCompressedBody,
  elfImage,
  frameUnit,
  gnuZdebugBody,
  namedUnit,
  splitDwarfSections,
  splitDwarfUnit,
} from "./DwarfUnits.fixture.js";

const inspect = async (bytes: Buffer, offset = 0, limit = 32) => {
  const directory = await createTestTempDirectory("rea-split-dwarf-");
  const path = join(directory, "explicit-debug-file");
  await writeFile(path, bytes);
  const provider = new DwarfUnitsProvider();
  try {
    const result = await provider.inspect(
      inspectDwarfUnitsInputSchema.parse({ path, offset, limit }),
    );
    if (!result.ok) throw result.error;
    return result.value;
  } finally {
    await provider.close();
  }
};

it.each([
  { version: 4, little: true, offsetSize: 4, tableOffsetSize: 4 },
  { version: 4, little: false, offsetSize: 8, tableOffsetSize: 8 },
  { version: 5, little: true, offsetSize: 4, tableOffsetSize: 4 },
  { version: 5, little: false, offsetSize: 8, tableOffsetSize: 8 },
  { version: 5, little: true, offsetSize: 4, tableOffsetSize: 8 },
  { version: 5, little: false, offsetSize: 8, tableOffsetSize: 4 },
] as const)("reads indexed split-unit facts: %j", async (options) => {
  const parts = splitDwarfUnit(options);
  const image = elfImage({
    little: options.little,
    sections: splitDwarfSections(parts),
  });
  const report = await inspect(image);
  expect(report.total_units).toBe(1);
  expect(report.coverage).toEqual({ status: "complete", reason: null });
  expect(report.units[0]).toMatchObject({
    version: options.version,
    offset_size: options.offsetSize,
    name: { state: "present", value: "split.c" },
    comp_dir: { state: "present", value: "/build/source" },
    producer: { state: "present", value: "fixture compiler" },
    language: { state: "present", value: 0x000c },
    issues: [],
  });
  const info = report.sections.find(({ role }) => role === ".debug_info");
  expect(info?.name).toBe(".debug_info.dwo");
  expect(report.units[0]?.file_offset).toBe(info?.offset);
  expect(
    image.subarray(info?.offset, (info?.offset ?? 0) + parts.info.length),
  ).toEqual(parts.info);
});

it.each(["gnu", "zlib", "zstd"] as const)(
  "reads all split sections using %s compression without inventing file offsets",
  async (compression) => {
    const report = await inspect(
      elfImage({
        sections: splitDwarfSections(splitDwarfUnit()).map(({ name, body }) =>
          compression === "gnu"
            ? {
                name: name.replace(".debug_", ".zdebug_"),
                body: gnuZdebugBody(body),
              }
            : {
                name,
                body: elfCompressedBody(body, compression),
                flags: 0x800n,
              },
        ),
      }),
    );
    expect(report.units[0]?.name).toEqual({
      state: "present",
      value: "split.c",
    });
    expect(report.units[0]?.file_offset).toBeNull();
    expect(report.units[0]?.issues).toEqual([]);
    expect(report.sections).toHaveLength(4);
    expect(
      report.sections.every(
        ({ compression: actual }) =>
          actual === (compression === "gnu" ? "zlib" : compression),
      ),
    ).toBe(true);
  },
);

it("never borrows ordinary abbreviation or string sections for a split unit", async () => {
  const parts = splitDwarfUnit();
  const ordinary = namedUnit({ name: "wrong.c" });
  const report = await inspect(
    elfImage({
      sections: [
        { name: ".debug_info.dwo", body: parts.info },
        { name: ".debug_abbrev", body: ordinary.abbrev },
        { name: ".debug_str", body: parts.str },
        { name: ".debug_str_offsets", body: parts.strOffsets },
      ],
    }),
  );
  expect(report.total_units).toBe(1);
  expect(report.units[0]?.name.state).toBe("unknown");
  expect(report.sections.map(({ name }) => name)).toEqual([".debug_info.dwo"]);
});

it("keeps indexed strings unresolved when only the ordinary string pool exists", async () => {
  const parts = splitDwarfUnit();
  const report = await inspect(
    elfImage({
      sections: splitDwarfSections(parts).map((section) =>
        section.name === ".debug_str.dwo"
          ? { ...section, name: ".debug_str" }
          : section,
      ),
    }),
  );
  expect(report.total_units).toBe(1);
  expect(report.units[0]?.name.state).toBe("unresolved");
  expect(report.units[0]?.language.value).toBe(0x000c);
});

it("preserves the ordinary family when both info families are declared", async () => {
  const ordinary = namedUnit({ name: "ordinary.c" });
  const report = await inspect(
    elfImage({
      sections: [
        ...splitDwarfSections(splitDwarfUnit()),
        { name: ".debug_info", body: ordinary.info },
        { name: ".debug_abbrev", body: ordinary.abbrev },
      ],
    }),
  );
  expect(report.units[0]?.name.value).toBe("ordinary.c");
  expect(report.total_units).toBe(1);
  expect(report.coverage.status).toBe("partial");
  expect(report.sections.every(({ name }) => !name.endsWith(".dwo"))).toBe(
    true,
  );
});

it("does not replace a declared unbacked ordinary info section with split bytes", async () => {
  const report = await inspect(
    elfImage({
      sections: [
        { name: ".debug_info", body: Buffer.alloc(0), type: 8 },
        ...splitDwarfSections(splitDwarfUnit()),
      ],
    }),
  );
  expect(report.total_units).toBe(0);
  expect(report.coverage.status).toBe("partial");
});

it.each([".debug_cu_index", ".debug_tu_index"])(
  "leaves packages with %s unread until their indexed contributions are supported",
  async (name) => {
    const report = await inspect(
      elfImage({
        sections: [
          ...splitDwarfSections(splitDwarfUnit()),
          { name, body: Buffer.alloc(0) },
        ],
      }),
    );
    expect(report.total_units).toBe(0);
    expect(report.coverage.status).toBe("partial");
    expect(report.coverage.reason).toContain("package");
  },
);

it.each([
  ["truncated", Buffer.from([4, 0, 0])],
  ["wrong version", Buffer.from([8, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0])],
  ["nonzero padding", Buffer.from([8, 0, 0, 0, 5, 0, 1, 0, 0, 0, 0, 0])],
  ["unframed entry", Buffer.from([7, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0])],
  [
    "length outside section",
    Buffer.from([16, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0]),
  ],
] as const)(
  "retains the unit when its split string table is %s",
  async (_name, strOffsets) => {
    const report = await inspect(
      elfImage({
        sections: splitDwarfSections({
          ...splitDwarfUnit(),
          strOffsets,
        }),
      }),
    );
    expect(report.total_units).toBe(1);
    expect(report.units[0]?.name.state).toBe("unresolved");
    expect(report.units[0]?.language.value).toBe(0x000c);
    expect(report.units[0]?.issues).toContainEqual(
      expect.objectContaining({ code: "string_unresolved" }),
    );
  },
);

it("does not resolve an index in a later string-offset contribution", async () => {
  const parts = splitDwarfUnit({ nameIndex: 3 });
  const report = await inspect(
    elfImage({
      sections: splitDwarfSections({
        ...parts,
        strOffsets: Buffer.concat([
          parts.strOffsets,
          frameUnit(Buffer.from([5, 0, 0, 0, 0, 0, 0, 0])),
        ]),
      }),
    }),
  );
  expect(report.units[0]?.name.state).toBe("unresolved");
  expect(report.units[0]?.comp_dir.value).toBe("/build/source");
});

it("does not infer a split table base for an ordinary unit", async () => {
  const report = await inspect(
    elfImage({
      sections: splitDwarfSections(splitDwarfUnit()).map((section) => ({
        ...section,
        name: section.name.replace(".dwo", ""),
      })),
    }),
  );
  expect(report.total_units).toBe(1);
  expect(report.units[0]?.name.state).toBe("unresolved");
  expect(report.units[0]?.issues).toContainEqual(
    expect.objectContaining({ code: "str_offsets_base_absent" }),
  );
});

it("preserves unit totals and source coordinates when paging split units", async () => {
  const parts = splitDwarfUnit();
  const report = await inspect(
    elfImage({
      sections: splitDwarfSections({
        ...parts,
        info: Buffer.concat([parts.info, parts.info]),
      }),
    }),
    1,
    1,
  );
  expect(report.total_units).toBe(2);
  expect(report.units).toHaveLength(1);
  expect(report.units[0]?.offset).toBe(parts.info.length);
  expect(report.units[0]?.name.value).toBe("split.c");
});

it.each([false, true])(
  "only treats relocations of the selected family as unapplied: %s",
  async (selected) => {
    const parts = splitDwarfUnit();
    const report = await inspect(
      elfImage({
        sections: [
          ...splitDwarfSections(parts),
          { name: ".debug_str", body: Buffer.from("ordinary\0") },
          {
            name: selected ? ".rela.debug_str.dwo" : ".rela.debug_str",
            type: 4,
            info: selected ? 3 : 5,
            body: Buffer.alloc(24),
          },
        ],
      }),
    );
    expect(report.units[0]?.name.state).toBe(
      selected ? "unresolved" : "present",
    );
    expect(report.units[0]?.language.value).toBe(0x000c);
    expect(
      report.units[0]?.issues.some(
        ({ code }) => code === "unapplied_relocation",
      ),
    ).toBe(selected);
  },
);
