import { expect, it } from "vitest";
import {
  elfDependenciesSchema,
  inspectElfDependenciesInputSchema,
} from "../../domain/native/elfDependencies.js";
import {
  elfDependencyByteSource,
  elfDependencyFixture,
} from "./ElfDependencies.fixture.js";
import { parseElfDependenciesFromHandle } from "./ElfDependencyParser.js";

const path = "/artifacts/versioned.so";
const parse = async (bytes: Buffer, max_versions = 4096) =>
  elfDependenciesSchema.parse(
    await parseElfDependenciesFromHandle(
      elfDependencyByteSource(bytes, 64),
      { path, sha256: "ab".repeat(32), bytes: bytes.length },
      inspectElfDependenciesInputSchema.parse({ path, max_versions }),
      async () => {},
    ),
  );

const definitions = [
  { name: "libversioned.so", index: 1, flags: 1 },
  { name: "VER_1", index: 2 },
  { name: "VER_2", index: 3, parents: ["VER_1"] },
  { name: "VER_3", index: 4, parents: ["VER_2", "VER_1"] },
];

for (const bits of [32, 64] as const)
  for (const little of [true, false])
    for (const stripped of [false, true])
      it(`observes version inheritance in ELF${bits} ${little ? "LE" : "BE"}, stripped=${stripped}`, async () => {
        const report = await parse(
          elfDependencyFixture({ bits, little, stripped, verdef: definitions }),
        );
        expect(report.version_definitions.names).toEqual([
          {
            name: "libversioned.so",
            index: 1,
            base: true,
            parents: [],
            parents_complete: true,
          },
          {
            name: "VER_1",
            index: 2,
            base: false,
            parents: [],
            parents_complete: true,
          },
          {
            name: "VER_2",
            index: 3,
            base: false,
            parents: ["VER_1"],
            parents_complete: true,
          },
          {
            name: "VER_3",
            index: 4,
            base: false,
            parents: ["VER_2", "VER_1"],
            parents_complete: true,
          },
        ]);
        expect(report.coverage.status).toBe("complete");
        expect(report.issues).toEqual([]);
      });

it("retains declared order, duplicate parents and ELF string bytes without a transitive closure", async () => {
  const report = await parse(
    elfDependencyFixture({
      verdef: [
        ...definitions,
        { name: "CHILD", index: 5, parents: ["VER_3", "caf\u00e9", "VER_3"] },
      ],
    }),
  );
  expect(report.version_definitions.names[4]).toMatchObject({
    parents: ["VER_3", "caf\u00e9", "VER_3"],
    parents_complete: true,
  });
});

/** This mutation fixture is ELF64 LE with identity-mapped dynamic addresses. */
const verdefOffset = (bytes: Buffer): number => {
  const phoff = Number(bytes.readBigUInt64LE(32));
  const phentsize = bytes.readUInt16LE(54);
  const phnum = bytes.readUInt16LE(56);
  for (let index = 0; index < phnum; index += 1) {
    const header = phoff + index * phentsize;
    if (bytes.readUInt32LE(header) !== 2) continue;
    const start = Number(bytes.readBigUInt64LE(header + 8));
    const end = start + Number(bytes.readBigUInt64LE(header + 32));
    for (let entry = start; entry < end; entry += 16)
      if (bytes.readBigInt64LE(entry) === 0x6ffffffcn)
        return Number(bytes.readBigUInt64LE(entry + 8));
  }
  throw new Error("Expected the fixture's DT_VERDEF declaration");
};

const inherited = () =>
  elfDependencyFixture({
    verdef: [
      { name: "BASE", index: 2 },
      { name: "CHILD", index: 3, parents: ["FIRST", "SECOND"] },
    ],
  });

it("retains an unreadable parent as null while observing its following sibling", async () => {
  const bytes = inherited();
  const child = verdefOffset(bytes) + 28;
  bytes.writeUInt32LE(0xffffffff, child + 28);
  const report = await parse(bytes);
  expect(report.version_definitions.names[1]).toMatchObject({
    name: "CHILD",
    parents: [null, "SECOND"],
    parents_complete: false,
  });
  expect(report.version_definitions.status).toBe("present");
  expect(report.coverage.status).toBe("partial");
  expect(report.issues).toContainEqual(
    expect.objectContaining({ code: "name_unreadable" }),
  );
});

it("keeps readable parents even when the definition's own name is unreadable", async () => {
  const bytes = inherited();
  const child = verdefOffset(bytes) + 28;
  bytes.writeUInt32LE(0xffffffff, child + 20);
  const report = await parse(bytes);
  expect(report.version_definitions.names[1]).toEqual({
    name: null,
    index: 3,
    base: false,
    parents: ["FIRST", "SECOND"],
    parents_complete: true,
  });
  expect(report.coverage.status).toBe("partial");
});

it.each([
  {
    label: "the definition name has an early zero link",
    field: 24,
    next: 0,
    parents: [],
  },
  {
    label: "a later parent has an early zero link",
    field: 32,
    next: 0,
    parents: ["FIRST"],
  },
  {
    label: "a later parent link leaves the table",
    field: 32,
    next: 0xffffffff,
    parents: ["FIRST"],
  },
  {
    label: "the final parent links beyond its count",
    field: 40,
    next: 8,
    parents: ["FIRST", "SECOND"],
  },
])(
  "keeps observed parent prefixes when $label",
  async ({ field, next, parents }) => {
    const bytes = inherited();
    const child = verdefOffset(bytes) + 28;
    bytes.writeUInt32LE(next, child + field);
    const report = await parse(bytes);
    expect(report.version_definitions.names).toEqual([
      {
        name: "BASE",
        index: 2,
        base: false,
        parents: [],
        parents_complete: true,
      },
      {
        name: "CHILD",
        index: 3,
        base: false,
        parents,
        parents_complete: false,
      },
    ]);
    expect(report.version_definitions.status).toBe("unreadable");
    expect(report.coverage.status).toBe("partial");
    expect(report.issues).toContainEqual(
      expect.objectContaining({ code: "version_unresolved" }),
    );
    expect(report.needed.map(({ name }) => name)).toEqual([
      "libstdc++.so.6",
      "libm.so.6",
      "libc.so.6",
    ]);
  },
);

it("uses the existing version-record budget for every parent", async () => {
  const bytes = elfDependencyFixture({
    verneed: [],
    imports: [],
    verdef: [{ name: "CHILD", index: 2, parents: ["FIRST", "SECOND"] }],
  });
  await expect(parse(bytes, 2)).rejects.toMatchObject({
    failure: {
      kind: "limit",
      limit: { name: "max_versions", maximum: 2, required: 3 },
    },
  });
  expect((await parse(bytes, 3)).coverage.examined_versions).toBe(3);
});

it("charges repeated parent names against the existing retained-text capacity", async () => {
  const name = "P".repeat(6000);
  const bytes = elfDependencyFixture({
    verneed: [],
    imports: [],
    needed: [],
    soname: null,
    runpath: null,
    verdef: [
      { name: "CHILD", index: 2, parents: Array<string>(64).fill(name) },
    ],
  });
  await expect(parse(bytes)).rejects.toMatchObject({
    failure: {
      kind: "limit",
      format: "elf-dependencies",
      limit: { name: "retained_text_bytes", maximum: bytes.length },
    },
  });
});

it("does not invent or preallocate parents from a large count and a broken first link", async () => {
  const bytes = elfDependencyFixture({
    verdef: [{ name: "CHILD", index: 2 }],
    verdefAuxiliary: { count: 65535, next: 0 },
  });
  const report = await parse(bytes);
  expect(report.version_definitions.names).toEqual([
    {
      name: "CHILD",
      index: 2,
      base: false,
      parents: [],
      parents_complete: false,
    },
  ]);
  expect(report.coverage.status).toBe("partial");
});
