import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import {
  elfDependenciesSchema,
  inspectElfDependenciesInputSchema,
} from "../../domain/native/elfDependencies.js";
import {
  elfDependencyByteSource,
  elfDependencyFixture,
} from "./ElfDependencies.fixture.js";
import { elfLoaderDirectivesFixture } from "./ElfLoaderDirectives.fixture.js";
import { parseElfDependenciesFromHandle } from "./ElfDependencyParser.js";

const path = "/artifacts/loader.so";
const parse = async (bytes: Buffer, extra: Record<string, unknown> = {}) =>
  elfDependenciesSchema.parse(
    await parseElfDependenciesFromHandle(
      elfDependencyByteSource(bytes, 16),
      {
        path,
        bytes: bytes.length,
        sha256: createHash("sha256").update(bytes).digest("hex"),
      },
      inspectElfDependenciesInputSchema.parse({ path, ...extra }),
      async () => {},
    ),
  );

it.each([
  { bits: 32, little: true, stripped: true },
  { bits: 32, little: false, stripped: false },
  { bits: 64, little: true, stripped: false },
  { bits: 64, little: false, stripped: true },
] as const)(
  "retains all four loader declarations and their physical sources in ELF$bits, little=$little",
  async (options) => {
    const { bytes, dynamicOffset, entryBytes } = elfLoaderDirectivesFixture(
      undefined,
      options,
    );
    const report = await parse(bytes);
    expect(report.needed.map(({ name }) => name)).toEqual(["libc.so.6"]);
    expect(
      report.loader_directives?.map(({ kind, value, tokens }) => ({
        kind,
        value,
        tokens,
      })),
    ).toEqual([
      { kind: "filter", value: "$ORIGIN/libfilter.so", tokens: ["$ORIGIN"] },
      { kind: "auxiliary", value: "libaux.so", tokens: [] },
      { kind: "audit", value: "audit.so:${LIB}/audit2.so", tokens: ["$LIB"] },
      { kind: "depaudit", value: "dep-audit.so", tokens: [] },
    ]);
    for (const [index, row] of (report.loader_directives ?? []).entries()) {
      expect(row.location).toEqual({
        offset: dynamicOffset + index * entryBytes,
        bytes: entryBytes,
      });
      expect(row.index).toBe(index);
      if (row.string_location === null)
        throw new Error("Expected a backed string");
      const value = bytes.subarray(
        row.string_location.offset,
        row.string_location.offset + row.string_location.bytes,
      );
      expect(value.toString("latin1")).toBe(`${row.value}\0`);
    }
    expect(report.coverage).toMatchObject({
      status: "complete",
      examined_loader_directives: 4,
    });
  },
);

it("keeps repeated directives in source order and preserves empty audit components", async () => {
  const { bytes } = elfLoaderDirectivesFixture([
    { tag: 0x7ffffffd, value: "same.so" },
    { tag: 0x6ffffefc, value: ":a.so::b.so:" },
    { tag: 0x7ffffffd, value: "same.so" },
  ]);
  const report = await parse(bytes);
  expect(
    report.loader_directives?.map(({ kind, value }) => ({ kind, value })),
  ).toEqual([
    { kind: "auxiliary", value: "same.so" },
    { kind: "audit", value: ":a.so::b.so:" },
    { kind: "auxiliary", value: "same.so" },
  ]);
});

it("preserves unreadable and empty values without dropping neighboring directives", async () => {
  const { bytes, dynamicOffset } = elfLoaderDirectivesFixture([
    { tag: 0x7fffffff, value: "outside", nameOffset: 0x10000 },
    { tag: 0x6ffffefc, value: "" },
    { tag: 0x7ffffffd, value: "valid.so" },
  ]);
  const report = await parse(bytes);
  expect(report.loader_directives?.map(({ value }) => value)).toEqual([
    null,
    "",
    "valid.so",
  ]);
  expect(report.loader_directives?.[0]).toMatchObject({
    name_offset: 0x10000,
    string_location: null,
  });
  expect(report.issues).toContainEqual(
    expect.objectContaining({
      code: "name_unreadable",
      location: `0x${dynamicOffset.toString(16)}`,
    }),
  );
  expect(report.coverage).toMatchObject({
    status: "partial",
    examined_loader_directives: 3,
  });
});

it("keeps tag identities when the dynamic string table is unavailable", async () => {
  const { bytes } = elfLoaderDirectivesFixture(undefined, {
    missingStrings: true,
  });
  const report = await parse(bytes);
  expect(
    report.loader_directives?.map(({ kind, value, string_location }) => ({
      kind,
      value,
      string_location,
    })),
  ).toEqual(
    ["filter", "auxiliary", "audit", "depaudit"].map((kind) => ({
      kind,
      value: null,
      string_location: null,
    })),
  );
  expect(report.coverage.status).toBe("partial");
});

it("refuses a caller-selected loader directive budget independently of DT_NEEDED", async () => {
  const { bytes } = elfLoaderDirectivesFixture();
  await expect(parse(bytes, { max_loader_directives: 3 })).rejects.toThrow(
    /loader directive.*3-entry/iu,
  );
  expect(
    (await parse(bytes, { max_needed: 1, max_loader_directives: 4 }))
      .loader_directives,
  ).toHaveLength(4);
});

it("does not reinterpret unrelated OS tags as a loader directive", async () => {
  const { bytes } = elfLoaderDirectivesFixture([
    { tag: 0x60000042, value: "other.so" },
  ]);
  const report = await parse(bytes);
  expect(report.loader_directives).toEqual([]);
  expect(report.coverage.examined_loader_directives).toBe(0);
});

it("records an observed empty inventory when PT_DYNAMIC is absent", async () => {
  const report = await parse(
    elfDependencyFixture({ omitDynamic: true, interpreter: null }),
  );
  expect(report.loader_directives).toEqual([]);
  expect(report.coverage).toMatchObject({
    status: "complete",
    examined_loader_directives: 0,
  });
});
