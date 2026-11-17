import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";
import { performance } from "node:perf_hooks";

const sourceRoot = process.env.REA_SOURCE_ROOT;
const directory = process.env.REA_VALIDATION_DIRECTORY;
assert(sourceRoot && directory);
const sourceUrl = (path) => pathToFileURL(join(sourceRoot, path)).href;
const { importVerifierSource } = await import(sourceUrl("scripts/lib/verifier-source-loader.mjs"));
const { createUf2Decoder } = await importVerifierSource(sourceUrl("src/domain/firmware/uf2.ts"), import.meta.url);
const { Uf2ArtifactReader } = await importVerifierSource(sourceUrl("src/artifacts/Uf2ArtifactReader.ts"), import.meta.url);
const [scenario = "absent", mode = "decoder", countText = "8"] = process.argv.slice(2);
assert(["absent", "ambiguous", "complete"].includes(scenario));
assert(["decoder", "reader"].includes(mode));
const count = Number(countText);
assert(Number.isInteger(count) && count > 0 && count <= 65_536);
const perGroup = scenario === "ambiguous" ? 3 : scenario === "complete" ? 2 : 1;
// Independent fixed-layout writer, checked against microsoft/uf2 README.md at
// cf3bd7f9c274b949528f8cd6a19eef2502a687d2. Payloads and addresses are 4-byte aligned.
const bytes = Buffer.alloc(count * perGroup * 512);
const payloadFor = (ordinal) => [ordinal + 1, 0xa5, 0x5a, 0xff];
const expectedPayload = createHash("sha256");
for (let family = 0; family < count; family++) {
  for (let ordinal = 0; ordinal < perGroup; ordinal++)
    expectedPayload.update(Buffer.from(payloadFor(ordinal)));
  for (let ordinal = 0; ordinal < perGroup; ordinal++) {
    const at = (family * perGroup + ordinal) * 512;
    const slot = scenario === "ambiguous" ? [0, 2, 1][ordinal] : ordinal;
    const number = scenario === "ambiguous" ? [0, 0, 1][ordinal] : ordinal;
    bytes.writeUInt32LE(0x0a324655, at);
    bytes.writeUInt32LE(0x9e5d5157, at + 4);
    bytes.writeUInt32LE(0x2000, at + 8);
    bytes.writeUInt32LE(0x08000000 + slot * 4, at + 12);
    bytes.writeUInt32LE(4, at + 16);
    bytes.writeUInt32LE(number, at + 20);
    bytes.writeUInt32LE(2, at + 24);
    bytes.writeUInt32LE(family + 1, at + 28);
    bytes.set(payloadFor(slot), at + 32);
    bytes.writeUInt32LE(0x0ab16f30, at + 508);
  }
}
const expectedPayloadHash = expectedPayload.digest("hex");
const hash = (value) => createHash("sha256").update(value).digest("hex");
const expectedWarning = [];
if (scenario !== "complete") {
  const names = Array.from({ length: Math.min(4, count) }, (_, index) => {
    const family = (index + 1).toString(16).padStart(8, "0");
    return "family 0x" + family + " with 2 numbered blocks" +
      (scenario === "absent" ? " has 1 of them" : " has some numbers at 1 address(es) and others at 2");
  });
  if (count > 4) names.push("and " + (count - 4) + " more");
  expectedWarning.push((scenario === "absent" ?
    "UF2 numbering declares " + count + " block(s) that are absent: " :
    "UF2 numbering cannot show that every copy of a block sequence is complete: ") + names.join("; ") + ".");
}
const assertMetadata = (metadata) => {
  assert.equal(metadata.block_count, count * perGroup);
  assert.equal(metadata.numbering_group_count, count);
  assert.equal(metadata.missing_block_count, scenario === "absent" ? count : 0);
  assert.equal(metadata.ambiguous_numbering_group_count, scenario === "ambiguous" ? count : 0);
  assert.equal(metadata.data_bytes, count * perGroup * 4);
  assert.equal(metadata.repeated_block_count, scenario === "ambiguous" ? count : 0);
  assert.equal(metadata.duplicate_bytes, 0);
  assert.equal(metadata.region_count, count);
};
await mkdir(directory, { recursive: true });
const fixture = join(directory, scenario + ".uf2");
await writeFile(fixture, bytes);
global.gc?.(); global.gc?.();
const memoryBefore = process.memoryUsage();
const peakBefore = process.resourceUsage().maxRSS;
const cpuBefore = process.cpuUsage();
const started = performance.now();
let output;
if (mode === "decoder") {
  const decoder = createUf2Decoder(bytes.length);
  assert.equal(decoder.ok, true);
  for (let offset = 0; offset < bytes.length; offset += 65536)
    assert.equal(decoder.value.write(bytes.subarray(offset, offset + 65536)).ok, true);
  const result = decoder.value.finish();
  assert.equal(result.ok, true);
  const image = result.value;
  assertMetadata(image.metadata);
  assert.equal(image.complete, scenario === "complete");
  assert.deepEqual(image.limitations, expectedWarning);
  const actualPayload = createHash("sha256");
  for (const [index, region] of image.regions.entries()) {
    assert.equal(region.familyId, index + 1);
    assert.equal(region.start, 0x08000000);
    assert.equal(region.end, 0x08000000 + perGroup * 4 - 1);
    assert.equal(region.blockCount, perGroup);
    assert.equal(region.firstFileBlock, index * perGroup);
    assert.equal(region.lastFileBlock, (index + 1) * perGroup - 1);
    actualPayload.update(region.bytes);
  }
  assert.equal(actualPayload.digest("hex"), expectedPayloadHash);
  output = image;
} else {
  const reader = new Uf2ArtifactReader(fixture);
  const entries = [];
  const payload = createHash("sha256");
  let coverage;
  try {
    await reader.prepareContainer(hash(bytes));
    for await (const entry of reader.entries(undefined, { onCoverage(value) { coverage = value; } })) {
      const index = entries.length;
      entries.push(entry);
      assert.equal(entry.byteOffset, null);
      assert.equal(entry.declaredSize, perGroup * 4);
      assert.equal(entry.formatMetadata.family_id, index + 1);
      assert.equal(entry.formatMetadata.start_address, 0x08000000);
      assert.equal(entry.formatMetadata.end_address, 0x08000000 + perGroup * 4 - 1);
      assert.equal(entry.formatMetadata.block_count, perGroup);
      assert.equal(entry.formatMetadata.first_file_block, index * perGroup);
      assert.equal(entry.formatMetadata.last_file_block, (index + 1) * perGroup - 1);
      // Small workflow opens every stream. Large workflow checks every retained
      // entry; its separate decoder run independently checks every payload byte.
      if (count <= 128) {
        const stream = await reader.open(entry);
        const chunks = [];
        for await (const chunk of stream) chunks.push(chunk);
        const value = Buffer.concat(chunks);
        assert.deepEqual([...value], Array.from({ length: perGroup }, (_, ordinal) => payloadFor(ordinal)).flat());
        payload.update(value);
      }
    }
    assert.equal(entries.length, count);
    assertMetadata(reader.formatMetadata());
    assert.equal(coverage.status, scenario === "complete" ? "complete" : "unknown");
    assert.deepEqual(coverage.limitations, expectedWarning);
    const payloadHash = count <= 128 ? payload.digest("hex") : null;
    if (payloadHash !== null) assert.equal(payloadHash, expectedPayloadHash);
    output = { metadata: reader.formatMetadata(), integrity: reader.containerIntegrity(), coverage, entries, extracted_sha256: payloadHash };
  } finally {
    await reader.close();
  }
}
const parsed = performance.now();
const parseCpu = process.cpuUsage(cpuBefore);
const memoryParsed = process.memoryUsage();
const peakParsed = process.resourceUsage().maxRSS;
const serialized = JSON.stringify(output);
const report = {
  scenario, mode, count, node: process.version, input_bytes: bytes.length,
  input_sha256: hash(bytes), source_sha256: hash(await readFile(join(sourceRoot, "src/domain/firmware/uf2.ts"))),
  result_sha256: hash(serialized), result_bytes: Buffer.byteLength(serialized),
  parse_ms: parsed - started, total_ms: performance.now() - started,
  parse_cpu: parseCpu, total_cpu: process.cpuUsage(cpuBefore),
  peak_rss_kib_before: peakBefore, parse_peak_rss_kib: peakParsed,
  peak_rss_kib: process.resourceUsage().maxRSS, memory_before: memoryBefore,
  memory_parsed: memoryParsed, memory_after: process.memoryUsage(),
  limitations: expectedWarning
};
await writeFile(join(directory, "report.json"), JSON.stringify(report, null, 2) + "\n");
await writeFile(join(directory, "output.json.gz"), gzipSync(serialized));
console.log("REA_UF2_BENCHMARK", JSON.stringify(report));
