import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { importVerifierSource } from "./scripts/lib/verifier-source-loader.mjs";

const [phase, inputDirectory, reportPath] = process.argv.slice(2);
assert(["before", "after"].includes(phase));
const modulePath = phase === "before" ? "src/domain/firmware/hexRecords.ts" : "src/domain/firmware/hexRecords-lazy.ts";
const { createHexRecordDecoder } = await importVerifierSource("./" + modulePath, import.meta.url);
const bytes = readFileSync(join(inputDirectory, "objcopy.hex"));
const expected = readFileSync(join(inputDirectory, "payload.bin"));
const hash = value => createHash("sha256").update(value).digest("hex");
global.gc?.(); global.gc?.();
const cpuBefore = process.cpuUsage();
const memoryBefore = process.memoryUsage();
const started = performance.now();
const created = createHexRecordDecoder("intel-hex", bytes.length);
assert.equal(created.ok, true);
for (let offset = 0; offset < bytes.length; offset += 65536)
  assert.equal(created.value.write(bytes.subarray(offset, offset + 65536)).ok, true);
const result = created.value.finish();
assert.equal(result.ok, true);
const parsed = performance.now();
const image = result.value;
assert.equal(image.regions.length, 1);
assert.equal(image.regions[0].start, 0x08000000);
assert.equal(image.regions[0].end, 0x08000000 + expected.length - 1);
assert.equal(Buffer.compare(Buffer.from(image.regions[0].bytes), expected), 0);
assert.equal(image.metadata.data_bytes, expected.length);
assert.equal(image.metadata.duplicate_bytes, 0);
assert.equal(image.terminated, true);
assert.deepEqual(image.limitations, []);
const facts = {metadata:image.metadata, regions:image.regions.map(({bytes,...r})=>({...r,bytes:bytes.length,payload_sha256:hash(bytes)})), terminated:image.terminated, limitations:image.limitations};
const serialized = JSON.stringify(facts);
const report = {phase, node:process.version, source_sha256:hash(readFileSync(modulePath)),
 input_bytes:bytes.length,input_sha256:hash(bytes),payload_bytes:expected.length,payload_sha256:hash(expected),
 parse_ms:parsed-started,total_ms:performance.now()-started,cpu:process.cpuUsage(cpuBefore),
 peak_rss_kib:process.resourceUsage().maxRSS,memory_before:memoryBefore,memory_after:process.memoryUsage(),
 result_sha256:hash(serialized),facts};
writeFileSync(reportPath, JSON.stringify(report,null,2)+"\n");
console.log(JSON.stringify(report));
