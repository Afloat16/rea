import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";
const sourceRoot=process.env.REA_SOURCE_ROOT;
assert(sourceRoot);
const url=path=>pathToFileURL(join(sourceRoot,path)).href;
const { importVerifierSource }=await import(url("scripts/lib/verifier-source-loader.mjs"));
const { comparePngScreenshots }=await importVerifierSource(url("src/domain/pngVisualDiff.ts"),import.meta.url);
const { compareWebScreenshotsInputSchema,createWebScreenshotArtifact,webScreenshotDiffSchema }=await importVerifierSource(url("src/domain/webScreenshot.ts"),import.meta.url);
const [fixtureDirectory,caseName,reportPath]=process.argv.slice(2);
const cases=JSON.parse(readFileSync(join(fixtureDirectory,"cases.json"),"utf8"));
const fixture=cases.find(x=>x.name===caseName);assert(fixture);
const before=readFileSync(join(fixtureDirectory,fixture.before));
const after=readFileSync(join(fixtureDirectory,fixture.after));
const trials=[];const outputs=[];
for(let iteration=0;iteration<7;iteration++){
  global.gc?.();
  const cpu=process.cpuUsage();const started=performance.now();
  const input=compareWebScreenshotsInputSchema.parse({
    before:createWebScreenshotArtifact(before),
    after:createWebScreenshotArtifact(after),
    channel_threshold:fixture.oracle.channel_threshold,
  });
  const result=comparePngScreenshots(input);
  const elapsed=performance.now()-started;
  const usage=process.cpuUsage(cpu);
  webScreenshotDiffSchema.parse(result);
  for(const [key,value] of Object.entries(fixture.oracle))assert.deepEqual(result[key],value,key);
  outputs.push(result);
  trials.push({iteration,ms:elapsed,cpu:usage});
}
const serialized=JSON.stringify(outputs);
const report={case:caseName,node:process.version,input_sha256:fixture.input_sha256,filters:fixture.filters,oracle:fixture.oracle,trials,outputs,output_sha256:createHash("sha256").update(serialized).digest("hex"),peak_rss_kib:process.resourceUsage().maxRSS,scope:"Complete public artifact creation, input schema validation and comparePngScreenshots; import and disk read excluded; independent Pillow RGBA metrics asserted"};
writeFileSync(reportPath,JSON.stringify(report,null,2)+"\n");
console.log(JSON.stringify(report));
