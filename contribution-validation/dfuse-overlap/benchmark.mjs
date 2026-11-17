import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";
const sourceRoot = process.env.REA_SOURCE_ROOT;
assert(sourceRoot);
const sourceUrl = (path) => pathToFileURL(join(sourceRoot,path)).href;
const { importVerifierSource } = await import(sourceUrl("scripts/lib/verifier-source-loader.mjs"));
const { createDfuSeDecoder } = await importVerifierSource(sourceUrl("src/domain/firmware/dfuse.ts"), import.meta.url);
const { dfuseFile } = await importVerifierSource(sourceUrl("src/domain/firmware/dfuse.fixture.ts"), import.meta.url);
const { DfuSeArtifactReader } = await importVerifierSource(sourceUrl("src/artifacts/DfuSeArtifactReader.ts"), import.meta.url);
const scenario = process.argv[2] ?? "dense";
const mode = process.argv[3] ?? "decoder";
const count = scenario === "dense" ? 65_536 : scenario === "small" ? 8 : scenario === "empty" ? 0 : 128;
const directory = process.env.REA_VALIDATION_DIRECTORY;
assert(directory);
const results = join(directory,"results");
await mkdir(results,{recursive:true});
const elements = Array.from({length:count},(_,index)=>({
  address: scenario === "separate" ? 0x08000000+index*16 : 0x08000000,
  data: [index&255,(index>>>8)&255,0x5a,0xa5],
}));
const bytes = dfuseFile({targets:count===0?[]:[{alternateSetting:0,name:"Internal Flash",elements}]});
const digest = (value) => createHash("sha256").update(value).digest("hex");
const path = join(directory,scenario+".dfu");
await writeFile(path,bytes);
global.gc?.();
const memoryBefore=process.memoryUsage();
const cpuBefore=process.cpuUsage();
const start=performance.now();
let output;
if(mode==="decoder"){
  const opened=createDfuSeDecoder(bytes.length);
  assert.equal(opened.ok,true);
  assert.equal(opened.value.write(bytes).ok,true);
  const result=opened.value.finish();
  assert.equal(result.ok,true);
  const image=result.value;
  assert.equal(image.elements.length,count);
  assert.equal(image.metadata.element_count,count);
  assert.equal(image.metadata.overlapping_element_count,scenario==="separate"?0:Math.max(0,count-1));
  assert.equal(image.metadata.computed_crc,image.metadata.suffix_crc);
  const content=createHash("sha256");
  for(const [i,element] of image.elements.entries()){
    assert.equal(element.address,elements[i].address);
    assert.deepEqual([...element.bytes],elements[i].data);
    content.update(element.bytes);
  }
  output={metadata:image.metadata,limitations:image.limitations,
    elementFacts:image.elements.map(({bytes,...rest})=>({...rest,bytes:[...bytes]})),
    extracted_sha256:content.digest("hex")};
}else{
  const reader=new DfuSeArtifactReader(path);
  const facts=[];
  const content=createHash("sha256");
  let coverage;
  try{
    await reader.prepareContainer(digest(bytes));
    for await(const entry of reader.entries(undefined,{onCoverage(value){coverage=value;}})){
      facts.push(entry);
      const ordinal = facts.length - 1;
      assert.equal(entry.byteOffset, 293 + ordinal * 12);
      assert.equal(entry.declaredSize, 4);
      assert.equal(entry.formatMetadata.element_index, ordinal);
      assert.equal(entry.formatMetadata.start_address, elements[ordinal].address);
      assert.equal(entry.formatMetadata.end_address, elements[ordinal].address + 3);
      // Verify every entry's retained bytes, without opening 65,536 streams in
      // the large memory probe. The small public-reader task opens all of them.
      if(count<=128){
        const stream=await reader.open(entry);
        const chunks=[];
        for await(const chunk of stream) chunks.push(chunk);
        content.update(Buffer.concat(chunks));
        const element=elements[facts.length-1];
        assert.deepEqual([...Buffer.concat(chunks)],element.data);
      }
    }
    assert.equal(facts.length,count);
    assert.equal(coverage.status,"complete");
    assert.equal(reader.formatMetadata().overlapping_element_count,scenario==="separate"?0:Math.max(0,count-1));
    output={metadata:reader.formatMetadata(),integrity:reader.containerIntegrity(),coverage,entries:facts,
      extracted_sha256:count<=128?content.digest("hex"):null};
  }finally{await reader.close();}
}
const parseElapsed=performance.now()-start;
const parseCpu=process.cpuUsage(cpuBefore);
const parseMemory=process.memoryUsage();
const parsePeak=process.resourceUsage().maxRSS;
const serialized=JSON.stringify(output);
const elapsed=performance.now()-start;
const cpu=process.cpuUsage(cpuBefore);
const memoryAfter=process.memoryUsage();
const peak=process.resourceUsage().maxRSS;
const report={scenario,mode,node:process.version,fixture_bytes:bytes.length,fixture_sha256:digest(bytes),
 elapsed_ms:elapsed,cpu_user_us:cpu.user,cpu_system_us:cpu.system,max_rss_kib:peak,
 parse_elapsed_ms:parseElapsed,parse_cpu:parseCpu,parse_memory:parseMemory,parse_peak_rss_kib:parsePeak,
 memory_before:memoryBefore,memory_after:memoryAfter,result_sha256:digest(serialized),result_bytes:Buffer.byteLength(serialized),
 elements:count,limitations:output.limitations??output.coverage.limitations};
console.log("REA_DFUSE_BENCHMARK",JSON.stringify(report));
await writeFile(join(results,scenario+"-"+mode+"-report.json"),JSON.stringify(report,null,2)+"\n");
await writeFile(join(results,scenario+"-"+mode+"-output.json"),serialized);
