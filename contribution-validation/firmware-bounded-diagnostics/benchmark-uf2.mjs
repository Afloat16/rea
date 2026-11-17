import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { performance } from "node:perf_hooks";
import { importVerifierSource } from "./scripts/lib/verifier-source-loader.mjs";

const [phase="before", scenario="absent", countText="8", label="one"]=process.argv.slice(2);
assert(["before","after"].includes(phase));
assert(["absent","ambiguous","complete"].includes(scenario));
const count=Number(countText); assert(Number.isInteger(count)&&count>=0&&count<=65536);
const path=phase==="before"?"src/domain/firmware/uf2.ts":"src/domain/firmware/uf2-bounded.ts";
const { createUf2Decoder }=await importVerifierSource("./"+path,import.meta.url);
const perGroup=scenario==="ambiguous"?3:scenario==="complete"?2:1;
// Independent block writer from the UF2 fixed layout: 32-byte header,
// little-endian words, payload at 32 and the end marker at 508.
const bytes=Buffer.alloc(count*perGroup*512);
const expectedPayload=createHash("sha256");
for(let family=0;family<count;family++){
 const payload=scenario==="ambiguous"?[1,2,3]:scenario==="complete"?[1,2]:[1];
 expectedPayload.update(Buffer.from(payload));
 for(let ordinal=0;ordinal<perGroup;ordinal++){
  const at=(family*perGroup+ordinal)*512;
  const offset=scenario==="ambiguous"?[0,2,1][ordinal]:ordinal;
  const number=scenario==="ambiguous"?[0,0,1][ordinal]:ordinal;
  bytes.writeUInt32LE(0x0a324655,at);bytes.writeUInt32LE(0x9e5d5157,at+4);
  bytes.writeUInt32LE(0x2000,at+8);bytes.writeUInt32LE(0x08000000+offset,at+12);
  bytes.writeUInt32LE(1,at+16);bytes.writeUInt32LE(number,at+20);
  bytes.writeUInt32LE(2,at+24);bytes.writeUInt32LE(family+1,at+28);
  bytes[at+32]=payload[offset];
  bytes.writeUInt32LE(0x0ab16f30,at+508);
 }
}
const hash=(value)=>createHash("sha256").update(value).digest("hex");
global.gc?.(); global.gc?.();
const memoryBefore=process.memoryUsage();
const peakBefore=process.resourceUsage().maxRSS;
const cpuBefore=process.cpuUsage();const started=performance.now();
const decoder=createUf2Decoder(bytes.length);assert.equal(decoder.ok,true);
for(let offset=0;offset<bytes.length;offset+=65536){
 const written=decoder.value.write(bytes.subarray(offset,offset+65536));
 assert.equal(written.ok,true);
}
const result=decoder.value.finish();assert.equal(result.ok,true);
const parsed=performance.now();const parseCpu=process.cpuUsage(cpuBefore);
const memoryParsed=process.memoryUsage();const peakParsed=process.resourceUsage().maxRSS;
const image=result.value;
assert.equal(image.metadata.block_count,count*perGroup);
assert.equal(image.metadata.numbering_group_count,count);
assert.equal(image.metadata.missing_block_count,scenario==="absent"?count:0);
assert.equal(image.metadata.ambiguous_numbering_group_count,scenario==="ambiguous"?count:0);
assert.equal(image.metadata.data_bytes,count*perGroup);
assert.equal(image.metadata.repeated_block_count,scenario==="ambiguous"?count:0);
assert.equal(image.metadata.duplicate_bytes,0);
assert.equal(image.regions.length,count);
assert.equal(image.complete,scenario==="complete"||count===0);
const actualPayload=createHash("sha256");
for(const [index,region] of image.regions.entries()){
 assert.equal(region.familyId,index+1);
 assert.equal(region.start,0x08000000);
 assert.equal(region.end,0x08000000+perGroup-1);
 actualPayload.update(region.bytes);
}
assert.equal(actualPayload.digest("hex"),expectedPayload.digest("hex"));
const expectedWarning=[];
if(count&&scenario!=="complete"){
 const names=Array.from({length:Math.min(4,count)},(_,index)=>{
  const family=(index+1).toString(16).padStart(8,"0");
  return "family 0x"+family+" with 2 numbered blocks"+
   (scenario==="absent"?" has 1 of them":" has some numbers at 1 address(es) and others at 2");
 });
 if(count>4)names.push("and "+(count-4)+" more");
 expectedWarning.push((scenario==="absent"?"UF2 numbering declares "+count+" block(s) that are absent: ":"UF2 numbering cannot show that every copy of a block sequence is complete: ")+names.join("; ")+".");
}
assert.deepEqual(image.limitations,expectedWarning);
const serialized=JSON.stringify(image);
const cpu=process.cpuUsage(cpuBefore);
const report={phase,scenario,count,label,node:process.version,input_bytes:bytes.length,
 input_sha256:hash(bytes),source_sha256:hash(readFileSync(path)),result_sha256:hash(serialized),
 result_bytes:Buffer.byteLength(serialized),parse_ms:parsed-started,total_ms:performance.now()-started,
 parse_cpu:parseCpu,total_cpu:cpu,peak_rss_kib_before:peakBefore,parse_peak_rss_kib:peakParsed,
 peak_rss_kib:process.resourceUsage().maxRSS,memory_before:memoryBefore,memory_parsed:memoryParsed,
 memory_after:process.memoryUsage(),limitations:image.limitations};
const output=process.env.REA_PROBE_OUTPUT;assert(output);
mkdirSync(output,{recursive:true});
writeFileSync(join(output,label+".json"),JSON.stringify(report,null,2)+"\n");
writeFileSync(join(output,label+"-output.json.gz"),gzipSync(serialized));
console.log(JSON.stringify(report));
