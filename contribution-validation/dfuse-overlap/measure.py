import hashlib, json, os, pathlib, shutil, subprocess, sys, time
repo=pathlib.Path.cwd()
source=pathlib.Path(os.environ["REA_SOURCE_ROOT"])
out=pathlib.Path(os.environ["REA_VALIDATION_OUTPUT"])
out.mkdir(parents=True,exist_ok=True)
payload=repo/"contribution-validation/dfuse-overlap"
production=source/"src/domain/firmware/dfuse.ts"
tests=source/"src/domain/firmware/dfuse.test.ts"
before=production.read_bytes()
after=(payload/"candidate-dfuse.ts.txt").read_bytes()
test_candidate=(payload/"candidate-dfuse.test.ts.txt").read_bytes()
npm=["node",os.environ["REA_NPM_CLI"]]
bench=payload/"benchmark.mjs"
records=[]
def sha(data): return hashlib.sha256(data).hexdigest()
def command(name,args,cwd=source,env=None,timeout=1200):
    start=time.time()
    with (out/(name+".log")).open("w") as log:
        result=subprocess.run(args,cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
    print("REA_DFUSE_COMMAND",json.dumps({"name":name,"exit_code":result.returncode,"seconds":time.time()-start}),flush=True)
    if result.returncode: print((out/(name+".log")).read_text()[-18000:],flush=True)
    if result.returncode: raise SystemExit(result.returncode)
def select(phase):
    production.write_bytes(before if phase=="before" else after)
    tests.write_bytes(test_candidate)
# Original implementation plus the same semantic regression.
select("before")
command("before-source-tests",npm+["run","test:local","--","src/domain/firmware/dfuse.test.ts","src/artifacts/DfuSeArtifactReader.test.ts"])
# Benchmark fresh native Node processes, alternating implementations by round.
for repeat in range(3):
    for phase in (["before","after"] if repeat%2==0 else ["after","before"]):
        select(phase)
        for scenario in ["empty","small","separate","dense"]:
            for mode in ["decoder","reader"]:
                label=f"{phase}-{repeat}-{scenario}-{mode}"
                location=out/label
                environment=os.environ|{"REA_VALIDATION_DIRECTORY":str(location)}
                command(label,["node","--expose-gc",str(bench),scenario,mode],env=environment,timeout=120)
                report=json.loads((location/"results"/f"{scenario}-{mode}-report.json").read_text())
                report|={"phase":phase,"repeat":repeat,"source_sha256":sha(production.read_bytes())}
                records.append(report)
                print("REA_DFUSE_MEASURE",json.dumps(report),flush=True)
# No projection-only comparison: complete producer and complete reader output
# bytes, including element identities, ranges, payload and every diagnostic.
for scenario in ["empty","small","separate","dense"]:
    for mode in ["decoder","reader"]:
        selected=[r for r in records if r["scenario"]==scenario and r["mode"]==mode]
        assert len({r["result_sha256"] for r in selected})==1,(scenario,mode,selected)
        reference=None
        for r in selected:
            data=(out/f'{r["phase"]}-{r["repeat"]}-{scenario}-{mode}'/"results"/f"{scenario}-{mode}-output.json").read_bytes()
            if reference is None: reference=data
            else: assert data==reference
print("REA_DFUSE_ALL_OUTPUTS_BYTE_EQUAL",json.dumps({"scenarios":4,"modes":2,"fresh_processes":len(records)}),flush=True)
select("before")
command("before-public-cli-mcp",npm+["run","test:focused","--","tests/acceptance/firmwareContainersCli.test.ts","tests/boundary/mcp/firmwareContainersMcp.test.ts"])
select("after")
command("candidate-format",["./node_modules/.bin/oxfmt","src/domain/firmware/dfuse.ts","src/domain/firmware/dfuse.test.ts"],timeout=120)
after=production.read_bytes()
test_candidate=tests.read_bytes()
(out/"measurement-summary.json").write_text(json.dumps(records,indent=2))
(out/"tested-dfuse.ts").write_bytes(after)
(out/"tested-dfuse.test.ts").write_bytes(test_candidate)
print("REA_DFUSE_FORMATTED_SOURCE_HASHES",json.dumps({"source":sha(after),"tests":sha(test_candidate)}),flush=True)
command("after-source-tests",npm+["run","test:local","--","src/domain/firmware/dfuse.test.ts","src/artifacts/DfuSeArtifactReader.test.ts"])
command("after-public-cli-mcp",npm+["run","test:focused","--","tests/acceptance/firmwareContainersCli.test.ts","tests/boundary/mcp/firmwareContainersMcp.test.ts"])
command("after-required-check",npm+["run","check"],timeout=1800)
(out/"measurement-summary.json").write_text(json.dumps(records,indent=2))
(out/"tested-dfuse.ts").write_bytes(after)
(out/"tested-dfuse.test.ts").write_bytes(test_candidate)
print("REA_DFUSE_TESTED_SOURCE",json.dumps({"path":"src/domain/firmware/dfuse.ts","sha256":sha(after),"content":after.decode()}),flush=True)
print("REA_DFUSE_TESTED_TESTS",json.dumps({"path":"src/domain/firmware/dfuse.test.ts","sha256":sha(test_candidate),"content":test_candidate.decode()}),flush=True)
print("REA_DFUSE_MEASURE_COMPLETE",json.dumps({"before_source_sha256":sha(before),"after_source_sha256":sha(after),"tests_sha256":sha(test_candidate),"success":True}),flush=True)
