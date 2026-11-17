import hashlib, json, os, pathlib, re, subprocess, time
repo=pathlib.Path.cwd(); source=pathlib.Path(os.environ["REA_SOURCE_ROOT"])
out=pathlib.Path(os.environ["REA_VALIDATION_OUTPUT"]); out.mkdir(parents=True,exist_ok=True)
payload=repo/"contribution-validation/native-dispatch-coverage"
npm=["node",os.environ["REA_NPM_CLI"]]
paths=["src/domain/native/nativeInvestigationGraph.ts","src/domain/native/nativeInvestigationGraph.test.ts"]
before={p:(source/p).read_bytes() for p in paths}
after={p:(payload/("candidate-"+pathlib.Path(p).name+".txt")).read_bytes() for p in paths}
records=[]
def command(name,args,expected=0,timeout=1800):
    start=time.time()
    with (out/(name+".log")).open("w") as stream:
        result=subprocess.run(args,cwd=source,stdout=stream,stderr=subprocess.STDOUT,timeout=timeout)
    text=(out/(name+".log")).read_text()
    record={"name":name,"exit_code":result.returncode,"seconds":time.time()-start,"expected_exit":expected}
    records.append(record); print("REA_DISPATCH_COMMAND",json.dumps(record),flush=True)
    print("REA_DISPATCH_LOG_TAIL",json.dumps({"name":name,"tail":text[-15000:]}),flush=True)
    if expected==0:
        assert result.returncode==0,(name,result.returncode)
    else:
        assert result.returncode==expected,(name,result.returncode)
    return text
def select(phase):
    for p in paths: (source/p).write_bytes(after[p] if phase=="after" or p.endswith(".test.ts") else before[p])
select("after")
command("format",["./node_modules/.bin/oxfmt",*paths],timeout=120)
after={p:(source/p).read_bytes() for p in paths}
select("before")
focused=["src/domain/native/nativeInvestigationGraph.test.ts","src/domain/apple/interfaceBuilderGraph.test.ts","src/application/native/EnhancedNativeInvestigation.test.ts"]
baseline=command("before-source-tests",npm+["run","test:local","--",*focused],expected=1)
expected=["counts all 2 authored actions","counts all 5 authored actions","counts only the genuinely unresolved action","retains complete action coverage"]
for label in expected: assert label in baseline,label
failed=re.search(r"Tests\s+(\d+) failed",baseline)
assert failed and int(failed.group(1))==4,baseline[-8000:]
print("REA_DISPATCH_BASELINE",json.dumps({"failed":4,"regressions":expected,"source":"unmodified pinned production files with six new public-API cases"}),flush=True)
select("after")
command("after-source-tests",npm+["run","test:local","--",*focused])
command("after-public-boundary",npm+["run","test:focused","--","tests/acceptance/applications/interfaceBuilderClassNameIdentity.test.ts","tests/boundary/mcp/interfaceBuilderSummaryMcp.test.ts"])
command("after-required-check",npm+["run","check"])
command("diff-check",["git","diff","--check"])
changed=subprocess.check_output(["git","diff","--name-only"],cwd=source,text=True).splitlines()
assert sorted(changed)==sorted(paths),changed
for p in paths:
    data=(source/p).read_bytes(); assert data==after[p]
    (out/("tested-"+pathlib.Path(p).name)).write_bytes(data)
    print("REA_DISPATCH_TESTED_FILE",json.dumps({"path":p,"sha256":hashlib.sha256(data).hexdigest(),"content":data.decode()}),flush=True)
summary={"baseline":"af062e7a2d290fec4307fb9444298a13c2fea630","regressions_failed_before":4,"new_cases":6,"source_hashes":{p:hashlib.sha256(after[p]).hexdigest() for p in paths},"success":True,"limits":"Synthetic ibtool document facts pass through real public UI-graph builder, dispatch join and route trace. No claim of live Apple ibtool/Hopper/Ghidra execution."}
(out/"commands.json").write_text(json.dumps(records,indent=2)); (out/"summary.json").write_text(json.dumps(summary,indent=2))
print("REA_DISPATCH_COMPLETE",json.dumps(summary),flush=True)
