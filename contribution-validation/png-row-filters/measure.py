import hashlib, json, os, pathlib, statistics, subprocess, time
repo=pathlib.Path.cwd();source=pathlib.Path(os.environ["REA_SOURCE_ROOT"])
out=pathlib.Path(os.environ["REA_VALIDATION_OUTPUT"]);out.mkdir(parents=True,exist_ok=True)
payload=repo/"contribution-validation/png-row-filters"
npm=["node",os.environ["REA_NPM_CLI"]]
paths=["src/domain/pngVisualDiff.ts","src/domain/pngVisualDiff.test.ts"]
before={p:(source/p).read_bytes() for p in paths}
after={p:(payload/("candidate-"+pathlib.Path(p).name+".txt")).read_bytes() for p in paths}
commands=[];records=[]
def command(name,args,cwd=source,timeout=1800):
    started=time.time()
    with (out/(name+".log")).open("w") as stream:
        run=subprocess.run(args,cwd=cwd,stdout=stream,stderr=subprocess.STDOUT,timeout=timeout)
    row={"name":name,"exit_code":run.returncode,"seconds":time.time()-started}
    commands.append(row);print("REA_PNG_COMMAND",json.dumps(row),flush=True)
    if run.returncode:
        print((out/(name+".log")).read_text()[-18000:],flush=True);raise SystemExit(run.returncode)
    if "tests" in name or "check" in name or "cli" in name:
        print("REA_PNG_LOG_TAIL",json.dumps({"name":name,"tail":(out/(name+".log")).read_text()[-2500:]}),flush=True)
def select(phase):
    for p in paths:(source/p).write_bytes(after[p] if phase=="after" or p.endswith(".test.ts") else before[p])
select("after")
command("format",["./node_modules/.bin/oxfmt",*paths],timeout=120)
after={p:(source/p).read_bytes() for p in paths}
select("before")
tests=["src/domain/pngVisualDiff.test.ts","src/domain/pngHeader.test.ts","tests/boundary/browser/browserToolContractExamples.test.ts"]
command("before-source-tests",npm+["run","test:local","--",*tests])
fixtures=out/"fixtures"
command("independent-producer",[os.environ["REA_PNG_PYTHON"],str(payload/"producer.py"),str(fixtures)])
cases=json.loads((fixtures/"cases.json").read_text())
for repeat in range(3):
    for phase in (["before","after"] if repeat%2==0 else ["after","before"]):
        select(phase)
        for case in cases:
            label=f"{phase}-{repeat}-{case['name']}"
            report=out/(label+".json")
            command(label,["node","--expose-gc",str(payload/"benchmark.mjs"),str(fixtures),case["name"],str(report)],timeout=180)
            row=json.loads(report.read_text())|{"phase":phase,"repeat":repeat}
            records.append(row)
            print("REA_PNG_MEASURE",json.dumps({k:v for k,v in row.items() if k!="outputs"}),flush=True)
for case in cases:
    selected=[r for r in records if r["case"]==case["name"]]
    assert len(selected)==6
    assert len({r["output_sha256"] for r in selected})==1
    first=json.dumps(selected[0]["outputs"],separators=(",",":"))
    for r in selected:assert json.dumps(r["outputs"],separators=(",",":"))==first
print("REA_PNG_OUTPUTS_BYTE_EQUAL",json.dumps({"cases":len(cases),"fresh_processes":len(records),"calls_per_process":7,"independent_oracle":"Pillow 13.0.0 exact RGBA difference metrics"}),flush=True)
select("after")
command("after-source-tests",npm+["run","test:local","--",*tests])
command("after-public-cli",npm+["run","test:focused","--","tests/boundary/cli/browserCli.test.ts"])
command("after-required-check",npm+["run","check"])
command("diff-check",["git","diff","--check"])
changed=subprocess.check_output(["git","diff","--name-only"],cwd=source,text=True).splitlines()
assert sorted(changed)==sorted(paths),changed
for p in paths:
    data=(source/p).read_bytes();assert data==after[p]
    (out/("tested-"+pathlib.Path(p).name)).write_bytes(data)
    print("REA_PNG_TESTED_FILE",json.dumps({"path":p,"sha256":hashlib.sha256(data).hexdigest(),"content":data.decode()}),flush=True)
summary={"baseline":"af062e7a2d290fec4307fb9444298a13c2fea630","source_hashes":{p:hashlib.sha256(after[p]).hexdigest() for p in paths},"cases":len(cases),"processes":len(records),"success":True,"timing_note":"Cold first and warmed subsequent calls reported separately; no system-wide or browser-capture throughput claim."}
(out/"measurements.json").write_text(json.dumps(records,indent=2))
(out/"commands.json").write_text(json.dumps(commands,indent=2))
(out/"summary.json").write_text(json.dumps(summary,indent=2))
print("REA_PNG_COMPLETE",json.dumps(summary),flush=True)
