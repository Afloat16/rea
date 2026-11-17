import gzip, hashlib, json, os, pathlib, subprocess, time

repo = pathlib.Path.cwd()
source = pathlib.Path(os.environ["REA_SOURCE_ROOT"])
out = pathlib.Path(os.environ["REA_VALIDATION_OUTPUT"])
out.mkdir(parents=True, exist_ok=True)
payload = repo / "contribution-validation/dfuse-overlap"
npm = ["node", os.environ["REA_NPM_CLI"]]
paths = ["src/domain/firmware/dfuse.ts", "src/domain/firmware/dfuse.test.ts",
         "src/domain/firmware/uf2.ts", "src/domain/firmware/uf2.test.ts"]
before = {p: (source / p).read_bytes() for p in paths}
after = {p: (payload / ("candidate-" + pathlib.Path(p).name + ".txt")).read_bytes() for p in paths}
records = []
commands = []
def sha(data):
    return hashlib.sha256(data).hexdigest()
def command(name, args, cwd=source, env=None, timeout=1200):
    start = time.time()
    with (out / (name + ".log")).open("w") as log:
        result = subprocess.run(args, cwd=cwd, env=env, stdout=log,
                                stderr=subprocess.STDOUT, timeout=timeout)
    summary = {"name": name, "exit_code": result.returncode, "seconds": time.time() - start}
    commands.append(summary)
    print("REA_FIRMWARE_COMMAND", json.dumps(summary), flush=True)
    if result.returncode:
        print((out / (name + ".log")).read_text()[-18000:], flush=True)
        raise SystemExit(result.returncode)
    if "tests" in name or "cli-mcp" in name or "required-check" in name:
        print("REA_FIRMWARE_LOG_TAIL", json.dumps({"name": name, "tail": (out / (name + ".log")).read_text()[-2500:]}), flush=True)
def select(phase):
    for path in paths:
        # Both implementations run the same semantic tests.
        data = after[path] if phase == "after" or path.endswith(".test.ts") else before[path]
        (source / path).write_bytes(data)
select("after")
command("candidate-format", ["./node_modules/.bin/oxfmt", *paths], timeout=120)
after = {p: (source / p).read_bytes() for p in paths}
select("before")
test_files = ["src/domain/firmware/dfuse.test.ts", "src/artifacts/DfuSeArtifactReader.test.ts",
              "src/domain/firmware/uf2.test.ts", "src/artifacts/Uf2ArtifactReader.test.ts"]
command("before-source-tests", npm + ["run", "test:local", "--", *test_files])
cases = [("absent", 8), ("absent", 65536), ("ambiguous", 21845), ("complete", 8192)]
for repeat in range(3):
    for phase in (["before", "after"] if repeat % 2 == 0 else ["after", "before"]):
        select(phase)
        for scenario, count in cases:
            for mode in ["decoder", "reader"]:
                label = f"{phase}-{repeat}-{scenario}-{count}-{mode}"
                location = out / label
                environment = os.environ | {"REA_VALIDATION_DIRECTORY": str(location)}
                command(label, ["node", "--expose-gc", str(payload / "benchmark-uf2-public.mjs"),
                                scenario, mode, str(count)], env=environment, timeout=180)
                record = json.loads((location / "report.json").read_text()) | {
                    "phase": phase, "repeat": repeat, "label": label}
                records.append(record)
                print("REA_UF2_MEASURE", json.dumps(record), flush=True)
for scenario, count in cases:
    for mode in ["decoder", "reader"]:
        selected = [r for r in records if r["scenario"] == scenario and r["count"] == count and r["mode"] == mode]
        assert len(selected) == 6
        assert len({r["result_sha256"] for r in selected}) == 1, (scenario, count, mode)
        reference = None
        for record in selected:
            with gzip.open(out / record["label"] / "output.json.gz", "rb") as stream:
                data = stream.read()
            if reference is None:
                reference = data
            else:
                assert reference == data, (scenario, count, mode, record["label"])
print("REA_FIRMWARE_OUTPUTS_BYTE_EQUAL", json.dumps({"uf2_cases": len(cases), "modes": 2, "fresh_processes": len(records),
    "dfuse_previous_run": "https://github.com/Afloat16/rea/actions/runs/44032525389",
    "dfuse_exact_source_sha256": sha(after["src/domain/firmware/dfuse.ts"])}), flush=True)
select("after")
command("after-source-tests", npm + ["run", "test:local", "--", *test_files])
command("after-public-cli-mcp", npm + ["run", "test:focused", "--",
    "tests/acceptance/firmwareContainersCli.test.ts", "tests/boundary/mcp/firmwareContainersMcp.test.ts"])
command("after-required-check", npm + ["run", "check"], timeout=1800)
command("diff-check", ["git", "diff", "--check"])
changed = subprocess.check_output(["git", "diff", "--name-only"], cwd=source, text=True).splitlines()
assert sorted(changed) == sorted(paths), changed
for path in paths:
    actual = (source / path).read_bytes()
    assert actual == after[path], path
    (out / ("tested-" + pathlib.Path(path).name)).write_bytes(actual)
    print("REA_FIRMWARE_TESTED_FILE", json.dumps({"path": path, "sha256": sha(actual), "content": actual.decode()}), flush=True)
(out / "measurement-summary.json").write_text(json.dumps(records, indent=2))
(out / "command-summary.json").write_text(json.dumps(commands, indent=2))
summary = {"baseline": "d5a942177fad030d3caf0f8d39856c116e3e5cda",
           "source_hashes": {p: sha(after[p]) for p in paths}, "success": True,
           "performance_scope": "Synthetic fixed-layout fixtures, Node 24.22.1, single Ubuntu runner; no general CPU/token reduction claim"}
(out / "summary.json").write_text(json.dumps(summary, indent=2))
print("REA_FIRMWARE_COMPLETE", json.dumps(summary), flush=True)
