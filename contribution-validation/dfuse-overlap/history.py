import hashlib, json, re, subprocess, pathlib, sys
def git(*args, **kwargs):
    return subprocess.check_output(["git", *args], text=True, **kwargs)
root=pathlib.Path("contribution-validation/dfuse-overlap/results")
root.mkdir(parents=True, exist_ok=True)
for label, url, specs in [
    ("upstream", "https://github.com/morluto/rea.git", ["+refs/heads/*:refs/audit-upstream/heads/*", "+refs/tags/*:refs/audit-upstream/tags/*", "+refs/pull/*/head:refs/audit-upstream/pull/*/head"]),
    ("fork", "https://github.com/Afloat16/rea.git", ["+refs/heads/*:refs/audit-fork/heads/*", "+refs/tags/*:refs/audit-fork/tags/*"]),
]:
    with (root/f"{label}-fetch.log").open("w") as log:
        subprocess.run(["git","fetch","--no-tags",url,*specs],check=True,stdout=log,stderr=subprocess.STDOUT)
refs=git("for-each-ref","--format=%(refname) %(objectname)","refs/audit-upstream","refs/audit-fork").splitlines()
objects=git("rev-list","--objects","--all").splitlines()
paths=sorted({line.partition(" ")[2] for line in objects if re.search(r"dfuse",line.partition(" ")[2],re.I) and line.partition(" ")[2].endswith((".ts",".js",".mjs",".py")) and "contribution-validation/" not in line})
# Follow both sides of historical renames. The file-name seed is supplemented
# with each path's full-history -m log so reverted and merge-parent variants survive.
changed=True
while changed:
    changed=False
    changes=git("log","--all","--full-history","-m","--format=","--name-status","-M","--",*paths).splitlines()
    for line in changes:
        fields=line.split("\t")
        if fields and fields[0].startswith(("R","C")):
            for path in fields[1:]:
                if path not in paths:
                    paths.append(path); changed=True
    paths.sort()
variant_objects={}
for line in git("rev-list","--objects","--all","--",*paths).splitlines():
    sha, sep, path=line.partition(" ")
    if sep and path in paths:
        variant_objects.setdefault(sha,set()).add(path)
variants=[]
for sha, names in sorted(variant_objects.items()):
    if git("cat-file","-t",sha).strip()!="blob": continue
    source=git("cat-file","blob",sha)
    if "overlappingElements" not in source and "overlapping_element_count" not in source: continue
    where=source.find("const overlappingElements")
    if where<0: where=source.find("function overlappingElements")
    if where<0: where=0
    # Keep full sources as well; extracted owner makes review logs manageable.
    owner=source[where:]
    metadata="\n".join(line for line in source.splitlines() if re.search(r"overlap|NAMED_ELEMENTS|const named",line,re.I))
    variants.append({"blob":sha,"paths":sorted(names),"overlap_owner":owner,"related_lines":metadata})
    (root/f"blob-{sha}.txt").write_text(source)
summary={"schema":1,"baseline":"d5a942177fad030d3caf0f8d39856c116e3e5cda","executed_checkout":git("rev-parse","HEAD").strip(),
 "refs":refs,"ref_count":len(refs),"commit_count":int(git("rev-list","--all","--count")),
 "candidate_paths":paths,"related_blob_count":len(variant_objects),"overlap_variant_count":len(variants),
 "variants":variants,"complete_git_fetch":True,"history_scope":"All reachable upstream heads/tags/PR heads and fork heads/tags; intermediate/reverted commits and merge parents; rename closure. Manual semantic review still required."}
(root/"history.json").write_text(json.dumps(summary,indent=2))
print("REA_DFUSE_HISTORY_SUMMARY",json.dumps({k:v for k,v in summary.items() if k not in ("refs","variants")}))
for variant in variants: print("REA_DFUSE_HISTORY_VARIANT",json.dumps(variant))
print("REA_DFUSE_HISTORY_REF_COUNTS",json.dumps({"upstream":sum(r.startswith("refs/audit-upstream/") for r in refs),"fork":sum(r.startswith("refs/audit-fork/") for r in refs),"ref_manifest_sha256":hashlib.sha256("\n".join(refs).encode()).hexdigest()}))
