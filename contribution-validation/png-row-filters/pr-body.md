## Summary

Reduce CPU work when comparing existing PNG screenshots by selecting the reconstruction filter once per scanline. Each filter now reads only its required neighbors; unfiltered rows use a buffer copy. The decoded pixels, comparison metrics, supported formats and admission limits remain unchanged.

## Problem and expected behavior

At base `af062e7a2d290fec4307fb9444298a13c2fea630`, `unfilter` computes all three neighbor values and dispatches through `applyFilter` for every byte, even though a row has one fixed filter. A 1920 × 1080 RGBA image therefore repeats that selection 8,294,400 times instead of 1,080 times.

The expected contract is identical reconstruction with less repeated work. This is a performance change, not a claim that existing filter arithmetic is incorrect. No separate issue is linked because the concrete reproduction, measurements and proposed repair are included here.

Related #11223 adds filter-coverage tests. This change addresses the reconstruction loop itself. Historical positional-helper implementations also still selected the filter per byte; removing an options object is not the basis of this optimization.

## Change and scope

Move the switch outside the byte loop and keep one loop per filter. None copies the row, Sub reads left, Up reads above, Average reads left and above, and Paeth reads all three neighbors. The Paeth predictor and tie-breaking code are unchanged. Unsupported filter values still fail.

The PR contains only the implementation and ten fixed RGB/RGBA scanline tests. Benchmark scripts, fixtures and validation workflow are retained separately as evidence.

## Contract and boundary impact

- Semantic owner and earliest changed stage: PNG scanline reconstruction in `pngVisualDiff.ts`; screenshot artifact comparison keeps the same pixel and metric contracts.
- Contribution scope: ordinary optimization within the existing PNG decoder; no advance scope decision required.
- CLI/MCP and provider compatibility: no input, output schema, tool, provider, format or platform change.
- Evidence/provenance: image identity, dimensions, transparency handling, comparison thresholds and unsupported-result limitations remain unchanged.
- Target authority and cleanup: the optimization processes already supplied image buffers; no new target interaction or resource lifetime.
- Generated metadata, packaging and installation: no changes.

Expected effects:

- [x] Read existing files or captured data.
- [ ] Launch or attach to a process.
- [ ] Inject instrumentation or run scripts/code.
- [ ] Change process memory, registers, files, or configuration.
- [ ] Contact network services.
- [ ] Recover protected code or work around protections.
- [ ] Documentation or usability only; no target interaction.
- [ ] Not sure yet; investigation or maintainer guidance needed.

## Evidence and regression coverage

The ten new vectors cover all five filters for both RGB and RGBA, first and later rows, initial columns and byte wraparound. Their PNG encodings were independently decoded and checked byte-for-byte with Pillow 13.0.0. The tests exercise the public screenshot-artifact and comparison APIs against explicit expected RGBA bytes. They pass before and after; the improvement is established by native measurements rather than a claimed functional failure.

The native benchmark uses Pillow-produced 640 × 360 RGB, 1920 × 1080 RGB and 1920 × 1080 RGBA images, each with identical and changed-image cases. An independent Pillow pixel oracle checks every comparison metric. Each timed task creates both screenshot artifacts, parses the comparison input and calls `comparePngScreenshots`. Disk reads, module import and fixture production are outside the timed task.

On Ubuntu 24.04 with Node 24.22.1, three alternating before/after rounds used **36 fresh processes and 252 completed public tasks**. Every complete output matched byte-for-byte. Cold is the median first task from three fresh processes; warm is the median of calls 5–7 in those processes after four warm-up calls, giving nine measurements per phase and case.

| Completed task | Cold before / after (ms) | Warm before / after (ms) |
| --- | ---: | ---: |
| RGB 640 × 360, identical | 32.480 / 23.469 | 23.979 / 14.271 |
| RGB 640 × 360, changed | 33.236 / 27.128 | 23.719 / 14.232 |
| RGB 1920 × 1080, identical | 175.836 / 127.061 | 163.130 / 115.460 |
| RGB 1920 × 1080, changed | 175.643 / 128.625 | 161.655 / 109.491 |
| RGBA 1920 × 1080, identical | 170.490 / 101.522 | 164.188 / 78.923 |
| RGBA 1920 × 1080, changed | 172.651 / 101.249 | 164.992 / 78.793 |

| Completed task | Warm CPU before / after (ms) | Process peak RSS before / after (KiB) |
| --- | ---: | ---: |
| RGB 640 × 360, identical | 35.204 / 20.965 | 124,524 / 116,984 |
| RGB 640 × 360, changed | 34.941 / 20.706 | 123,680 / 116,236 |
| RGB 1920 × 1080, identical | 196.985 / 147.259 | 166,500 / 158,228 |
| RGB 1920 × 1080, changed | 194.322 / 139.915 | 166,800 / 157,460 |
| RGBA 1920 × 1080, identical | 195.760 / 104.541 | 160,160 / 161,724 |
| RGBA 1920 × 1080, changed | 197.655 / 103.842 | 162,904 / 161,540 |

These measurements support approximately 29–52% lower median warm elapsed time and 18–41% lower median cold elapsed time for these tasks. They do not establish an end-to-end browser capture, network, token or general memory improvement; one RGBA case has a higher process peak. The real-producer fixtures predominantly exercise Up, Paeth and Sub; the fixed vectors separately cover all five filters.

For evidence-bearing changes:

- [x] Observed, derived, and inferred claims remain distinguishable.
- [x] Artifact identity, source provenance, and failed attempts remain preserved.
- [x] Unsupported, incomplete, unavailable, or uncertain outcomes remain visible.

## Validation performed

At the pinned base plus the exact two files in this PR:

- `npm run test:local -- src/domain/pngVisualDiff.test.ts src/domain/pngHeader.test.ts` — **53 passed before and 53 after**.
- `npm run test:focused -- tests/boundary/cli/browserCli.test.ts tests/boundary/browser/browserToolContractExamples.test.ts` — **19 passed** against the compiled package.
- `npm run check` — **passed**, including typecheck, lint, formatting, Knip, metadata and architecture checks; the run reports zero errors and 5,026 advisory lint warnings.
- `git diff --check` — passed; the isolated source worktree changed only these two files.
- The independent pixel oracle and full-output equality checks passed for all 252 timed public tasks.
- [Successful native validation, exact-file hashes and full evidence](https://github.com/Afloat16/rea/actions/runs/44037879806). Production readback matches both tested file hashes.
- [Durable full evidence archive](https://github.com/Afloat16/rea/blob/3d5df6bf144b243d1c644fa3c83dc3f9eae12124/contribution-validation/png-row-filters/native-full-evidence.zip), including all individual timings, complete outputs, PNG inputs, independent expected metrics and command logs.

An earlier workflow attempt selected built boundary tests with `test:local` and stopped with the runner's instruction to use `test:focused`. The corrected run above completed. That earlier attempt is retained and is not counted as a pass.

## Compatibility, safety, and release

No breaking change, migration, dependency or package change. The comparison budget, CRC checks, image admission, failure behavior and schemas are unchanged. Validation covers native Linux/Node decoding and compiled CLI/browser-contract tests using the repository's controlled CDP fixture; it does not claim a live browser or other-OS performance measurement. No new execution, mutation or external communication capability is introduced.

## Author readiness

Human owner: @Afloat16

- [ ] I reviewed the final diff and relevant existing code, understand the change and its edge cases, and take responsibility for the complete PR, including AI-assisted work.
- [ ] I checked the evidence above, confirmed it supports the current change, and recorded meaningful validation gaps.
- [ ] I declare this PR ready for initial maintainer review.

## Before merge

- [x] This PR addresses a concrete problem or an agreed enhancement.
- [x] Material scope and authority questions are resolved, and any required maintainer scope decision covers the final diff.
- [x] The PR has one focused outcome and the title follows `type(scope): outcome`.
- [x] Related issue is linked, or the reason for not linking one is stated above.
- [x] Tests cover changed observable behavior and meaningful failure paths.
- [x] Owning docs, contracts, and generated metadata are updated where needed.
- [x] User-visible CLI/MCP changes include representative output.
- [x] I checked the final diff for secrets, unrelated cleanup, and unsupported claims.
