import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { parseEvidence } from "../../src/domain/evidence.js";
import { kernelModuleSchema } from "../../src/domain/native/kernelModule.js";
import { kernelModuleFixture } from "../../src/native/elf/KernelModule.fixture.js";
import { connectLocalToolsMcp } from "../fixtures/localToolsMcp.js";
import { fileIdentity } from "../fixtures/evidenceSubject.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

cliTest(
  "CLI and stdio MCP agree on extended module versions and recover omitted long names",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-kernel-extended-");
    const path = join(root, "extended.ko");
    const name = "_R" + "long_kernel_symbol_".repeat(240);
    const crcs = Buffer.from([0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x90]);
    const bytes = kernelModuleFixture({
      versions: null,
      extendedNames: Buffer.from(name + "\0module_layout\0\0"),
      extendedCrcs: crcs,
    });
    await writeFile(path, bytes);
    const { call } = await connectLocalToolsMcp();
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    for (const selected of [undefined, name.length]) {
      const output = await cli.run({
        arguments: [
          "inspect-kernel-module",
          path,
          "--json",
          "--full-output",
          ...(selected === undefined
            ? []
            : ["--max-version-name-bytes", String(selected)]),
        ],
      });
      expect(output.exitCode, output.stderr).toBe(0);
      const cliEvidence = parseEvidence(
        (output.json as { data: unknown }).data,
      );
      const cliReport = kernelModuleSchema.parse(cliEvidence.normalized_result);
      const response = await call("inspect_kernel_module", {
        path,
        ...(selected === undefined ? {} : { max_version_name_bytes: selected }),
      });
      expect(response.isError, JSON.stringify(response)).not.toBe(true);
      const mcpEvidence = parseEvidence(response.structuredContent);
      const mcpReport = kernelModuleSchema.parse(mcpEvidence.normalized_result);
      expect(mcpReport).toEqual(cliReport);
      expect(fileIdentity(cliEvidence.subject).sha256).toBe(sha256);
      expect(fileIdentity(mcpEvidence.subject).sha256).toBe(sha256);
      expect(cliReport).toMatchObject({
        extended_versions: {
          status: "present",
          entries: [
            {
              index: 0,
              crc_hex: "12345678",
              name: selected === undefined ? null : name,
              status: "observed",
              omitted_fields: selected === undefined ? ["name"] : [],
            },
            { index: 1, crc_hex: "90abcdef", name: "module_layout" },
          ],
          trailing_names: { zero_padding: true },
        },
        coverage: { status: selected === undefined ? "partial" : "complete" },
      });
      if (selected === undefined) {
        expect(cliReport.extended_versions?.omission_limits).toMatchObject([
          { parameter: "max_version_name_bytes", effective_value: 4096 },
        ]);
        expect(output.json).toMatchObject({
          meta: {
            cli_controls: {
              max_version_name_bytes: "--max-version-name-bytes",
            },
          },
        });
      }
    }
  },
);
