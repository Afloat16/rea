import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { contractNamed } from "../../src/cli/contractCliDescription.js";
import { BINARY_DIAGNOSTICS_TOOL_CONTRACTS } from "../../src/contracts/native/binaryDiagnosticsToolContracts.js";

import {
  elfDebugImage,
  elfImage,
  macho64,
  namedUnit,
  peImage,
  splitDwarfSections,
  splitDwarfUnit,
} from "../../src/native/dwarf/DwarfUnits.fixture.js";
import {
  CPU_ARM64,
  CPU_X86_64,
  universalMacho,
} from "../fixtures/universalMacho.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

const dwarfUnitsContract = contractNamed(
  BINARY_DIAGNOSTICS_TOOL_CONTRACTS,
  "inspect_dwarf_units",
);

cliTest(
  "CLI and stdio MCP page explicit split-debug files with matching provenance",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-split-dwarf-cli-");
    const call = await cli.sharedMcpCall?.();
    if (call === undefined)
      throw new Error("Compiled MCP fixture is unavailable");
    for (const version of [4, 5] as const) {
      const parts = splitDwarfUnit({ version });
      const path = join(root, `split-${String(version)}.dwo`);
      await writeFile(
        path,
        elfImage({
          sections: splitDwarfSections({
            ...parts,
            info: Buffer.concat([parts.info, parts.info]),
          }),
        }),
      );
      const output = await cli.run({
        arguments: [
          "inspect-dwarf-units",
          path,
          "--offset",
          "1",
          "--limit",
          "1",
          "--json",
        ],
      });
      expect(output.exitCode, output.stderr).toBe(0);
      const cliEvidence = dwarfUnitsContract.outputSchema.parse(output.json);
      const response = await call("inspect_dwarf_units", {
        path,
        offset: 1,
        limit: 1,
      });
      expect(response.isError, JSON.stringify(response)).not.toBe(true);
      const mcpEvidence = dwarfUnitsContract.outputSchema.parse(
        response.structuredContent,
      );
      expect(mcpEvidence.normalized_result).toEqual(
        cliEvidence.normalized_result,
      );
      expect(mcpEvidence.subject?.identity).toEqual(
        cliEvidence.subject?.identity,
      );
      expect(mcpEvidence.parameters).toEqual({ path, offset: 1, limit: 1 });
      expect(cliEvidence.normalized_result).toMatchObject({
        coverage: { status: "complete", reason: null },
        total_units: 2,
        page: { offset: 1, limit: 1 },
        units: [
          {
            version,
            offset: parts.info.length,
            name: { state: "present", value: "split.c" },
            issues: [],
          },
        ],
      });
    }
  },
);

cliTest("reports a compile unit through the public CLI", async ({ cli }) => {
  const root = await createTestTempDirectory("rea-dwarf-units-cli-");
  const path = join(root, "program");
  await writeFile(path, elfDebugImage(namedUnit({ name: "main.c" })));
  const result = await cli.run({
    arguments: ["inspect-dwarf-units", path, "--json"],
  });
  expect(result.exitCode, result.stderr).toBe(0);
  const evidence = dwarfUnitsContract.outputSchema.parse(result.json);
  expect(evidence.normalized_result.units[0]?.name).toEqual({
    state: "present",
    value: "main.c",
  });
  expect(evidence.normalized_result.coverage.status).toBe("complete");
  expect(evidence.parameters).toEqual({ path });
  expect(evidence.subject?.identity).toMatchObject({ format: "elf" });
});

cliTest(
  "resolves a relative path against the working directory",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dwarf-units-cli-rel-");
    await writeFile(join(root, "plain"), elfImage());
    const result = await cli.run({
      arguments: ["inspect-dwarf-units", "plain", "--json"],
      cwd: root,
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const evidence = dwarfUnitsContract.outputSchema.parse(result.json);
    expect(evidence.normalized_result.debug_info).toBe("absent");
    expect(evidence.subject?.local_path).toBe(join(root, "plain"));
  },
);

cliTest("requires an architecture for a universal Mach-O", async ({ cli }) => {
  const root = await createTestTempDirectory("rea-dwarf-units-cli-fat-");
  const path = join(root, "universal");
  await writeFile(
    path,
    universalMacho([
      {
        bytes: macho64({ cpuType: CPU_X86_64 }),
        cpuType: CPU_X86_64,
        cpuSubtype: 0,
      },
      {
        bytes: macho64({ cpuType: CPU_ARM64 }),
        cpuType: CPU_ARM64,
        cpuSubtype: 0,
      },
    ]).bytes,
  );
  const result = await cli.run({
    arguments: ["inspect-dwarf-units", path, "--json"],
  });
  expect(result.exitCode).toBe(1);
  expect(result.json).toMatchObject({
    code: "invalid_request",
    details: { operation: "inspect_dwarf_units" },
  });
});

cliTest(
  "rejects a PE long section name when PointerToSymbolTable is zero",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-dwarf-units-cli-pe-");
    const path = join(root, "zero-symtab.exe");
    const named = namedUnit({ name: "spoof.c" });
    const base = peImage([
      { name: "/32", body: named.info },
      { name: ".debug_abbrev", body: named.abbrev },
    ]);
    const image = Buffer.alloc(Math.max(base.length, 0x5a4d + 4));
    base.copy(image);
    image.write(".debug_info\0", 32, "latin1");
    const pe = image.readUInt32LE(0x3c);
    image.writeUInt32LE(0, pe + 12);
    image.writeUInt32LE(0, pe + 16);
    await writeFile(path, image);
    const result = await cli.run({
      arguments: ["inspect-dwarf-units", path, "--json"],
    });
    expect(result.exitCode).toBe(1);
    expect(result.json).toMatchObject({
      code: "invalid_request",
      details: {
        operation: "inspect_dwarf_units",
        issues: [
          {
            path: ["path"],
            reason: "invalid_format",
            message: expect.stringContaining(
              "PE long section name string table is unavailable",
            ),
          },
        ],
      },
    });
  },
);
