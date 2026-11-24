import { insideArtifact } from "./artifactRange.js";
import type { ExecutionOptions } from "../../ports/AnalysisProvider.js";
import type { PeImportsPort } from "../../ports/binaryDiagnostics/PeImportsPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  inspectPeImportsInputSchema,
  peImportsSchema,
  type PeImports,
} from "../../domain/native/peImports.js";
import { peSubjectArchitecture } from "../../domain/peMachine.js";
import type { Result } from "../../domain/result.js";
import { executeArtifactInspection } from "../ArtifactInspectionExecution.js";

const OPERATION = "inspect_pe_imports";

/** Shared caller validation, output parsing and Evidence provenance for CLI/MCP. */
export class PeImportsService {
  constructor(readonly provider: PeImportsPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeArtifactInspection(
      {
        operation: OPERATION,
        inputSchema: inspectPeImportsInputSchema,
        outputSchema: peImportsSchema,
        provider: this.provider,
        invalidOutputMessage:
          "PE import provider returned malformed output or changed artifact identity.",
        toParameters: (input) => input,
        validateReport: (report, input) =>
          report.artifact.path === input.path && validReport(report, input),
        buildEvidence: (value, identity, parameters) => {
          const architecture = peSubjectArchitecture(
            value.machine,
            value.format,
          );
          return createEvidence(
            {
              path: value.artifact.path,
              format: "pe",
              sha256: value.artifact.sha256,
              ...(architecture === undefined ? {} : { architecture }),
            },
            identity,
            {
              operation: OPERATION,
              parameters,
              result: value,
              confidence: "observed",
              limitations: value.limitations,
              locations: [
                { kind: "artifact-path" as const, path: value.artifact.path },
                ...fileRange(value.import_directory),
                ...fileRange(value.delay_import_directory),
                ...fileRange(value.bound_import_directory ?? null),
              ],
            },
          );
        },
      },
      rawInput,
      options,
    );
  }
}

const fileRange = (
  directory: PeImports["import_directory"],
): readonly {
  kind: "file-offset-range";
  start: number;
  end: number;
}[] =>
  directory === null
    ? []
    : directory.locations.map(({ offset, bytes }) => ({
        kind: "file-offset-range" as const,
        start: offset,
        end: offset + bytes,
      }));

const validReport = (
  report: PeImports,
  input: {
    readonly max_dlls: number;
    readonly max_bound_records: number;
    readonly max_functions: number;
    readonly max_file_bytes: number;
  },
): boolean => {
  const inside = insideArtifact(report.artifact.bytes);
  const dllCount = report.imports.length + report.delay_imports.length;
  const boundCount = report.bound_imports?.reduce(
    (count, dll) => count + 1 + dll.forwarders.length,
    0,
  );
  if (
    boundCount !== report.coverage.examined_bound_records ||
    (boundCount !== undefined && boundCount > input.max_bound_records) ||
    (report.bound_imports === undefined) !==
      (report.bound_import_directory === undefined) ||
    (report.bound_import_directory === null &&
      boundCount !== 0 &&
      boundCount !== undefined)
  )
    return false;
  if (
    report.artifact.bytes > input.max_file_bytes ||
    report.coverage.examined_dlls > input.max_dlls ||
    dllCount > report.coverage.examined_dlls ||
    (report.coverage.status === "complete" &&
      (dllCount !== report.coverage.examined_dlls || report.issues.length > 0))
  )
    return false;
  const importCount = report.imports.reduce(
    (count, dll) => count + dll.functions.length,
    0,
  );
  const delayImportCount = report.delay_imports.reduce(
    (count, dll) => count + dll.functions.length,
    0,
  );
  if (
    importCount !== report.coverage.imports ||
    delayImportCount !== report.coverage.delay_imports ||
    importCount + delayImportCount > input.max_functions
  )
    return false;
  for (const directory of [
    report.import_directory,
    report.delay_import_directory,
    report.bound_import_directory ?? null,
  ]) {
    if (
      directory !== null &&
      (!directory.locations.every(inside) ||
        (directory.locations.length === 0 &&
          report.coverage.status === "complete"))
    )
      return false;
  }
  const descriptorsFit = (
    rows: readonly { location: { offset: number; bytes: number } }[],
  ) => rows.every((row) => inside(row.location));
  return (
    descriptorsFit(report.imports) &&
    descriptorsFit(report.delay_imports) &&
    (report.bound_imports ?? []).every(
      (dll) =>
        inside(dll.location) &&
        dll.location.bytes === 8 &&
        dll.forwarders.length <= dll.number_of_forwarder_refs &&
        (report.coverage.status !== "complete" ||
          dll.forwarders.length === dll.number_of_forwarder_refs) &&
        dll.forwarders.every(
          (forwarder) =>
            inside(forwarder.location) && forwarder.location.bytes === 8,
        ),
    )
  );
};
