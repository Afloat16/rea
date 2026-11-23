import { BinaryReader } from "../domain/binaryContainer.js";
import type {
  ManagedMemberInspection,
  ManagedParseIssue,
} from "../domain/managed/managedArtifact.js";
import {
  admitManagedProjection,
  managedDecodeBudget,
} from "../domain/managed/managedDecodeBudget.js";
import {
  decodeMetadataCodedIndex,
  metadataRowCursor,
  metadataToken,
  readMetadataString,
} from "../domain/managed/managedMetadataHeaps.js";
import {
  MANAGED_CODED_INDEXES,
  type ManagedMetadataLayout,
} from "../domain/managed/managedMetadataLayout.js";
import { readManagedValue } from "../domain/managed/managedReaderFailure.js";
import type {
  parseTypes,
  TypeRange,
} from "../domain/managed/managedMemberInspectorCore.js";
import { managedSignatureTypeNames } from "../domain/managed/managedSignatureTypeNames.js";
import { managedTypeReferences } from "../domain/managed/managedTypeReferences.js";
import { typeNameLookup } from "./ManagedTypeNames.js";

type GenericInventory = NonNullable<
  ManagedMemberInspection["generic_parameters"]
>;

/** Read generic declarations attached to returned physical type/method owners. */
export const parseManagedGenericParameters = (
  bytes: Buffer,
  layout: ManagedMetadataLayout,
  ranges: readonly TypeRange[],
  parsedTypes: Pick<ReturnType<typeof parseTypes>, "types" | "nesting">,
  owners: Pick<ManagedMemberInspection, "types" | "methods">,
): GenericInventory => {
  const issues: ManagedParseIssue[] = [];
  const rows: GenericInventory["rows"] = [];
  const constraints: GenericInventory["constraints"] = [];
  const budget = managedDecodeBudget(layout);
  const parameterTable = layout.table(42);
  const constraintTable = layout.table(44);
  const parameterCount = parameterTable?.rowCount ?? 0;
  const constraintCount = constraintTable?.rowCount ?? 0;
  const ownerWidth = layout.codedIndexSize("TypeOrMethodDef");
  const parameterWidth = layout.tableIndexSize(42);
  const reader = new BinaryReader(bytes, true, "managed-generics");
  if (parameterCount === 0 && constraintCount === 0)
    return { state: "complete", rows, constraints, issues };
  // These indexes stay live across TypeSpec decoding, whose nested owner
  // releases its transient budget. Keep their capacity reserved for the facet.
  budget.reserve((owners.types.length + owners.methods.length) * 96, null);
  const selected = new Set<string>();
  for (const type of owners.types) selected.add(type.token);
  for (const method of owners.methods) selected.add(method.token);
  const parameters = new Map<number, GenericInventory["rows"][number]>();
  const seenParameters = new Set<string>();
  const seenConstraints = new Set<string>();
  let names: ReturnType<typeof typeNameLookup> | undefined;
  const typeName = (
    reference: Parameters<ReturnType<typeof typeNameLookup>["name"]>[0],
  ) => {
    if (names === undefined) {
      // Reuse metadata name owners with facet-local failures: constraint-name
      // decoding must not mutate already admitted member coverage.
      const references = managedTypeReferences(bytes, layout, issues);
      const signatures = managedSignatureTypeNames(
        layout,
        issues,
        parsedTypes,
        references,
      );
      names = typeNameLookup(
        bytes,
        layout,
        ranges,
        issues,
        references,
        signatures.operand,
      );
    }
    return names.name(reference);
  };
  const issue = (scope: string, offset: number, detail: string): void => {
    issues.push(
      admitManagedProjection(
        { code: "invalid-row", scope, offset, detail },
        budget,
      ),
    );
  };
  for (let row = 1; row <= parameterCount; row += 1) {
    // The admitted fixed-width table bounds this prefix. Excluded owners
    // must not consume decoded-row or heap capacity for a narrow selection.
    const offset = parameterTable!.offset + (row - 1) * parameterTable!.rowSize;
    const ownerRaw =
      ownerWidth === 2 ? reader.u16(offset + 4) : reader.u32(offset + 4);
    const ownerRow = Math.floor(ownerRaw / 2);
    const ownerTable = ownerRaw % 2 === 0 ? 2 : 6;
    if (
      ownerRow > 0 &&
      ownerRow <= (layout.table(ownerTable)?.rowCount ?? 0) &&
      !selected.has(metadataToken(ownerTable, ownerRow))
    )
      continue;
    readManagedValue(() => {
      const cursor = metadataRowCursor(bytes, layout, 42, row);
      const number = cursor.u16();
      const flags = cursor.u16();
      const ownerOffset = cursor.offset;
      cursor.readIndex(ownerWidth);
      const owner = decodeMetadataCodedIndex(
        ownerRaw,
        MANAGED_CODED_INDEXES.TypeOrMethodDef.bits,
        MANAGED_CODED_INDEXES.TypeOrMethodDef.tables,
        layout.rowCounts,
      );
      const nameOffset = cursor.offset;
      const nameIndex = cursor.readIndex(layout.stringIndexSize);
      const token = metadataToken(42, row);
      const scope = `metadata.GenericParam:${token}`;
      if (owner.kind !== "valid")
        issue(
          scope,
          ownerOffset,
          `GenericParam Owner must reference an existing TypeDef or MethodDef; observed 0x${ownerRaw.toString(16)}`,
        );
      else {
        const key = `${ownerRaw}:${number}`;
        if (seenParameters.has(key))
          issue(
            scope,
            cursor.start,
            "Duplicate Owner and Number declaration; the original rows are retained",
          );
        else {
          budget.reserve(128, cursor.start);
          seenParameters.add(key);
        }
      }
      const name = readManagedValue(
        () => readMetadataString(bytes, layout, nameIndex),
        issues,
      );
      if (name === undefined)
        issue(
          scope,
          nameOffset,
          "GenericParam Name could not be established; the original name index and declaration are retained",
        );
      const parameter = admitManagedProjection(
        {
          token,
          row_offset: cursor.start,
          number,
          flags,
          owner_coded_index: ownerRaw,
          owner_token: owner.kind === "valid" ? owner.token : null,
          owner_kind:
            owner.kind !== "valid"
              ? ("unknown" as const)
              : owner.table === 2
                ? ("type" as const)
                : ("method" as const),
          name_index: nameIndex,
          name: name ?? null,
        },
        budget,
      );
      budget.reserve(96, cursor.start);
      parameters.set(row, parameter);
      rows.push(parameter);
    }, issues);
  }
  for (let row = 1; row <= constraintCount; row += 1) {
    const offset =
      constraintTable!.offset + (row - 1) * constraintTable!.rowSize;
    const parameterRow =
      parameterWidth === 2 ? reader.u16(offset) : reader.u32(offset);
    const parameterValid = parameterRow > 0 && parameterRow <= parameterCount;
    const parameter = parameters.get(parameterRow);
    // Valid parameters outside the returned owner set do not expand scope.
    // Malformed owners are retained because their selection is unknown.
    if (parameterValid && parameter === undefined) continue;
    readManagedValue(() => {
      const cursor = metadataRowCursor(bytes, layout, 44, row);
      cursor.readIndex(parameterWidth);
      const constraintOffset = cursor.offset;
      const constraintRaw = cursor.readIndex(
        layout.codedIndexSize("TypeDefOrRef"),
      );
      const token = metadataToken(44, row);
      const scope = `metadata.GenericParamConstraint:${token}`;
      if (!parameterValid)
        issue(
          scope,
          cursor.start,
          `GenericParamConstraint Owner must reference an existing GenericParam row; observed ${parameterRow}`,
        );
      const constraint = decodeMetadataCodedIndex(
        constraintRaw,
        MANAGED_CODED_INDEXES.TypeDefOrRef.bits,
        MANAGED_CODED_INDEXES.TypeDefOrRef.tables,
        layout.rowCounts,
      );
      if (constraint.kind !== "valid")
        issue(
          scope,
          constraintOffset,
          `GenericParamConstraint Constraint must reference an existing TypeDef, TypeRef or TypeSpec; observed 0x${constraintRaw.toString(16)}`,
        );
      if (parameterValid && constraint.kind === "valid") {
        const key = `${parameterRow}:${constraintRaw}`;
        if (seenConstraints.has(key))
          issue(
            scope,
            cursor.start,
            "Duplicate Owner and Constraint declaration; the original rows are retained",
          );
        else {
          budget.reserve(128, cursor.start);
          seenConstraints.add(key);
        }
      }
      constraints.push(
        admitManagedProjection(
          {
            token,
            row_offset: cursor.start,
            parameter_row: parameterRow,
            parameter_token: parameterValid
              ? metadataToken(42, parameterRow)
              : null,
            owner_token: parameter?.owner_token ?? null,
            constraint_coded_index: constraintRaw,
            constraint_token:
              constraint.kind === "valid" ? constraint.token : null,
            constraint_name:
              constraint.kind === "valid" ? typeName(constraint) : null,
          },
          budget,
        ),
      );
    }, issues);
  }
  return {
    state: issues.length === 0 ? "complete" : "partial",
    rows,
    constraints,
    issues,
  };
};
