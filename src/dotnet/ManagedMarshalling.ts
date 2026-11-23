import { BinaryReader } from "../domain/binaryContainer.js";
import type {
  ManagedMemberInspection,
  ManagedParseIssue,
} from "../domain/managed/managedArtifact.js";
import {
  admitManagedProjection,
  managedDecodeBudget,
  ManagedRepresentationFailure,
} from "../domain/managed/managedDecodeBudget.js";
import {
  decodeMetadataCodedIndex,
  metadataRowCursor,
  metadataToken,
  readMetadataBlob,
  readMetadataString,
} from "../domain/managed/managedMetadataHeaps.js";
import {
  MANAGED_CODED_INDEXES,
  type ManagedMetadataLayout,
} from "../domain/managed/managedMetadataLayout.js";
import {
  memberListIndexSize,
  memberListRowLookup,
  memberListTable,
  validatedMemberListStart,
} from "../domain/managed/managedMemberPointers.js";
import {
  managedFailure,
  ManagedReaderFailure,
} from "../domain/managed/managedReaderFailure.js";

type Marshalling = NonNullable<ManagedMemberInspection["marshalling"]>;
type Declaration = Marshalling["declarations"][number];
interface Context {
  readonly bytes: Buffer;
  readonly layout: ManagedMetadataLayout;
  readonly report: ManagedMemberInspection;
}

// These are native-type tag names, not decoded array/custom-marshaler payloads.
const NATIVE_TYPES: Readonly<Record<number, string>> = {
  0x02: "Bool",
  0x03: "I1",
  0x04: "U1",
  0x05: "I2",
  0x06: "U2",
  0x07: "I4",
  0x08: "U4",
  0x09: "I8",
  0x0a: "U8",
  0x0b: "R4",
  0x0c: "R8",
  0x0f: "Currency",
  0x13: "BStr",
  0x14: "LPStr",
  0x15: "LPWStr",
  0x16: "LPTStr",
  0x17: "ByValTStr",
  0x19: "IUnknown",
  0x1a: "IDispatch",
  0x1b: "Struct",
  0x1c: "Interface",
  0x1d: "SafeArray",
  0x1e: "ByValArray",
  0x1f: "SysInt",
  0x20: "SysUInt",
  0x22: "VBByRefStr",
  0x23: "AnsiBStr",
  0x24: "TBStr",
  0x25: "VariantBool",
  0x26: "FunctionPtr",
  0x28: "AsAny",
  0x2a: "LPArray",
  0x2b: "LPStruct",
  0x2c: "CustomMarshaler",
  0x2d: "Error",
  0x2e: "IInspectable",
  0x2f: "HString",
  0x30: "LPUTF8Str",
};

/** Physical Param identities are independent of optional ParamPtr list positions. */
const parameterOwner = ({
  bytes,
  layout,
}: Context): ((row: number) => number) => {
  const methods = layout.table(6);
  const count = methods?.rowCount ?? 0;
  const parameters = memberListTable(layout, 8);
  const parameterPosition = memberListRowLookup(bytes, layout, 8);
  managedDecodeBudget(layout).admitTransient(
    (count + 1) * Uint32Array.BYTES_PER_ELEMENT + 256,
    methods?.offset ?? null,
  );
  const starts = new Uint32Array(count + 1);
  const width = memberListIndexSize(layout, 8);
  const reader = new BinaryReader(bytes, true, "managed-parameter-ownership");
  let previous = 1;
  for (let row = 1; row <= count; row += 1) {
    // Other method columns and signatures are not decoded to establish a list span.
    const offset =
      methods!.offset +
      (row - 1) * methods!.rowSize +
      8 +
      layout.stringIndexSize +
      layout.blobIndexSize;
    const raw = width === 2 ? reader.u16(offset) : reader.u32(offset);
    const start = validatedMemberListStart(raw, parameters);
    if (start === null || start < previous)
      throw managedFailure(
        "invalid-row",
        "metadata.MethodDef.ParamList",
        `MethodDef row ${String(row)} has an invalid or decreasing ParamList; parameter ownership is unknown`,
        offset,
      );
    starts[row - 1] = start;
    previous = start;
  }
  starts[count] = (parameters?.rowCount ?? 0) + 1;
  return (row) => {
    const position = parameterPosition(row);
    // Upper-bound lookup keeps empty lists (equal starts) attached to no rows.
    let low = 0;
    let high = count;
    while (low < high) {
      const middle = Math.floor((low + high) / 2);
      if (starts[middle]! <= position) low = middle + 1;
      else high = middle;
    }
    if (low === 0 || position >= starts[low]!)
      throw managedFailure(
        "invalid-row",
        "metadata.MethodDef.ParamList",
        `Param row ${String(row)} has no declaring MethodDef list span`,
        layout.table(8)?.offset ?? null,
      );
    return low;
  };
};

const readMarshalling = (context: Context): Marshalling => {
  const { bytes, layout, report } = context;
  const budget = managedDecodeBudget(layout);
  const issues: ManagedParseIssue[] = [];
  const issue = (value: ManagedParseIssue): void => {
    issues.push(admitManagedProjection(value, budget));
  };
  const attempt = <T>(read: () => T): T | undefined => {
    try {
      return read();
    } catch (cause: unknown) {
      if (
        !(cause instanceof ManagedReaderFailure) ||
        cause instanceof ManagedRepresentationFailure
      )
        throw cause;
      // This facet has its own coverage, including an ambiguous shared heap.
      issue(cause.issue);
      return undefined;
    }
  };
  try {
    const table = layout.table(13);
    if (table === undefined || table.rowCount === 0)
      return { state: "complete", declarations: [], issues: [] };
    budget.admitTransient(
      (report.fields.length + report.methods.length) * 96,
      null,
    );
    const fields = new Map(report.fields.map((field) => [field.token, field]));
    const methods = new Map(
      report.methods.map((method) => [method.token, method]),
    );
    let ownerLookup: ((row: number) => number) | null | undefined;
    const width = layout.codedIndexSize("HasFieldMarshal");
    const reader = new BinaryReader(bytes, true, "managed-marshalling");
    const declarations: Declaration[] = [];
    const seen = new Set<number>();
    for (let row = 1; row <= table.rowCount; row += 1) {
      const offset = table.offset + (row - 1) * table.rowSize;
      const raw = width === 2 ? reader.u16(offset) : reader.u32(offset);
      const parent = decodeMetadataCodedIndex(
        raw,
        MANAGED_CODED_INDEXES.HasFieldMarshal.bits,
        MANAGED_CODED_INDEXES.HasFieldMarshal.tables,
        layout.rowCounts,
      );
      const token = metadataToken(13, row);
      const scope = `metadata.FieldMarshal:${token}`;
      const field =
        parent.kind === "valid" && parent.table === 4
          ? fields.get(parent.token)
          : undefined;
      if (parent.kind === "valid" && parent.table === 4 && field === undefined)
        continue;
      let method: ManagedMemberInspection["methods"][number] | undefined;
      if (parent.kind === "valid" && parent.table === 8) {
        if (ownerLookup === undefined)
          ownerLookup = attempt(() => parameterOwner(context)) ?? null;
        const owner =
          ownerLookup === null
            ? undefined
            : attempt(() => ownerLookup!(parent.row));
        if (owner !== undefined) {
          method = methods.get(metadataToken(6, owner));
          if (method === undefined) continue;
        }
      }
      // Unselected known owners skip both the row reservation and heap decoding.
      const cursor = metadataRowCursor(bytes, layout, 13, row);
      cursor.readIndex(width);
      const blobIndex = cursor.readIndex(layout.blobIndexSize);
      const declaration: Declaration = {
        token,
        row_offset: offset,
        parent_raw: raw,
        parent_kind:
          parent.kind === "valid"
            ? parent.table === 4
              ? "field"
              : "parameter"
            : "unknown",
        parent_token: parent.kind === "valid" ? parent.token : null,
        parent_row_offset:
          parent.kind === "valid"
            ? layout.table(parent.table)!.offset +
              (parent.row - 1) * layout.table(parent.table)!.rowSize
            : null,
        parent_name: field?.name ?? null,
        parent_flags: field?.flags ?? null,
        parameter_sequence: null,
        method_token: method?.token ?? null,
        method_name: method?.name ?? null,
        declaring_type: field?.declaring_type ?? method?.declaring_type ?? null,
        native_type: {
          blob_index: blobIndex,
          blob_offset:
            blobIndex > 0 &&
            layout.blob?.kind === "available" &&
            blobIndex < layout.blob.stream.size
              ? layout.blob.stream.offset + blobIndex
              : null,
          data_offset: null,
          byte_length: null,
          raw_hex: null,
          root_code: null,
          root_name: null,
        },
      };
      if (parent.kind !== "valid")
        issue({
          code: "invalid-row",
          scope,
          offset,
          detail: `FieldMarshal Parent 0x${raw.toString(16)} does not name an existing Field or Param; selection membership is unknown`,
        });
      else if (parent.table === 8) {
        const parameter = metadataRowCursor(bytes, layout, 8, parent.row);
        declaration.parent_flags = parameter.u16();
        declaration.parameter_sequence = parameter.u16();
        const nameIndex = parameter.readIndex(layout.stringIndexSize);
        declaration.parent_name =
          attempt(() => readMetadataString(bytes, layout, nameIndex)) ?? null;
      }
      if (seen.has(raw))
        issue({
          code: "invalid-row",
          scope,
          offset,
          detail:
            "Duplicate FieldMarshal Parent; all source declarations are retained",
        });
      else {
        budget.admitTransient(64, offset);
        seen.add(raw);
      }
      const blob = attempt(() => readMetadataBlob(bytes, layout, blobIndex));
      if (blob !== undefined) {
        budget.admitTransient(
          blob.length * 2,
          declaration.native_type.blob_offset,
        );
        declaration.native_type.byte_length = blob.length;
        declaration.native_type.raw_hex = blob.toString("hex");
        declaration.native_type.data_offset =
          blobIndex === 0 ? null : blob.byteOffset - bytes.byteOffset;
        const root = blob[0];
        declaration.native_type.root_code = root ?? null;
        declaration.native_type.root_name =
          root === undefined ? null : (NATIVE_TYPES[root] ?? null);
        if (root === undefined)
          issue({
            code: "invalid-blob",
            scope,
            offset: declaration.native_type.blob_offset,
            detail:
              "FieldMarshal NativeType is empty; a native-type tag is unavailable",
          });
        else if (declaration.native_type.root_name === null)
          issue({
            code: "unsupported-metadata",
            scope,
            offset: declaration.native_type.data_offset,
            detail: `Unrecognized native-type tag 0x${root.toString(16)}; original descriptor bytes are retained`,
          });
      }
      declarations.push(admitManagedProjection(declaration, budget));
    }
    return {
      state: issues.length === 0 ? "complete" : "partial",
      declarations,
      issues,
    };
  } finally {
    budget.releaseTransient();
  }
};

/** Admit recovery before attempting this facet, preserving completed member/string evidence. */
export const withManagedMarshalling = (
  context: Context,
): ManagedMemberInspection => {
  const budget = managedDecodeBudget(context.layout);
  let recovery: Marshalling;
  try {
    recovery = admitManagedProjection(
      {
        state: "partial",
        declarations: [],
        issues: [
          {
            ...new ManagedRepresentationFailure(
              Number.MAX_SAFE_INTEGER,
              budget.maximumBytes,
            ).issue,
            scope: "metadata.FieldMarshal",
          },
        ],
      },
      budget,
    );
  } catch (cause: unknown) {
    if (!(cause instanceof ManagedRepresentationFailure)) throw cause;
    return { ...context.report, marshalling: null };
  }
  try {
    return {
      ...context.report,
      marshalling: admitManagedProjection(readMarshalling(context), budget),
    };
  } catch (cause: unknown) {
    if (!(cause instanceof ManagedRepresentationFailure)) throw cause;
    return {
      ...context.report,
      marshalling: {
        ...recovery,
        issues: [{ ...recovery.issues[0]!, offset: cause.issue.offset }],
      },
    };
  }
};
