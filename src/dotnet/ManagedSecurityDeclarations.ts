import { isUtf8 } from "node:buffer";
import type {
  ManagedMemberInspection,
  ManagedParseIssue,
  ManagedSecurityDeclaration,
  ManagedSecurityDeclarations,
} from "../domain/managed/managedArtifact.js";
import {
  admitManagedProjection,
  managedDecodeBudget,
  ManagedRepresentationFailure,
} from "../domain/managed/managedDecodeBudget.js";
import {
  decodeMetadataCodedIndex,
  MetadataRowCursor,
  metadataToken,
  readManagedCompressedUnsigned,
  readMetadataBlob,
} from "../domain/managed/managedMetadataHeaps.js";
import {
  MANAGED_CODED_INDEXES,
  metadataRowOffset,
  type ManagedMetadataLayout,
} from "../domain/managed/managedMetadataLayout.js";
import {
  managedFailure,
  ManagedReaderFailure,
} from "../domain/managed/managedReaderFailure.js";
import { memberDeclaringTypeRowLookup } from "../domain/managed/managedMemberOwnership.js";
import type { TypeMemberListFacts } from "../domain/managed/managedTypeMemberLists.js";

const actions = new Map<number, string>([
  [2, "Demand"],
  [3, "Assert"],
  [4, "Deny"],
  [5, "PermitOnly"],
  [6, "LinkDemand"],
  [7, "InheritanceDemand"],
  [8, "RequestMinimum"],
  [9, "RequestOptional"],
  [10, "RequestRefuse"],
]);
type PermissionSet = NonNullable<ManagedSecurityDeclaration["permission_set"]>;
type Parent = Pick<
  ManagedSecurityDeclaration,
  | "parent_token"
  | "parent_kind"
  | "parent_name"
  | "parent_flags"
  | "declaring_type_token"
  | "declaring_type"
>;
type IssueSink = (issue: ManagedParseIssue) => void;

/** Reuse the member owner's selection and physical MethodDef identities, including MethodPtr. */
const selectedParents = ({
  bytes,
  report,
  layout,
  memberLists,
  issue,
}: {
  readonly bytes: Buffer;
  readonly report: ManagedMemberInspection;
  readonly layout: ManagedMetadataLayout;
  readonly memberLists: TypeMemberListFacts;
  readonly issue: IssueSink;
}) => {
  const types = new Map(report.types.map((row) => [row.token, row]));
  const methods = new Map(report.methods.map((row) => [row.token, row]));
  const unresolved = new Set(
    report.unresolved_definitions?.rows.map((row) => row.token),
  );
  let ownerOf: ((row: number) => number) | undefined;
  let ownerAttempted = false;
  const methodOwner = (row: number): number | undefined => {
    try {
      if (!ownerAttempted) {
        ownerAttempted = true;
        ownerOf = memberDeclaringTypeRowLookup(bytes, layout, 6, memberLists);
      }
      return ownerOf?.(row);
    } catch (cause: unknown) {
      if (
        !(cause instanceof ManagedReaderFailure) ||
        cause instanceof ManagedRepresentationFailure
      )
        throw cause;
      issue(cause.issue);
      return undefined;
    }
  };
  return (raw: number): Parent | "excluded" => {
    const descriptor = MANAGED_CODED_INDEXES.HasDeclSecurity;
    const parent = decodeMetadataCodedIndex(
      raw,
      descriptor.bits,
      descriptor.tables,
      layout.rowCounts,
    );
    const unknown: Parent = {
      parent_token: null,
      parent_kind: "unknown",
      parent_name: null,
      parent_flags: null,
      declaring_type_token: null,
      declaring_type: null,
    };
    if (parent.kind !== "valid") return unknown;
    const shared = { ...unknown, parent_token: parent.token };
    if (parent.table === 32) {
      const assembly =
        report.assembly?.token === parent.token ? report.assembly : null;
      return {
        ...shared,
        parent_kind: "Assembly",
        parent_name: assembly?.name ?? null,
        parent_flags: assembly?.flags ?? null,
      };
    }
    if (parent.table === 2) {
      const type = types.get(parent.token);
      if (
        report.selection !== null &&
        type === undefined &&
        !unresolved.has(parent.token)
      )
        return "excluded";
      return {
        ...shared,
        parent_kind: "TypeDef",
        parent_name: type?.full_name ?? null,
        parent_flags: type?.flags ?? null,
        declaring_type_token: parent.token,
        declaring_type: type?.full_name ?? null,
      };
    }
    const page = report.method_rows;
    if (
      page !== null &&
      (parent.row <= page.offset || parent.row > page.offset + page.count)
    )
      return "excluded";
    const method = methods.get(parent.token);
    // A signature or body failure can omit a method whose owner was selected.
    // Only the shared physical-row owner can establish exclusion; absence
    // from the successful method projection cannot.
    const owner = method === undefined ? methodOwner(parent.row) : undefined;
    const ownerToken =
      method?.declaring_type_token ??
      (owner === undefined || owner === 0 ? null : metadataToken(2, owner));
    const ownerType = ownerToken === null ? undefined : types.get(ownerToken);
    if (
      report.selection !== null &&
      method === undefined &&
      ownerToken !== null &&
      ownerType === undefined &&
      !unresolved.has(ownerToken)
    )
      return "excluded";
    return {
      ...shared,
      parent_kind: "MethodDef",
      parent_name: method?.name ?? null,
      parent_flags: method?.flags ?? null,
      declaring_type_token: ownerToken,
      declaring_type: method?.declaring_type ?? ownerType?.full_name ?? null,
    };
  };
};

const permissionSet = (
  bytes: Buffer,
  layout: ManagedMetadataLayout,
  index: number,
  scope: string,
  issue: IssueSink,
): PermissionSet => {
  const raw = readMetadataBlob(bytes, layout, index);
  const budget = managedDecodeBudget(layout);
  const blobOffset =
    index === 0 || layout.blob?.kind !== "available"
      ? null
      : layout.blob.stream.offset + index;
  const dataOffset = index === 0 ? null : raw.byteOffset - bytes.byteOffset;
  budget.reserve(raw.length * 2 + 256, dataOffset);
  const result: PermissionSet = {
    blob_index: index,
    blob_offset: blobOffset,
    data_offset: dataOffset,
    byte_length: raw.length,
    sha256: budget.digest(raw, "sha256"),
    raw_hex: raw.toString("hex"),
    format:
      raw.length === 0
        ? "empty"
        : raw[0] === 0x2e
          ? "binary"
          : "legacy-or-unknown",
    attribute_count: null,
    attributes: [],
  };
  const at = (relative: number) =>
    dataOffset === null ? null : dataOffset + relative;
  const malformed = (detail: string, relative: number) =>
    managedFailure("invalid-blob", scope, detail, at(relative));
  if (result.format !== "binary") {
    issue({
      code: result.format === "empty" ? "invalid-blob" : "unsupported-metadata",
      scope,
      offset: dataOffset,
      detail:
        result.format === "empty"
          ? "PermissionSet is empty; no binary attribute count is present."
          : "Legacy or unknown PermissionSet encoding is retained as exact bytes; XML and permission semantics are not interpreted.",
    });
    return result;
  }
  let cursor = 1;
  const compressed = (end = raw.length): number => {
    const position = cursor;
    const decoded = readManagedCompressedUnsigned(
      raw.subarray(0, end),
      position,
    );
    if (!decoded.ok)
      throw malformed(
        "PermissionSet compressed integer is truncated or reserved.",
        position,
      );
    cursor += decoded.value.width;
    if (!decoded.value.minimal)
      issue(
        malformed(
          "PermissionSet compressed integer uses a nonminimal width; its readable value is retained.",
          position,
        ).issue,
      );
    return decoded.value.value;
  };
  try {
    result.attribute_count = compressed();
    for (let index = 0; index < result.attribute_count; index++) {
      const offset = cursor;
      const nameLength = compressed();
      if (cursor > raw.length - nameLength)
        throw malformed(
          "Security attribute type name leaves PermissionSet.",
          cursor,
        );
      const nameBytes = raw.subarray(cursor, cursor + nameLength);
      cursor += nameLength;
      const length = compressed();
      if (cursor > raw.length - length)
        throw malformed(
          "Security attribute arguments leave PermissionSet.",
          cursor,
        );
      const argumentOffset = cursor;
      const end = cursor + length;
      budget.reserveString(nameLength, at(offset));
      budget.reserve(nameLength * 2 + length * 2 + 512, at(offset));
      const nameValid = nameBytes.length > 0 && isUtf8(nameBytes);
      if (!nameValid)
        issue(
          malformed(
            "Security attribute type name is empty or invalid UTF-8; its original bytes are retained.",
            offset,
          ).issue,
        );
      let namedCount: number | null = null;
      try {
        namedCount = compressed(end);
        if ((namedCount === 0 && cursor !== end) || namedCount > end - cursor)
          issue(
            malformed(
              "Named-argument count is inconsistent with its framed byte extent; argument values remain opaque.",
              argumentOffset,
            ).issue,
          );
      } catch (cause: unknown) {
        if (
          !(cause instanceof ManagedReaderFailure) ||
          cause instanceof ManagedRepresentationFailure
        )
          throw cause;
        issue(cause.issue);
      }
      result.attributes.push({
        offset: at(offset)!,
        type_name: nameValid ? nameBytes.toString("utf8") : null,
        type_name_hex: nameBytes.toString("hex"),
        arguments_offset: at(argumentOffset)!,
        arguments_length: length,
        named_argument_count: namedCount,
        arguments_hex: raw.subarray(argumentOffset, end).toString("hex"),
      });
      cursor = end;
    }
    if (cursor !== raw.length)
      issue(
        malformed(
          "PermissionSet has bytes after the declared attributes; all bytes remain retained.",
          cursor,
        ).issue,
      );
  } catch (cause: unknown) {
    if (
      !(cause instanceof ManagedReaderFailure) ||
      cause instanceof ManagedRepresentationFailure
    )
      throw cause;
    issue(cause.issue);
  }
  return result;
};

/** Add the independent facet after admitting members and literals, preserving them on capacity failure. */
export const withManagedSecurityDeclarations = (
  bytes: Buffer,
  layout: ManagedMetadataLayout,
  report: ManagedMemberInspection,
  memberLists: TypeMemberListFacts,
): ManagedMemberInspection => {
  const budget = managedDecodeBudget(layout);
  const capacityIssue = {
    ...new ManagedRepresentationFailure(null, budget.maximumBytes).issue,
    scope: "metadata.DeclSecurity",
  };
  try {
    // Reserve the complete failure envelope before examining rows. Additional
    // admitted rows/issues and their array delimiters are charged separately.
    admitManagedProjection(
      { state: "partial", declarations: [], issues: [capacityIssue] },
      budget,
    );
  } catch (cause: unknown) {
    if (!(cause instanceof ManagedRepresentationFailure)) throw cause;
    return { ...report, security_declarations: null };
  }
  const declarations: ManagedSecurityDeclaration[] = [];
  const issues: ManagedParseIssue[] = [];
  const issue: IssueSink = (value) => {
    budget.reserve(1, value.offset);
    issues.push(admitManagedProjection(value, budget));
  };
  const table = layout.table(14);
  if (table === undefined || table.rowCount === 0)
    return {
      ...report,
      security_declarations: {
        state: "complete",
        declarations: [],
        issues: [],
      },
    };
  try {
    budget.reserve(
      (report.types.length +
        report.methods.length +
        (report.unresolved_definitions?.rows.length ?? 0)) *
        64,
      null,
    );
    const parentFor = selectedParents({
      bytes,
      report,
      layout,
      memberLists,
      issue,
    });
    const seen = new Set<string>();
    for (let row = 1; row <= table.rowCount; row++) {
      const offset = metadataRowOffset(layout, 14, row);
      // Read fixed coordinates first: excluded declarations must not decode
      // their blobs or consume per-row retained representation capacity.
      const cursor = new MetadataRowCursor(
        bytes,
        offset,
        offset + table.rowSize,
        "metadata.DeclSecurity",
      );
      const action = cursor.u16();
      const raw = cursor.readIndex(layout.codedIndexSize("HasDeclSecurity"));
      const blob = cursor.readIndex(layout.blobIndexSize);
      const parent = parentFor(raw);
      if (parent === "excluded") continue;
      budget.reserveRow(14, row, offset);
      const token = metadataToken(14, row);
      const scope = `metadata.DeclSecurity:${token}`;
      const actionName = actions.get(action) ?? null;
      if (parent.parent_kind === "unknown")
        issue({
          code: "invalid-row",
          scope,
          offset: offset + 2,
          detail: `HasDeclSecurity parent ${String(raw)} does not identify a valid TypeDef, MethodDef or Assembly row.`,
        });
      else if (parent.parent_name === null)
        issue({
          code: "invalid-row",
          scope,
          offset: offset + 2,
          detail:
            "The checked parent coordinate has no resolved name in the inspected member scope; identity remains unknown.",
        });
      if (actionName === null)
        issue({
          code: "unsupported-metadata",
          scope,
          offset,
          detail: `Security action ${String(action)} is not interpreted; the raw action is retained.`,
        });
      else if (
        parent.parent_kind !== "unknown" &&
        action >= 8 !== (parent.parent_kind === "Assembly")
      )
        issue({
          code: "invalid-row",
          scope,
          offset,
          detail: `${actionName} is declared on an incompatible parent kind ${parent.parent_kind}.`,
        });
      const flag =
        parent.parent_kind === "TypeDef"
          ? 0x40000
          : parent.parent_kind === "MethodDef"
            ? 0x4000
            : null;
      if (
        flag !== null &&
        parent.parent_flags !== null &&
        (parent.parent_flags & flag) === 0
      )
        issue({
          code: "invalid-row",
          scope,
          offset,
          detail:
            "The parent does not carry HasSecurity although a DeclSecurity row references it.",
        });
      const key = `${String(raw)}:${String(action)}`;
      if (seen.has(key))
        issue({
          code: "invalid-row",
          scope,
          offset,
          detail:
            "Duplicate DeclSecurity parent/action pair; every declaration is retained in physical row order.",
        });
      else {
        budget.reserve(64, offset);
        seen.add(key);
      }
      let permission: PermissionSet | null = null;
      try {
        permission = permissionSet(bytes, layout, blob, scope, issue);
      } catch (cause: unknown) {
        if (
          !(cause instanceof ManagedReaderFailure) ||
          cause instanceof ManagedRepresentationFailure
        )
          throw cause;
        issue(cause.issue);
      }
      budget.reserve(1, offset);
      declarations.push(
        admitManagedProjection(
          {
            token,
            row_offset: offset,
            parent_raw: raw,
            ...parent,
            action,
            action_name: actionName,
            permission_set: permission,
          },
          budget,
        ),
      );
    }
  } catch (cause: unknown) {
    if (!(cause instanceof ManagedRepresentationFailure)) throw cause;
    issues.push(capacityIssue);
  }
  const facet: ManagedSecurityDeclarations = {
    state: issues.length === 0 ? "complete" : "partial",
    declarations,
    issues,
  };
  return { ...report, security_declarations: facet };
};
