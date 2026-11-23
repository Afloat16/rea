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
  type MetadataTokenFact,
} from "../domain/managed/managedMetadataHeaps.js";
import {
  MANAGED_CODED_INDEXES,
  type ManagedMetadataLayout,
} from "../domain/managed/managedMetadataLayout.js";
import type {
  MemberCore,
  TypeRange,
} from "../domain/managed/managedMemberInspectorCore.js";
import type { TypeMemberListFacts } from "../domain/managed/managedTypeMemberLists.js";
import { readReferencedMemberCores } from "./ManagedMemberRows.js";

type Implementations = NonNullable<
  ManagedMemberInspection["method_implementations"]
>;
type Declaration = Implementations["declarations"][number];
interface Context {
  readonly bytes: Buffer;
  readonly layout: ManagedMetadataLayout;
  readonly report: ManagedMemberInspection;
  readonly ranges: readonly TypeRange[];
  readonly memberLists: TypeMemberListFacts;
  readonly cores: readonly ReadonlyMap<string, MemberCore>[];
}
interface Reference {
  readonly raw: number;
  readonly offset: number;
  readonly coordinate: ReturnType<typeof decodeMetadataCodedIndex>;
}
interface RawDeclaration {
  readonly token: string;
  readonly rowOffset: number;
  readonly classRaw: number;
  readonly owner: ManagedMemberInspection["types"][number] | undefined;
  readonly body: Reference;
  readonly declaration: Reference;
}

const knownCore = (
  cores: Context["cores"],
  token: string,
): MemberCore | undefined => {
  for (const core of cores) {
    const value = core.get(token);
    if (value !== undefined) return value;
  }
  return undefined;
};

const readDeclarations = (context: Context, issues: ManagedParseIssue[]) => {
  const { bytes, layout, report } = context;
  const budget = managedDecodeBudget(layout);
  budget.admitTransient(report.types.length * 96, null);
  const selected = new Map(report.types.map((type) => [type.token, type]));
  const rows: RawDeclaration[] = [];
  const references = new Map<
    string,
    Pick<MetadataTokenFact, "table" | "row" | "token">
  >();
  const seen = new Set<string>();
  const table = layout.table(25);
  const classCount = layout.table(2)?.rowCount ?? 0;
  const classWidth = layout.tableIndexSize(2);
  const reader = new BinaryReader(
    bytes,
    true,
    "managed-method-implementations",
  );
  const issue = (scope: string, offset: number, detail: string): void => {
    issues.push(
      admitManagedProjection(
        { code: "invalid-row", scope, offset, detail },
        budget,
      ),
    );
  };
  for (let row = 1; row <= (table?.rowCount ?? 0); row += 1) {
    const offset = table!.offset + (row - 1) * table!.rowSize;
    // The layout already admitted this fixed-width prefix. Unselected classes
    // do not reserve decoded rows or read either referenced method.
    const classRaw = classWidth === 2 ? reader.u16(offset) : reader.u32(offset);
    const validClass = classRaw > 0 && classRaw <= classCount;
    const owner = validClass
      ? selected.get(metadataToken(2, classRaw))
      : undefined;
    if (validClass && owner === undefined) continue;
    const token = metadataToken(25, row);
    const scope = `metadata.MethodImpl:${token}`;
    if (!validClass)
      issue(
        scope,
        offset,
        `MethodImpl Class row ${String(classRaw)} is outside the TypeDef table; selection membership is unknown`,
      );
    const cursor = metadataRowCursor(bytes, layout, 25, row);
    cursor.readIndex(classWidth);
    const reference = (): Reference => {
      const referenceOffset = cursor.offset;
      const raw = cursor.readIndex(layout.codedIndexSize("MethodDefOrRef"));
      const coordinate = decodeMetadataCodedIndex(
        raw,
        MANAGED_CODED_INDEXES.MethodDefOrRef.bits,
        MANAGED_CODED_INDEXES.MethodDefOrRef.tables,
        layout.rowCounts,
      );
      if (coordinate.kind !== "valid") {
        issue(
          scope,
          referenceOffset,
          `MethodImpl method coordinate 0x${raw.toString(16)} must reference an existing MethodDef or MemberRef row`,
        );
      } else if (
        coordinate.table === 6 &&
        knownCore(context.cores, coordinate.token) === undefined &&
        !references.has(coordinate.token)
      ) {
        budget.admitTransient(128, referenceOffset);
        references.set(coordinate.token, coordinate);
      }
      return { raw, offset: referenceOffset, coordinate };
    };
    const body = reference();
    const declaration = reference();
    if (validClass && declaration.coordinate.kind === "valid") {
      const key = `${String(classRaw)}:${String(declaration.raw)}`;
      if (seen.has(key))
        issue(
          scope,
          offset,
          "Duplicate Class and MethodDeclaration pair; all original declarations are retained",
        );
      else {
        budget.admitTransient(128, offset);
        seen.add(key);
      }
    }
    budget.admitTransient(256, offset);
    rows.push({ token, rowOffset: offset, classRaw, owner, body, declaration });
  }
  return { rows, references };
};

const projectReference = (
  reference: Reference,
  context: Context,
  scope: string,
  issues: ManagedParseIssue[],
): Declaration["body"] => {
  const { raw, offset, coordinate } = reference;
  if (coordinate.kind !== "valid")
    return {
      raw,
      token: null,
      kind: "unknown",
      row_offset: null,
      name: null,
      declaring_type: null,
      member_kind: "unknown",
    };
  const core = knownCore(context.cores, coordinate.token);
  const name = core?.name ? core.name : null;
  const memberKind =
    coordinate.table === 6 ? "method" : (core?.kind ?? "unknown");
  if (name === null || memberKind !== "method")
    issues.push(
      admitManagedProjection(
        {
          code: "invalid-row",
          scope,
          offset,
          detail: `MethodImpl target ${coordinate.token} has an unreadable name or lacks a decoded method signature kind; its original coordinate is retained`,
        },
        managedDecodeBudget(context.layout),
      ),
    );
  const table = context.layout.table(coordinate.table)!;
  return {
    raw,
    token: coordinate.token,
    kind: coordinate.table === 6 ? "method-def" : "member-ref",
    row_offset: table.offset + (coordinate.row - 1) * table.rowSize,
    name,
    declaring_type: core?.declaringType ?? null,
    member_kind: memberKind,
  };
};

const readImplementations = (context: Context): Implementations => {
  const { layout, bytes, ranges, memberLists, report } = context;
  const budget = managedDecodeBudget(layout);
  const issues: ManagedParseIssue[] = [];
  try {
    const { rows, references } = readDeclarations(context, issues);
    // Reuse the existing physical member-name/owner reader. Targets outside the
    // MethodDef page are named without decoding their signatures or IL bodies.
    const recovered = readReferencedMemberCores(
      bytes,
      layout,
      ranges,
      memberLists,
      references.values(),
    );
    for (const issue of recovered.issues)
      issues.push(admitManagedProjection(issue, budget));
    const resolved = { ...context, cores: [...context.cores, recovered.core] };
    const declarations = rows.map((row) =>
      admitManagedProjection(
        {
          token: row.token,
          row_offset: row.rowOffset,
          class_raw: row.classRaw,
          class_token: row.owner?.token ?? null,
          class_name: row.owner?.full_name ?? null,
          body: projectReference(
            row.body,
            resolved,
            `metadata.MethodImpl:${row.token}.MethodBody`,
            issues,
          ),
          declaration: projectReference(
            row.declaration,
            resolved,
            `metadata.MethodImpl:${row.token}.MethodDeclaration`,
            issues,
          ),
        },
        budget,
      ),
    );
    return {
      state:
        issues.length === 0 &&
        (report.unresolved_definitions?.rows.length ?? 0) === 0
          ? "complete"
          : "partial",
      declarations,
      issues,
    };
  } finally {
    budget.releaseTransient();
  }
};

/** Keep existing member/string evidence when this separately bounded facet is unavailable. */
export const withManagedMethodImplementations = (
  context: Context,
): ManagedMemberInspection => {
  const budget = managedDecodeBudget(context.layout);
  let recovery: Implementations;
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
            scope: "metadata.MethodImpl",
          },
        ],
      },
      budget,
    );
  } catch (cause: unknown) {
    if (!(cause instanceof ManagedRepresentationFailure)) throw cause;
    return { ...context.report, method_implementations: null };
  }
  try {
    return {
      ...context.report,
      method_implementations: admitManagedProjection(
        readImplementations(context),
        budget,
      ),
    };
  } catch (cause: unknown) {
    if (!(cause instanceof ManagedRepresentationFailure)) throw cause;
    return {
      ...context.report,
      method_implementations: {
        ...recovery,
        issues: [{ ...recovery.issues[0]!, offset: cause.issue.offset }],
      },
    };
  }
};
