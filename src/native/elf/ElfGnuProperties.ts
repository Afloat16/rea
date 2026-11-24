import { BinaryReader } from "../../domain/binaryContainer.js";
import { readElfGnuPropertyFrame } from "../../domain/native/elfNoteLayout.js";
import type {
  GnuProperties,
  GnuPropertyEntry,
} from "../../domain/native/elfNotes.js";
import { sha256Hex } from "../../kernel/sha256Hex.js";

// Like the adjacent FDO note decoder, admit descriptor work and expanded
// metadata independently. Raw note ranges and hashes survive either refusal.
const PROPERTY_ALLOWANCE = 65_536;
const PAYLOAD_PREVIEW_BYTES = 64;

type Bits = readonly (readonly [number, string])[];
const X86_ISA_BITS: Bits = [
  [1, "x86-64-baseline"],
  [2, "x86-64-v2"],
  [4, "x86-64-v3"],
  [8, "x86-64-v4"],
];

interface Interpretation {
  readonly name: string;
  readonly bytes: number;
  readonly bits?: Bits;
}

const interpretation = (
  type: number,
  elfClass: 32 | 64,
  machine: number,
): Interpretation | undefined => {
  if (type === 1)
    return { name: "GNU_PROPERTY_STACK_SIZE", bytes: elfClass / 8 };
  if (type === 2)
    return { name: "GNU_PROPERTY_NO_COPY_ON_PROTECTED", bytes: 0 };
  if (type === 0xb0008000)
    return {
      name: "GNU_PROPERTY_1_NEEDED",
      bytes: 4,
      bits: [[1, "INDIRECT_EXTERN_ACCESS"]],
    };
  if (machine === 183 && type === 0xc0000000)
    return {
      name: "GNU_PROPERTY_AARCH64_FEATURE_1_AND",
      bytes: 4,
      bits: [
        [1, "BTI"],
        [2, "PAC"],
        [4, "GCS"],
      ],
    };
  if (machine !== 3 && machine !== 62) return undefined;
  if (type === 0xc0000002)
    return {
      name: "GNU_PROPERTY_X86_FEATURE_1_AND",
      bytes: 4,
      bits: [
        [1, "IBT"],
        [2, "SHSTK"],
      ],
    };
  if (type === 0xc0008002 || type === 0xc0010002)
    return {
      name:
        type === 0xc0008002
          ? "GNU_PROPERTY_X86_ISA_1_NEEDED"
          : "GNU_PROPERTY_X86_ISA_1_USED",
      bytes: 4,
      bits: X86_ISA_BITS,
    };
  return undefined;
};

interface Decoded {
  readonly properties: GnuProperties;
  readonly projectedBytes: number;
}

export interface GnuPropertyDecodeBudget {
  decoded: number;
  retained: number;
  readonly descriptors: Map<string, Decoded>;
}

const unavailable = (issue: string): Decoded => ({
  properties: { entries: null, issue },
  projectedBytes: 0,
});

const PROJECTED_LIMIT =
  "GNU properties exceed the report's 64 KiB projected JSON allowance; use the note descriptor range to read the original bytes.";

const interpretEntry = (
  type: number,
  data: Buffer,
  offset: number,
  little: boolean,
  elfClass: 32 | 64,
  machine: number,
): GnuPropertyEntry => {
  const known = interpretation(type, elfClass, machine);
  const entry: GnuPropertyEntry = {
    type,
    type_name: known?.name ?? null,
    data_location: { offset, bytes: data.length },
    data_sha256: sha256Hex(data),
    data_hex:
      data.length <= PAYLOAD_PREVIEW_BYTES ? data.toString("hex") : null,
    value_hex: null,
    flags: null,
    unknown_bits_hex: null,
    issue: null,
  };
  if (known === undefined) return entry;
  if (data.length !== known.bytes) {
    entry.issue = `${known.name} requires a ${String(known.bytes)}-byte payload.`;
    return entry;
  }
  if (known.bytes === 0) return entry;
  const reader = new BinaryReader(data, little, "elf-notes");
  const value = reader.word(0, known.bytes === 8 ? 64 : 32);
  entry.value_hex = `0x${value.toString(16)}`;
  if (known.bits === undefined) return entry;
  entry.flags = [];
  let unknown = value;
  for (const [mask, name] of known.bits) {
    const bit = BigInt(mask);
    if ((value & bit) !== 0n) {
      entry.flags.push(name);
      unknown &= ~bit;
    }
  }
  entry.unknown_bits_hex = `0x${unknown.toString(16)}`;
  return entry;
};

const decodeDescriptor = (
  descriptor: Buffer,
  offset: number,
  little: boolean,
  elfClass: 32 | 64,
  machine: number,
): Decoded => {
  const entries: GnuPropertyEntry[] = [];
  const reader = new BinaryReader(descriptor, little, "elf-notes");
  let cursor = 0;
  // Reserve the enclosing object and a bounded framing issue before entries.
  let projected = 256;
  let issue: string | null = null;
  while (cursor < descriptor.length) {
    const frame = readElfGnuPropertyFrame(
      reader,
      cursor,
      descriptor.length - cursor,
      elfClass / 8,
    );
    if (!frame.ok) {
      issue = frame.error.message;
      break;
    }
    const { type, dataSize, next } = frame.value;
    const data = descriptor.subarray(cursor + 8, cursor + 8 + dataSize);
    // One bounded entry is constructed at a time; no descriptor-sized array
    // or hex expansion is allocated before checking the retained allowance.
    const entry = interpretEntry(
      type,
      data,
      offset + cursor + 8,
      little,
      elfClass,
      machine,
    );
    const bytes = Buffer.byteLength(JSON.stringify(entry)) + 1;
    if (bytes > PROPERTY_ALLOWANCE - projected)
      return unavailable(PROJECTED_LIMIT);
    projected += bytes;
    entries.push(entry);
    cursor += next;
  }
  const properties = { entries, issue };
  return {
    properties,
    projectedBytes: Buffer.byteLength(JSON.stringify(properties)),
  };
};

/** Describe recorded properties; do not infer a loader's effective policy. */
export const decodeGnuProperties = (
  descriptor: Buffer,
  offset: number,
  little: boolean,
  elfClass: 32 | 64,
  machine: number,
  budget: GnuPropertyDecodeBudget,
): GnuProperties => {
  const key = `${String(offset)}:${String(descriptor.length)}`;
  let decoded = budget.descriptors.get(key);
  if (decoded === undefined) {
    if (descriptor.length > PROPERTY_ALLOWANCE - budget.decoded)
      return unavailable(
        "GNU properties exceed the report's 64 KiB descriptor decode allowance; use the note descriptor range to read the original bytes.",
      ).properties;
    budget.decoded += descriptor.length;
    decoded = decodeDescriptor(descriptor, offset, little, elfClass, machine);
    budget.descriptors.set(key, decoded);
  }
  if (decoded.projectedBytes > PROPERTY_ALLOWANCE - budget.retained)
    return unavailable(PROJECTED_LIMIT).properties;
  budget.retained += decoded.projectedBytes;
  return decoded.properties;
};
