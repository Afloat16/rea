import { createHash } from "node:crypto";
import type { ByteSource } from "../../domain/byteSource.js";
import {
  BinaryReader,
  type ImageSection,
} from "../../domain/binaryContainer.js";
import {
  kernelModuleVersionNameLimit,
  type InspectKernelModuleInput,
  type KernelModule,
} from "../../domain/native/kernelModule.js";
import {
  ArtifactReaderFailure,
  yieldArtifactRead,
} from "../../resources/index.js";
import { sha256Hex } from "../../kernel/sha256Hex.js";

type Section = Extract<ImageSection, { format: "elf" }>;
type Report = NonNullable<KernelModule["extended_versions"]>;
type Range = { readonly offset: number; readonly bytes: number };
type Entry = Report["entries"][number];
// A transport window, not a format or caller-selectable content limit.
const WINDOW_BYTES = 65536;
const CRC_BYTES = 4;

const extent = (
  section: Section | undefined,
  fileSize: number,
): Range | null => {
  if (section === undefined || section.type === 8) return null;
  const { offset, size } = section.declared_range;
  if (
    offset < 0n ||
    size < 0n ||
    offset > BigInt(fileSize) ||
    size > BigInt(fileSize) - offset
  )
    return null;
  return { offset: Number(offset), bytes: Number(size) };
};

const read = (
  source: ByteSource,
  offset: number,
  bytes: number,
): Promise<Buffer> =>
  bytes === 0
    ? Promise.resolve(Buffer.alloc(0))
    : source.prefix !== undefined && offset + bytes <= source.prefix.length
      ? Promise.resolve(source.prefix.subarray(offset, offset + bytes))
      : source.readRange(offset, bytes);

const hashSection = async (
  source: ByteSource,
  location: Range | null,
  signal?: AbortSignal,
): Promise<Report["names"]> => {
  if (location === null) return null;
  const hash = createHash("sha256");
  for (let at = 0; at < location.bytes; at += WINDOW_BYTES) {
    await yieldArtifactRead(signal);
    hash.update(
      await read(
        source,
        location.offset + at,
        Math.min(WINDOW_BYTES, location.bytes - at),
      ),
    );
  }
  return { location, sha256: hash.digest("hex") };
};

/** One name stream; overlong names keep a digest instead of their byte chunks. */
class ExtendedNameStream {
  readonly entries: Entry[] = [];
  readonly #crcReader: BinaryReader;
  readonly #count: number;
  readonly #parts: Buffer[] = [];
  #nameHash = createHash("sha256");
  #nameBytes = 0;
  #consumed = 0;
  #omitted = false;
  #largestOmission = 0;
  readonly #tailHash = createHash("sha256");
  #tailBytes = 0;
  #tailZero = true;

  constructor(
    readonly crcs: Range,
    bytes: Buffer,
    little: boolean,
    readonly names: Range,
    readonly maximumNameBytes: number,
  ) {
    this.#crcReader = new BinaryReader(
      bytes,
      little,
      "kernel-module-extended-versions",
    );
    this.#count = bytes.length / CRC_BYTES;
  }

  write(chunk: Buffer): void {
    let at = 0;
    while (at < chunk.length) {
      if (this.entries.length === this.#count) {
        const tail = chunk.subarray(at);
        this.#tailHash.update(tail);
        this.#tailBytes += tail.length;
        this.#tailZero &&= !tail.some((byte) => byte !== 0);
        this.#consumed += tail.length;
        break;
      }
      const nul = chunk.indexOf(0, at);
      const end = nul < 0 ? chunk.length : nul + 1;
      const part = chunk.subarray(at, end);
      this.#nameHash.update(part);
      this.#nameBytes += part.length;
      this.#consumed += part.length;
      const contentBytes = this.#nameBytes - (nul < 0 ? 0 : 1);
      if (contentBytes > this.maximumNameBytes) {
        this.#omitted = true;
        this.#parts.length = 0;
      } else if (!this.#omitted) this.#parts.push(part);
      if (nul >= 0) this.#finishName(contentBytes === 0 ? "name_empty" : null);
      at = end;
    }
  }

  #finishName(reason: Entry["reason"]): void {
    const index = this.entries.length;
    const hasBytes = this.#nameBytes > 0;
    const omitted = reason === null && this.#omitted;
    if (omitted)
      this.#largestOmission = Math.max(
        this.#largestOmission,
        this.#nameBytes - 1,
      );
    this.entries.push({
      index,
      crc_location: {
        offset: this.crcs.offset + index * CRC_BYTES,
        bytes: CRC_BYTES,
      },
      crc_hex: this.#crcReader
        .u32(index * CRC_BYTES)
        .toString(16)
        .padStart(8, "0"),
      name_location: hasBytes
        ? {
            offset: this.names.offset + this.#consumed - this.#nameBytes,
            bytes: this.#nameBytes,
          }
        : null,
      name_sha256: hasBytes ? this.#nameHash.digest("hex") : null,
      name:
        reason === null && !omitted
          ? Buffer.concat(this.#parts, this.#nameBytes).toString(
              "latin1",
              0,
              this.#nameBytes - 1,
            )
          : null,
      status: reason === null ? "observed" : "malformed",
      reason,
      omitted_fields: omitted ? ["name"] : [],
    });
    this.#nameHash = createHash("sha256");
    this.#nameBytes = 0;
    this.#parts.length = 0;
    this.#omitted = false;
  }

  finish(): {
    readonly entries: Entry[];
    readonly tail: Report["trailing_names"];
    readonly largestOmission: number;
  } {
    if (this.#nameBytes > 0) this.#finishName("name_unterminated");
    while (this.entries.length < this.#count) this.#finishName("name_missing");
    return {
      entries: this.entries,
      tail:
        this.#tailBytes === 0
          ? null
          : {
              location: {
                offset: this.names.offset + this.#consumed - this.#tailBytes,
                bytes: this.#tailBytes,
              },
              sha256: this.#tailHash.digest("hex"),
              zero_padding: this.#tailZero,
            },
      largestOmission: this.#largestOmission,
    };
  }
}

interface Context {
  readonly source: ByteSource;
  readonly crcs: Section | undefined;
  readonly names: Section | undefined;
  readonly namesComplete: boolean;
  readonly little: boolean;
  readonly input: InspectKernelModuleInput;
  readonly examined: { count: number };
  readonly limitations: string[];
  readonly signal?: AbortSignal | undefined;
}

const unavailableReason = (
  { crcs, names, namesComplete }: Context,
  crcRange: Range | null,
  nameRange: Range | null,
): Report["reason"] => {
  if (crcs === undefined || names === undefined)
    return !namesComplete
      ? "section_names_incomplete"
      : crcs === undefined
        ? "missing_crcs"
        : "missing_names";
  if (crcRange === null) return "crcs_not_file_backed";
  if (nameRange === null) return "names_not_file_backed";
  if (crcs.compressed) return "crcs_compressed";
  if (names.compressed) return "names_compressed";
  return crcRange.bytes % CRC_BYTES === 0 ? null : "crcs_size_not_multiple";
};

/** Join the two physical arrays by ordinal, as the kernel's extended iterator does. */
export const readKernelModuleExtendedVersions = async (
  context: Context,
): Promise<Report> => {
  const {
    source,
    crcs,
    names,
    namesComplete,
    little,
    input,
    examined,
    limitations,
    signal,
  } = context;
  const empty = {
    crcs: null,
    names: null,
    entries: [],
    trailing_names: null,
    reason: null,
  };
  if (crcs === undefined && names === undefined)
    return { ...empty, status: namesComplete ? "absent" : "unknown" };
  const crcRange = extent(crcs, source.size);
  const nameRange = extent(names, source.size);
  const reason = unavailableReason(context, crcRange, nameRange);
  if (reason !== null || crcRange === null || nameRange === null) {
    return {
      ...empty,
      status:
        reason === "section_names_incomplete"
          ? "unknown"
          : reason === "names_compressed" || reason === "crcs_compressed"
            ? "unsupported"
            : "malformed",
      reason,
      crcs: await hashSection(source, crcRange, signal),
      names: await hashSection(source, nameRange, signal),
    };
  }
  const count = crcRange.bytes / CRC_BYTES;
  if (count > input.max_entries - examined.count)
    throw new ArtifactReaderFailure(
      "limit",
      `Kernel module entries exceed the ${String(input.max_entries)}-entry budget.`,
      { boundary: "capacity" },
    );
  // The shared entry admission bounds this allocation to four bytes per row.
  const crcBytes = await read(source, crcRange.offset, crcRange.bytes);
  const stream = new ExtendedNameStream(
    crcRange,
    crcBytes,
    little,
    nameRange,
    input.max_version_name_bytes,
  );
  const hash = createHash("sha256");
  for (let at = 0; at < nameRange.bytes; at += WINDOW_BYTES) {
    await yieldArtifactRead(signal);
    const chunk = await read(
      source,
      nameRange.offset + at,
      Math.min(WINDOW_BYTES, nameRange.bytes - at),
    );
    hash.update(chunk);
    stream.write(chunk);
  }
  const result = stream.finish();
  examined.count += result.entries.length;
  if (result.largestOmission > 0)
    limitations.push(
      `Extended module symbol names exceed max_version_name_bytes=${String(input.max_version_name_bytes)} bytes. Raise max_version_name_bytes to at least ${String(result.largestOmission)} on the next call to retain them; their ranges, digests and CRCs remain available.`,
    );
  if (result.tail !== null && !result.tail.zero_padding)
    limitations.push(
      "Extended module name bytes continue after the final CRC; the unmatched bytes are retained as a range and digest, not assigned to a symbol.",
    );
  return {
    status: "present",
    crcs: { location: crcRange, sha256: sha256Hex(crcBytes) },
    names: { location: nameRange, sha256: hash.digest("hex") },
    entries: result.entries,
    trailing_names: result.tail,
    reason: null,
    ...(result.largestOmission > 0
      ? {
          omission_limits: [
            kernelModuleVersionNameLimit(input.max_version_name_bytes),
          ],
        }
      : {}),
  };
};
