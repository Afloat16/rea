import { peImportImage } from "./peImports.js";

interface BoundModule {
  readonly name: string;
  readonly timestamp?: number;
  readonly nameOffset?: number;
  readonly reserved?: number;
}

interface BoundDll extends BoundModule {
  readonly forwarders?: readonly BoundModule[];
  readonly declaredForwarders?: number;
}

/** Owned byte fixture with a directory-relative bound-name pool. */
export const peBoundImportsFixture = (
  options: {
    readonly bits?: 32 | 64;
    readonly rows?: readonly BoundDll[];
    readonly headers?: boolean;
    readonly splitAt?: number;
    readonly declaredSize?: number;
    readonly omitTerminator?: boolean;
  } = {},
) => {
  const bits = options.bits ?? 64;
  const rows = options.rows ?? [
    {
      name: "KERNEL32.dll",
      timestamp: 0x12345678,
      forwarders: [{ name: "NTDLL.dll", timestamp: 0x23456789 }],
    },
    { name: "USER32.dll", timestamp: 0x3456789a },
  ];
  const recordCount = rows.reduce(
    (count, row) => count + 1 + (row.forwarders?.length ?? 0),
    0,
  );
  const tableBytes = (recordCount + (options.omitTerminator ? 0 : 1)) * 8;
  const strings: Buffer[] = [];
  const names = new Map<string, number>();
  let length = tableBytes;
  for (const row of rows.flatMap((row) => [row, ...(row.forwarders ?? [])])) {
    if (names.has(row.name)) continue;
    names.set(row.name, length);
    const text = Buffer.from(`${row.name}\0`, "latin1");
    strings.push(text);
    length += text.length;
  }
  const table = Buffer.concat([Buffer.alloc(tableBytes), ...strings]);
  let cursor = 0;
  for (const row of rows) {
    table.writeUInt32LE(row.timestamp ?? 0x12345678, cursor);
    table.writeUInt16LE(row.nameOffset ?? names.get(row.name) ?? 0, cursor + 4);
    table.writeUInt16LE(
      row.declaredForwarders ?? row.forwarders?.length ?? 0,
      cursor + 6,
    );
    cursor += 8;
    for (const forwarder of row.forwarders ?? []) {
      table.writeUInt32LE(forwarder.timestamp ?? 0x23456789, cursor);
      table.writeUInt16LE(
        forwarder.nameOffset ?? names.get(forwarder.name) ?? 0,
        cursor + 4,
      );
      table.writeUInt16LE(forwarder.reserved ?? 0, cursor + 6);
      cursor += 8;
    }
  }
  const rva = options.headers ? 0x300 : 0x1600;
  const sectionBytes = Math.max(0x800, 0x600 + table.length);
  const bytes = peImportImage({
    bits,
    sectionBytes,
    ...(options.splitAt === undefined ? {} : { splitAt: options.splitAt }),
  });
  const at = (address: number) =>
    address < 0x400
      ? address
      : options.splitAt !== undefined && address >= 0x1000 + options.splitAt
        ? 0x400 + sectionBytes + 0x200 + address - 0x1000 - options.splitAt
        : 0x400 + address - 0x1000;
  for (let index = 0; index < table.length; index++)
    bytes[at(rva + index)] = table[index] ?? 0;
  const directoryOffset = 152 + (bits === 64 ? 112 : 96) + 11 * 8;
  bytes.writeUInt32LE(rva, directoryOffset);
  bytes.writeUInt32LE(
    options.declaredSize ?? table.length,
    directoryOffset + 4,
  );
  return { bytes, rva, directoryOffset, tableBytes: table.length, at };
};
