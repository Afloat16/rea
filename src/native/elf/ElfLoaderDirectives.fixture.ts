import { elfDependencyFixture } from "./ElfDependencies.fixture.js";

export const elfLoaderDirectivesFixture = (
  directives: readonly {
    readonly tag: number;
    readonly value: string;
    readonly nameOffset?: number;
  }[] = [
    { tag: 0x7fffffff, value: "$ORIGIN/libfilter.so" },
    { tag: 0x7ffffffd, value: "libaux.so" },
    { tag: 0x6ffffefc, value: "audit.so:${LIB}/audit2.so" },
    { tag: 0x6ffffefb, value: "dep-audit.so" },
  ],
  options: {
    readonly bits?: 32 | 64;
    readonly little?: boolean;
    readonly stripped?: boolean;
    readonly missingStrings?: boolean;
  } = {},
) => {
  const bits = options.bits ?? 64;
  const little = options.little ?? true;
  const bytes = elfDependencyFixture({
    bits,
    little,
    stripped: options.stripped ?? true,
    interpreter: null,
    needed: [...directives.map(({ value }) => value), "libc.so.6"],
    soname: null,
    runpath: null,
    imports: [],
    verneed: [],
    verdef: [],
  });
  const u16 = (offset: number) =>
    little ? bytes.readUInt16LE(offset) : bytes.readUInt16BE(offset);
  const u32 = (offset: number) =>
    little ? bytes.readUInt32LE(offset) : bytes.readUInt32BE(offset);
  const word = (offset: number) =>
    bits === 32
      ? u32(offset)
      : Number(
          little
            ? bytes.readBigUInt64LE(offset)
            : bytes.readBigUInt64BE(offset),
        );
  const writeWord = (offset: number, value: number) => {
    if (bits === 64) {
      if (little) bytes.writeBigUInt64LE(BigInt(value), offset);
      else bytes.writeBigUInt64BE(BigInt(value), offset);
    } else if (little) bytes.writeUInt32LE(value, offset);
    else bytes.writeUInt32BE(value, offset);
  };
  const phoff = word(bits === 64 ? 32 : 28);
  const phentsize = u16(bits === 64 ? 54 : 42);
  const phnum = u16(bits === 64 ? 56 : 44);
  const dynamicHeader = phoff + (phnum - 1) * phentsize;
  const dynamicOffset = word(dynamicHeader + (bits === 64 ? 8 : 4));
  const entryBytes = bits / 4;
  for (const [index, directive] of directives.entries()) {
    const offset = dynamicOffset + index * entryBytes;
    writeWord(offset, directive.tag);
    if (directive.nameOffset !== undefined)
      writeWord(offset + bits / 8, directive.nameOffset);
  }
  if (options.missingStrings) {
    for (let offset = dynamicOffset; word(offset) !== 0; offset += entryBytes)
      if (word(offset) === 5) writeWord(offset, 0x60000042);
  }
  return { bytes, dynamicOffset, entryBytes };
};
