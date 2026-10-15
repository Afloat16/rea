import { createHash } from "node:crypto";
import {
  constants,
  createReadStream,
  read,
  type BigIntStats,
  type ReadStream,
  type ReadStreamOptions,
} from "node:fs";
import { lstat, open, type FileHandle } from "node:fs/promises";
import { ArtifactReaderFailure } from "./ArtifactReader.js";
import type { ArtifactResourceScope } from "./ArtifactResourceScope.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";

/** Filesystem boundary for stable reads, including deterministic replacement probes. */
export interface StableArtifactFileSystem {
  lstat(path: string): Promise<BigIntStats>;
  open(path: string, flags: number): Promise<FileHandle>;
  createReadStream?(path: string, options: ReadStreamOptions): ReadStream;
}

const FILE_SYSTEM: StableArtifactFileSystem = {
  lstat: (path) => lstat(path, { bigint: true }),
  open,
};

const afterValidation = async <T>(
  path: string,
  stage: string,
  read: () => Promise<T>,
): Promise<T> => {
  try {
    return await read();
  } catch (cause) {
    if (
      cause instanceof Error &&
      "code" in cause &&
      ["ENOENT", "ENOTDIR", "ELOOP"].includes(String(cause.code))
    )
      throw new ArtifactReaderFailure(
        "integrity",
        `Artifact changed ${stage}: ${path}`,
        { cause },
      );
    throw cause;
  }
};

const assertReadActive = (signal: AbortSignal | undefined): void => {
  if (signal?.aborted)
    throw new ArtifactReaderFailure("cancelled", "Artifact read cancelled", {
      cause: signal.reason,
    });
};

const nextActiveChunk = async (
  iterator: AsyncIterator<unknown>,
  signal?: AbortSignal,
): Promise<IteratorResult<unknown>> => {
  assertReadActive(signal);
  if (signal === undefined) return iterator.next();
  let onAbort: () => void = () => undefined;
  const cancelled = new Promise<never>((_resolve, reject) => {
    onAbort = () =>
      reject(
        new ArtifactReaderFailure("cancelled", "Artifact read cancelled", {
          cause: signal.reason,
        }),
      );
  });
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    assertReadActive(signal);
    return await Promise.race([iterator.next(), cancelled]);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
};

/** Await native read quiescence without transferring descriptor ownership. */
const closeReadSource = async (
  source: ReadStream | undefined,
): Promise<void> => {
  if (source === undefined || source.closed) return;
  await new Promise<void>((resolve, reject) => {
    const onError = (): void => undefined;
    source.on("error", onError);
    source.once("close", () => {
      source.off("error", onError);
      resolve();
    });
    try {
      source.destroy();
    } catch (cause: unknown) {
      source.off("error", onError);
      reject(cause);
    }
  });
};

/** Read one bounded regular file and reject replacement or in-place changes. */
export const readStableArtifact = async (
  path: string,
  maximumBytes: number,
  signal?: AbortSignal,
  fileSystem: StableArtifactFileSystem = FILE_SYSTEM,
  resourceScope?: ArtifactResourceScope,
): Promise<{ readonly bytes: Buffer; readonly sha256: string }> => {
  assertReadActive(signal);
  const before = await fileSystem.lstat(path);
  if (!before.isFile() || before.isSymbolicLink())
    throw new ArtifactReaderFailure(
      "path",
      `Expected a regular file without a symlink: ${path}`,
    );
  if (before.size > BigInt(maximumBytes))
    throw new ArtifactReaderFailure(
      "limit",
      `Selected artifact exceeds ${String(maximumBytes)} bytes: ${path}`,
    );
  const file = await afterValidation(path, "before open", () =>
    fileSystem.open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    ),
  );
  let source: ReadStream | undefined;
  let iterator: AsyncIterator<unknown> | undefined;
  const owner = new OwnedFileHandle(file);
  let failure: unknown;
  try {
    const initial = await file.stat({ bigint: true });
    if (
      !initial.isFile() ||
      initial.dev !== before.dev ||
      initial.ino !== before.ino
    )
      throw new ArtifactReaderFailure(
        "integrity",
        `Artifact changed before open: ${path}`,
      );
    const chunks: Buffer[] = [];
    let count = 0;
    source = (fileSystem.createReadStream ?? createReadStream)(path, {
      // Supplying the admitted numeric fd prevents any path reopen. The
      // source releases only its read state; owner closes the actual handle.
      fd: file.fd,
      autoClose: false,
      highWaterMark: 65536,
      fs: { read, close: (_fd, callback) => callback(null) },
    });
    iterator = source.iterator({ destroyOnReturn: false });
    for (;;) {
      const chunk = await nextActiveChunk(iterator, signal);
      if (chunk.done === true) break;
      assertReadActive(signal);
      const value: unknown = chunk.value;
      if (!Buffer.isBuffer(value))
        throw new ArtifactReaderFailure(
          "format",
          `Artifact stream did not return bytes: ${path}`,
        );
      const bytes = value;
      count += bytes.length;
      if (count > maximumBytes)
        throw new ArtifactReaderFailure(
          "limit",
          `Selected artifact grew beyond its byte limit: ${path}`,
        );
      chunks.push(bytes);
    }
    const after = await file.stat({ bigint: true });
    const current = await afterValidation(path, "during read", () =>
      fileSystem.lstat(path),
    );
    if (
      [after, current].some(
        (stat) =>
          !stat.isFile() ||
          stat.dev !== initial.dev ||
          stat.ino !== initial.ino ||
          stat.size !== initial.size ||
          stat.mtimeNs !== initial.mtimeNs ||
          stat.ctimeNs !== initial.ctimeNs,
      ) ||
      BigInt(count) !== initial.size
    )
      throw new ArtifactReaderFailure(
        "integrity",
        `Artifact changed during read: ${path}`,
      );
    assertReadActive(signal);
    const bytes = Buffer.concat(chunks, count);
    return { bytes, sha256: createHash("sha256").update(bytes).digest("hex") };
  } catch (cause: unknown) {
    failure = cause;
    throw cause;
  } finally {
    await closeReadSource(source);
    await iterator?.return?.().catch(() => undefined);
    const cleanup =
      resourceScope === undefined
        ? await owner.close().then(
            () => ({ kind: "released" as const }),
            (cause: unknown) => ({ kind: "failed" as const, cause }),
          )
        : await resourceScope.release({
            kind: "file-handle",
            resource: path,
            handle: owner,
          });
    if (cleanup.kind === "failed") {
      throw ArtifactReaderFailure.withCleanup(
        failure ?? cleanup.cause,
        ArtifactReaderFailure.cleanupObservation(cleanup.cause, path),
      );
    }
  }
};
