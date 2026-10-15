import {
  lstat,
  open,
  rename,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { createReadStream, type ReadStream } from "node:fs";
import { expect, it, vi } from "vitest";
import {
  readStableArtifact,
  type StableArtifactFileSystem,
} from "../../../src/artifacts/readStableArtifact.js";
import { ArtifactResourceScope } from "../../../src/artifacts/ArtifactResourceScope.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

it("reads exact binary and empty bytes and rejects symlink/size/cancellation boundaries", async () => {
  const root = await createTestTempDirectory("rea-stable-artifact-");
  const path = join(root, "source.bin");
  await writeFile(path, Buffer.from([0, 255, 254]));
  expect(await readStableArtifact(path, 3)).toEqual({
    bytes: Buffer.from([0, 255, 254]),
    sha256: "d590f90f7944340fb253f0c59cb89fd41d4ec255ff246f524f8f7c94f0a233e5",
  });
  await expect(readStableArtifact(path, 2)).rejects.toMatchObject({
    reason: "limit",
  });
  await writeFile(path, "");
  expect((await readStableArtifact(path, 0)).bytes.length).toBe(0);
  const real = join(root, "original.bin");
  await rename(path, real);
  await symlink(real, path);
  await expect(readStableArtifact(path, 3)).rejects.toMatchObject({
    reason: "path",
  });
  const controller = new AbortController();
  controller.abort();
  await expect(
    readStableArtifact(real, 3, controller.signal),
  ).rejects.toMatchObject({
    reason: "cancelled",
    cause: controller.signal.reason,
  });
});

const checkChange = async (
  stage: "before-open" | "after-read" | "symlink-replacement",
): Promise<void> => {
  const root = await createTestTempDirectory("rea-stable-read-");
  const path = join(root, "selected");
  await writeFile(path, "original evidence");
  let inspected = 0;
  const reading = readStableArtifact(path, 1024, undefined, {
    async lstat(selected) {
      inspected++;
      if (stage === "after-read" && inspected === 2) await unlink(selected);
      const metadata = await lstat(selected, { bigint: true });
      if (inspected === 1 && stage !== "after-read") {
        await unlink(selected);
        if (stage === "symlink-replacement") await symlink("missing", selected);
      }
      return metadata;
    },
    open,
  });
  await expect(reading).rejects.toMatchObject({ reason: "integrity" });
};

it.each(["before-open", "after-read"] as const)(
  "retains an actual post-validation %s change as integrity failure",
  checkChange,
);

it.skipIf(process.platform === "win32")(
  "retains a post-validation symlink replacement as an integrity failure",
  () => checkChange("symlink-replacement"),
);

it("keeps initially missing inputs distinguishable from later changes", async () => {
  const root = await createTestTempDirectory("rea-stable-missing-");
  await expect(
    readStableArtifact(join(root, "missing"), 1024),
  ).rejects.toMatchObject({ code: "ENOENT" });
});

it.each([false, true])(
  "cancels an idle snapshot stream and retains a failed close: %s",
  async (failFirstClose) => {
    const root = await createTestTempDirectory("rea-stable-idle-");
    const path = join(root, "source");
    await writeFile(path, "unchanged selected bytes");
    const file = await open(path, "r");
    const nativeClose = file.close.bind(file);
    let source: ReadStream | undefined;
    let started: (() => void) | undefined;
    const readingStarted = new Promise<void>((resolve) => {
      started = resolve;
    });
    const openSource: NonNullable<
      StableArtifactFileSystem["createReadStream"]
    > = (selected, options) => {
      expect(options.fd).toBe(file.fd);
      source = createReadStream(selected, options);
      // Keep a real descriptor-backed stream idle without issuing an OS read.
      vi.spyOn(source, "_read").mockImplementation(() => started?.());
      return source;
    };
    const closeFailure = new Error("synthetic snapshot close EIO");
    let attempts = 0;
    const closeSpy = vi.spyOn(file, "close").mockImplementation(async () => {
      attempts += 1;
      if (failFirstClose && attempts === 1) throw closeFailure;
      await nativeClose();
    });
    const controller = new AbortController();
    const reason = new Error("requested cancellation");
    const addListener = vi.spyOn(controller.signal, "addEventListener");
    const removeListener = vi.spyOn(controller.signal, "removeEventListener");
    const scope = new ArtifactResourceScope();
    let settled = false;
    const outcome = readStableArtifact(
      path,
      1024,
      controller.signal,
      {
        lstat: (selected) => lstat(selected, { bigint: true }),
        open: async () => file,
        createReadStream: openSource,
      },
      scope,
    ).then(
      (value) => {
        settled = true;
        return { value };
      },
      (error: unknown) => {
        settled = true;
        return { error };
      },
    );
    try {
      await readingStarted;
      controller.abort(reason);
      await vi.waitFor(() => expect(settled).toBe(true), { timeout: 500 });
      expect(await outcome).toMatchObject({ error: { reason: "cancelled" } });
      const abortListener = addListener.mock.calls.find(
        ([event]) => event === "abort",
      )?.[1];
      expect(abortListener).toBeDefined();
      expect(removeListener).toHaveBeenCalledWith("abort", abortListener);
      expect(attempts).toBe(1);
      expect(scope.hasPending).toBe(failFirstClose);
      if (failFirstClose) {
        expect(await outcome).toMatchObject({
          error: {
            cause: { reason: "cancelled", cause: reason },
            cleanup: { reason: closeFailure.message, resources: [path] },
          },
        });
        expect(file.fd).toBeGreaterThanOrEqual(0);
        await scope.close();
        expect(attempts).toBe(2);
        expect(scope.hasPending).toBe(false);
      }
      expect(file.fd).toBe(-1);
      expect(source?.closed).toBe(true);
    } finally {
      source?.destroy();
      await outcome;
      await scope.close().catch(() => undefined);
      closeSpy.mockRestore();
      addListener.mockRestore();
      removeListener.mockRestore();
      await nativeClose();
    }
  },
);

it.each([false, true])(
  "awaits an invalidated descriptor's actual close result during cancellation: %s",
  async (rejectClose) => {
    const root = await createTestTempDirectory("rea-stable-close-result-");
    const path = join(root, "source");
    await writeFile(path, "selected bytes");
    const file = await open(path, "r");
    const nativeClose = file.close.bind(file);
    let source: ReadStream | undefined;
    let started: (() => void) | undefined;
    const readingStarted = new Promise<void>((resolve) => {
      started = resolve;
    });
    let invalidated: (() => void) | undefined;
    const descriptorInvalidated = new Promise<void>((resolve) => {
      invalidated = resolve;
    });
    let finishClose: (() => void) | undefined;
    const closeResult = new Promise<void>((resolve) => {
      finishClose = resolve;
    });
    const openSource: NonNullable<
      StableArtifactFileSystem["createReadStream"]
    > = (selected, options) => {
      expect(options.fd).toBe(file.fd);
      source = createReadStream(selected, options);
      vi.spyOn(source, "_read").mockImplementation(() => started?.());
      return source;
    };
    const closeFailure = new Error(
      "synthetic close failed after fd invalidation",
    );
    const closeSpy = vi.spyOn(file, "close").mockImplementation(async () => {
      expect(source?.closed).toBe(true);
      expect(file.fd).toBeGreaterThanOrEqual(0);
      await nativeClose();
      invalidated?.();
      await closeResult;
      if (rejectClose) throw closeFailure;
    });
    const controller = new AbortController();
    const scope = new ArtifactResourceScope();
    let settled = false;
    const outcome = readStableArtifact(
      path,
      1024,
      controller.signal,
      {
        lstat: (selected) => lstat(selected, { bigint: true }),
        open: async () => file,
        createReadStream: openSource,
      },
      scope,
    ).then(
      (value) => {
        settled = true;
        return { value };
      },
      (error: unknown) => {
        settled = true;
        return { error };
      },
    );
    try {
      await readingStarted;
      controller.abort();
      await descriptorInvalidated;
      expect(file.fd).toBe(-1);
      expect(settled).toBe(false);
      expect(source?.destroyed).toBe(true);
      expect(source?.closed).toBe(true);
      finishClose?.();
      await vi.waitFor(() => expect(settled).toBe(true), { timeout: 500 });
      expect(await outcome).toMatchObject({ error: { reason: "cancelled" } });
      expect(closeSpy).toHaveBeenCalledTimes(1);
      if (rejectClose) {
        expect(await outcome).toMatchObject({
          error: {
            cleanup: { reason: closeFailure.message, resources: [path] },
          },
        });
        expect(scope.hasPending).toBe(true);
        await expect(scope.close()).rejects.toMatchObject({
          cleanup: { reason: closeFailure.message, resources: [path] },
        });
        expect(closeSpy).toHaveBeenCalledTimes(1);
      } else {
        expect(scope.hasPending).toBe(false);
      }
      expect(source?.closed).toBe(true);
    } finally {
      finishClose?.();
      source?.destroy();
      await outcome;
      await scope.close().catch(() => undefined);
      closeSpy.mockRestore();
      await nativeClose();
    }
  },
);

it.each([false, true])(
  "keeps a source read error separate from the actual descriptor close result: %s",
  async (rejectClose) => {
    const root = await createTestTempDirectory("rea-stable-read-error-");
    const path = join(root, "source");
    await writeFile(path, "selected bytes");
    const file = await open(path, "r");
    const nativeClose = file.close.bind(file);
    const readFailure = Object.assign(new Error("synthetic source read EIO"), {
      code: "EIO",
    });
    const closeFailure = new Error("separate actual close failure");
    let source: ReadStream | undefined;
    let releaseClose: (() => void) | undefined;
    const closeResult = new Promise<void>((resolve) => {
      releaseClose = resolve;
    });
    let startedClose: (() => void) | undefined;
    const closing = new Promise<void>((resolve) => {
      startedClose = resolve;
    });
    let restoreRead: () => void = () => undefined;
    const openSource: NonNullable<
      StableArtifactFileSystem["createReadStream"]
    > = (selected, options) => {
      if (options.fs?.read === undefined)
        throw new Error("Expected the owned stream adapter");
      const fault = vi
        .spyOn(options.fs, "read")
        .mockImplementation((...args: unknown[]) => {
          const callback = args[5];
          if (typeof callback !== "function")
            throw new Error("Expected native read callback");
          Reflect.apply(callback, undefined, [readFailure, 0, args[1]]);
        });
      restoreRead = () => fault.mockRestore();
      source = createReadStream(selected, options);
      return source;
    };
    const closeSpy = vi.spyOn(file, "close").mockImplementation(async () => {
      expect(source?.closed).toBe(true);
      expect(file.fd).toBeGreaterThanOrEqual(0);
      await nativeClose();
      startedClose?.();
      await closeResult;
      if (rejectClose) throw closeFailure;
    });
    const scope = new ArtifactResourceScope();
    let settled = false;
    const outcome = readStableArtifact(
      path,
      1024,
      undefined,
      {
        lstat: (selected) => lstat(selected, { bigint: true }),
        open: async () => file,
        createReadStream: openSource,
      },
      scope,
    ).then(
      (value) => {
        settled = true;
        return { value };
      },
      (error: unknown) => {
        settled = true;
        return { error };
      },
    );
    try {
      await closing;
      expect(source?.errored).toBe(readFailure);
      expect(settled).toBe(false);
      releaseClose?.();
      if (rejectClose) {
        expect(await outcome).toMatchObject({
          error: {
            reason: "io",
            cause: { cause: readFailure },
            cleanup: { reason: closeFailure.message, resources: [path] },
          },
        });
        await expect(scope.close()).rejects.toMatchObject({
          cleanup: { reason: closeFailure.message, resources: [path] },
        });
      } else {
        expect(await outcome).toEqual({ error: readFailure });
        expect(scope.hasPending).toBe(false);
      }
      expect(closeSpy).toHaveBeenCalledTimes(1);
    } finally {
      releaseClose?.();
      source?.destroy();
      await outcome;
      await scope.close().catch(() => undefined);
      restoreRead();
      closeSpy.mockRestore();
      await nativeClose();
    }
  },
);
