import type { BigIntStats } from "node:fs";
import type { FileHandle } from "node:fs/promises";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it, onTestFinished, vi } from "vitest";

const injected = vi.hoisted(() => ({
  opened: undefined as
    | ((path: unknown, handle: FileHandle) => void)
    | undefined,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    open: async (...args: Parameters<typeof actual.open>) => {
      const handle = await actual.open(...args);
      injected.opened?.(args[0], handle);
      return handle;
    },
  };
});

import { createRustBinaryService } from "../../../src/composition/rust.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";
import { createDeferred } from "../../fixtures/binarySession.js";
import { createRustImage } from "../../fixtures/rust/image.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

it.each(["read", "integrity", "cancellation"] as const)(
  "retains Rust snapshot close ownership after %s and retries it through the composed service",
  async (failure) => {
    const root = await createTestTempDirectory("rea-rust-read-ownership-");
    const path = join(root, "sample.elf");
    await writeFile(path, createRustImage({ format: "elf" }));
    const service = createRustBinaryService();
    const controller = new AbortController();
    const closeFailure = new Error("injected Rust descriptor close failure");
    let descriptor: FileHandle | undefined;
    let attempts = 0;
    const closes: Array<() => Promise<void>> = [];
    injected.opened = (openedPath, handle) => {
      if (openedPath !== path) return;
      descriptor = handle;
      const close = handle.close.bind(handle);
      closes.push(close);
      vi.spyOn(handle, "close").mockImplementation(async () => {
        attempts += 1;
        if (attempts <= (failure === "read" ? 2 : 1)) throw closeFailure;
        return close();
      });
      const big: { stat(options: { bigint: true }): Promise<BigIntStats> } =
        handle;
      const stat = big.stat.bind(handle);
      vi.spyOn(big, "stat").mockImplementation(async (...args) => {
        const metadata = await stat(...args);
        if (failure === "cancellation") controller.abort();
        if (failure === "integrity") metadata.ino += 1n;
        return metadata;
      });
    };
    onTestFinished(async () => {
      injected.opened = undefined;
      await service.close?.().catch(() => undefined);
      vi.restoreAllMocks();
      for (const close of closes) await close();
    });
    const inspected = await service.inspect(
      { path },
      { signal: controller.signal },
    );
    if (inspected.ok) throw new Error("Expected snapshot close failure");
    const projected = projectAnalysisError(inspected.error);
    expect(projected).toMatchObject({ code: "cleanup_incomplete" });
    expect(inspected.error.cleanupResources).toEqual([path]);
    if (failure !== "read")
      expect(projected).toMatchObject({
        details: {
          diagnostics: {
            primary_error: {
              code: failure === "integrity" ? "artifact_changed" : "cancelled",
            },
          },
        },
      });
    expect(descriptor?.fd).toBeGreaterThanOrEqual(0);
    expect(attempts).toBe(1);
    if (failure === "integrity") {
      injected.opened = undefined;
      const retried = await service.inspect({ path });
      if (!retried.ok) throw retried.error;
      expect(retried.value.normalized_result).toMatchObject({
        auditable_metadata: { root_package_index: 1 },
      });
      expect(descriptor?.fd).toBe(-1);
    }
    if (failure === "read") {
      await expect(service.close()).rejects.toMatchObject({
        cleanup: { resources: [path] },
      });
      expect(descriptor?.fd).toBeGreaterThanOrEqual(0);
      expect(attempts).toBe(2);
    }
    await service.close();
    // Closing a FileHandle with an associated ReadStream may re-enter its
    // close method; the retained descriptor's confirmed state is authoritative.
    expect(attempts).toBeGreaterThanOrEqual(failure === "read" ? 3 : 2);
    expect(descriptor?.fd).toBe(-1);
  },
);

it("keeps an unconfirmed invalidated Rust descriptor close sticky through repeated service closure", async () => {
  const root = await createTestTempDirectory("rea-rust-sticky-close-");
  const path = join(root, "sample.elf");
  await writeFile(path, createRustImage({ format: "elf" }));
  const service = createRustBinaryService();
  const closeFailure = new Error(
    "close rejected after descriptor invalidation",
  );
  let descriptor: FileHandle | undefined;
  let close: (() => Promise<void>) | undefined;
  let attempts = 0;
  injected.opened = (openedPath, handle) => {
    if (openedPath !== path) return;
    descriptor = handle;
    const nativeClose = handle.close.bind(handle);
    close = nativeClose;
    vi.spyOn(handle, "close").mockImplementation(async () => {
      attempts += 1;
      await nativeClose();
      throw closeFailure;
    });
    const big: { stat(options: { bigint: true }): Promise<BigIntStats> } =
      handle;
    const stat = big.stat.bind(handle);
    vi.spyOn(big, "stat").mockImplementation(async (...args) => {
      const metadata = await stat(...args);
      metadata.ino += 1n;
      return metadata;
    });
  };
  onTestFinished(async () => {
    injected.opened = undefined;
    await service.close().catch(() => undefined);
    vi.restoreAllMocks();
    await close?.();
  });
  const inspected = await service.inspect({ path });
  if (inspected.ok) throw new Error("Expected invalidation plus close failure");
  expect(projectAnalysisError(inspected.error)).toMatchObject({
    code: "cleanup_incomplete",
    details: { diagnostics: { primary_error: { code: "artifact_changed" } } },
  });
  expect(descriptor?.fd).toBe(-1);
  for (let retry = 0; retry < 2; retry += 1)
    await expect(service.close()).rejects.toMatchObject({
      cleanup: { resources: [path] },
    });
  expect(attempts).toBe(1);
});

it("drains an admitted Rust snapshot before composed service closure and refuses later reads", async () => {
  const root = await createTestTempDirectory("rea-rust-read-drain-");
  const path = join(root, "sample.elf");
  await writeFile(path, createRustImage({ format: "elf" }));
  const service = createRustBinaryService();
  const entered = createDeferred<void>();
  const release = createDeferred<void>();
  let opens = 0;
  let closed = false;
  injected.opened = (openedPath, handle) => {
    if (openedPath !== path) return;
    opens += 1;
    const stat = handle.stat.bind(handle);
    vi.spyOn(handle, "stat").mockImplementation(async (...args) => {
      entered.resolve();
      await release.promise;
      return stat(...args);
    });
  };
  onTestFinished(async () => {
    release.resolve();
    injected.opened = undefined;
    await service.close?.();
    vi.restoreAllMocks();
  });
  const reading = service.inspect({ path });
  await entered.promise;
  const closing = service.close().then(() => {
    closed = true;
  });
  await Promise.resolve();
  expect(closed).toBe(false);
  release.resolve();
  const inspected = await reading;
  if (!inspected.ok) throw inspected.error;
  expect(inspected.value.normalized_result).toMatchObject({
    artifact: { path },
    auditable_metadata: { root_package_index: 1 },
  });
  await closing;
  expect(closed).toBe(true);
  const later = await service.inspect({ path });
  expect(later.ok).toBe(false);
  expect(opens).toBe(1);
});
