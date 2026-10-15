import type { UpdateResult } from "./Update.js";

/** Whether the update or availability check failed. */
export const isUpdateFailure = (result: UpdateResult): boolean => {
  if (result.cleanupFailure !== undefined) return true;
  const status = result.status;
  switch (status) {
    case "current":
    case "available":
    case "updated":
      return false;
    case "failed":
      return true;
    default: {
      const exhaustive: never = status;
      throw new TypeError(
        `Unhandled update result status: ${String(exhaustive)}`,
      );
    }
  }
};
