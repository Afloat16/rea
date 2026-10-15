import { z } from "incur";
import { resolve } from "node:path";
import { createRustBinaryService } from "../composition/rust.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";

/** Resolve caller paths and inspect embedded Rust dependencies through the shared workflow. */
export const registerRustCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.inspectRustBinary, {
    description:
      "Inspect an embedded cargo-auditable Rust dependency list without target execution",
    args: z.object({
      path: z.string().describe("Local ELF, PE or thin Mach-O image"),
    }),
    run: ({ args }) =>
      withCommandCancellation(async (signal) => {
        const service = createRustBinaryService();
        return await logCliCommand(
          logger,
          CLI_COMMANDS.inspectRustBinary,
          async () =>
            finishAnalysisCommand(
              () => service.inspect({ path: resolve(args.path) }, { signal }),
              service,
              "rust-auditable",
              "inspect_rust_binary",
            ),
        );
      }),
  });
};
