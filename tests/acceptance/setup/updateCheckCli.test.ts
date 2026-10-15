import {
  access,
  cp,
  mkdir,
  readFile,
  symlink,
  writeFile,
} from "node:fs/promises";
import { delimiter, dirname, join, resolve } from "node:path";

import { expect } from "vitest";

import { PRODUCT_IDENTITY } from "../../../src/identity.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

cliTest(
  "checks an isolated global installation without installing or changing integrations",
  async ({ processes }) => {
    const directory = await createTestTempDirectory("rea-update-check-");
    const home = join(directory, "home");
    const prefix = join(directory, "prefix");
    const globalRoot = join(prefix, "lib/node_modules");
    const packageRoot = join(globalRoot, PRODUCT_IDENTITY.packageName);
    const project = join(directory, "project");
    const bin = join(directory, "bin");
    const log = join(directory, "npm-invocations.jsonl");
    const unexpected = join(directory, "unexpected-npm-command");
    const configuration = join(home, ".codex/config.toml");
    const originalConfiguration = 'model = "caller-model"\n';
    const projectManifest = '{"private":true}\n';
    const nextVersion = "9999.0.0";
    await mkdir(packageRoot, { recursive: true });
    await mkdir(project);
    await mkdir(bin);
    await mkdir(dirname(configuration), { recursive: true });
    await writeFile(configuration, originalConfiguration);
    await writeFile(join(project, "package.json"), projectManifest);
    await cp(resolve("dist"), join(packageRoot, "dist"), { recursive: true });
    await cp(resolve("scripts"), join(packageRoot, "scripts"), {
      recursive: true,
    });
    await cp(resolve("package.json"), join(packageRoot, "package.json"));
    await symlink(
      resolve("node_modules"),
      join(packageRoot, "node_modules"),
      process.platform === "win32" ? "junction" : "dir",
    );
    const packageManifest = await readFile(join(packageRoot, "package.json"));
    const recorder = join(bin, "record-npm.mjs");
    const recordingSource = [
      'import { appendFileSync, writeFileSync } from "node:fs";',
      "const args = process.argv.slice(2);",
      `appendFileSync(${JSON.stringify(log)}, JSON.stringify({ args, cwd: process.cwd() }) + "\\n");`,
      `if (JSON.stringify(args) === '["root","--global"]') console.log(${JSON.stringify(globalRoot)});`,
      `else if (JSON.stringify(args) === '["prefix","--global"]') console.log(${JSON.stringify(prefix)});`,
      `else if (args[0] === "view") console.log(JSON.stringify(${JSON.stringify(nextVersion)}));`,
      `else { writeFileSync(${JSON.stringify(unexpected)}, JSON.stringify(args)); process.exitCode = 88; }`,
      "",
    ].join("\n");
    await writeFile(recorder, recordingSource);
    if (process.platform === "win32")
      await writeFile(
        join(bin, "npm.cmd"),
        `@"${process.execPath}" "${recorder}" %*\r\n`,
      );
    else
      await writeFile(
        join(bin, "npm"),
        `#!/usr/bin/env node\n${recordingSource}`,
        {
          mode: 0o755,
        },
      );

    const result = await processes.run(
      process.execPath,
      [join(packageRoot, "scripts/rea.mjs"), "update", "--check", "--json"],
      {
        cwd: project,
        env: {
          PATH: `${bin}${delimiter}${process.env.PATH ?? ""}`,
          HOME: home,
          USERPROFILE: home,
          TMPDIR: directory,
          TURBO_TELEMETRY_DISABLED: "1",
          DO_NOT_TRACK: "1",
          ...(process.platform === "win32"
            ? {
                SystemRoot: process.env.SystemRoot,
                TEMP: directory,
                TMP: directory,
              }
            : {}),
        },
      },
    );

    expect(result.exitCode, result.stdout || result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({
      status: "available",
      currentVersion: PRODUCT_IDENTITY.packageVersion,
      latestVersion: nextVersion,
      installMethod: "npm",
      installation: { manager: "npm", prefix, packageRoot },
      command: [
        "npm",
        "install",
        "--global",
        "--ignore-scripts",
        "--prefix",
        prefix,
        `${PRODUCT_IDENTITY.packageName}@${nextVersion}`,
      ],
    });
    const invocations = (await readFile(log, "utf8"))
      .trim()
      .split("\n")
      .map((line): unknown => JSON.parse(line));
    expect(invocations).toEqual([
      { args: ["root", "--global"], cwd: project },
      { args: ["prefix", "--global"], cwd: project },
      {
        args: [
          "view",
          "--global",
          "--prefix",
          prefix,
          PRODUCT_IDENTITY.packageName,
          "dist-tags.latest",
          "--json",
          "--fetch-retries=0",
          "--fetch-timeout=10000",
        ],
        cwd: project,
      },
    ]);
    await expect(access(unexpected)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readFile(configuration, "utf8")).toBe(originalConfiguration);
    expect(await readFile(join(project, "package.json"), "utf8")).toBe(
      projectManifest,
    );
    expect(await readFile(join(packageRoot, "package.json"))).toEqual(
      packageManifest,
    );
    await expect(access(`${configuration}.rea.backup`)).rejects.toMatchObject({
      code: "ENOENT",
    });
  },
);
