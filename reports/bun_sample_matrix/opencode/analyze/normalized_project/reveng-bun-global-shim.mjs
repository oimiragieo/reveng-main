import { fileURLToPath } from "url";
import { spawnSync } from "child_process";

const existingBun = globalThis.Bun ?? {};

function runShellCommand(command) {
  const shell = process.platform === "win32" ? "cmd.exe" : "/bin/sh";
  const shellArgs = process.platform === "win32" ? ["/d", "/s", "/c", command] : ["-lc", command];
  const result = spawnSync(shell, shellArgs, { encoding: null });
  return {
    stdout: Buffer.from(result.stdout ?? []),
    stderr: Buffer.from(result.stderr ?? []),
    exitCode: result.status ?? 1,
  };
}

function dollar(strings, ...values) {
  const command = String.raw({ raw: strings }, ...values);
  return {
    quiet() {
      return Promise.resolve(runShellCommand(command));
    },
  };
}

function locateCommand(command) {
  const locator = process.platform === "win32" ? "where" : "which";
  const result = spawnSync(locator, [command], { encoding: "utf8" });
  if (result.status !== 0) {
    return null;
  }
  const firstLine = result.stdout.split(/\r?\n/, 1)[0]?.trim();
  return firstLine || null;
}

const bunShim = {
  ...existingBun,
  $: existingBun.$ ?? dollar,
  env: existingBun.env ?? process.env,
  fileURLToPath: existingBun.fileURLToPath ?? fileURLToPath,
  which: existingBun.which ?? locateCommand,
};

globalThis.Bun = bunShim;
export default bunShim;
export const $ = bunShim.$;
export const env = bunShim.env;
export const which = bunShim.which;
export const bunFileURLToPath = bunShim.fileURLToPath;
