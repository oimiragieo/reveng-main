import { greet } from "./lib/greet";

/** CLI-style entry used when the bundle is executed with node. */
export function run(argv: readonly string[]): string {
  const flag = argv.find((value) => value.startsWith("--name="));
  const name = flag ? flag.split("=", 2)[1]! : "tracked";
  return greet(name);
}
