#!/usr/bin/env node

import { writeGreeting } from "../lib/greet";

export function main(argv: string[] = process.argv): void {
  const flag = argv.find((value) => value.startsWith("--name="));
  const name = flag ? flag.split("=")[1] : "world";
  writeGreeting(name);
}

if (require.main === module) {
  main();
}
