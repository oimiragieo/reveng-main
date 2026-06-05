#!/usr/bin/env node

const fs = require("fs");

function main() {
  const flag = process.argv.find((value) => value.startsWith("--name="));
  const name = flag ? flag.split("=")[1] : "world";
  fs.writeFileSync("sample_bundle_output.txt", `hello ${name}\n`, "utf8");
}

if (require.main === module) {
  main();
}
