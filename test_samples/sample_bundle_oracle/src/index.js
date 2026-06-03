#!/usr/bin/env node

const { parseNameFlag } = require("./lib/flags");
const { writeGreeting } = require("./lib/output");

function main(argv = process.argv) {
  const name = parseNameFlag(argv) || "world";
  writeGreeting(name);
}

if (require.main === module) {
  main();
}

module.exports = { main };
