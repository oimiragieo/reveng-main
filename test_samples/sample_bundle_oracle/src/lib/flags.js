function parseNameFlag(argv) {
  const flag = argv.find((value) => value.startsWith("--name="));
  return flag ? flag.split("=")[1] : null;
}

module.exports = { parseNameFlag };
