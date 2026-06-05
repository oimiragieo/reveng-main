const fs = require("fs");

function writeGreeting(name) {
  fs.writeFileSync("sample_bundle_output.txt", `hello ${name}\n`, "utf8");
}

module.exports = { writeGreeting };
