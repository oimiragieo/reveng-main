import fs from "node:fs";

export function writeGreeting(name: string): void {
  fs.writeFileSync("sample_tsx_output.txt", `hello ${name}\n`, "utf8");
}
