const { pathToFileURL } = require("url");
const path = require("path");
const fs = require("fs");
const os = require("os");
const crypto = require("crypto");

function resolveRuntimeRoot() {
  let sea;
  try {
    sea = require("node:sea");
  } catch (_error) {
    return __dirname;
  }
  let assetKeys;
  try {
    assetKeys = typeof sea.getAssetKeys === "function" ? sea.getAssetKeys() : [];
  } catch (_error) {
    return __dirname;
  }
  if (!assetKeys.length) {
    return __dirname;
  }
  const runtimeId = crypto
    .createHash("sha256")
    .update(process.execPath)
    .digest("hex")
    .slice(0, 16);
  const runtimeRoot = path.join(os.tmpdir(), "reveng-sea-runtime", runtimeId);
  for (const assetKey of assetKeys) {
    const targetPath = path.join(runtimeRoot, ...assetKey.split("/"));
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.writeFileSync(targetPath, Buffer.from(sea.getAsset(assetKey)));
  }
  return runtimeRoot;
}

(async () => {
  const runtimeRoot = resolveRuntimeRoot();
  await import(pathToFileURL(path.join(runtimeRoot, "index.mjs")).href);
})();
