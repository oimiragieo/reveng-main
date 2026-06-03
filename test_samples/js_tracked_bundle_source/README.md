# Tracked JS bundle — source

Multi-file TypeScript used to produce the **checked-in** esbuild bundle under `../js_tracked_bundle_artifact/`.

- **Rebuild artifact + manifest:** from repo root, `make js-tracked-bundle-build` or `python scripts/build_tracked_js_bundle.py`
- **Verify hashes only:** `make js-tracked-bundle-verify`
- **`node_modules/`** is gitignored; run `npm install` via the build script when refreshing the bundle.

Pinned toolchain: `esbuild@0.21.5` (see `package.json` / `package-lock.json`).
