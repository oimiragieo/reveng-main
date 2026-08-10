# Wave 5 spike — Bun multi-module unpack feasibility (Tier B gate)

**Status:** spike / not ready — Thinktank demoted Tier B pending this probe.  
**Date:** 2026-08-09

## Question

Can current Bun VFS / `claude.exe` extracts be split into discrete module/function targets for MinHash structural align (astdiff-class Tier B)?

## Observed prior (operator-local)

- Dogfood extract under `/tmp/claude_bun_extract/.../root/src/` was effectively **one** large `entrypoints/cli.js` (~23MB), not a multi-file TS tree.
- Map-era npm package had multi-file `sourcesContent`; native Bun packaging does not ship a matching `.map`.

## Feasibility bar (when re-run)

1. Extract Bun PE → count files under VFS `root/` with JS/TS suffixes.
2. If file_count ≤ 2 and largest file > 5MB → **boundaries unrecoverable for Tier B**; Wave 5 Tier A remains **hints/attribution only** on the exe surface.
3. If file_count ≥ 20 with plausible module paths → re-open Tier B plan.

## Current disposition

**Unrecoverable for Tier B as of last dogfood** (single mega-`cli.js`). Do not schedule MinHash align as the next ship slice. Revisit only after a measured unpack improves module cardinality.

Tier A fingerprint transfer does **not** require this spike to ship.
