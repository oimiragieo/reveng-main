# Wave 4 research bank — JS recovered-root + generic naming (2026-08-09)

Exa MCP search (accessed **2026-08-09**). Adopt vs defer for REVENG Wave 4.

## Prior art — Bun extract / sourcemap

| Source | URL | Adopt? |
| --- | --- | --- |
| Dissecting Droid: Bun StandaloneModuleGraph + zstd sourcemap sourcesContent | https://0day.gg/blog/dissecting-droid-reversing-bun-executables/ | **Adopt concepts** — when Bun modules embed sourcemaps, prefer original tree recovery; our dogfood 2.1.226 had `sourcemap_size=0` so path is optional |
| bun-unpack | https://github.com/xpcmdshell/bun-unpack | Reference only (don’t vendor) |
| unbun (notes Claude `--bytecode` still embeds JS) | https://github.com/skelpo/unbun | Confirms extract≠bytecode decompile |
| bun-demincer export-key / `MR()` rename | https://github.com/vicnaum/bun-demincer | **Adopt pattern class** — export string keys as rename hints; do not copy their DB/code |
| debun / unbuned | https://github.com/iivankin/debun · https://github.com/vibheksoni/unbuned | Reference |
| Sourcemap Explorer — reconstruct tree from `sources`+`sourcesContent` | https://sme.mapree.dev/how-to/reconstruct-source-code-from-a-sourcemap | **Adopt** path normalize / synthetic skip (Wave 4 sanitize) |
| unmapjs / sourcemap-extract / dl-webapp-sources | https://github.com/atiilla/unmapjs · https://github.com/anandpilania/sourcemap-extract · https://github.com/llllvvuu/dl-webapp-sources | Reference — sibling `.map` + path sanitize; do not vendor |
| Frontend RE via public maps (Claude leak context) | https://www.neerajbhatt.com/blog/reverse-engineering-frontend-source-maps | Legal/context only |

## Prior art — bundle split / demangle

| Source | URL | Adopt? |
| --- | --- | --- |
| webcrack unpack | https://github.com/j4k0xb/webcrack | Optional later; not hard dep Wave 4 |
| wakaru unpack | https://github.com/pionxzh/wakaru | Optional later |
| JSNaughty / Autonym (FSE 2017) | https://cmustrudel.github.io/papers/fse17jsnaughty.pdf | Defer SMT/ML rename |
| AST fingerprinting link dump | https://gist.github.com/0xdevalias/31c6574891db3e36f15069b859065267 | Future symbol scorecard |

## Claude Code map disclosure (legal context only)

| Source | URL |
| --- | --- |
| HN thread | https://news.ycombinator.com/item?id=47584540 |
| InfoQ | https://www.infoq.com/news/2026/04/claude-code-source-leak/ |

**REVENG posture:** do not commit Anthropic recovered trees or full extracted bundles. Operator-local provenance template only.

## What Wave 4 ships vs defers

**Ships:** `output_dir/project/` materialization; source-map→project when present; Bun VFS→project when present; structural export-key hints JSON; tracked-bundle Ralph without `no_recovered_root`.

**Defers:** full Bun binary sourcemap zstd parser; LLM rename; Anthropic-specific modules; Phase 6 / RALPH-2 close; “any claude.exe → full codebase” claims.
