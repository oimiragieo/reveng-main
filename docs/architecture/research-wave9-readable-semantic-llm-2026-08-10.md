# Research — Wave 9 readable + semantic + AST-chunked LLM (2026-08-10)

Builds on Wave 8.5 defrag (~52% Claude oracle). Addresses the three roadblocks
called out in operator analysis.

## Roadblocks → toolkit answers

| Roadblock | Wrong approach | What we do |
|-----------|----------------|------------|
| Context window | Dump 24MB beautified into one LLM | **AST/module chunk** digests only (`llm_digest`, max N modules); industry: [humanify](https://github.com/jehna/humanify), [re-Script](https://github.com/roeintheglasses/re-Script), [deobfuscate-mcp](https://github.com/MadeByTokens/deobfuscate-mcp-server) |
| String concealment | Hope LLM guesses `lookupArray(0x4b)` | **webcrack / synchrony / deobfuscate-js** first (optional `--run-external`); hermetic path uses plaintext anchors still visible |
| Control-flow flattening | Ask LLM to trace giant switch/while | **webcrack CFF unflatten** (expert tools beat GPT-4o on CFF benchmarks per deobfuscate-js table); wakaru after, not before |

## Industry chain (Exa)

```
bundle → webcrack (deobfuscate CFF/string-array)
      → wakaru (unminify / unpack)
      → humanify/LLM rename on **per-module** AST chunks
```

Wakaru docs: deliberately **not** a deobfuscator — strip with webcrack first.

## Hermetic Wave 9 (CI)

| Stage | Module | Role |
|-------|--------|------|
| Beautify-lite | `readable_normalize` | `void 0`/`!0`/`!1` + line breaks |
| Semantic digest | `semantic_digest` | API/HTTP/DOM/CFF fingerprint tags (no LLM) |
| Defrag | `iterative_defrag` | + `semantic_digest` unlock method |
| LLM digest | `llm_digest` | optional; default heuristic stand-in; plug real provider |

## Honesty

- Beautify ≠ understand. Variable names don't matter to an LLM **once** strings/CFF are restored and chunks fit context.
- Claude Bun is mostly **minified**, not obfuscator.io — CFF path may be inert; readable+semantic+defrag still apply.
- R-RALPH-2 / GA stay open. `decoded_exe_claim=false`.
