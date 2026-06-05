# REVENG JavaScript Module

JavaScript reverse-engineering and deobfuscation tooling under active development.

## Current Position

- Package version in this repo is `4.0.0`, not a separate verified `6.0.0` product line.
- The module is useful for bundle recovery, normalization, malware-oriented inspection, and optional deeper deobfuscation.
- Some deeper stages depend on optional external tools such as `webcrack` and `prettier`.
- Broad claims like "complete" or "most comprehensive" are not currently backed by a tracked corpus in this checkout.

## Practical Entry Points

```bash
reveng-js --help
reveng-js reverse-engineer-bundle path/to/cli.js -o analysis_js

# Optional deeper pass
reveng-js reverse-engineer-bundle path/to/cli.js -o analysis_js --run-deobfuscator
```

## What Works Well

- bundle-oriented inspection and normalization
- topic-by-topic `SPECS` generation
- optional use of the existing deobfuscator
- malware signal extraction and artifact generation

## What Still Needs Verification

- deobfuscation quality across a real tracked corpus
- end-to-end success claims for all advertised pipeline stages
- equivalence or semantic-preservation guarantees after deep transformation

## Related Docs

- [System Paper](../../../docs/architecture/reveng-system-paper.md)
- [App Reverse Engineering TDD Plan](../../../docs/architecture/app-reverse-engineering-tdd-plan.md)
