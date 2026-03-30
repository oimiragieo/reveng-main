# Bun Escalation Paths and Known Limits

This guide explains when REVENG's Bun-specific static workflow is sufficient, when it is only partially sufficient, and when you should escalate to runtime observation, dump reconstruction, or manual analyst review.

## Philosophy

REVENG treats Bun executable recovery as an evidence-driven pipeline:

1. recover the cleanest static artifact available
2. normalize it in a reproducible way
3. compare normalization against the original artifact
4. verify the rebuild workspace and generated SEA artifact
5. escalate only when the evidence says static recovery is no longer enough

The toolkit should not silently overclaim source fidelity.

## Static Workflow Boundaries

The current Bun pipeline is strongest when the sample provides:

- a recognizable `.bun` section
- Bun trailer or virtual path markers
- directly recoverable `// @bun` JavaScript
- parseable Bun module metadata
- enough source structure to infer dependencies and runtime features

The workflow is weaker when the sample relies on:

- runtime-only unpacking
- dynamic import resolution or loader-heavy startup
- partial or custom module layouts
- aggressive self-modification or opaque bootstrap code
- missing or low-value BunFS metadata

## Use the Report Surfaces as the Escalation Trigger

`runtime_escalation` is the compact contract that rolls the underlying evidence into a single recommendation. Use it first, then drop into the lower-level `native_stub.runtime_readiness` and `native_stub.dump_guidance` details when you need exact breakpoint or dump targets.

`equivalence_validation` is the build-side companion contract. It does not replace `runtime_escalation`; it tells you how strong the current equivalence claim is after normalization and SEA packaging.

### Stay in static mode when these are healthy

- `runtime_escalation.status` is `static_sufficient`
- `equivalence_validation.equivalence_level` is `artifact_identity_candidate` or `semantic_candidate`
- `report_severity.level` is `low` or a mild `medium`
- `differential_validation.status` is `pass`
- `sea_build.verification.status` is `pass`
- `native_stub.dump_guidance.recommended` is `false`
- `native_stub.runtime_readiness` is present, but only offers ordinary first-hop breakpoints

### Escalate when these surfaces turn noisy

- `runtime_escalation.recommended` is `true`
- `equivalence_validation.equivalence_level` is `structural_candidate` or `not_equivalent`
- `report_severity.level` is `high` or `critical`
- `differential_validation` reports dropped preserved runtime features
- `sea_build.verification` fails on output generation, dependency alignment, or shim continuity
- `native_stub.dump_guidance.recommended` is `true`
- `native_stub.startup_classification` is `runtime_bootstrap_likely`
- `native_stub.startup_graph.truncated` is `true` and handoff evidence is strong

## Escalation Ladder

### 1. Targeted breakpointing

Use `native_stub.runtime_readiness.breakpoints` first.

Prioritize:

- entrypoint
- TLS callbacks
- import/IAT-backed startup callsites
- startup targets that land in `.text` or `.bun`

Use this stage when the handoff is visible but static control flow is still ambiguous.

### 2. Memory dumping near Bun handoff

Use `native_stub.runtime_readiness.dump_points` and `native_stub.dump_guidance.actions` when startup actually reaches `.bun`-backed nodes.

Use this stage when:

- the Bun payload appears to be materialized or transformed at runtime
- startup targets reach `.bun`, but recovered static artifacts remain incomplete
- rebuilt output diverges from the source-recovery story in a way static checks cannot explain

### 3. Import reconstruction

Escalate here when:

- startup edges resolve through IAT/import callsites
- loader-style imports dominate the startup profile
- the sample appears to resolve critical APIs late

This is especially relevant when `dump_guidance.actions[*].kind` includes `import_reconstruction`.

### 4. Manual source recovery refinement

Before claiming success, review:

- `normalized_project.semantic_checks`
- `normalized_project.postprocessing_hooks`
- `differential_validation.expected_rewrites`
- `differential_validation.missing_runtime_features`

Use recommended post-processing tools only as additive steps. The report should remain the source of truth about what was inferred versus what was manually improved later.

## Known Limits

### Static BunFS recovery is layout-sensitive

REVENG currently supports observed module-record layouts and a conservative fallback path scan. If a sample uses a different internal layout or strips the strongest path markers, recovery may stop at a partial artifact set.

### Rebuild verification is not runtime equivalence

`sea_build.verification` proves the workspace is structurally coherent and the SEA artifact was generated, but it does not prove behavior is identical to the original sample.

### Differential validation is semantic, not byte-for-byte

Normalized output is expected to differ when REVENG applies known Bun-to-Node rewrites. A content delta is not automatically a regression; missing preserved runtime features is the real warning sign.

### Real samples may require mixed static/dynamic workflows

If the sample resembles a loader, trampoline-heavy bootstrapper, or runtime-transformed payload, the correct next step is controlled observation, not increasingly speculative static rewriting.

## Recommended Analyst Loop

1. Run `analyze` and inspect `bun_analysis.json`
2. Review `report_severity`, startup triage, and dump guidance
3. Review `runtime_escalation` and follow `next_steps` in priority order
4. Normalize and inspect semantic checks plus post-processing hooks
5. Run `recompile` and inspect `bun_sea_build.json`
6. Compare `differential_validation` and `sea_build.verification`
7. Escalate to breakpoints or dumps only if the report surfaces justify it
8. Preserve every artifact and report path for reproducibility

## Related Docs

- [Bun Executable Reversing](../user-guide/bun-reversing.md)
- [CLI Usage](../user-guide/cli-usage.md)
- [Architecture Overview](overview.md)
