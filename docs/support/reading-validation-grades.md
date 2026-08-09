# Reading validation grades

> **Maturity:** preview · **critical for trust**
>
> REVENG has **two different grade ladders**. Mixing them is a common junior mistake.

## Ladder A — App reverse engineering

Defined in `src/reveng/app_reverse_engineering/contracts.py` (`build_validation_summary`).

| Grade | Plain meaning |
| --- | --- |
| `evidence_backed` | Strong recovery: sources + enough topic evidence (and/or JS behavior promotion) |
| `partial_recovery` | Some sources + at least one topic evidence item |
| `structure_only` | Artifacts / topic crumbs; little or no recovered source |
| `packaging_only` | Mostly packaging / empty recovery |

**JS promotion:** some `partial_recovery` / `structure_only` results can promote to `evidence_backed` when behavior probes pass (tier ≥ 2 + syntax ok).

Look at accompanying **evidence** and **provenance** fields — the grade is a summary, not a proof by itself.

## Ladder B — VRL (Verified Recompilation Loop)

Defined in `src/reveng/verification/models.py` (`VALIDATION_GRADE_LADDER`).

Rough climb (low → high):

`unknown` → `analysis_only` → `compile_only` → `structural_candidate` → `launches_but_divergent` → `partial_equivalence` → `behavior_matched` → `source_reconstruction_match` → `evidence_backed`

VRL grades answer: “Did decompile → compile → differential verify (→ LLM refine) converge?”

## Do not confuse

| If you see… | It means… | It does **not** mean… |
| --- | --- | --- |
| App RE `evidence_backed` | Adapter recovery looks well evidenced | Native PE is GA / VRL converged |
| VRL `behavior_matched` | Oracle I/O matched for seeds | App SPECS quality is high |
| Process exit 0 / `completed` | Process finished | Native analyze GA (DF-5) |

## Related

- [Honesty rules](honesty-rules.md)
- Explanation: [Result contracts](../explanation/result-contracts.md)
- Explanation: [VRL and verification](../explanation/vrl-and-verification.md)
