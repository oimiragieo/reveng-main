# How to: update the support matrix

> **Maturity:** the matrix document is the **supported** customer boundary
>
> Gates and release scripts read **JSON**. Markdown is the human mirror. If they disagree, fix Markdown (or stop claiming the Markdown status). See [honesty rules](../../support/honesty-rules.md).

## Sources of truth

| Artifact | Role |
| --- | --- |
| `docs/support_matrix.json` | Machine SoT — workflows, `status`, languages, surfaces, notes |
| `docs/support/support-matrix.md` | Human-readable mirror |
| `docs/support/maturity-badges.md` | How to badge other docs |

Consumers (non-exhaustive):

- `scripts/verify_ga_readiness.py`
- `scripts/generate_release_report.py`
- Unit guards under `tests/unit/test_verify_ga_readiness.py`, `test_generate_release_report.py`

## Edit order

1. **Change `docs/support_matrix.json`**
   - Update the correct workflow `id` (`cli_triage`, `app_reverse_engineering`, `ghidra_backed_native_analysis`, `source_binary_reconstruction`, `exploit_generation`, `symbolic_execution`, …).
   - Set `status` to one of the real vocabulary values used in-repo (`supported`, `limited`, `experimental`, …).
   - For app RE language claims, edit the `languages` array — only list languages with registered default adapters and corpus/gate coverage.
2. **Mirror in `docs/support/support-matrix.md`**
   - Same status, surfaces, languages, and caveats.
   - Keep the page’s warning that gates read JSON.
3. **Propagate maturity callouts** on any tutorial / how-to / explanation that stated the old claim.
4. **Run honesty gates** (prefer `/usr/bin/python3.9`):

```bash
python3.9 scripts/verify_ga_readiness.py --profile baseline
python3.9 scripts/verify_ga_readiness.py --profile ga
```

Open the JSON reports those commands cite — a green exit alone is not enough ([honesty rules](../../support/honesty-rules.md)).

## What not to do

- Do not mark native analyze GA because a fixture exists (`fixture_only`).
- Do not move `exploit_generation` off `experimental` without R-SEC-1 sandbox proofs ([Security and exploits](../../explanation/security-and-exploits.md)).
- Do not add a language to JSON before `create_default_framework()` registers it ([Add adapter](add-adapter.md)).
- Do not invent success percentages in notes.

## Related

- [Support matrix](../../support/support-matrix.md)
- [Maturity badges](../../support/maturity-badges.md)
- [Ghidra boundary](../../explanation/ghidra-boundary.md)
- Skill: `.cursor/skills/reveng-release-honesty/SKILL.md`
