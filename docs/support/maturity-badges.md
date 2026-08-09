# Maturity badges

Every feature-oriented REVENG doc page should open with a **maturity badge** so juniors know what they can trust.

## Vocabulary

| Badge | Meaning | Typical source |
| --- | --- | --- |
| **supported** | Documented workflow is customer-safe for the stated scope | `docs/support_matrix.json` `status: supported` |
| **limited** | Usable with known gaps (often needs external tools like Ghidra) | matrix `limited` |
| **preview** | Product is beta / public preview overall; behavior can still harden | package `4.0.0` beta |
| **experimental** | Present and watermarked; may change, break, or be removed | matrix `experimental` |
| **unsupported** | This surface explicitly refuses or ignores the capability | MCP/API honesty responses |
| **fixture_only** | Sample proves CLI byte-stability only — **not** analyze GA | `test_samples/native/`, DF-5 |

## How to use on a page

```markdown
> **Maturity:** supported (app reverse engineering) · preview (product overall)
>
> Trust: adapter outputs + validation/evidence fields. Do not treat fixture samples as native GA.
```

## Rules

1. Prefer the matrix over marketing language.
2. Never invent success percentages.
3. If code returns `unsupported`, the docs must say **unsupported**, not “coming soon” as if it works.
4. `fixture_only` and process `completed` are **not** native GA (see [Honesty rules](honesty-rules.md)).

## Related

- [Support matrix](support-matrix.md)
- [Honesty rules](honesty-rules.md)
- Machine SoT: [`../support_matrix.json`](../support_matrix.json)
