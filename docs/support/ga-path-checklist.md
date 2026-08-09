# GA-ish analyst path checklist

> **Maturity:** preview product · checklist for the **supported** customer surface
>
> Use this one-pager after the dual-door tutorials.

## Do this

1. [ ] Install + `reveng --help` works ([tutorial](../tutorials/analyst/01-install-and-triage.md))
2. [ ] Run `reveng triage …` on a sample (supported `cli_triage`)
3. [ ] Run `reveng reverse-engineer-app …` on JS **or** JVM **or** Python **or** .NET ([tutorial](../tutorials/analyst/02-app-reverse-engineer.md))
4. [ ] Open outputs and find validation grade + one evidence item ([reading outputs](../tutorials/analyst/03-reading-outputs.md))
5. [ ] Confirm you used the **App RE** grade ladder, not VRL ([grades](reading-validation-grades.md))
6. [ ] Skim [Support matrix](support-matrix.md) so you know what is limited/experimental

## Do not claim yet

- [ ] Native PE/ELF recompile without Ghidra is GA
- [ ] `generate-exploit` is production-ready
- [ ] Fixture native samples prove analyze GA
- [ ] Invented “95%+” success rates

## Related

- [Honesty rules](honesty-rules.md)
- [Maturity badges](maturity-badges.md)
