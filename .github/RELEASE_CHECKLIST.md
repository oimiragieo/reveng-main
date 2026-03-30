# REVENG Release Checklist

Use this checklist before cutting a customer-facing release.

## Product Scope

- Confirm the supported workflows match the current support matrix and docs.
- Remove or clearly mark any experimental claims that are not benchmarked.
- Ensure release notes describe tracked evidence, not aspiration.

## Required Reports

- Run `make app-corpus`
- Run `make verify-ga-baseline`
- Run `make verify-ga-target`
- Run `make skip-inventory`
- Run `python scripts/generate_release_report.py`
- Review `reports/ga_readiness_baseline.json`
- Review `reports/ga_readiness_target.json`
- Review `reports/release_report.json`
- Review `reports/release_report.md`
- Review `reports/skip_inventory.json`
- Review `reports/skip_inventory.md`
- Review `reports/app_reverse_engineering_corpus_report.json`
- Review `reports/source_binary_benchmarks_report.json`
- Review `reports/bun_sample_matrix.json`

## Required Outcomes

- Baseline readiness report status is `pass`
- App reverse-engineering corpus `summary.matrix_status` is `pass`
- Native benchmark report exists and is current
- Bun matrix report exists and is current
- No release-blocking workflow regressions are unresolved

## GA Audit

- Verify the strict GA audit was generated from the strict `.ga.json` inputs
- If the GA audit fails, do not market the release as GA
- Any waiver must be explicit in release notes and internal approval records

## CI / Docs

- CI workflows are green on the release candidate commit
- Docs workflow builds successfully
- Public docs and README wording match the verified platform state
- Skipped lanes are documented and acceptable for the release scope

## Packaging

- Build artifacts pass `python -m build`
- `twine check dist/*` passes
- Release evidence archive is generated and uploaded
- Build artifacts are attested in CI
- Version metadata, changelog, and release notes are aligned

## External Tooling

- Document whether `ilspycmd`, `pyi-archive_viewer`, Ghidra, and Java are required, optional, or unsupported for the release
- Note any environment-aware tests that were skipped on CI

## Final Approval

- Support owner approves the release scope
- Engineering owner approves the readiness reports
- Security owner approves any open waivers or exceptions
