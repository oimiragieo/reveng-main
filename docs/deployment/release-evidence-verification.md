# Release Evidence Verification

Use this guide to verify a REVENG release beyond “CI was green.”

## What To Review

- `reports/ga_readiness_baseline.json`
- `reports/ga_readiness_target.json`
- `reports/release_report.json`
- `reports/release_report.md`
- `reports/skip_inventory.json`
- `reports/skip_inventory.md`
- `dist/reveng-release-evidence.tar.gz`

## Minimum Checks

- Confirm `release_report.json` shows `ship_status: ready`.
- Confirm `ga_readiness_target.json` shows `overall_status: pass`.
- Confirm the strict GA report uses the strict `.ga.json` inputs for app corpus, source benchmarks, and Bun matrix.
- Confirm the skip inventory matches the intended support policy for the release.

## Verify GitHub Attestations

GitHub’s current attestation flow is documented in the official artifact attestation docs and the `gh attestation` CLI manuals.

Example verification flow:

```bash
gh attestation verify dist/reveng-release-evidence.tar.gz --repo <owner>/<repo>
gh attestation verify dist/<artifact-name> --repo <owner>/<repo>
```

What to check:

- the attestation verification succeeds
- the subject digest matches the release artifact you downloaded
- the attestation points to the expected repository and workflow
- the workflow run corresponds to the release candidate or release tag you approved

## Verify Evidence Consistency

- `release_report.json` should reference the same readiness and corpus artifacts included in the evidence bundle.
- `skip_inventory.json` should explain any environment-gated or optional lanes that were not exercised in the release environment.
- The support matrix in `docs/support_matrix.json` must align with the workflows described in the release notes.

## If Verification Fails

- Do not market the build as GA.
- Re-run the strict GA path on the candidate commit.
- Regenerate the release report and evidence bundle.
- Record the failure and remediation in internal release notes.
