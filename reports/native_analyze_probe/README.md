# Native analyze probe evidence

## Multi-result contract

Release evidence for a probe run is **exactly**:

1. `latest.json` — canonical multi-result report for the directory
2. One timestamped sibling `20*.json` (UTC stamp, e.g. `2026-08-06T035133Z.json`)

Those two files must be **byte-identical**. Any extra `20*.json` stamp, a missing
stamp, a missing `latest.json`, or a byte mismatch is a hygiene failure
(`tests/unit/test_evidence_dir_hygiene.py`).

Keep alongside them (not stamps): this README, optional `wave_a_job.json`, and
`runs/` job output dirs. Do not treat those as corroborating stamps.

Synthetic/`true`-command runs and pre-v1.1 reports that mislabeled nonzero exits
as `completed` must not be retained here.

## Job / result shape

A Wave A job file lists one or more results (`id`, `binary`, `analyze_cmd`,
`timeout_s`). The written report carries a `results` array. Each result has its
own `status` / `measured` / `reason` / `semantic` object.

Notable reason class:

- `tool_absent:<name>` — the analyze executable was not found (`shutil.which`
  miss and path is not an existing file). This is **not** a timed hexyl success
  and does **not** close R-HEX-1; it only records that the tool was unavailable.

Process `completed` is not native GA success. Semantic fields on executed runs
attribute whether an analysis report appeared under that result's fresh
`job_output_dir`.

## Redaction rules (stdout / stderr tails)

Before truncating tails to 2000 characters (stdout and stderr independently),
sanitize lines matching (case-insensitive):

```text
(?i)(api[_-]?key|token|authorization|password)\s*[:=]
```

Do not commit secrets in tracked probe JSON. If a tail cannot be sanitized
safely, omit or replace the offending line rather than shipping credentials.
