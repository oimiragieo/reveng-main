# How to: Generate/scan YARA and use VirusTotal helpers

> **Maturity:** preview · depends on local `yara-python` / YARA rules and VirusTotal API configuration
>
> These helpers sit beside supported triage; they are **not** a substitute for [app reverse-engineer](../../tutorials/analyst/02-app-reverse-engineer.md) quality grades. Do not invent detection percentages.

## Goal

Generate or scan YARA rules against a binary, and optionally look up or submit a sample via VirusTotal CLI helpers — with org-policy awareness.

## Prerequisites

- Working `reveng` CLI — [Install and triage](../../tutorials/analyst/01-install-and-triage.md)
- For YARA commands: `yara-python` installed (`pip install yara-python` if missing)
- For VT: API key via `--api-key` or the environment/config your build expects (never commit keys)
- Authorization before **submitting** any sample to a third party

## Steps

### Generate a YARA rule

```bash
reveng generate-yara path/to/sample.exe \
  --rule-name SuspectedFamily \
  --output suspected_family.yar
```

Optional: `--analysis-results` pointing at prior analysis JSON.

### Scan with rules

```bash
reveng scan-yara path/to/sample.exe --rules-dir path/to/rules/
# or a single file:
reveng scan-yara path/to/sample.exe --rule-file suspected_family.yar
```

### VirusTotal lookup

The CLI argument is a **binary path** (hash lookup flows derive from the file), not a bare hash string:

```bash
reveng vt-lookup path/to/sample.exe
reveng vt-lookup path/to/sample.exe --api-key "$VT_API_KEY"
```

### VirusTotal submit (policy-gated)

```bash
reveng vt-submit path/to/sample.exe --api-key "$VT_API_KEY"
# optional wait for analysis:
reveng vt-submit path/to/sample.exe --api-key "$VT_API_KEY" --wait
```

Confirm with `reveng vt-lookup --help` / `vt-submit --help` for current flags.

## Expected outputs

| Command | Expected |
| --- | --- |
| `generate-yara` | Rule text on stdout and/or `--output` file |
| `scan-yara` | Match report for the supplied rules |
| `vt-lookup` | VT metadata / detections for the sample |
| `vt-submit` | Submission receipt; optionally waited analysis |

Treat generated rules as **draft** hunting aids, not SOC-ready signature packs.

## Failure modes

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| Import / install hint for yara | Missing `yara-python` | Install dep; re-run |
| VT auth errors | Missing/invalid API key | Pass `--api-key` or configure env |
| Empty / weak YARA | Thin analysis input | Run `analyze` first; pass `--analysis-results` |
| Accidental sample leak | Used `vt-submit` without approval | Stop; follow org policy |

## Related

- [Triage a PE](triage-pe.md)
- [Honesty rules](../../support/honesty-rules.md)
- [Support matrix](../../support/support-matrix.md)
- [CLI reference](../../reference/cli.md)
