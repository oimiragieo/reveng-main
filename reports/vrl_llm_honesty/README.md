# VRL LLM honesty evidence

Tracked output of `scripts/verify_vrl_llm_honesty.py` for Phase 4 / VRL-LLM-1.

## Current stamp

* `latest.json` / `2026-08-07.json` — **`runtime_status: measured`** (WSL→Windows
  Ollama via `OLLAMA_HOST`; see `docs/architecture/evidence-vrl-llm-honesty-phase-04.md`).
* Dogfood writer: `scripts/dogfood_vrl_llm_honesty.py`.

## Contract

* `latest.json` — canonical evidence for the honesty gate.
* `runtime_status` is either `measured` or `could_not_measure` (never a silent pass).
* `measured` **requires** non-empty `seed_runs` with ≥3 executed rows carrying
  **distinct** non-empty `seed_id`s and valid ValidationGrade values, plus
  provider identity, `ollama_actually_ran: true`, and an **executed** failing
  no-LLM control (`control_arm.executed: true`, `passed: false`,
  `llm_enabled: false`).
* Legacy bare `grades` (even `len(grades) >= 3`) is informational only —
  **grades-only never unlocks** measured / exit 0 (`seed_runs_required`).
* Preferred run-log schema: `seed_runs: [{seed_id, grade, argv, executed}, ...]`
  — one row per declared corpus seed; unrun seeds stay `executed: false`.
* Probe / CNM honor `OLLAMA_HOST` / `REVENG_OLLAMA_HOST` (default
  `http://127.0.0.1:11434/api/tags`). From WSL use the Hyper-V gateway IP, not
  localhost.
* When Ollama is unreachable, stamp `could_not_measure` with
  `control_arm.executed: false` / `passed: null` (no phantom control fail).

See `docs/architecture/evidence-vrl-llm-honesty-phase-04.md` and
`docs/architecture/decision-r-vrl-1-seeds-and-provider.md`.
