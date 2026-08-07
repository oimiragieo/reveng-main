# VRL LLM honesty evidence

Tracked output of `scripts/verify_vrl_llm_honesty.py` for Phase 4 / VRL-LLM-1.

## Contract

* `latest.json` — canonical evidence for the honesty gate.
* `runtime_status` is either `measured` or `could_not_measure` (never a silent pass).
* `measured` requires `min_seeds >= 3`, real ValidationGrade entries, provider
  identity, `ollama_actually_ran: true`, and a failing no-LLM control arm.
* When Ollama is unreachable, stamp `could_not_measure` with an explicit reason
  and keep Phase 4 VRL half open/partial.

See `docs/architecture/evidence-vrl-llm-honesty-phase-04.md` and
`docs/architecture/decision-r-vrl-1-seeds-and-provider.md`.
