## Verdict: APPROVE_WITH_NITS

## Critical

None. The plan explicitly prevents claims of:

- all-backlog completion;
- native GA;
- RALPH-2 completion;
- M1-NATIVE-FAM completion;
- phases 4–13 completion.

Hexyl is correctly measured as the `reveng analyze` subject binary, not invoked as a dependency whose absence produces `tool_absent`.

## Important

- Define exact closure predicates for M0 and DF-5. Mark them `done` only if their existing backlog acceptance criteria are fully satisfied—not merely because this wave adds related evidence. Otherwise use `partial`.
- Make the non-closure safeguards executable invariants: RALPH-2 and M2 remain open, M1-NATIVE-FAM remains open with `required != true`, phases 4–13 remain open, and T3 remains parked.
- DF-5’s test must not imply that `status=completed` plus semantic keys proves correctness or native GA. It should prove only the documented reporting contract and explicitly require non-GA/preview attribution.
- Pin the evidence to binary identity: the probe result should record the subject’s SHA-256 and resolved path, matching the generated provenance manifest.
- Specify timeout semantics: a process killed at the 120-second budget must be recorded as `timeout`, never `completed` or generic failure.

## Minor

- Replace “skip or tool_absent OK” with explicit expected outcomes per test. CI absence may be a loud skip for local-ELF tests, while synthetic contract tests should still run and pass.
- Clarify that the build script generates the checksum/provenance file; documentation should not require manually maintained hashes.
- Ensure “latest + one stamp” means exactly one committed timestamped result and that stale stamps are rejected.
- `verify_ga baseline+ga` should be described as dogfooding a command/reporting path, not evidence that GA status has been achieved.

## Must-fix (if REJECT)

Not applicable.

RECOMMENDED: APPROVE_WITH_NITS
