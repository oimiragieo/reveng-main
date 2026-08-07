# REVENG Phase 13 — Blue-ocean / v6.1+ futures (2026-08-07)

> **Authorization:** Phase 13 **only**. **Unauthorized** until Phase 12 stop/go = **go**.
> Prior gate: Phase 4 is currently **partial** — phases 5–13 remain unauthorized.
> **Charter:** [`docs/architecture/scope-c-execution-charter.md`](../../architecture/scope-c-execution-charter.md)
> **Catalog:** [`docs/architecture/scope-c-phase-catalog-contracts.md`](../../architecture/scope-c-phase-catalog-contracts.md)

**Goal:** Dispose blue-ocean / v6.1+ futures honestly — scaffold+tests only where authorized, otherwise `deferred`/`parked`/`wontfix` with rationale. **Never** hollow GA claims.

## SEC sandbox + Track J (hard stop)

- **Any exploit-surface work** (Track J, new generators, CLI paths, watermark relaxation, exploit demos) requires **Phase 10 SEC-1 sandbox proofs** already green.
- Track J exploit product work needs a **separate** stop/go after those proofs — this phase stub does **not** authorize Track J by default.
- Until proofs: keep `SEC-EXP-1` EXPERIMENTAL / non-GA; no expansion.

Cite: [`decision-r-sec-1-sandbox-class.md`](../../architecture/decision-r-sec-1-sandbox-class.md), charter SEC stop gate.

## Tier-3 items — parked disposition (honesty guards only)

| id | title | disposition |
| --- | --- | --- |
| T3-KERNEL | Kernel reverse engineering | **parked** |
| T3-PACKED | Packed/protected binaries depth | **parked** |
| T3-JIT | Self-modifying/JIT outside JS | **parked** |
| T3-ANTI | Malware anti-analysis depth | **parked** |
| T3-GUI | Large GUI-first without eval strategy | **parked** |

Allowed work on T3-*: honesty guards / watermarks / “not claimed” matrix language only. **No** capability builds. Disposition ≠ capability `done`.

## Entry dependencies / research blockers

| Dep | Required state | Source |
| --- | --- | --- |
| Phase 12 stop/go | **go** | catalog |
| Phase 10 SEC proofs | **required before any exploit/Track J slice** | Phase 10 plan |
| REV-COMPILER-ARCH / REV-XARCH / REV-SEMDIFF / REV-NLQ / REV-YARA / REV-ARCH-OWN / REV-SPA / REV-IDE | open | backlog J |
| V6-* futures | open | backlog J / changelogs/v6.0.md |
| T3-* | **parked** | backlog G |

## Exit criteria (evidence predicates)

- [ ] Every Phase 13 backlog row is either measured preview with tracked artifact **or** explicit `deferred`/`parked`/`wontfix` with reconsideration trigger.
- [ ] Honesty guard: claiming T3-* or exploit GA fails a bidirectional packaging/matrix check.
- [ ] If any exploit slice is authorized: SEC-1 four proofs cited + Track J stop/go recorded; else exploit rows stay experimental/non-expanded.
- [ ] No `done` status used for disposition-only closures.
- [ ] CEO/backlog language lists what is preview vs parked.

## Permitted release claim vs forbidden

| Permitted after go | Forbidden |
| --- | --- |
| “Blue-ocean items **dispositioned**; named previews only where measured.” | “Scope C complete”, “v6.1 GA”, T3-* shipped |
| Parked / deferred rationale | Track J / exploit GA without SEC proofs |

## Kill / park / rollback

| Condition | Action |
| --- | --- |
| Exploit work without SEC proofs | **Kill** + revert |
| T3-* treated as done | Rollback to `parked`; fix claims |
| Scaffold without tests claiming product | Park; no GA language |

## Explicit non-goals

Unparking T3-* depth; calendar-driven exploit scaffolding; treating deferred as shipped; re-opening phases 1–12 as “done” via this phase.
