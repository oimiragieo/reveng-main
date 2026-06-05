# Reverse-Compilation Master Roadmap

## Purpose

This is the platform-level source of truth for where REVENG is supposed to go.

It exists to answer a broader question than the near-term `hexyl` frontier or the current GA gate:

- what does "working as intended" actually mean for this codebase
- what capabilities must exist before claims about full reverse compilation are credible
- what major tracks have to be completed before layering exploit development and vendor-grade bug reporting on top

This document is intentionally larger in scope than `reveng-world-class-implementation-roadmap.md` and
`reveng-world-class-execution-backlog.md`. Those two documents remain the operational execution surfaces. This
document is the master roadmap.

## North star

Build a reverse-compilation platform that can, for supported target classes:

- ingest arbitrary binaries or JavaScript/npm application artifacts
- recover a structured intermediate representation with provenance and uncertainty
- emit a readable, organized, multi-file reconstructed codebase
- rebuild a behavior-matching artifact or explain the remaining gaps precisely
- validate behavior against the original target automatically
- surface trustworthy findings that can support bug reports and later exploit-development workflows

## What "100%" means

The repository is only at 100% when all of these are true:

1. supported target classes are explicit, versioned, and benchmarked
2. reconstruction output is multi-file, readable, and rebuildable for the supported corpus
3. rebuilt artifacts pass deterministic behavior checks against originals
4. native and JavaScript/npm targets both flow through a common reconstruction contract
5. gaps, shims, uncertainty, and unsupported features are reported explicitly
6. tracked reports, the backlog, the implementation roadmap, and the system paper all match
7. bug-report generation operates on validated findings rather than speculative reconstructed code

That is the standard for "the codebase works as intended." Compilation alone is not success. A giant monolithic
fallback file is not success. A plausible-looking project with no behavioral proof is not success.

## Current validated state

The strongest validated repository facts as of March 30, 2026 are:

- the native `recompile` path no longer hard-blocks on a missing or unhealthy Ghidra server for PE inputs
- the tracked strict GA report is green
- a repo-local Ralph-style execute/verify/retry loop exists for source-binary benchmarks
- direct `hexyl` fallback recompilation succeeds and produces GCC and Clang candidates
- the bounded local native fallback now reaches CLI-adjacent and output-adjacent regions in the direct `hexyl`
  source, including `GetCommandLineW`, `GetStdHandle`, `WriteConsoleW`, `NtWriteFile`, and their immediate setup
  blocks
- the active native blocker is now runtime semantics at critical output-path APIs rather than pure output discovery

The strongest validated non-facts are:

- the repo does not yet reconstruct arbitrary native targets into readable, organized, behavior-matched projects
- the repo does not yet reconstruct arbitrary JavaScript/npm packages into a rebuildable source tree
- the repo does not yet justify claims like "fully reverse engineered any exe"
- the bug-report and exploit-development vision is not yet grounded on a trustworthy semantic reconstruction layer

## Supported-target strategy

The roadmap needs explicit support tiers.

### Tier 1: first-wave supported targets

These are the targets the platform should prove first:

- Windows native CLIs built in Rust
- Windows native CLIs built in C or C++
- Linux native CLIs built in Rust
- small to medium ELF utilities with source available for evaluation
- bundled Node/npm CLIs
- unbundled npm packages with a CLI or module entrypoint

### Tier 2: second-wave targets

Only after Tier 1 is solid:

- moderately complex Electron applications
- mixed native and JavaScript desktop applications
- stripped commercial CLIs without direct source access but with behavior validation harnesses
- larger bundle graphs with code splitting and plugin systems

### Tier 3: explicitly deferred or unsupported for now

These should not be used to market false completeness:

- kernel targets
- heavily packed or protected binaries
- self-modifying or JIT-heavy targets outside the supported JS runtime model
- malware-grade anti-analysis targets
- large GUI-first applications without a validated evaluation strategy

## Platform tracks

### Track A: gold evaluation corpus

This is the anchor the current repo needed earlier and now must have.

#### Objective

Build a source-of-truth evaluation corpus that pairs original source with compiled or bundled artifacts.

#### Native corpus requirements

At minimum:

- `hexyl`
- `fd`
- `hyperfine`
- one C CLI
- one C++ CLI
- one Go CLI
- one stripped PE with known source
- one stripped ELF with known source

For each target, store or define:

- source repo snapshot or vendored source fixture
- build recipe
- produced artifacts
- strip mode and optimization mode
- expected commands
- expected stdout and stderr
- expected exit codes
- expected filesystem side effects where relevant
- expected validation tier

#### JavaScript/npm corpus requirements

At minimum:

- one unbundled npm CLI
- one webpack-bundled CLI
- one esbuild-bundled CLI
- one rollup-bundled CLI
- one real-world open source CLI with a moderate module graph
- one package with mixed JS and TS outputs
- the local `C:\dev\projects\claude-code-main` tree as an explicit source-side oracle for the bundled `cli.js` reconstruction track

For each target, store or define:

- original package source
- lockfile
- package metadata
- built or bundled distribution artifact
- expected command behavior
- expected output snapshots
- expected module graph or source tree anchors
- for `cli.js`-style targets, a checked-out oracle source tree that can be diffed directly against `artifacts/reconstructed_project/`

#### Acceptance

The platform cannot claim maturity without a gold corpus that has:

- reproducible inputs
- reproducible expected outputs
- automated comparison harnesses
- tracked results in CI

### Track B: unified intermediate representation

The platform needs a canonical IR instead of target-specific one-off outputs.

#### Objective

Create a shared IR that both native and JavaScript reconstruction flows emit and consume.

#### IR responsibilities

- modules or files
- functions or methods
- imports and exports
- globals and constants
- strings and resources
- control-flow shape
- call graph
- data-flow hints
- recovered types
- provenance
- uncertainty markers
- synthetic patches and shims

#### Acceptance

- native and JavaScript pipelines both emit the same core IR contract
- source generation traces back to IR provenance
- validation reports can point back to IR elements instead of raw ad hoc text

### Track C: native reverse-compilation engine

This is the native platform core, beyond the current bounded fallback.

#### Objective

Recover enough structure and semantics from supported native targets to emit readable multi-file source and rebuild
behavior-matching artifacts.

#### Capability areas

- multi-engine analysis orchestration:
  - Ghidra when available
  - local Capstone fallback
  - CFG and data-flow augmentation
  - import, thunk, and resource analysis
  - unwind and exception metadata where available
- function-boundary recovery:
  - direct calls
  - indirect calls
  - jump tables
  - thunks
  - tail calls
  - entry and main discovery
- semantic recovery:
  - argv and env handling
  - console and output handling
  - filesystem IO
  - allocator model
  - encoding conversion
  - runtime helper recognition
  - Rust patterns
  - Go patterns
  - C++ RTTI and vtable patterns where applicable
- structured project synthesis:
  - module clustering
  - header and source separation
  - build manifests
  - runtime shim library
  - stable synthetic naming
  - uncertainty comments and gap manifests

#### Acceptance

- first-wave native corpus targets emit multi-file reconstructed projects
- those projects rebuild successfully
- deterministic behavior checks reach at least `partial_equivalence` for the supported corpus

### Track D: JavaScript and npm reverse-compilation engine

This must be a first-class capability, not a future note.

#### Objective

Recover bundled or packaged JavaScript/npm applications into organized, readable, rebuildable source trees.

#### Capability areas

- bundle and package detection:
  - webpack
  - esbuild
  - rollup
  - parcel
  - plain Node/CommonJS
  - ESM packages
- JS IR extraction:
  - module graph
  - import and export relationships
  - source map usage when present
  - chunk boundaries
  - CommonJS and ESM normalization
  - config and environment boundaries
- source regeneration:
  - organized module tree
  - readable JS or TS
  - reconstructed package metadata
  - rebuildable project structure
  - synthetic annotations where gaps remain
- behavior validation:
  - CLI parity
  - module behavior parity
  - package script parity
  - rebuild validation where possible

#### Acceptance

Before claiming support for targets like Anthropic CLI or Cursor-like packaged apps, the system should first recover at
least one open-source bundled CLI into a readable, rebuildable multi-file project with tracked behavior checks.

### Track E: validation and scoring engine

This is what turns "interesting output" into evidence.

#### Objective

Score reconstructed outputs against originals in a way that is machine-readable, reproducible, and honest.

#### Scoring dimensions

- build success
- launch success
- CLI behavior parity
- stdout and stderr parity
- filesystem side-effect parity
- network side-effect parity where applicable
- module or function coverage
- symbol or naming recovery
- source readability
- shim reliance
- unresolved-gap count

#### Status tiers

- `compile_only_candidate`
- `launches_but_divergent`
- `partial_equivalence`
- `behavior_match`
- `source_reconstruction_match`

#### Acceptance

- all benchmark reports include these scores
- regressions are visible in CI
- direct runs and tracked runs use the same grading language

### Track F: Ralph loop as the outer optimization harness

The Ralph loop should orchestrate improvement, not just perform blind retries.

#### Objective

Use a bounded execute, verify, classify, retry loop to drive the highest-value repair families automatically.

#### Loop responsibilities

1. run analysis
2. run reconstruction
3. rebuild artifacts
4. execute deterministic validation checks
5. compare behavior against gold expectations
6. classify the failure family
7. select the next repair family or stop on plateau
8. preserve the best attempt and its evidence

#### Example repair families

- function-boundary expansion
- output-path promotion
- runtime-shim activation
- naming or type recovery
- module clustering adjustment
- JS bundle unflattening
- source formatting and organization cleanup

#### Acceptance

- attempts are ranked by validation improvement, not only by compilation success
- plateau reasons are recorded
- best-attempt artifacts are retained
- loop metadata is part of tracked benchmark reports

### Track G: runtime shim library

The platform will need a controlled, explicit shim layer.

#### Objective

Provide minimal, transparent runtime behavior for recovered code where direct semantic reconstruction is not yet enough
to execute meaningful validation paths.

#### Native shim categories

- console handles
- output writers
- argv and env helpers
- encoding conversion helpers
- allocator or runtime helpers
- filesystem IO wrappers
- selected synchronization helpers

#### JavaScript shim categories

- process and env surfaces
- fs, path, and os runtime helpers
- CLI parser environment
- terminal capability detection

#### Rules

- shim usage must be explicit and measurable
- shim usage must appear in reports
- shims should preserve behavior where possible rather than only return zero
- broad fake runtimes are out of scope

### Track H: readable source reconstruction quality

The platform is not done if it only emits machine-shaped code.

#### Objective

Produce reconstructed source trees that a human can navigate, reason about, and modify.

#### Quality targets

- module or file naming
- subsystem clustering
- stable symbol naming
- decompiler provenance comments
- uncertainty markers
- gap manifests
- per-project generated README
- build instructions for the reconstructed project

#### Acceptance

- a recovered project is navigable like a real repository
- humans can identify major subsystems without parsing one giant fallback file

### Track I: bug discovery and vendor report generation

This belongs after reconstruction and validation are trustworthy enough.

#### Objective

Generate vendor-grade bug reports from validated findings rooted in recovered semantics and execution evidence.

#### Workflow

1. analyze target
2. reconstruct semantics
3. run static and dynamic finding passes
4. validate the finding against observed behavior
5. generate a vendor-ready report

#### Report contents

- summary
- target and version
- affected component
- root cause
- impact
- reproduction steps
- proof artifacts
- confidence score
- suggested remediation

#### Acceptance

- only validated findings are reported
- speculative reconstructed code does not get turned into vendor claims

### Track J: exploit-development layer

This is a later layer, not the core reconstruction milestone.

#### Objective

Support exploit-development workflows on authorized targets once finding quality is already high.

#### Scope

- crash triage
- root-cause localization
- proof-of-concept harness generation
- exploit primitive classification

#### Guardrails

- only for authorized targets
- explicitly separated from reconstruction core
- auditable and gated

## Cross-cutting engineering requirements

The roadmap only succeeds if these are treated as mandatory, not optional cleanup.

### 1. contract discipline

- stable result contracts
- stable CLI and API outputs
- provenance in every important artifact

### 2. testing discipline

- regression tests for every frontier-moving fix
- corpus-backed behavior tests
- IR contract tests
- rebuild tests
- loop policy tests
- shim usage tests

### 3. evidence discipline

- tracked reports outrank one-off claims
- docs and paper must cite tracked evidence
- unsupported targets must be called unsupported

### 4. source-of-truth discipline

The following must agree after every significant tracked refresh:

- `docs/architecture/reverse-compilation-master-roadmap.md`
- `docs/architecture/reveng-world-class-implementation-roadmap.md`
- `docs/architecture/reveng-world-class-execution-backlog.md`
- `docs/architecture/reveng-system-paper.md`

## Parallel delivery model

This platform should be executed as a coordinated multi-lane program, not a single heroic thread.

### Required lanes

- corpus and benchmark lane
- IR and provenance lane
- native analysis lane
- native codegen and runtime lane
- JS/npm reconstruction lane
- validation and equivalence lane
- product surface lane
- bug-report and exploit-readiness lane

### Coordination rule

The integration owner should keep tracked reports and source-of-truth docs aligned, while worker lanes ship changes
inside clearly owned surfaces. Native analysis, native codegen, and validation can advance in parallel, but they
should converge through shared report contracts and tracked benchmark reruns rather than informal local claims.

### Subagent policy

When agent capacity is available:

- use explorer subagents for codebase reconnaissance, benchmark gap mapping, and research intake
- use worker subagents for bounded code changes on disjoint write surfaces
- keep one integration lane local so cross-lane report truth and doc updates remain coherent

## Milestone map

### M1: gold corpus foundation

Deliver:

- first-wave native corpus
- first-wave JS/npm corpus
- reproducible build recipes
- deterministic validation harnesses

### M2: unified IR

Deliver:

- shared IR contract
- native IR emitters
- JS IR emitters
- provenance-bearing IR artifacts

### M3: native multi-file reconstruction

Deliver:

- project synthesis instead of one giant fallback file
- runtime shim library
- rebuild manifests
- tracked native behavior scoring

### M4: JS/npm reconstruction

Deliver:

- bundle detection
- module graph recovery
- multi-file source regeneration
- rebuildable package structure

### M5: behavior equivalence engine

Deliver:

- richer grading tiers
- side-effect-aware validation
- normalized diff engine
- tracked behavior reports across the gold corpus

### M6: Ralph-loop optimization harness

Deliver:

- repair-family orchestration
- best-attempt retention
- plateau detection
- tracked loop metadata

### M7: bug-report layer

Deliver:

- validated finding generation
- vendor-ready reporting templates
- confidence-scored evidence output

### M8: exploit-development layer

Deliver:

- crash triage support
- proof-of-concept harness generation
- exploit primitive classification

## Priority order

This roadmap should be executed in this order:

1. build the gold corpus
2. build the unified IR
3. replace monolithic outputs with multi-file reconstruction
4. build behavior-backed validation
5. make the Ralph loop optimize against those validation metrics
6. prove the system on open-source native and JavaScript targets
7. only then scale to harder commercial targets
8. only then layer bug-report generation and exploit-development workflows on top

## Explicit examples

### Anthropic CLI or other bundled JS target

The platform should:

- detect bundle style
- recover module graph
- emit a readable multi-file project
- rebuild the package
- pass deterministic CLI checks

### Droid.exe or arbitrary native executable

The platform should:

- detect target class and runtime
- recover a structured IR
- emit an organized project
- rebuild a candidate artifact
- pass deterministic behavior checks where the target is inside the supported class
- explicitly report unsupported gaps where it is not

### Cursor or other large mixed apps

These are phase-two targets that should only be attempted after first-wave native and JavaScript targets are already
working in tracked evaluation.

## Hard truth

The repository already has useful foundations:

- CLI and result contracts
- tracked reports
- native fallback infrastructure
- Ralph-loop scaffolding
- evidence-aware documentation

But those foundations are not the same thing as a finished reverse-compilation platform. The biggest strategic gap has
been the lack of a rigorous gold corpus and source-comparison discipline across open-source targets. This roadmap fixes
that by making a source-of-truth benchmark corpus and behavior-backed validation part of the definition of success.

## Relationship to the current execution backlog

The current `hexyl` frontier remains important because it is the lead native validation problem. But it is only one
slice of the full platform. The execution backlog should continue to drive the near-term work, while this document
holds the broader standard for what the repository is ultimately supposed to become.
