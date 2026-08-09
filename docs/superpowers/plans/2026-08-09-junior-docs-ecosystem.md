# Junior Docs Ecosystem Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a Diátaxis dual-track (analyst + engineer) documentation ecosystem with maturity badges, wired through README + MkDocs, honest against `support_matrix.json`.

**Architecture:** New `docs/support|tutorials|how-to|explanation|reference|ops` trees; rewrite `docs/README.md` + `mkdocs.yml` + root `README.md` Documentation section; honesty-fix MCP/getting-started/cli-usage/API paths; leave CEO/thinktank under ops pointer.

**Tech Stack:** Markdown, MkDocs Material, existing `docs/support_matrix.json`.

## Global Constraints

- Python floor 3.9; no fictional capability claims
- Maturity badges on every feature-oriented page
- Named-path commits only if committing; no stash
- Prefer `/usr/bin/python3.9` for any verification scripts

---

### Task 1: Spine (support + index + nav)

- [x] Write `docs/support/maturity-badges.md`, `honesty-rules.md`, complete `support-matrix.md`, `reading-validation-grades.md`
- [x] Rewrite `docs/README.md` as dual-door home
- [x] Rewrite `mkdocs.yml` nav
- [x] Update root `README.md` Documentation section
- [x] Add `docs/ops/README.md`

### Task 2: Tutorials + analyst how-tos

- [x] Analyst tutorials 01–03; engineer tutorials 01–02
- [x] Analyst how-tos: triage-pe, yara-vt, bun, ghidra-required, per-language app RE

### Task 3: Explanation + engineer how-tos

- [x] Explanation pages: architecture, analysis pipeline, app RE dispatch, VRL, result contracts, Ghidra boundary, AI providers, pipeline-vs-pipelines, security/exploits
- [x] Engineer how-tos: add-adapter, extend-cli, wire-mcp-tool, update-support-matrix, scoped-git

### Task 4: Reference + honesty fixes

- [x] Reference: cli, python-api, mcp-tools, config-env, corpus-ga-scripts
- [x] Honesty rewrite `docs/mcp/README.md`; fix dead paths in cli-usage / overview / DEVELOPER_GUIDE / API_REFERENCE; align getting-started with `reverse-engineer-app`

### Task 5: Audit

- [x] Fresh subagent scores depth/honesty/link graph; fix nits; confirm README↔MkDocs↔Support consistency
