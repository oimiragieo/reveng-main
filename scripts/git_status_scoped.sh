#!/usr/bin/env bash
# DF-4: a repo-wide `git status` hangs on the dirty reports/ tree over DrvFS.
# Always scope with pathspec exclusions; never run a bare status here.
set -euo pipefail

git status --porcelain -- \
  ':(exclude)reports/' \
  ':(exclude)analysis_*' \
  ':(exclude)external/ghidra*' \
  .
