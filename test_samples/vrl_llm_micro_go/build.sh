#!/usr/bin/env bash
# Build the original ELF for the VRL-LLM honesty micro subject.
# Output is gitignored (*.bin); dogfood / corpus consumers rebuild as needed.
# Only main.go is the original; broken_main.go is the control candidate (separate).
set -euo pipefail
cd "$(dirname "$0")"
CGO_ENABLED=0 go build -o micro.bin ./main.go
echo "built $(pwd)/micro.bin"
