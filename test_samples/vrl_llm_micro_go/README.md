# VRL LLM micro Go subject

Linux-hermetic CLI used by `scripts/dogfood_vrl_llm_honesty.py` when the C
toolchain cannot link on WSL (`vrl_compile_toolchain_broken` for hexyl/PE).

- `main.go` — behavior-correct original (`argv[1]` or `ok`)
- `broken_main.go` — control candidate (always `WRONG`)
- Seeds (argv): `--help`, `--version`, `sample`

Build original: `bash build.sh` (or `CGO_ENABLED=0 go build -o micro.bin ./main.go`).
Do not `go build .` — `broken_main.go` also declares `main`.
