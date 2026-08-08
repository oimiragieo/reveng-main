# Native micro-CLI fixtures (C + Go)

These binaries exist so REVENG can **measure** native analyze behavior on tiny,
hermetic inputs. They are **analysis fixtures**, not a demonstration that REVENG
analyzes native binaries successfully.

**No GA claim attaches to their presence.** Measured analyze outcomes live in
`reports/native_analyze_probe/` (see `latest.json`).

## Host note (this WSL dogfood box)

`cc`/`clang` link may fail with `libc.so.6: unknown type … .relr.dyn` (broken
cross-linker vs host libc). **Go fixture still builds** (`CGO_ENABLED=0`).
C sources remain tracked; unit tests **skip** `hello_c` with an actionable
make reason until a working C toolchain is available. Do not treat a skip as
“C fixture works.”


## Toolchain-absent skips

When `cc`/`go` are missing, unit tests skip and may emit
`NATIVE_FIXTURE_SKIPPED: <name> reason=<...>`. **Consumer today: none** — the
marker exists so a future CI job can count skips. Until that job exists, the
marker is a visibility aid, not coverage.
