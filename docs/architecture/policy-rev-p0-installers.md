# Policy — REV-P0-INSTALLERS (Wave 1)

**Status:** deprecate stubs (Wave 1). Finish real installers = future Sol-gated work.

## Scope

`DependencyManager` maps these tools to `None` installers:

- `dnspy`, `uncompyle6`, `exeinfo_pe`, `x64dbg`, `imhex`, `lordpe`
- (plus any Windows-only None entries when not on Windows)

## Rules

1. **Never report install success** for a None stub (`InstallationResult.success` must be `False`).
2. Status must use `install_method="deprecated_stub"`.
3. `error_message` must include the stable token `deprecated_stub` (may also say `not supported`).
4. Do **not** assert host `is_installed` for honesty — a manually installed tool may exist on PATH; honesty is about **installer support**, not host inventory.
5. Callers must treat `deprecated_stub` as unsupported for auto-install UX.

## Non-goals

Implementing full installers for dnSpy / x64dbg / etc. in Wave 1.
