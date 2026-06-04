"""
Adapter that wraps SmartCompiler into the compile_fn callable expected by IterativeRefiner.

The IterativeRefiner accepts a ``compile_fn: Callable[[str], Path]`` — a
synchronous callable that takes C source text and returns a :class:`Path` to the
compiled binary.

This module provides :func:`make_compile_fn` which wires up the
gcc → clang → msvc fallback chain from :class:`SmartCompiler` into that
contract, without requiring any ``async`` machinery from the caller.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable


def make_compile_fn(workspace_dir: Path | str | None = None) -> Callable[[str], Path]:
    """
    Return a ``compile_fn`` callable compatible with :class:`IterativeRefiner`.

    The returned callable has the signature ``(c_source: str) -> Path`` and:

    1. Computes an MD5 hash of *c_source* to derive deterministic filenames.
    2. Writes *c_source* to ``vrl_source_{hash[:8]}.c`` inside the workspace
       directory (or the system temp directory when *workspace_dir* is
       ``None``).
    3. Attempts to compile using the gcc → clang → msvc fallback chain,
       mirroring :class:`~reveng.compilation.SmartCompiler` behaviour.
    4. Returns a :class:`Path` pointing to the compiled binary.

    Files are **never** auto-cleaned by this function; callers are responsible
    for cleanup.  Retaining files is intentional for debugging the VRL loop.

    Args:
        workspace_dir:
            Directory where source and binary files are placed.  Created if it
            does not exist.  When ``None`` the system temp directory is used
            (a new directory is *not* created — files land directly in the
            system temp root, or in whatever ``tempfile.gettempdir()`` returns).

    Returns:
        A synchronous callable ``(c_source: str) -> Path``.

    Raises:
        RuntimeError:
            Re-raised from the underlying compiler calls if all compilers in
            the fallback chain fail to produce a binary.
    """
    # Resolve and optionally create the workspace directory once at factory time.
    if workspace_dir is not None:
        resolved_dir = Path(workspace_dir)
        resolved_dir.mkdir(parents=True, exist_ok=True)
    else:
        resolved_dir = Path(tempfile.gettempdir())

    def _compile(c_source: str) -> Path:
        # Derive a short, deterministic identifier from source content.
        content_hash = hashlib.md5(c_source.encode("utf-8", errors="replace")).hexdigest()
        short_hash = content_hash[:8]

        source_path = resolved_dir / f"vrl_source_{short_hash}.c"
        binary_suffix = ".exe" if sys.platform == "win32" else ""
        binary_path = resolved_dir / f"vrl_binary_{short_hash}{binary_suffix}"

        # Write source to disk.
        source_path.write_text(c_source, encoding="utf-8")

        # Freshness: remove any stale binary left over from a previous run with
        # the same content hash.  Otherwise a compiler that silently fails to
        # emit a fresh artifact could leave us returning an outdated binary.
        if binary_path.exists():
            binary_path.unlink()

        # Try compilers in fallback order: gcc → clang → cl (MSVC).
        compilers = ["gcc", "clang", "cl"]
        last_error: str = ""

        for compiler in compilers:
            try:
                if compiler == "cl":
                    # MSVC uses different flag conventions.
                    cmd = [compiler, str(source_path), f"/Fe{binary_path}", "/nologo"]
                else:
                    cmd = [compiler, str(source_path), "-o", str(binary_path)]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=60,
                    shell=False,
                )
                if result.returncode == 0:
                    # A zero exit code must be backed by a real artifact on
                    # disk; otherwise treat it as a failure and fall through to
                    # the next compiler rather than returning a phantom path.
                    if binary_path.exists():
                        return binary_path
                    last_error = (
                        f"{compiler}: returncode 0 but no binary at {binary_path}"
                    )
                    continue

                last_error = result.stderr.decode(errors="replace")

            except FileNotFoundError:
                # Compiler not installed — try next.
                last_error = f"{compiler}: not found"
                continue
            except subprocess.TimeoutExpired:
                last_error = f"{compiler}: compilation timeout"
                continue

        raise RuntimeError(
            f"All compilers failed for vrl_source_{short_hash}. " f"Last error: {last_error}"
        )

    return _compile
